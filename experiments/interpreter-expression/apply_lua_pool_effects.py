"""Apply the shared lifetime effects to a frozen Lua native helper summary."""
from copy import deepcopy
import gzip
from hashlib import sha256
import json

from apply_pool_lifetime import apply_call, state_words
from common_lifetime_effects import LifetimeError, access, apply_effect, get_resource, initialize
from composed_native_transition import parse_segments
from prove_cross_full_flow import ROOT
from trace_lua_pool_lifetime import BINARY

SOURCE = ROOT / "artifacts/lua_pool_source.json.gz"
SUMMARY = ROOT / "lua_pool_native_transition_summary.json"
PROOF = ROOT / "lua_pool_native_refinement_result.json"
RESULT = ROOT / "lua_pool_common_effect_application_result.json"
SPACE = "native_virtual"
DOMAIN = "controlled_lua_string_pool"
CASES = ((0, "source"), (1, "holdout"), (2, "holdout_embedded_nul"))


def resources(meta):
    if ({key: meta[key] for key in ("slots", "capacity", "requested", "alignment", "initial_live")}
            != {"slots": 4, "capacity": 128, "requested": 105,
                "alignment": 16, "initial_live": 0}):
        raise ValueError("Lua pool geometry changed")
    return [{"address_space_id": SPACE, "domain_id": DOMAIN,
             "resource_id": f"pool_slot_{slot}",
             "base": meta["pool_base"] + slot * meta["capacity"],
             "capacity": meta["capacity"], "alignment": meta["alignment"],
             "generation": 0, "live": False, "requested_extent": 0}
            for slot in range(4)]


def words(state):
    entries = [get_resource(state, DOMAIN, f"pool_slot_{slot}") for slot in range(4)]
    return [sum(1 << slot for slot, item in enumerate(entries) if item["live"]),
            *(item["generation"] for item in entries)]


def expected_checksum(seed, index):
    data = [ord("A") + (seed + position * 7 + index * 11) % 26
            for position in range(80)]
    if seed == 2 and index == 1:
        data[17] = 0
    value = 1469598103934665603
    for byte in data:
        value = ((value ^ byte) * 1099511628211) & ((1 << 64) - 1)
    return value


def observed_inventory(run, seed):
    records = run["fixture_records"]
    meta, result = records[0], records[-1]
    events = [row for row in records if row["type"] == "event"]
    objects = [row for row in records if row["type"] == "object"]
    if (meta["type"] != "meta" or meta["seed"] != seed or meta["version"] != 504 or
            result != {"type": "result", "errors": 0, "final_live": 0} or
            len(events) != 6 or len(objects) != 3 or len(run["calls"]) != 6):
        raise ValueError("incomplete Lua allocator/GC observation")
    return meta, events, objects


def require_frozen_requests(run):
    if any(event["requested"] != 105 for event in run["fixture_records"]
           if event["type"] == "event"):
        raise ValueError("allocator request differs from frozen extent")


def run_case(seed, origin, summary, segments, decls, summary_hash, proof_hash):
    path = SOURCE if origin == "source" else ROOT / "artifacts" / f"lua_pool_holdout_{seed}.json.gz"
    with gzip.open(path, "rt") as stream:
        run = json.load(stream)
    if (run["input"] != seed or run["binary_sha256"] != summary["binary_sha256"] or
            run["fixture_source_sha256"] != sha256(BINARY.with_suffix(".c").read_bytes()).hexdigest()):
        raise ValueError("Lua trace/binary/source identity changed")
    meta, events, objects = observed_inventory(run, seed)
    require_frozen_requests(run)
    authority = {"kind": "static_reservations_v1",
        "source_sha256": run["fixture_source_sha256"],
        "initial_state": "declared_reservations"}
    lifetime = initialize(resources(meta), authority)
    trace_hash = sha256(path.read_bytes()).hexdigest()
    native = [0] * 5
    state_address = run["calls"][0]["state_address"]
    effects = []
    reused = None
    native_steps = 0
    for index, (event, call) in enumerate(zip(events, run["calls"])):
        if (event["sequence"] != index or words(lifetime) != native or
                call["state_address"] != state_address or
                state_words(call["state_before"]) != native or
                call["slot"] != event["slot"] or
                call["operation"] != (1 if event["kind"] == "Allocate" else 2)):
            raise ValueError("Lua allocator event and native entry differ")
        before = native[:]
        evidence = {"mode": "native_refined", "cutpoint": "helper_return",
            "trace_sha256": trace_hash, "native_summary_sha256": summary_hash,
            "native_refinement_sha256": proof_hash,
            "preconditions_checked": True, "binding": "observed"}
        applied = apply_call(call, segments, summary, decls, lifetime,
                             evidence, summary_hash, proof_hash, domain=DOMAIN)
        lifetime = applied["next_lifetime"]
        effect = applied["logical_effect"]
        native = applied["after"]
        native_steps += applied["native_steps"]
        if (event["kind"] != effect["kind"] or
                event["requested"] != effect["requested_extent"] or
                event["pointer"] != effect["address"] or
                event["generation"] != effect["generation"] or
                event["live_before"] != before[0] or
                event["live_after"] != native[0] or words(lifetime) != native):
            raise ValueError("Lua allocation/free binding differs from common effect")
        effects.append(effect)
        if index == 3:
            reused = deepcopy(lifetime)
    if native != [0, 2, 1, 0, 0] or reused is None:
        raise ValueError("Lua lifetime state did not close")
    allocations = {(effect["resource_id"], effect["generation"]): effect
                   for effect in effects if effect["kind"] == "Allocate"}
    if len(allocations) != 3:
        raise ValueError("missing string allocation")
    for index, obj in enumerate(objects):
        effect = allocations.get((f"pool_slot_{obj['slot']}", obj["generation"]))
        if (effect is None or obj["pointer"] != effect["address"] or
                obj["data"] != obj["pointer"] + 24 or obj["length"] != 80 or
                obj["checksum"] != expected_checksum(seed, index)):
            raise ValueError("Lua string data and allocator object differ")
    if (objects[0]["pointer"] != objects[2]["pointer"] or
            objects[0]["generation"] != 1 or objects[2]["generation"] != 2 or
            objects[1]["pointer"] == objects[0]["pointer"]):
        raise ValueError("Lua same-address generation reuse absent")
    try:
        access(reused, SPACE, DOMAIN, "pool_slot_0", 1)
    except LifetimeError:
        stale_rejected = True
    else:
        raise ValueError("stale Lua string generation admitted")
    return {"input": seed, "origin": origin, "trace_sha256": trace_hash,
        "native_helper_calls": len(run["calls"]), "native_steps": native_steps,
        "common_effects": len(effects), "allocate": 3, "free": 3,
        "objects": objects, "effects": effects,
        "same_address_new_generation": True,
        "stale_generation_rejected": stale_rejected, "final_live_mask": native[0]}


def rejection_controls(summary, segments, decls, summary_hash, proof_hash):
    with gzip.open(SOURCE, "rt") as stream:
        run = json.load(stream)
    meta = run["fixture_records"][0]
    initial = initialize(resources(meta), {"kind": "static_reservations_v1",
        "source_sha256": run["fixture_source_sha256"],
        "initial_state": "declared_reservations"})
    evidence = {"mode": "native_refined", "cutpoint": "helper_return",
        "trace_sha256": sha256(SOURCE.read_bytes()).hexdigest(),
        "native_summary_sha256": summary_hash,
        "native_refinement_sha256": proof_hash,
        "preconditions_checked": True, "binding": "observed"}
    first = run["calls"][0]
    request = {"kind": "Allocate", "address_space_id": SPACE,
        "domain_id": DOMAIN, "resource_id": "pool_slot_0",
        "address": meta["pool_base"], "requested_extent": 105}
    allocated, _ = apply_effect(initial, request, evidence)
    controls = {}

    def reject(name, state, operation):
        before = deepcopy(state)
        try:
            operation(state)
        except (LifetimeError, ValueError) as error:
            if state != before:
                raise ValueError(f"{name} partially changed input")
            controls[name] = str(error)
        else:
            raise ValueError(f"invalid Lua lifetime case accepted: {name}")

    reject("wrong_request_extent", initial,
           lambda state: apply_effect(state, {**request, "requested_extent": 129}, evidence))
    reject("duplicate_live_allocation", allocated,
           lambda state: apply_effect(state, request, evidence))
    reject("free_before_allocate", initial,
           lambda state: apply_effect(state, {**request, "kind": "Free", "generation": 1}, evidence))
    reject("wrong_generation", allocated,
           lambda state: apply_effect(state, {**request, "kind": "Free", "generation": 2}, evidence))
    reject("native_lifetime_entry_mismatch", allocated,
           lambda state: apply_call(first, segments, summary, decls, state,
                                   evidence, summary_hash, proof_hash, domain=DOMAIN))
    changed = deepcopy(segments["allocate"])
    changed["logical_effect"]["requested_extent"] = 80
    reject("frozen_extent_tamper", initial,
           lambda state: apply_call(first, {**segments, "allocate": changed},
               summary, decls, state, evidence, summary_hash, proof_hash, domain=DOMAIN))
    changed = deepcopy(segments["allocate"])
    changed["logical_effect"] = None
    reject("missing_effect", initial,
           lambda state: apply_call(first, {**segments, "allocate": changed},
               summary, decls, state, evidence, summary_hash, proof_hash, domain=DOMAIN))
    changed_run = deepcopy(run)
    changed_run["fixture_records"] = [row for row in changed_run["fixture_records"]
                                      if row.get("sequence") != 2]
    reject("missing_gc_free_event", initial,
           lambda state: observed_inventory(changed_run, 0))
    changed_run = deepcopy(run)
    changed_run["fixture_records"][1]["requested"] = 106
    reject("allocator_request_observation_changed", initial,
           lambda state: require_frozen_requests(changed_run))
    return controls


def main():
    summary = json.loads(SUMMARY.read_text())
    proof = json.loads(PROOF.read_text())
    summary_hash = sha256(SUMMARY.read_bytes()).hexdigest()
    proof_hash = sha256(PROOF.read_bytes()).hexdigest()
    if (summary["binary_sha256"] != sha256(BINARY.read_bytes()).hexdigest() or
            summary["source_trace_sha256"] != sha256(SOURCE.read_bytes()).hexdigest() or
            proof["summary_sha256"] != summary_hash or
            any(len(proof["proofs"][name]) != 4 for name in ("allocate", "release")) or
            any(value != "unsat" for group in proof["proofs"].values()
                for item in group for key, value in item.items() if key != "slot")):
        raise ValueError("frozen Lua native proof identity changed")
    decls, segments = parse_segments(summary, {"allocate", "release"})
    cases = [run_case(seed, origin, summary, segments, decls,
                      summary_hash, proof_hash) for seed, origin in CASES]
    controls = rejection_controls(summary, segments, decls, summary_hash, proof_hash)
    report = {"schema_version": "lua-common-lifetime-effect-v1",
        "native_summary_sha256": summary_hash,
        "native_refinement_sha256": proof_hash,
        "cases": cases, "rejection_controls": controls,
        "evidence_boundary": {
            "native_helper": "conditional full-byte-memory refinement",
            "lua_binding": "observed allocator callback, string content and GC frees",
            "initial_resources": "fixture-declared finite static reservations"},
        "limits": ["only 80-byte Lua long strings, 105-byte allocation requests, and controlled pool",
                   "other Lua allocations, arbitrary GC reachability, realloc and failure are unknown"]}
    RESULT.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"cases": len(cases),
        "native_helper_calls": sum(c["native_helper_calls"] for c in cases),
        "common_effects": sum(c["common_effects"] for c in cases),
        "rejections": len(controls)}))


if __name__ == "__main__":
    main()
