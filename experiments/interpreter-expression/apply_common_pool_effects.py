"""Compose generic ownership effects with frozen native CPython pool segments."""
from copy import deepcopy
from hashlib import sha256
import json

from apply_pool_lifetime import (CASES, PROOF, ROOT, SUMMARY, apply_call,
                                 load_run, state_words)
from common_lifetime_effects import (LifetimeError, access, apply_effect,
                                     get_resource, initialize)
from composed_native_transition import parse_segments
from trace_python_pool_lifetime import BINARY


RESULT = ROOT / "common_pool_effect_application_result.json"
SPACE = "native_virtual"
DOMAIN = "controlled_obj_pool"


def resources(meta):
    if (meta["slots"] != 4 or meta["capacity"] != 32 or
            meta["requested"] != 32 or meta["alignment"] != 16 or
            meta["initial_live"] != 0):
        raise ValueError("controlled pool geometry changed")
    return [{"address_space_id": SPACE, "domain_id": DOMAIN,
             "resource_id": f"pool_slot_{slot}",
             "base": meta["pool_base"] + slot * meta["capacity"],
             "capacity": meta["capacity"], "alignment": meta["alignment"],
             "generation": 0, "live": False, "requested_extent": 0}
            for slot in range(meta["slots"])]


def mask_and_generations(state):
    entries = [get_resource(state, DOMAIN, f"pool_slot_{slot}")
               for slot in range(4)]
    return [sum((1 << slot) for slot, item in enumerate(entries) if item["live"]),
            *(item["generation"] for item in entries)]


def verify_snapshots(records, effects, value):
    if (len(records) != 18 or records[0]["type"] != "meta" or
            records[-1]["type"] != "result" or
            records[0]["version"] != "3.13.5" or
            records[0]["base_value"] != value or
            records[-1]["errors"] != 0 or records[-1]["final_live"] != 0 or
            records[-1]["cached_path_pool_allocations"] != 0):
        raise ValueError("incomplete CPython fixture inventory")
    objects = [row for row in records if row["type"] == "object"]
    if len(objects) != 5 or len(effects) != 11:
        raise ValueError("incomplete object snapshots or effects")
    allocations = {(int(effect["resource_id"].removeprefix("pool_slot_")),
                    effect["generation"]): effect for effect in effects
                   if effect["kind"] == "Allocate"}
    keys = [(obj["slot"], obj["generation"]) for obj in objects]
    if len(allocations) != 5 or len(set(keys)) != 5 or set(keys) != set(allocations):
        raise ValueError("object snapshots and allocations are not bijective")
    type_pointers = {obj["type_pointer"] for obj in objects}
    if len(type_pointers) != 1 or 0 in type_pointers:
        raise ValueError("inconsistent observed PyLong type")
    for index, obj in enumerate(objects):
        effect = allocations[(obj["slot"], obj["generation"])]
        if (obj["pointer"] != effect["address"] or
                obj["value"] != value + index or obj["refcount"] != 1 or
                obj["size_tag"] != 16 or
                obj["digit_low"] != obj["value"] & ((1 << 30) - 1) or
                obj["digit_high"] != obj["value"] >> 30):
            raise ValueError("PyLong snapshot differs from lifetime identity")
    return {"constructed_objects": len(objects), "snapshot_bytes": 32 * len(objects),
            "object_identity_keys": len(keys)}


def observed_event_matches(event, effect, before, after):
    if (event["kind"] != effect["kind"] or
            event["requested"] != effect["requested_extent"] or
            event["live_before"] != before[0] or
            event["live_after"] != after[0]):
        return False
    if effect["kind"] == "AllocationFailed":
        return (event["slot"] == 4 and event["generation"] == 0 and
                event["pointer"] == 0 and before == after and
                effect["lifetime_state_preserved"] is True)
    return (event["slot"] == int(effect["resource_id"].removeprefix("pool_slot_")) and
            event["generation"] == effect["generation"] and
            event["pointer"] == effect["address"])


def apply_case(value, origin, summary, decls, segments, summary_hash, proof_hash):
    run, trace_path = load_run(value, origin, summary)
    trace_hash = sha256(trace_path.read_bytes()).hexdigest()
    records = run["fixture_records"]
    meta = records[0]
    authority = {"kind": "static_reservations_v1",
        "source_sha256": run["fixture_source_sha256"],
        "initial_state": "declared_reservations"}
    lifetime = initialize(resources(meta), authority)
    initial_lifetime = deepcopy(lifetime)
    events = [row for row in records if row["type"] == "event"]
    if len(events) != 11 or len(run["calls"]) != 10:
        raise ValueError("incomplete event/helper inventory")
    native_state = [0] * 5
    state_address = run["calls"][0]["state_address"]
    effects = []
    first_live = None
    reused_state = None
    call_index = 0
    for sequence, event in enumerate(events):
        if event["sequence"] != sequence:
            raise ValueError("noncontiguous allocator event history")
        before = mask_and_generations(lifetime)
        if before != native_state:
            raise ValueError("native state and prior ownership state diverged")
        if event["kind"] == "AllocationFailed":
            if (event["requested"] != meta["requested"] or before[0] != 15 or
                    any(not resource["live"] for resource in lifetime["resources"])):
                raise ValueError("controlled pool was not exhausted")
            native_before = native_state[:]
            owned_before = deepcopy(lifetime["resources"])
            lifetime, effect = apply_effect(lifetime,
                {"kind": "AllocationFailed", "domain_id": DOMAIN,
                 "requested_extent": meta["requested"],
                 "reason": "observed_allocator_exhaustion"},
                {"mode": "observed", "cutpoint": "allocator_failure",
                 "trace_sha256": trace_hash})
            if native_state != native_before or lifetime["resources"] != owned_before:
                raise ValueError("failure changed native pool state")
        else:
            if call_index >= len(run["calls"]):
                raise ValueError("event lacks native helper call")
            call = run["calls"][call_index]
            call_index += 1
            if (call["state_address"] != state_address or
                    state_words(call["state_before"]) != native_state or
                    call["slot"] != event["slot"] or
                    call["operation"] != (1 if event["kind"] == "Allocate" else 2)):
                raise ValueError("event and native helper input disagree")
            evidence = {"mode": "native_refined", "cutpoint": "helper_return",
                "trace_sha256": trace_hash,
                "native_summary_sha256": summary_hash,
                "native_refinement_sha256": proof_hash,
                "preconditions_checked": True, "binding": "observed"}
            result = apply_call(call, segments, summary, decls, lifetime,
                                evidence, summary_hash, proof_hash)
            lifetime = result["next_lifetime"]
            effect = result["logical_effect"]
            native_state = result["after"]
            if mask_and_generations(lifetime) != native_state:
                raise ValueError("native helper and generic effect state disagree")
            if sequence == 0:
                first_live = deepcopy(lifetime)
            if sequence == 3:
                reused_state = deepcopy(lifetime)
        after = mask_and_generations(lifetime)
        if not observed_event_matches(event, effect, before, after):
            raise ValueError("observed allocator event differs from derived effect")
        effects.append(effect)
    if (call_index != len(run["calls"]) or native_state != [0, 2, 1, 1, 1] or
            mask_and_generations(lifetime) != native_state or
            any(resource["live"] for resource in lifetime["resources"])):
        raise ValueError("composed lifetime did not close")
    if (lifetime["resources"] == initial_lifetime["resources"] or
            len(lifetime["events"]) != 11 or
            effects[6]["evidence"]["mode"] != "observed" or
            "native_refinement_sha256" in effects[6]["evidence"]):
        raise ValueError("lifetime identity or failure evidence was lost")
    snapshots = verify_snapshots(records, effects, value)
    if first_live is None or reused_state is None:
        raise ValueError("missing address reuse witness")
    old_id = effects[0]["identity"]
    new_id = effects[3]["identity"]
    if (old_id[:2] != new_id[:2] or old_id[2] != 1 or new_id[2] != 2 or
            effects[0]["address"] != effects[3]["address"]):
        raise ValueError("same-address new-generation identity missing")
    try:
        access(reused_state, SPACE, DOMAIN, "pool_slot_0", 1)
    except LifetimeError:
        stale_generation_rejected = True
    else:
        raise ValueError("stale generation access was admitted")
    return {"input": value, "origin": origin,
        "trace_sha256": trace_hash, "native_helper_calls": call_index,
        "common_effects": len(effects), "effects": effects,
        "allocate": sum(effect["kind"] == "Allocate" for effect in effects),
        "free": sum(effect["kind"] == "Free" for effect in effects),
        "allocation_failed_observed": 1,
        "failure_has_native_refinement": False,
        "stale_generation_rejected": stale_generation_rejected,
        "same_address_new_identity": [old_id, new_id],
        "final_live_mask": native_state[0], "snapshots": snapshots,
        "status": "common_effects_composed_with_native_summary"}


def rejection_controls(summary, decls, segments, summary_hash, proof_hash):
    run, trace_path = load_run(CASES[0][0], CASES[0][1], summary)
    meta = run["fixture_records"][0]
    initial = initialize(resources(meta), {"kind": "static_reservations_v1",
        "source_sha256": run["fixture_source_sha256"],
        "initial_state": "declared_reservations"})
    trace_hash = sha256(trace_path.read_bytes()).hexdigest()
    evidence = {"mode": "native_refined", "cutpoint": "helper_return",
        "trace_sha256": trace_hash, "native_summary_sha256": summary_hash,
        "native_refinement_sha256": proof_hash,
        "preconditions_checked": True, "binding": "observed"}
    base = resources(meta)[0]["base"]
    request = {"kind": "Allocate", "address_space_id": SPACE,
        "domain_id": DOMAIN, "resource_id": "pool_slot_0", "address": base,
        "requested_extent": 32}
    after_first, _ = apply_effect(initial, request, evidence)
    controls = {}

    def reject(name, state, proposed, proof=evidence):
        before = deepcopy(state)
        try:
            apply_effect(state, proposed, proof)
        except LifetimeError as error:
            if state != before:
                raise ValueError(f"{name} partially changed input lifetime state")
            controls[name] = str(error)
        else:
            raise ValueError(f"invalid common effect admitted: {name}")

    reject("duplicate_allocate", after_first, request)
    reject("wrong_extent", initial, {**request, "requested_extent": 33})
    reject("interior_address", initial, {**request, "address": base + 1})
    reject("free_before_allocate", initial,
           {**request, "kind": "Free", "generation": 1})
    reject("wrong_resource", initial, {**request, "resource_id": "pool_slot_9"})
    reject("unknown_kind", initial, {**request, "kind": "Alias"})
    overflow = deepcopy(initial)
    get_resource(overflow, DOMAIN, "pool_slot_0")["generation"] = (1 << 64) - 1
    reject("generation_overflow", overflow, request)
    reject("failure_with_native_proof", after_first,
           {"kind": "AllocationFailed", "domain_id": DOMAIN,
            "requested_extent": 32, "reason": "observed_allocator_exhaustion"}, evidence)
    try:
        initialize(resources(meta) + [{**resources(meta)[0],
            "domain_id": "other_domain", "resource_id": "other"}],
            initial["authority"])
    except LifetimeError as error:
        controls["cross_domain_address_overlap"] = str(error)
    else:
        raise ValueError("cross-domain overlapping resources admitted")
    short = initialize([{**resources(meta)[0], "capacity": 64}],
                       initial["authority"])
    short, _ = apply_effect(short, request, evidence)
    try:
        access(short, SPACE, DOMAIN, "pool_slot_0", 1, offset=33)
    except LifetimeError as error:
        controls["access_uses_requested_extent"] = str(error)
    else:
        raise ValueError("access beyond requested extent admitted")
    changed = deepcopy(segments["allocate"])
    changed["logical_effect"] = None
    before = deepcopy(initial)
    call = run["calls"][0]
    try:
        apply_call(run["calls"][0], {**segments, "allocate": changed}, summary, decls,
                   initial, evidence, summary_hash, proof_hash)
    except ValueError as error:
        if initial != before:
            raise ValueError("missing effect partially changed input state")
        controls["missing_frozen_effect"] = str(error)
    else:
        raise ValueError("missing frozen lifetime effect admitted")
    bad = {**evidence, "native_refinement_sha256": "0" * 64}
    try:
        apply_call(call, segments, summary, decls, initial, bad,
                   summary_hash, proof_hash)
    except ValueError as error:
        if initial != before:
            raise ValueError("wrong proof partially changed input state")
        controls["wrong_proof_reference"] = str(error)
    else:
        raise ValueError("wrong native proof reference admitted")
    for name, call, owned in (
            ("composed_duplicate_allocate", run["calls"][0], after_first),
            ("composed_free_before_allocate", run["calls"][2], initial)):
        before = deepcopy(owned)
        try:
            apply_call(call, segments, summary, decls, owned, evidence,
                       summary_hash, proof_hash)
        except ValueError as error:
            if owned != before:
                raise ValueError(f"{name} partially changed input state")
            controls[name] = str(error)
        else:
            raise ValueError(f"{name} admitted invalid effect order")
    changed_decls, changed_segments = parse_segments(summary, {"allocate", "release"})
    changed_segments["allocate"]["logical_effect"]["requested_extent"] = 16
    if next(item for item in summary["segments"] if item["label"] == "allocate")[
            "logical_effect"]["requested_extent"] != 32:
        raise ValueError("parsed effect mutated the frozen summary")
    before = deepcopy(initial)
    try:
        apply_call(run["calls"][0], changed_segments, summary, changed_decls,
                   initial, evidence, summary_hash, proof_hash)
    except ValueError as error:
        if (initial != before or "lifetime effect contract" not in str(error)):
            raise ValueError("tampered frozen extent was not rejected")
        controls["tampered_frozen_extent"] = str(error)
    else:
        raise ValueError("wrong frozen extent admitted")
    wrong_generation = deepcopy(initial)
    get_resource(wrong_generation, DOMAIN, "pool_slot_0")["generation"] = 5
    before = deepcopy(wrong_generation)
    try:
        apply_call(run["calls"][0], segments, summary, decls,
                   wrong_generation, evidence, summary_hash, proof_hash)
    except ValueError as error:
        if (wrong_generation != before or
                str(error) != "native and lifetime entry state disagree"):
            raise ValueError("wrong generation binding rejection changed")
        controls["native_lifetime_generation_mismatch"] = str(error)
    else:
        raise ValueError("mismatched native and lifetime generations admitted")
    wrong_live = deepcopy(initial)
    other = get_resource(wrong_live, DOMAIN, "pool_slot_1")
    other.update(live=True, generation=1, requested_extent=32)
    before = deepcopy(wrong_live)
    try:
        apply_call(run["calls"][0], segments, summary, decls,
                   wrong_live, evidence, summary_hash, proof_hash)
    except ValueError as error:
        if (wrong_live != before or
                str(error) != "native and lifetime entry state disagree"):
            raise ValueError("wrong live-state binding rejection changed")
        controls["native_lifetime_other_slot_live"] = str(error)
    else:
        raise ValueError("mismatched live slot admitted")
    smaller = deepcopy(initial)
    get_resource(smaller, DOMAIN, "pool_slot_0")["capacity"] = 16
    before = deepcopy(smaller)
    try:
        apply_call(run["calls"][0], segments, summary, decls,
                   smaller, evidence, summary_hash, proof_hash)
    except ValueError as error:
        if (smaller != before or
                "effect violates resource extent or alignment" not in str(error)):
            raise ValueError("post-native lifetime failure was not atomic")
        controls["post_native_capacity_failure_atomic"] = str(error)
    else:
        raise ValueError("resource capacity smaller than allocation admitted")
    return controls


def main():
    summary = json.loads(SUMMARY.read_text())
    proof = json.loads(PROOF.read_text())
    summary_hash = sha256(SUMMARY.read_bytes()).hexdigest()
    proof_hash = sha256(PROOF.read_bytes()).hexdigest()
    if (summary["binary_sha256"] != sha256(BINARY.read_bytes()).hexdigest() or
            summary["source_trace_sha256"] != sha256(
                (ROOT / "artifacts/python_pool_source.json.gz").read_bytes()).hexdigest() or
            summary.get("logical_effect_schema_version") !=
            "common-lifetime-effect-v1" or
            proof["summary_sha256"] != summary_hash or
            any(len(proof["proofs"][name]) != 4
                for name in ("allocate", "release")) or
            any(value != "unsat" for group in proof["proofs"].values()
                for item in group for key, value in item.items() if key != "slot")):
        raise ValueError("frozen native proof identity changed")
    decls, segments = parse_segments(summary, {"allocate", "release"})
    cases = [apply_case(value, origin, summary, decls, segments,
                        summary_hash, proof_hash) for value, origin in CASES]
    controls = rejection_controls(summary, decls, segments,
                                  summary_hash, proof_hash)
    report = {"schema_version": "common-lifetime-effect-application-v1",
        "native_summary_sha256": summary_hash,
        "native_refinement_sha256": proof_hash,
        "cases": cases, "rejection_controls": controls,
        "evidence_boundary": {
            "successful_helper": "conditional native refinement plus observed allocator binding",
            "allocation_failure": "observed allocator event, without successful-helper native refinement",
            "initial_resources": "fixture-owned static reservations, initially free"},
        "limits": ["finite reservation authority comes from the controlled fixture",
                   "native helper proof does not prove CPython hook or object initialization",
                   "failure event has no frozen native path; byte-memory behavior outside the helper is not summarized",
                   "other allocators and arbitrary heap objects remain unknown"]}
    RESULT.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"cases": len(cases),
                      "native_helper_calls": sum(c["native_helper_calls"] for c in cases),
                      "common_effects": sum(c["common_effects"] for c in cases),
                      "rejections": len(controls)}))


if __name__ == "__main__":
    main()
