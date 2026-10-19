"""Compose six frozen Lua allocator cutpoints with common lifetime effects."""
from copy import deepcopy
import gzip
from hashlib import sha256
import json
import z3

from common_lifetime_effects import (LifetimeError, access, apply_effect,
                                     get_resource, initialize)
from composed_native_transition import apply_segment, parse_segments
from freeze_lua_allocator_paths import (BINARY, LABELS, OUTPUT as SUMMARY,
                                        PROOF, ROOT)
from pcode_transition_summary import FLAG_OFFSETS, REGISTER_OFFSETS
from prove_lua_full_flow import initial_memory


RESULT = ROOT / "lua_allocator_common_lifetime_result.json"
SPACE = "native_virtual"
DOMAIN = "controlled_lua_retry_pool"


def digest(path):
    return sha256(path.read_bytes()).hexdigest()


def words(state):
    resource = get_resource(state, DOMAIN, "pool_slot_0")
    return int(resource["live"]), resource["generation"], resource["requested_extent"]


def make_lifetime(meta, source_hash):
    return initialize([{"address_space_id": SPACE, "domain_id": DOMAIN,
        "resource_id": "pool_slot_0", "base": meta["pool_base"],
        "capacity": meta["capacity"], "alignment": meta["alignment"],
        "generation": 0, "live": False, "requested_extent": 0}],
        {"kind": "static_reservations_v1", "source_sha256": source_hash,
         "initial_state": "declared_reservations"})


def memory_owned(memory, addresses):
    return {name: sum(z3.simplify(z3.Select(memory,
        z3.BitVecVal(address + index, 64))).as_long() << (8 * index)
        for index in range(8 if name == "live_extent" else 4))
        for name, address in addresses.items()}


def bind_owned(memory, values, addresses):
    for name, address in addresses.items():
        for index in range(8 if name == "live_extent" else 4):
            memory = z3.Store(memory, z3.BitVecVal(address + index, 64),
                              z3.BitVecVal((values[name] >> (8 * index)) & 255, 8))
    return memory


def owned_words(values):
    return values["live"], values["generation"], values["live_extent"]


def run_case(length, summary, proof_hash, parsed, decls, summary_hash,
             addresses, mutate=None):
    path = ROOT / "artifacts" / f"next_lua_allocator_{length}.json.gz"
    with gzip.open(path, "rt") as stream:
        run = json.load(stream)
    if mutate is not None:
        mutate(run)
    if (run["binary_sha256"] != digest(BINARY) or
            run["source_sha256"] != summary["fixture_source_sha256"] or
            run["retry_length"] != length or len(run["calls"]) != 6):
        raise ValueError("Lua allocator target identity changed")
    records = run["fixture_records"]
    meta = records[0]
    events = [row for row in records if row["type"] == "event"]
    if (meta["retry_length"] != length or meta["slots"] != 1 or
            meta["capacity"] != 160 or len(events) != 6 or
            records[-1] != {"type": "result", "errors": 0,
                            "final_live": 0, "final_generation": 2}):
        raise ValueError("Lua allocator fixture inventory changed")
    lifetime = make_lifetime(meta, run["source_sha256"])
    trace_hash = digest(path)
    stages = []
    stale_state = None
    reallocated_state = None
    for index, (label, call, event) in enumerate(
            zip(LABELS, run["calls"], events)):
        rows = call["rows"]
        entry = rows[0]["registers"]
        owned_before = call["owned_state_before"]
        owned_after = call["owned_state_after"]
        expected_before = words(lifetime)
        if (event["sequence"] != index or
                event["kind"] != ("AllocationFailed" if index in (1, 2)
                                  else "Free" if index in (3, 5) else "Allocate") or
                not 0x100000000 < entry["rsp"] < 0x800000000000 or
                call["pointer"] != (meta["pool_base"] if index in (3, 5) else 0) or
                call["request"] != (0 if index in (3, 5) else
                                    105 if index == 0 else 25 + length) or
                (index in (3, 5) and call["old_extent"] != event["requested"]) or
                (index not in (3, 5) and call["request"] != event["requested"]) or
                event["live_before"] != expected_before[0] or
                owned_words(owned_before) != expected_before or
                entry["rsi"] != call["pointer"] or
                entry["rcx"] != call["request"] or
                entry["rdx"] != call["old_extent"] or
                (index in (0, 4) and
                 (not 1 <= entry["rcx"] <= 160 or
                  owned_before["generation"] == 0xffffffff))):
            raise ValueError("Lua logical event did not bind to native call")
        state = {name: entry[name] for name in REGISTER_OFFSETS.values()}
        flags = {bit: (entry["eflags"] >> bit) & 1
                 for bit in FLAG_OFFSETS.values()}
        memory, _ = initial_memory(rows)
        memory = bind_owned(memory, owned_before, addresses)
        native, reason = apply_segment(label, parsed[label], rows, summary,
                                       decls, state, flags, memory)
        if reason:
            raise ValueError(f"{label}: {reason}")
        next_state, _, next_memory, native_evidence = native
        predicted_after = memory_owned(next_memory, addresses)
        if (next_state["rax"] != call["return_raw"] or
                predicted_after != owned_after or
                (event["kind"] == "Allocate" and
                 next_state["rax"] != meta["pool_base"]) or
                (event["kind"] != "Allocate" and next_state["rax"] != 0)):
            raise ValueError("allocator native return mismatched observed call")
        if event["kind"] == "AllocationFailed":
            request = {"kind": "AllocationFailed", "domain_id": DOMAIN,
                "requested_extent": event["requested"], "reason": "pool_occupied"}
            evidence = {"mode": "observed", "cutpoint": "allocator_failure",
                        "trace_sha256": trace_hash}
        else:
            resource = get_resource(lifetime, DOMAIN, "pool_slot_0")
            request = {"kind": event["kind"], "address_space_id": SPACE,
                "domain_id": DOMAIN, "resource_id": "pool_slot_0",
                "address": meta["pool_base"],
                "requested_extent": event["requested"]}
            if event["kind"] == "Free":
                request["generation"] = resource["generation"]
            evidence = {"mode": "native_refined", "cutpoint": "helper_return",
                "native_cutpoint": "allocator_return",
                "trace_sha256": trace_hash,
                "native_summary_sha256": summary_hash,
                "native_refinement_sha256": proof_hash,
                "preconditions_checked": True, "binding": "observed"}
        before = words(lifetime)
        updated, logical = apply_effect(lifetime, request, evidence)
        after = words(updated)
        if (event["generation"] != after[1] or
                event["live_after"] != after[0] or
                owned_words(predicted_after) != after or
                (event["kind"] == "AllocationFailed" and before != after) or
                (event["kind"] != "AllocationFailed" and
                 event["pointer"] != meta["pool_base"])):
            raise ValueError("common lifetime effect differs from Lua fixture")
        lifetime = updated
        stages.append({"label": label, "native_steps": len(rows),
            "native_ordered_writes_checked": native_evidence["ordered_writes_checked"],
            "target_pcode_operations_replayed": 0,
            "logical_effect": logical,
            "owned_native_before": owned_before,
            "owned_native_after": predicted_after,
            "requested_extent": logical["requested_extent"],
            "generation": after[1], "live_after": after[0]})
        if index == 3:
            stale_state = deepcopy(lifetime)
        if index == 4:
            reallocated_state = deepcopy(lifetime)
    if words(lifetime) != (0, 2, 0) or stale_state is None or reallocated_state is None:
        raise ValueError("Lua lifetime history did not close")
    for checkpoint in (stale_state, reallocated_state):
        try:
            access(checkpoint, SPACE, DOMAIN, "pool_slot_0", 1)
        except LifetimeError:
            pass
        else:
            raise ValueError("stale Lua allocation generation admitted")
    return {"retry_length": length, "trace_sha256": trace_hash,
        "native_steps": sum(stage["native_steps"] for stage in stages),
        "stages": stages, "stale_generation_rejected_after_reallocation": True,
        "access_rejected_after_free": True,
        "final_live_mask": 0}


def negative_controls(summary, parsed, decls):
    path = ROOT / "artifacts/next_lua_allocator_94.json.gz"
    with gzip.open(path, "rt") as stream:
        run = json.load(stream)
    rows = run["calls"][1]["rows"]
    entry = rows[0]["registers"]
    state = {name: entry[name] for name in REGISTER_OFFSETS.values()}
    flags = {bit: (entry["eflags"] >> bit) & 1
             for bit in FLAG_OFFSETS.values()}
    memory, _ = initial_memory(rows)
    controls = {}
    for label, mutate in (
            ("wrong_native_write", lambda path: next(
                item for row in path for item in row["memory"] if item["access"] & 2)
                .update(after=0)),
            ("wrong_native_successor", lambda path: path[-1].update(
                next_pc=path[-1]["next_pc"] ^ 1))):
        changed = deepcopy(rows)
        mutate(changed)
        _, reason = apply_segment("failure_first", parsed["failure_first"],
                                  changed, summary, decls, state, flags, memory)
        if not reason or not reason.startswith("unknown("):
            raise ValueError(f"changed Lua allocator path admitted: {label}")
        controls[label] = reason
    return controls


def state_negative_controls(summary, proof_hash, parsed, decls,
                            summary_hash, addresses):
    controls = {}
    for label, mutate in (
            ("wrong_native_entry_generation", lambda run:
             run["calls"][0]["owned_state_before"].update(generation=0xffffffff)),
            ("wrong_native_exit_live", lambda run:
             run["calls"][0]["owned_state_after"].update(live=0)),
            ("wrong_native_request_register", lambda run:
             run["calls"][0]["rows"][0]["registers"].update(rcx=104))):
        try:
            run_case(94, summary, proof_hash, parsed, decls,
                     summary_hash, addresses, mutate)
        except ValueError as error:
            controls[label] = str(error)
        else:
            raise ValueError(f"Lua native/lifetime binding mutation admitted: {label}")
    return controls


def main():
    summary = json.loads(SUMMARY.read_text())
    proof = json.loads(PROOF.read_text())
    summary_hash, proof_hash = digest(SUMMARY), digest(PROOF)
    if (summary["binary_sha256"] != digest(BINARY) or
            proof["summary_sha256"] != summary_hash or
            set(proof["conditional_proofs"]) != set(LABELS) or
            any(value != "unsat" for case in proof["conditional_proofs"].values()
                for value in case.values())):
        raise ValueError("Lua allocator native proof identity changed")
    decls, parsed = parse_segments(summary, set(LABELS))
    addresses = {name: int(proof["protected_globals"][name], 16)
                 for name in ("live", "generation", "live_extent")}
    cases = [run_case(length, summary, proof_hash, parsed, decls,
                      summary_hash, addresses) for length in (94, 95)]
    controls = {**negative_controls(summary, parsed, decls),
                **state_negative_controls(summary, proof_hash, parsed, decls,
                                          summary_hash, addresses)}
    RESULT.write_text(json.dumps({"schema_version": 1,
        "summary_sha256": summary_hash,
        "native_refinement_sha256": proof_hash,
        "cases": cases, "negative_controls": controls,
        "native_logical_cutpoint_contract": "the verified allocator function return is the helper_return accepted by the shared lifetime-effect schema",
        "evidence_boundary": {"successful_allocate_free": "conditional native SMT proof and target transition validation",
                              "allocation_failure": "native no-owned-state-write proof plus observed AllocationFailed logical event",
                              "lua_errmem_throw": "fixture checks LUA_ERRMEM; unwind remains outside native summary"}},
        indent=2) + "\n")
    print(json.dumps({"holdouts": len(cases),
                      "native_cutpoints": sum(len(case["stages"]) for case in cases),
                      "rejected_controls": len(controls)}))


if __name__ == "__main__":
    main()
