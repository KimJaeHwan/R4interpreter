"""Apply frozen native pool transitions to new CPython runs and a lifetime ledger."""
from copy import deepcopy
import gzip
from hashlib import sha256
import json
from pathlib import Path

import z3

from composed_native_transition import (apply_composed_segment, apply_segment,
                                        parse_segments)
from common_lifetime_effects import get_resource
from pcode_transition_summary import FLAG_OFFSETS, REGISTER_OFFSETS
from pool_lifetime_ledger import rejection_controls, verify_history
from prove_cross_full_flow import ROOT
from prove_lua_full_flow import initial_memory
from trace_python_pool_lifetime import BINARY, LIBRARY


SUMMARY = ROOT / "pool_native_transition_summary.json"
PROOF = ROOT / "pool_native_refinement_result.json"
RESULT = ROOT / "pool_lifetime_application_result.json"
CASES = ((1073741824, "source"), (1073742000, "holdout"),
         (1074741800, "holdout"))


def state_words(blob):
    raw = bytes.fromhex(blob)
    if len(raw) != 40:
        raise ValueError("incomplete pool state snapshot")
    return [int.from_bytes(raw[i:i + 8], "little") for i in range(0, 40, 8)]


def concrete_word(memory, address):
    return int.from_bytes(bytes(z3.simplify(z3.Select(
        memory, z3.BitVecVal(address + index, 64))).as_long()
        for index in range(8)), "little")


def lifetime_words(lifetime_state, domain="controlled_obj_pool"):
    entries = [get_resource(lifetime_state, domain, f"pool_slot_{slot}")
               for slot in range(4)]
    return [sum(1 << slot for slot, item in enumerate(entries) if item["live"]),
            *(item["generation"] for item in entries)]


def apply_call(call, segment, summary, decls, lifetime_state=None,
               effect_evidence=None, summary_digest=None, proof_digest=None,
               domain="controlled_obj_pool"):
    rows = call["rows"]
    first = rows[0]["registers"]
    base, stack = first["rdi"], first["rsp"]
    slot, operation = call["slot"], call["operation"]
    before_words = state_words(call["state_before"])
    if lifetime_state is not None and before_words != lifetime_words(lifetime_state, domain):
        raise ValueError("native and lifetime entry state disagree")
    bit = 1 << slot if 0 <= slot < 4 else 0
    if (first["rdi"] != call["state_address"] or
            first["rsi"] != slot or first["rdx"] != operation or
            call["return_value"] != 1 or
            rows[-1]["registers_after"]["rax"] != 1):
        raise ValueError("helper call ABI or return witness changed")
    if (base > (1 << 64) - 41 or stack > (1 << 64) - 9 or
            not (base + 40 <= stack or stack + 8 <= base) or
            before_words[0] > 15 or not 0 <= slot < 4 or
            operation not in (1, 2) or
            (operation == 1 and
             (before_words[0] & bit or before_words[slot + 1] == (1 << 64) - 1)) or
            (operation == 2 and not before_words[0] & bit)):
        raise ValueError("native helper refinement precondition failed")
    state = {name: first[name] for name in REGISTER_OFFSETS.values()}
    flags = {bit: (first["eflags"] >> bit) & 1 for bit in FLAG_OFFSETS.values()}
    memory, initial_bytes = initial_memory(rows)
    for index, byte in enumerate(bytes.fromhex(call["state_before"])):
        memory = z3.Store(memory,
            z3.BitVecVal(call["state_address"] + index, 64), z3.BitVecVal(byte, 8))
    if concrete_word(memory, stack) != rows[-1]["next_pc"]:
        raise ValueError("return stack word differs from proof precondition")
    label = "allocate" if call["operation"] == 1 else "release"
    if lifetime_state is None:
        applied, reason = apply_segment(label, segment[label], rows, summary, decls,
                                        state, flags, memory)
    else:
        applied, reason = apply_composed_segment(label, segment[label], rows,
            summary, decls, state, flags, memory, lifetime_state,
            effect_evidence, summary_digest, proof_digest)
    if reason:
        raise ValueError(f"{label}/slot {call['slot']}: {reason}")
    if lifetime_state is None:
        _, _, final_memory, evidence = applied
    else:
        _, _, final_memory, next_lifetime, evidence = applied
    predicted = [concrete_word(final_memory, call["state_address"] + i * 8)
                 for i in range(5)]
    if predicted != state_words(call["state_after"]):
        raise ValueError("predicted complete pool state differs from native state")
    if lifetime_state is not None and predicted != lifetime_words(next_lifetime, domain):
        raise ValueError("native and lifetime exit state disagree")
    result = {"operation": label, "slot": call["slot"],
            "native_steps": len(rows), "reads_checked": evidence["reads_checked"],
            "ordered_writes_checked": evidence["ordered_writes_checked"],
            "outputs_checked": evidence["outputs_checked"],
            "initial_read_bytes": initial_bytes,
            "before": state_words(call["state_before"]), "after": predicted}
    if lifetime_state is not None:
        result["next_lifetime"] = next_lifetime
        result["logical_effect"] = evidence["logical_effect"]
    return result


def load_run(value, origin, summary):
    trace = (ROOT / "artifacts" / ("python_pool_source.json.gz" if origin == "source"
              else f"python_pool_holdout_{value}.json.gz"))
    with gzip.open(trace, "rt") as stream:
        run = json.load(stream)
    mapped = run["loaded_python_library"]
    if (run["input"] != value or
            run["binary_sha256"] != summary["binary_sha256"] or
            run["binary_sha256"] != sha256(BINARY.read_bytes()).hexdigest() or
            run["fixture_source_sha256"] !=
            sha256(BINARY.with_suffix(".c").read_bytes()).hexdigest() or
            run["python_library_sha256"] != sha256(LIBRARY.read_bytes()).hexdigest() or
            mapped["sha256"] != run["python_library_sha256"] or
            not Path(mapped["path"]).is_absolute() or
            Path(mapped["path"]).name != LIBRARY.name or
            mapped["inode"] <= 0 or len(mapped["device"].split(":")) != 2 or
            mapped["mapping_count"] < 1):
        raise ValueError("trace, native binary or Python library identity changed")
    return run, trace


def case(value, origin, summary, decls, segments):
    run, trace = load_run(value, origin, summary)
    ledger, ownership = verify_history(run["fixture_records"], value)
    controls = rejection_controls(run["fixture_records"])
    events = [r for r in run["fixture_records"] if r["type"] == "event"]
    transitions = [e for e in events if e["kind"] != "AllocationFailed"]
    calls = run["calls"]
    if len(calls) != 10 or len(transitions) != len(calls):
        raise ValueError("native helper calls do not cover all successful events")
    results = []
    last_state = [0] * 5
    expected_state_address = calls[0]["state_address"]
    for call, event in zip(calls, transitions):
        if (call["state_address"] != expected_state_address or
                state_words(call["state_before"]) != last_state or
                call["slot"] != event["slot"] or
                call["operation"] != (1 if event["kind"] == "Allocate" else 2) or
                event["live_before"] != last_state[0]):
            raise ValueError("native helper and allocator history are disconnected")
        item = apply_call(call, segments, summary, decls)
        after = item["after"]
        if (event["live_after"] != after[0] or
                event["generation"] != after[call["slot"] + 1]):
            raise ValueError("native transition and ownership ledger disagree")
        last_state = after
        results.append(item)
    if last_state[0] != 0 or last_state[1:] != ledger.generations:
        raise ValueError("final native pool state and ledger disagree")
    return {"input": value, "origin": origin,
            "trace_sha256": sha256(trace.read_bytes()).hexdigest(),
            "native_helper_calls_matched": len(results),
            "native_steps_matched": sum(r["native_steps"] for r in results),
            "native_reads_checked": sum(r["reads_checked"] for r in results),
            "ordered_writes_checked": sum(r["ordered_writes_checked"] for r in results),
            "ownership": ownership, "ledger_rejection_controls": controls,
            "status": "native_summary_and_controlled_lifetime_matched"}


def admission_controls(summary, decls, segments):
    with gzip.open(ROOT / "artifacts/python_pool_source.json.gz", "rt") as stream:
        original = json.load(stream)["calls"][0]
    probes = {}

    def reject(name, changed, expected):
        try:
            apply_call(changed, segments, summary, decls)
        except ValueError as error:
            if str(error) != expected:
                raise ValueError(f"{name}: wrong rejection: {error}") from error
            probes[name] = str(error)
        else:
            raise ValueError(f"native proof precondition admitted: {name}")

    changed = deepcopy(original)
    changed["rows"][0]["registers"]["rsp"] = changed["state_address"] + 8
    reject("state_return_stack_overlap", changed,
           "native helper refinement precondition failed")
    changed = deepcopy(original)
    changed["state_before"] = (16).to_bytes(8, "little").hex() + changed["state_before"][16:]
    reject("invalid_live_partition", changed,
           "native helper refinement precondition failed")
    changed = deepcopy(original)
    changed["rows"][-1]["next_pc"] ^= 1
    reject("wrong_return_stack_word", changed,
           "return stack word differs from proof precondition")
    changed = deepcopy(original)
    changed["slot"] = 4
    changed["rows"][0]["registers"]["rsi"] = 4
    reject("out_of_range_slot", changed,
           "native helper refinement precondition failed")
    return probes


def main():
    summary = json.loads(SUMMARY.read_text())
    proof = json.loads(PROOF.read_text())
    if (summary["schema_version"] != "controlled-pool-native-v1" or
            proof["summary_sha256"] != sha256(SUMMARY.read_bytes()).hexdigest() or
            summary["source_trace_sha256"] != sha256(
                (ROOT / "artifacts/python_pool_source.json.gz").read_bytes()).hexdigest() or
            any(len(proof["proofs"][label]) != 4
                for label in ("allocate", "release")) or
            any(value != "unsat"
                for cases in proof["proofs"].values()
                for item in cases for key, value in item.items() if key != "slot")):
        raise ValueError("pool proof or summary is missing")
    decls, segments = parse_segments(summary, {"allocate", "release"})
    cases = [case(value, origin, summary, decls, segments)
             for value, origin in CASES]
    controls = admission_controls(summary, decls, segments)
    report = {"schema_version": 1,
        "native_summary_sha256": sha256(SUMMARY.read_bytes()).hexdigest(),
        "native_refinement_sha256": sha256(PROOF.read_bytes()).hexdigest(),
        "cases": cases,
        "native_admission_controls": controls,
        "proof_levels": {
            "native_helper": "SMT conditional refinement for both successful paths and four slots; complete byte-memory frame",
            "allocation_ledger": "checked full event history under explicit static-pool, bounded, initially-free assumptions",
            "cpython_binding": "observed hook and PyLong object snapshots on exact CPython 3.13.5 library"},
        "limits": ["helper proof assumes ABI, nonoverlapping state and return stack, valid live mask and operation preconditions",
                   "hook-to-CPython allocation and object initialization are observational checks",
                   "only explicitly scoped PyLong calls in a fixed-size controlled pool are covered",
                   "default CPython allocator and other Python code paths remain outside this result"]}
    RESULT.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"cases": len(cases),
                      "holdouts": sum(c["origin"] == "holdout" for c in cases),
                      "matched_helper_calls": sum(c["native_helper_calls_matched"] for c in cases),
                      "native_admission_controls": len(controls),
                      "negative_ledger_controls": len(cases[0]["ledger_rejection_controls"])}))


if __name__ == "__main__":
    main()
