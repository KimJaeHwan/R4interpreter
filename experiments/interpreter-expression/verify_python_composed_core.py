"""Direct core controls and two-segment CPython TLS-base composition."""
from copy import deepcopy
from hashlib import sha256
import json

import z3

from build_expanded_native_paths import ARTIFACTS, records
from composed_native_transition import apply_segment, parse_segments, path_shape
from pcode_transition_summary import FLAG_OFFSETS, REGISTER_OFFSETS
from prove_cross_full_flow import NativePathReplay, PYTHON, ROOT
from prove_cross_value_path import lifted_instructions
from prove_lua_full_flow import initial_memory


SUMMARY = ROOT / "python_two_segment_summary.json"
RESULT = ROOT / "python_core_validation_result.json"
SPLIT = 80  # The FS-relative read is at source instruction 88.


def seed(rows):
    first = rows[0]["registers"]
    state = {name: first[name] for name in REGISTER_OFFSETS.values()}
    state.update({name: first[name] for name in ("fs_base", "gs_base")})
    return state, {bit: (first["eflags"] >> bit) & 1
                   for bit in FLAG_OFFSETS.values()}, initial_memory(rows)[0]


def freeze_segment(rows, label):
    regs = {offset: z3.BitVec(f"R_{name.upper()}", 64)
            for offset, name in REGISTER_OFFSETS.items()}
    flags = {offset: z3.BitVec(f"F_{bit}", 8)
             for offset, bit in FLAG_OFFSETS.items()}
    model = NativePathReplay(rows[0], rows, lifted_instructions(PYTHON, rows),
        register_symbols=regs, flag_symbols=flags,
        memory_symbol=z3.Array("M0", z3.BitVecSort(64), z3.BitVecSort(8)),
        address_guards=False)
    model.segment_base_symbols = {name: z3.BitVec(name.upper(), 64)
                                  for name in ("fs_base", "gs_base")}
    model.run()
    successor = getattr(model, "successor", None)
    return {"label": label,
        "identity": {"entry_pc": hex(rows[0]["pc"]),
            "next_pc": hex(rows[-1]["next_pc"]), "native_steps": len(rows),
            "path_shape_mode": "pc_bytes_next",
            "path_shape_sha256": path_shape(rows, "pc_bytes_next")},
        "preserved_state": {name: "x86_scalar_no_base_write_v1"
                            for name in ("fs_base", "gs_base")},
        "guard": z3.simplify(z3.And(*(g["condition"] for g in model.guards))).sexpr(),
        "outputs": ([{"name": f"R_{name.upper()}", "sort": "BV64",
            "expression": z3.simplify(model.regs[offset]).sexpr()}
            for offset, name in REGISTER_OFFSETS.items()] +
            [{"name": f"F_{bit}", "sort": "BV8",
              "expression": z3.simplify(model.flags[offset]).sexpr()}
             for offset, bit in FLAG_OFFSETS.items()]),
        "reads": [{"pc": r["pc"], "width": r["width"],
            "address": z3.simplify(r["address"]).sexpr(),
            "value": z3.simplify(r["value_expression"]).sexpr()}
            for r in model.reads],
        "effects": [{"kind": "Write", "pc": e["pc"], "width": e["width"],
            "address": z3.simplify(e["address"]).sexpr(),
            "value": z3.simplify(e["value"]).sexpr()} for e in model.effects],
        "successor": z3.simplify(successor if successor is not None else
            z3.BitVecVal(rows[-1]["next_pc"], 64)).sexpr(),
        "evidence": {"source_pcode_operations": model.operation_count}}


def main():
    original = json.loads((ROOT / "python_allocated_composed_summary.json").read_text())
    decls, parsed = parse_segments(original, {"allocated_pylong_path"})
    rows = records(ARTIFACTS / "python_holdout_252.json.gz")[1]["rows"]
    state, flags, memory = seed(rows)  # Keep these original inputs for every mutation.
    segment = parsed["allocated_pylong_path"]
    valid, reason = apply_segment("control", segment, rows, original, decls,
                                  state, flags, memory)
    if reason or valid is None:
        raise ValueError(reason)
    controls = {}
    mutations = {}
    changed = deepcopy(rows)
    next(a for r in changed for a in r["memory"] if a["access"] & 1)["before"] ^= 1
    mutations["read_value"] = (changed, "unknown(control read footprint/value)")
    changed = deepcopy(rows)
    next(a for r in changed for a in r["memory"] if a["access"] & 2)["after"] ^= 1
    mutations["write_value"] = (changed, "unknown(control ordered effects)")
    changed = deepcopy(rows)
    writes = [(r, i) for r in changed for i, a in enumerate(r["memory"])
              if a["access"] == 2]
    (left, li), (right, ri) = writes[:2]
    left["memory"][li], right["memory"][ri] = right["memory"][ri], left["memory"][li]
    mutations["write_order"] = (changed, "unknown(control ordered effects)")
    changed = deepcopy(rows)
    changed[-1]["registers_after"]["rax"] ^= 1
    mutations["final_state"] = (changed, "unknown(control state)")
    changed = deepcopy(rows)
    changed[-1]["next_pc"] ^= 1
    mutations["successor_observation"] = (changed, "unknown(control path shape)")
    changed = deepcopy(rows)
    changed[40]["registers"]["rax"] ^= 1
    mutations["trace_continuity"] = (changed, "unknown(control trace state continuity)")
    changed = deepcopy(rows)
    changed[-1]["registers_after"]["fs_base"] ^= 1
    mutations["base_change"] = (changed, "unknown(control segment base changed)")
    for name, (comparison, expected) in mutations.items():
        _, reason = apply_segment("control", segment, comparison, original, decls,
                                   state, flags, memory)
        if reason != expected:
            raise ValueError(f"{name}: expected {expected}, got {reason}")
        controls[name] = reason
    no_frame = {**segment, "preserved_state": {}}
    _, reason = apply_segment("control", no_frame, rows, original, decls,
                              state, flags, memory)
    if reason != "unknown(control segment base frame contract)":
        raise ValueError("missing frame was accepted")
    controls["missing_base_contract"] = reason
    wrong_successor = {**segment, "successor": segment["successor"] + 1}
    _, reason = apply_segment("control", wrong_successor, rows, original, decls,
                              state, flags, memory)
    if reason != "unknown(control successor)":
        raise ValueError("wrong frozen successor was accepted")
    controls["frozen_successor"] = reason
    summary = {**original, "segments": [
        freeze_segment(rows[:SPLIT], "before_tls"),
        freeze_segment(rows[SPLIT:], "after_tls")]}
    SUMMARY.write_text(json.dumps(summary, indent=2) + "\n")
    # Load the frozen file before applying to the source and independent inputs.
    summary = json.loads(SUMMARY.read_text())
    decls, segments = parse_segments(summary, {"before_tls", "after_tls"})
    cases = []
    for value in (252, 253, 254, 256):
        target = records(ARTIFACTS / f"python_holdout_{value}.json.gz")[1]["rows"]
        state, flags, memory = seed(target)
        for label, part in (("before_tls", target[:SPLIT]), ("after_tls", target[SPLIT:])):
            result, reason = apply_segment(label, segments[label], part,
                summary, decls, state, flags, memory)
            if reason:
                raise ValueError(f"{value}/{label}: {reason}")
            state, flags, memory, evidence = result
        if any(name not in state for name in ("fs_base", "gs_base")):
            raise ValueError("segment bases were dropped")
        cases.append({"input": value, "status": "differentially_validated",
                      "segments": 2, "base_inputs_consumed_after_boundary": True})
    report = {"schema_version": 1, "direct_core_valid_control": True,
        "direct_core_rejections": controls, "two_segment_cases": cases,
        "fixed_original_inputs_during_mutations": True,
        "python_admission_used_in_direct_controls": False,
        "summary_sha256": sha256(SUMMARY.read_bytes()).hexdigest()}
    RESULT.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"direct_rejections": len(controls), "two_segment_matches": len(cases)}))


if __name__ == "__main__":
    main()
