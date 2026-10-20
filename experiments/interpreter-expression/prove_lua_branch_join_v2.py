"""Bind seven Lua branch traces to bytecode and prove their callee value slots.

Every SMT claim is local to one captured native path and its fixed non-input
entry state.  The shared handler/cursor is an observed join for values, not a
proof that all VM state or exceptional exits agree.
"""
from __future__ import annotations

from collections import Counter
from copy import deepcopy
import json
import sys

import z3

from build_common_program_representation import (
    LUA_BINARY, LUA_BYTECODE, LUA_FLOW_LABELS, ROOT, digest, lua_flow_trace,
    lua_vm_rows, build as rebuild_program)
from build_control_frontier_progress import build as rebuild_prior_progress
from common_program_path_il import require
from map_lua_branch_dispatch import extract, static_site_check
from pcode_transition_summary import FLAG_OFFSETS, REGISTER_OFFSETS, PathReplay
from project_lua_call_bridge import BUNDLE, load_instructions, output_word
from prove_lua_full_flow import (
    first_memory, initial_memory, prove_vm_path, require_unsat, trace_records)
from prove_lua_native_branch_predicate import case as prove_predicate


OUTPUT = ROOT / "lua_branch_join_v2.json"
MATRIX = ROOT / "control_frontier_matrix_v1.json"
PRIOR_MAP = ROOT / "lua_branch_dispatch_map_v1.json"
PRIOR_PREDICATE = ROOT / "lua_native_branch_predicate_v1.json"
PROGRAM = ROOT / "common_program_representation_v1.json"
PRIOR_PROGRESS = ROOT / "control_frontier_progress_v1.json"
MASK = (1 << 64) - 1


def unique_event(mapping, offset, opcode, handler):
    found = [event for event in mapping["events"] if
             event["file_byte_offset"] == offset and
             event["numeric_opcode"] == opcode and
             event["handler_entry_pc"] == handler]
    require(len(found) == 1, f"missing/ambiguous Lua dispatch at file offset {offset}")
    return found[0]


def last_witness_write(rows, before, address, size, expected):
    matches = [(row, access) for row in rows[:before]
               for access in row["memory"] if access["access"] & 2 and
               access["address"] == address and access["size"] == size]
    require(matches and matches[-1][1]["after"] == expected,
            "callee slot lacks its recorded producer")
    last_step = matches[-1][0]["step"]
    require(not any(access["access"] & 2 and
                    access["address"] < address + size and
                    address < access["address"] + access["size"]
                    for row in rows[:before] if row["step"] > last_step
                    for access in row["memory"]),
            "callee slot has a later overlapping write")
    return {"native_step": matches[-1][0]["step"],
            "native_pc": hex(matches[-1][0]["pc"])}


def one(label, chain, matrix_item, records_override=None):
    trace = lua_flow_trace(label)
    records = (trace_records(trace) if records_override is None else
               records_override)
    rows = lua_vm_rows(records)
    mapping = extract(label)
    predicate = prove_predicate(label)
    require(mapping["trace_sha256"] == predicate["trace_sha256"] ==
            chain["trace_sha256"] == matrix_item["trace_sha256"] == digest(trace)
            and chain["binary_sha256"] == digest(LUA_BINARY)
            and chain["bytecode_sha256"] == digest(LUA_BYTECODE)
            and predicate["target_occurrence_id"] == matrix_item["occurrence_id"]
            and matrix_item["opposite_evidence"],
            "Lua branch sources do not identify the same run/fixture")
    require(matrix_item["classification"] in (
                "opposite_observed_same_prefix_and_bytecode_context",
                "opposite_observed_same_prefix_bytecode_unknown") and
            matrix_item["observed_successor"] ==
            predicate["observed_successor"],
            "Lua frontier is not the proved branch occurrence")
    old_context = matrix_item["bytecode_context"]
    require((old_context is None and label not in ("x0", "x9")) or
            (old_context is not None and label in ("x0", "x9") and
             old_context["fixture_offset"] == 51 and
             old_context["numeric_opcode"] == 61 and
             old_context["handler_entry_pc"] == "0x415ee0"),
            "prior bytecode context does not match this occurrence")
    counterpart = ("lua_branch_x9:branch:32" if label == "x0" else
                   "lua_branch_x0:branch:32")
    require(counterpart in {item["occurrence_id"] for item in
                            matrix_item["opposite_evidence"]},
            "Lua frontier lacks its opposite occurrence")
    branch = unique_event(mapping, 51, 61, "0x415ee0")
    call_offset = 67 if label == "x0" else 83
    call = unique_event(mapping, call_offset, 69, "0x415780")
    arithmetic = unique_event(mapping, 111, 21, "0x4164b8")
    branch_index = predicate["native_steps_through_target"] - 1
    require(branch_index == 32 and rows[branch_index]["pc"] == 0x415F30 and
            branch["dispatch_trace_step"] < rows[branch_index]["step"] <
            call["dispatch_trace_step"] < arithmetic["dispatch_trace_step"] and
            rows[branch_index]["next_pc"] ==
            int(predicate["observed_successor"], 16),
            "branch occurrence or downstream call context changed")
    by_step = {row["step"]: row for row in rows}
    for event in (branch, call, arithmetic):
        dispatch = by_step[event["dispatch_trace_step"]]
        successor = by_step[event["dispatch_trace_step"] + 1]
        require(dispatch["next_pc"] == successor["pc"] ==
                int(event["handler_entry_pc"], 16),
                "dispatch and handler entry are not adjacent")
    callee_index = next(i for i, row in enumerate(rows)
                        if row["step"] == arithmetic["dispatch_trace_step"] + 1)
    require(rows[callee_index]["pc"] == 0x4164B8 and
            len([row for row in rows if row["pc"] == 0x4164B8]) == 1,
            "arithmetic handler entry occurrence changed")

    # Replay from the watched VM source to just before the arithmetic handler.
    # The source input has already been linked to the parsed argument by the
    # independently re-run predicate proof above.
    prefix = rows[:callee_index]
    x = z3.BitVec("X", 64)
    source = first_memory(prefix[0], 1)
    require(hex(source["address"]) == predicate["source_slot_address"] and
            source["before"] == records[0]["input_word"],
            "callee replay starts from a different VM source slot")
    memory, first_reads = initial_memory(prefix,
        [(source["address"], x, source["before"])])
    entry = prefix[0]["registers"]
    model = PathReplay(prefix[0], prefix,
        load_instructions((row["pc"] for row in prefix), BUNDLE),
        register_symbols={offset: z3.BitVecVal(entry[name], 64)
                          for offset, name in REGISTER_OFFSETS.items()},
        flag_symbols={offset: z3.BitVecVal((entry["eflags"] >> bit) & 1, 8)
                      for offset, bit in FLAG_OFFSETS.items()},
        memory_symbol=memory, address_guards=True)
    model.run()
    guard = z3.And(*(item["condition"] for item in model.guards))
    zero = label == "x0"
    expected_guard = x == 0 if zero else x != 0
    require_unsat(z3.Xor(guard, expected_guard))
    solver = z3.Solver()
    solver.set(timeout=30000)
    solver.add(guard, x == z3.BitVecVal(records[0]["input_word"], 64))
    require(solver.check() == z3.sat, "callee path excludes its witness")
    base = rows[callee_index]["registers"]["rbx"]
    require(model.regs_concrete[next(offset for offset, name in
            REGISTER_OFFSETS.items() if name == "rbx")] == base,
            "projected VM frame base differs from handler entry")
    rbx_offset = next(offset for offset, name in REGISTER_OFFSETS.items()
                      if name == "rbx")
    require_unsat(guard, model.regs[rbx_offset] != z3.BitVecVal(base, 64))
    argument = z3.BitVecVal(5, 64) if zero else x
    require_unsat(guard, output_word(model.memory, base) != argument)
    require_unsat(guard, z3.Select(model.memory, z3.BitVecVal(base + 8, 64)) !=
                  z3.BitVecVal(3, 8))
    witness_argument = 5 if zero else records[0]["input_word"]
    argument_write = last_witness_write(rows, callee_index, base, 8,
                                        witness_argument)
    tag_write = last_witness_write(rows, callee_index, base + 8, 1, 3)

    payload = chain["output_word"]
    result_proof = prove_vm_path(records, x, payload)
    require(result_proof == chain["proof_evidence"]["vm_path"] and
            result_proof["guard"] == ("X == 0" if zero else "X != 0") and
            result_proof["payload_expression"] ==
            ("10" if zero else "X + 5") and
            payload == (witness_argument + 5) & MASK,
            "callee result does not match the stored native P-code proof")
    result_access = first_memory(rows[-1], 2)
    require(rows[-1]["pc"] == 0x417CEA and
            result_access["address"] == base + 16 and
            result_access["after"] == payload,
            "result slot does not have the common frame-relative role")
    require_unsat(guard, (argument + z3.BitVecVal(5, 64)) !=
                  (z3.BitVecVal(10, 64) if zero else x + z3.BitVecVal(5, 64)))
    return {"input_label": label, "trace_sha256": digest(trace),
        "frontier_occurrence_id": matrix_item["occurrence_id"],
        "branch_bytecode": {"file_byte_offset": 51, "numeric_opcode": 61,
                            "handler_entry_pc": "0x415ee0",
                            "fetch_trace_step": branch["fetch_trace_step"],
                            "dispatch_trace_step": branch["dispatch_trace_step"]},
        "branch_native_step": rows[branch_index]["step"],
        "branch_observed_successor": predicate["observed_successor"],
        "branch_predicate": "X == 0", "predicate_proof_grade":
        "native_pcode_under_prior_guards_and_source_fixed_snapshot",
        "call_bytecode": {"file_byte_offset": call_offset,
                          "numeric_opcode": 69,
                          "handler_entry_pc": "0x415780",
                          "dispatch_trace_step": call["dispatch_trace_step"]},
        "callee_bytecode": {"file_byte_offset": 111,
                            "numeric_opcode": 21,
                            "handler_entry_pc": "0x4164b8",
                            "dispatch_trace_step": arithmetic["dispatch_trace_step"]},
        "callee_native_step": rows[callee_index]["step"],
        "frame_base_witness": hex(base),
        "argument_slot_offset": 0, "tag_slot_offset": 8,
        "tag_size_bytes": 1,
        "result_slot_offset": 16,
        "argument_expression": "5" if zero else "X",
        "argument_witness_unsigned_bv64": str(witness_argument),
        "tag_witness": 3,
        "argument_last_recorded_write": argument_write,
        "tag_last_recorded_write": tag_write,
        "argument_and_tag_pcode_equivalence": "unsat",
        "frame_base_symbolic_equivalence": "unsat",
        "path_guard_equivalence": "unsat",
        "result_expression": "10" if zero else "(X + 5) mod 2^64",
        "result_witness_unsigned_bv64": str(payload),
        "result_pcode_equivalence": result_proof["payload_equivalence"],
        "callee_prefix_native_instructions": len(prefix),
        "callee_prefix_pcode_operations": model.operation_count,
        "callee_prefix_guard_count": len(model.guards),
        "callee_prefix_first_read_bytes": first_reads}


def build():
    static_site_check()
    prior_map = json.loads(PRIOR_MAP.read_text())
    prior_predicate = json.loads(PRIOR_PREDICATE.read_text())
    program = json.loads(PROGRAM.read_text())
    matrix = json.loads(MATRIX.read_text())
    prior_progress = json.loads(PRIOR_PROGRESS.read_text())
    require(program == rebuild_program() and
            prior_progress == rebuild_prior_progress() and
            prior_map["traces"] == [extract("x0"), extract("x9")] and
            prior_predicate["cases"] ==
            [prove_predicate("x0"), prove_predicate("x9")] and
            matrix["occurrence_count"] == 720 and
            len(program["proof_chains"]) >= 7 and
            prior_progress["matrix_sha256"] == digest(MATRIX) and
            prior_progress["individually_proved_predicate_occurrences"] == 6 and
            len([item for item in prior_progress["predicate_links"]
                 if item["engine"] == "python"]) == 4,
            "pinned prior Lua/control evidence changed")
    chains = {item["id"]: item for item in program["proof_chains"]}
    occurrences = {item["occurrence_id"]: item
                   for item in matrix["occurrences"]}
    cases = [one(label, chains[f"lua_branch_{label}"],
                 occurrences[f"lua_branch_{label}:branch:32"])
             for label in LUA_FLOW_LABELS]
    require(len(cases) == 7 and
            {item["branch_observed_successor"] for item in cases} ==
            {"0x415d51", "0x415f36"} and
            {item["callee_bytecode"]["file_byte_offset"] for item in cases} ==
            {111}, "Lua alternate-path or shared callee evidence changed")
    counts = dict(matrix["classification_counts"])
    require(counts["opposite_observed_same_prefix_and_bytecode_context"] == 6
            and counts["opposite_observed_same_prefix_bytecode_unknown"] == 5,
            "prior frontier classifications changed")
    updated = {item["occurrence_id"]: item["classification"]
               for item in matrix["occurrences"]}
    require(len(updated) == matrix["occurrence_count"],
            "duplicate frontier occurrence ID")
    for case in cases:
        oid = case["frontier_occurrence_id"]
        prior = ("opposite_observed_same_prefix_and_bytecode_context"
                 if case["input_label"] in ("x0", "x9") else
                 "opposite_observed_same_prefix_bytecode_unknown")
        require(updated[oid] == prior,
                "frontier occurrence cannot be reclassified")
        updated[oid] = "opposite_observed_same_prefix_and_bytecode_context"
    counts = dict(Counter(updated.values()))
    require(counts["opposite_observed_same_prefix_and_bytecode_context"] == 11
            and counts.get("opposite_observed_same_prefix_bytecode_unknown", 0) == 0
            and sum(counts.values()) == 720,
            "recomputed frontier totals changed")
    counts["opposite_observed_same_prefix_bytecode_unknown"] = 0
    python_predicate_count = len([item for item in prior_progress["predicate_links"]
                                  if item["engine"] == "python"])
    return {"schema_version": "lua-branch-join-v2",
        "binary_sha256": digest(LUA_BINARY),
        "bytecode_sha256": digest(LUA_BYTECODE),
        "bundle_sha256": digest(BUNDLE),
        "frontier_matrix_v1_sha256": digest(MATRIX),
        "prior_dispatch_map_v1_sha256": digest(PRIOR_MAP),
        "prior_predicate_v1_sha256": digest(PRIOR_PREDICATE),
        "common_program_v1_sha256": digest(PROGRAM),
        "prior_control_progress_v1_sha256": digest(PRIOR_PROGRESS),
        "upstream_source_rebuild_equal_to_saved_artifacts": True,
        "cases": cases, "updated_frontier_classification_counts": counts,
        "observed_opposite_occurrences": 11,
        "same_trace_bytecode_context_occurrences":
            counts["opposite_observed_same_prefix_and_bytecode_context"],
        "individually_proved_predicate_occurrences":
            python_predicate_count + len(cases),
        "complete_handler_alternate_exit_sets": 0,
        "value_join": {"bytecode_file_offset": 111,
                       "numeric_opcode": 21,
                       "native_handler_entry_pc": "0x4164b8",
                       "frame_relative_argument": 0,
                       "frame_relative_tag": 8,
                       "frame_relative_result": 16,
                       "argument": "if X == 0 then 5 else X",
                       "result": "(argument + 5) mod 2^64",
                       "grade": "seven source-fixed observed paths; argument/tag and result value P-code proved"},
        "limits": ["next captured bytecode fetch is not established as the immediate successor",
                   "same handler PC and frame offsets do not prove full VM-state join",
                   "input binding uses the pinned x86-64 ABI and watched-slot assumptions",
                   "native effects outside proved values and object ownership remain open",
                   "exception, GC and unobserved VM-state exits remain open"],
        "whole_program_complete": False}


def validate(doc, canonical):
    require(doc == canonical, "saved Lua join differs from source replay")


def negative_controls(canonical):
    changes = {
        "foreign_trace_fetch": lambda d: d["cases"][2]["branch_bytecode"].update(
            d["cases"][0]["branch_bytecode"]),
        "wrong_repeated_occurrence": lambda d: d["cases"][1].update(
            branch_native_step=d["cases"][1]["branch_native_step"] + 1),
        "wrong_frame_slot": lambda d: d["cases"][1].update(
            argument_slot_offset=8),
        "changed_tag": lambda d: d["cases"][1].update(tag_witness=4),
        "changed_argument": lambda d: d["cases"][1].update(
            argument_witness_unsigned_bv64="10"),
        "changed_result": lambda d: d["cases"][1].update(
            result_witness_unsigned_bv64="15"),
        "changed_join_cursor": lambda d: d["value_join"].update(
            bytecode_file_offset=75),
        "integer_not_bv64": lambda d: d["value_join"].update(
            result="argument + 5 over unbounded integers"),
    }
    rejected = {}
    for name, mutate in changes.items():
        changed = deepcopy(canonical)
        mutate(changed)
        try:
            validate(changed, canonical)
        except ValueError:
            rejected[name] = True
        else:
            rejected[name] = False
    require(all(rejected.values()), "mutated join evidence was accepted")
    return rejected


def negative_trace_controls(canonical):
    """Modify actual replay rows and demand a failure inside the proof path."""
    example = canonical["cases"][0]
    records = trace_records(lua_flow_trace("x0"))
    program = json.loads(PROGRAM.read_text())
    matrix = json.loads(MATRIX.read_text())
    chain = next(item for item in program["proof_chains"]
                 if item["id"] == "lua_branch_x0")
    occurrence = next(item for item in matrix["occurrences"]
                      if item["occurrence_id"] == example["frontier_occurrence_id"])
    targets = {
        "argument_observed_write":
            (example["argument_last_recorded_write"]["native_step"],
             "replay_step", "memory_after"),
        "tag_observed_write":
            (example["tag_last_recorded_write"]["native_step"],
             "replay_step", "memory_after"),
        "result_observed_write":
            (next(row["step"] for row in records if row.get("type") == "step"
                  and row.get("pc") == 0x417CEA), "step", "memory_after"),
        "wrong_callee_frame":
            (example["callee_native_step"], "replay_step", "rbx"),
    }
    rejected = {}
    for name, (step, kind, field) in targets.items():
        changed = list(records)
        locations = [i for i, row in enumerate(changed)
                     if row.get("type") == kind and row.get("step") == step]
        require(len(locations) == 1, "negative control target row ambiguous")
        position = locations[0]
        changed[position] = deepcopy(changed[position])
        if field == "rbx":
            changed[position]["registers"]["rbx"] += 8
        else:
            writes = [access for access in changed[position]["memory"]
                      if access["access"] & 2]
            require(len(writes) == 1, "negative control target write ambiguous")
            writes[0]["after"] ^= 1
        try:
            one("x0", chain, occurrence, records_override=changed)
        except (ValueError, AssertionError):
            rejected[name] = True
        else:
            rejected[name] = False
    require(all(rejected.values()), "mutated native replay was accepted")
    return rejected


def main():
    require(sys.argv[1:] in ([], ["--verify"]),
            "usage: prove_lua_branch_join_v2.py [--verify]")
    doc = build()
    doc["negative_controls_rejected"] = {
        "artifact_integrity": negative_controls(doc),
        "native_trace_mutations": negative_trace_controls(doc)}
    if sys.argv[1:] == ["--verify"]:
        validate(json.loads(OUTPUT.read_text()), doc)
    else:
        OUTPUT.write_text(json.dumps(doc, indent=2) + "\n")
    require(json.loads(OUTPUT.read_text()) == doc,
            "saved Lua join changed after writing")
    print(json.dumps({"cases": len(doc["cases"]),
                      "bytecode_bound_frontiers":
                      doc["same_trace_bytecode_context_occurrences"],
                      "predicate_proofs":
                      doc["individually_proved_predicate_occurrences"],
                      "negative_controls_rejected":
                      sum(len(group) for group in
                          doc["negative_controls_rejected"].values()),
                      "complete_handler_alternate_exit_sets": 0}))


if __name__ == "__main__":
    main()
