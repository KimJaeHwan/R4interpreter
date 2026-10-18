"""Compose observed V8 prefix/suffix paths with a reusable two-byte loop step.

The target supplies entry registers and first-read memory from a native trace.
All intermediate states and effects are predicted from source P-code segments;
target P-code and target intermediate registers are only used for comparison.
"""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import shutil

import z3

from build_expanded_native_paths import ARTIFACTS, records
from pcode_transition_summary import FLAG_OFFSETS, REGISTER_OFFSETS
from prove_cross_full_flow import NativePathReplay, ROOT
from prove_cross_value_path import lifted_instructions
from prove_js_handler_transition import observed_accesses
from prove_js_string_copy_family import trace_for
from prove_lua_full_flow import initial_memory
from project_expanded_values import prove


RESULT = ROOT / "js_string_loop_composition_result.json"
ODD_SOURCE = ARTIFACTS / "js_string_full_251.json.gz"
EVEN_SOURCE = ARTIFACTS / "js_string_full_1000.json.gz"
PREFIX_END = 187
LOOP_STEPS = 7
TARGET_VALUES = (37, 251, 1000, 10000, 123456, 1234567, 12345678,
                 123456789, 1234567890, 12345678901, 123456789012,
                 1234567890123, 12345678901234, 123456789012345,
                 1234567890123456)


def number(term):
    result = z3.simplify(term)
    if not z3.is_bv_value(result):
        raise ValueError(f"unresolved target expression: {result}")
    return result.as_long()


def same_path(source, target):
    return [(row["pc"], row["bytes"], row["next_pc"]) for row in source] == [
        (row["pc"], row["bytes"], row["next_pc"]) for row in target]


def model_segment(source_rows, node, state, flags, memory):
    model = NativePathReplay(source_rows[0], source_rows,
        lifted_instructions(node, source_rows),
        register_symbols={offset: z3.BitVecVal(state[name], 64)
                          for offset, name in REGISTER_OFFSETS.items()},
        flag_symbols={offset: z3.BitVecVal(flags[bit], 8)
                      for offset, bit in FLAG_OFFSETS.items()},
        memory_symbol=memory, address_guards=False)
    model.run()
    return model


def symbolic_model(rows, node, replacements, memory=None, flag_replacements=None):
    before = rows[0]["registers"]
    flag_replacements = flag_replacements or {}
    model = NativePathReplay(rows[0], rows, lifted_instructions(node, rows),
        register_symbols={offset: replacements.get(name,
                          z3.BitVecVal(before[name], 64))
                          for offset, name in REGISTER_OFFSETS.items()},
        flag_symbols={offset: flag_replacements.get(bit,
                          z3.BitVecVal((before["eflags"] >> bit) & 1, 8))
                      for offset, bit in FLAG_OFFSETS.items()},
        memory_symbol=memory, address_guards=False)
    model.run()
    return model


def prove_parametric_loop(odd, even, node):
    source_base, destination_base, cursor, threshold = [z3.BitVec(name, 64)
        for name in ("LOOP_SRC", "LOOP_DST", "LOOP_CURSOR", "LOOP_END")]
    memory = z3.Array("LOOP_M0", z3.BitVecSort(64), z3.BitVecSort(8))
    replacements = {"r11": source_base, "r14": destination_base,
                    "r12": cursor, "r8": threshold}
    src = source_base + cursor
    dst = destination_base + cursor
    nonalias = dst != src + 1
    branches = []
    for taken, rows in ((True, even[PREFIX_END:PREFIX_END + LOOP_STEPS]),
                        (False, odd[PREFIX_END:PREFIX_END + LOOP_STEPS])):
        model = symbolic_model(rows, node, replacements, memory)
        if len(model.reads) != 2 or len(model.effects) != 2 or len(model.guards) != 1:
            raise ValueError("loop step read/write/branch inventory changed")
        condition = model.guards[0]["condition"]
        expected = z3.ULT(cursor + 2, threshold)
        if not taken:
            expected = z3.Not(expected)
        checks = {"guard_inequality": prove(z3.Xor(condition, expected)),
                  "cursor_inequality": prove(model.regs[160] != cursor + 2),
                  "threshold_change": prove(model.regs[128] != threshold),
                  "source_base_change": prove(model.regs[152] != source_base),
                  "destination_base_change": prove(model.regs[176] != destination_base)}
        for position, item in enumerate(model.reads):
            if item["width"] != 1:
                raise ValueError("loop byte read width changed")
            checks[f"read_{position}_address_inequality"] = prove(
                item["address"] != src + position)
        for position, item in enumerate(model.effects):
            if item["width"] != 1:
                raise ValueError("loop byte write width changed")
            checks[f"write_{position}_address_inequality"] = prove(
                item["address"] != dst + position)
            checks[f"write_{position}_value_inequality"] = prove(z3.And(
                nonalias, item["value"] != z3.Select(memory, src + position)))
        branches.append({"branch": "continue" if taken else "exit",
                         "native_steps": len(rows),
                         "pcode_operations": model.operation_count,
                         "checks": checks})
    tail_branches = []
    for odd_tail, rows in ((True, odd[PREFIX_END + LOOP_STEPS:
                                              PREFIX_END + LOOP_STEPS + 2]),
                           (False, even[201:203])):
        model = symbolic_model(rows, node,
                               {"r8": threshold, "r12": cursor})
        if len(model.guards) != 1 or model.reads or model.effects:
            raise ValueError("tail branch inventory changed")
        desired = threshold == cursor if odd_tail else threshold != cursor
        tail_branches.append({"path": "odd_tail" if odd_tail else "even_exit",
                              "guard_inequality": prove(z3.Xor(
                                  model.guards[0]["condition"], desired))})
    length, iteration = z3.Ints("STRING_LENGTH LOOP_ITERATION")
    pairs = length / 2
    domain = z3.And(length >= 2, length <= 11,
                    iteration >= 0, iteration < pairs)
    symbolic_cursor = z3.Int2BV(15 + 2 * iteration, 64)
    symbolic_end = z3.Int2BV(14 + length, 64)
    schedule = prove(z3.And(domain, z3.Xor(
        z3.ULT(symbolic_cursor + 2, symbolic_end), iteration + 1 < pairs)))
    final_cursor = 15 + 2 * pairs
    parity = prove(z3.And(length >= 2, length <= 11,
        (14 + length == final_cursor) != (length % 2 == 1)))
    return {"entry_cursor": 15, "threshold": "14 + string_length",
            "next_cursor": "cursor + 2", "continue_guard":
            "unsigned(cursor + 2) < unsigned(threshold)",
            "copy_alias_condition": "destination + cursor != source + cursor + 1",
            "loop_branches": branches, "tail_branches": tail_branches,
            "bounded_length_domain": [2, 11],
            "iteration_schedule_inequality": schedule,
            "odd_tail_parity_inequality": parity}


def apply_segment(label, source_rows, target_rows, node, state, flags, memory):
    if not same_path(source_rows, target_rows):
        return None, f"unknown({label} path shape)"
    model = model_segment(source_rows, node, state, flags, memory)
    if any(not z3.is_true(z3.simplify(item["condition"]))
           for item in model.guards):
        return None, f"unknown({label} path guard)"
    predicted_reads = []
    for item in model.reads:
        address = number(item["address"])
        value = number(item["value_expression"])
        key = (item["pc"], address, item["width"])
        if key not in [(r["pc"], r["address"], r["width"])
                       for r in predicted_reads]:
            predicted_reads.append({"pc": item["pc"], "address": address,
                                    "width": item["width"], "value": value})
    native_reads = [{"pc": hex(row["pc"]), "address": item["address"],
                     "width": item["size"], "value": item["before"]}
                    for row in target_rows for item in row["memory"]
                    if item["access"] & 1]
    if predicted_reads != native_reads:
        return None, f"unknown({label} read footprint/value)"
    predicted_writes = [{"pc": item["pc"], "address": number(item["address"]),
                         "width": item["width"], "value": number(item["value"])}
                        for item in model.effects]
    actual_writes = observed_accesses(target_rows, 2)
    if predicted_writes != actual_writes:
        return None, f"unknown({label} ordered effects)"
    next_state = {name: number(model.regs[offset])
                  for offset, name in REGISTER_OFFSETS.items()}
    next_flags = {bit: number(model.flags[offset])
                  for offset, bit in FLAG_OFFSETS.items()}
    observed = target_rows[-1]["registers_after"]
    if (any(next_state[name] != observed[name] for name in next_state) or
            any(next_flags[bit] != (observed["eflags"] >> bit) & 1
                for bit in next_flags)):
        return None, f"unknown({label} final state)"
    successor = getattr(model, "successor", None)
    if successor is not None and number(successor) != target_rows[-1]["next_pc"]:
        return None, f"unknown({label} successor)"
    next_memory = memory
    for item in predicted_writes:
        for index in range(item["width"]):
            next_memory = z3.Store(next_memory,
                z3.BitVecVal((item["address"] + index) & ((1 << 64) - 1), 64),
                z3.BitVecVal((item["value"] >> (8 * index)) & 255, 8))
    evidence = {"label": label, "source_first_pc": hex(source_rows[0]["pc"]),
                "source_last_pc": hex(source_rows[-1]["pc"]),
                "native_steps": len(source_rows),
                "source_pcode_operations": model.operation_count,
                "guards": len(model.guards), "reads": len(predicted_reads),
                "ordered_writes": len(predicted_writes),
                "state_match": True, "read_effect_match": True}
    return (next_state, next_flags, next_memory, evidence), None


def compose(value, source_odd, source_even, node, binary_hash):
    path = trace_for(value)
    meta, body, result = records(path)
    target = body["rows"]
    digits = len(str(value))
    if (digits < 2 or meta["binary_sha256"] != binary_hash or
            meta["input_type"] != "string"):
        return {"input": value, "status": "unknown(input contract)"}
    first = target[0]["registers"]
    state = {name: first[name] for name in REGISTER_OFFSETS.values()}
    flags = {bit: (first["eflags"] >> bit) & 1 for bit in FLAG_OFFSETS.values()}
    memory, _ = initial_memory(target)
    stages = []
    layout = [("prefix", source_odd[:PREFIX_END], target[:PREFIX_END])]
    cursor = PREFIX_END
    pair_count = digits // 2
    for index in range(pair_count):
        source = (source_even[PREFIX_END:PREFIX_END + LOOP_STEPS]
                  if index + 1 < pair_count else
                  source_odd[PREFIX_END:PREFIX_END + LOOP_STEPS])
        layout.append((f"pair_{index + 1}_{'continue' if index + 1 < pair_count else 'exit'}",
                       source, target[cursor:cursor + LOOP_STEPS]))
        cursor += LOOP_STEPS
    suffix = source_odd[PREFIX_END + LOOP_STEPS:] if digits & 1 else source_even[201:]
    layout.append(("odd_tail_and_return" if digits & 1 else "even_return",
                   suffix, target[cursor:]))
    for label, source_rows, target_rows in layout:
        applied, reason = apply_segment(label, source_rows, target_rows,
                                        node, state, flags, memory)
        if reason:
            return {"input": value, "status": reason,
                    "completed_stages": stages}
        state, flags, memory, evidence = applied
        stages.append(evidence)
    char_base = state["rax"] - 1 + 16
    output_bytes = []
    for index in range(digits + 1):
        output_bytes.append(number(z3.Select(memory,
            z3.BitVecVal(char_base + index, 64))))
    projected = bytes(output_bytes).decode("ascii")
    if projected != result["output"]:
        return {"input": value, "status": "unknown(final output)"}
    return {"input": value, "status": "differentially_validated",
            "trace_sha256": sha256(path.read_bytes()).hexdigest(),
            "length": digits, "pair_iterations": pair_count,
            "odd_tail": bool(digits & 1), "output": projected,
            "native_steps": len(target),
            "source_pcode_operations_replayed": sum(s["source_pcode_operations"]
                                                    for s in stages),
            "target_pcode_operations_replayed": 0,
            "target_intermediate_state_used_as_input": False,
            "stages": stages}


def main():
    node = Path(shutil.which("node"))
    binary_hash = sha256(node.read_bytes()).hexdigest()
    odd = records(ODD_SOURCE)[1]["rows"]
    even = records(EVEN_SOURCE)[1]["rows"]
    loop_proof = prove_parametric_loop(odd, even, node)
    cases = [compose(value, odd, even, node, binary_hash)
             for value in TARGET_VALUES]
    if (sum(case["status"] == "differentially_validated" for case in cases) != 10 or
            any(case["status"] != "unknown(prefix path shape)" for case in cases[10:])):
        raise ValueError("unexpected loop composition applicability")
    report = {"schema_version": 1, "binary_sha256": binary_hash,
              "parametric_loop_proof": loop_proof,
              "sources": {"odd": {"trace": ODD_SOURCE.name,
                                  "sha256": sha256(ODD_SOURCE.read_bytes()).hexdigest()},
                          "even": {"trace": EVEN_SOURCE.name,
                                   "sha256": sha256(EVEN_SOURCE.read_bytes()).hexdigest()}},
              "targets": cases,
              "metrics": {"targets": len(cases),
                          "full_native_transitions_matched": sum(
                              case["status"] == "differentially_validated" for case in cases),
                          "target_pcode_operations_replayed": 0},
              "limits": ["target native trace supplies path and first-read memory",
                         "only observed scalar state and native read/write effects are modeled",
                         "source P-code is replayed per segment at application time",
                         "segment boundaries and source choices are currently manual"]}
    RESULT.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"metrics": report["metrics"],
                      "statuses": {str(case["input"]): case["status"] for case in cases}}))


if __name__ == "__main__":
    main()
