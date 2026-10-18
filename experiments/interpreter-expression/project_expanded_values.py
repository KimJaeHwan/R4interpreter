"""Prove small path-local value projections from the expanded native traces.

The proofs use fixed observed cutpoint states apart from the named live-in.
They do not replace the complete ordered native transition or prove that an
unobserved execution reaches these cutpoints.
"""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import shutil

import z3

from build_expanded_native_paths import ARTIFACTS, JS_SOURCE, PYTHON_SOURCE, records
from prove_cross_full_flow import NativePathReplay, PYTHON, ROOT
from prove_cross_value_path import lifted_instructions
from prove_lua_full_flow import initial_memory
from pcode_transition_summary import FLAG_OFFSETS, REGISTER_OFFSETS


RESULT = ROOT / "expanded_value_projection_result.json"


def replay(rows, binary, symbols=None, memory=None):
    before = rows[0]["registers"]
    if memory is None:
        memory, _ = initial_memory(rows)
    model = NativePathReplay(
        rows[0], rows, lifted_instructions(binary, rows),
        register_symbols={offset: (symbols or {}).get(name,
            z3.BitVecVal(before[name], 64))
            for offset, name in REGISTER_OFFSETS.items()},
        flag_symbols={offset: z3.BitVecVal((before["eflags"] >> bit) & 1, 8)
                      for offset, bit in FLAG_OFFSETS.items()},
        memory_symbol=memory, address_guards=True)
    model.run()
    return model


def prove(condition):
    solver = z3.Solver()
    solver.set(timeout=30000)
    solver.add(condition)
    verdict = solver.check()
    if verdict != z3.unsat:
        raise ValueError(f"value projection is not proved: {verdict}")
    return "unsat"


def interval(variable, low, high):
    return z3.And(z3.UGE(variable, z3.BitVecVal(low, variable.size())),
                  z3.ULE(variable, z3.BitVecVal(high, variable.size())))


def guard(model):
    return z3.And(*(item["condition"] for item in model.guards))


def effect_at(model, pc):
    effects = [item for item in model.effects if item["pc"] == hex(pc)]
    if len(effects) != 1:
        raise ValueError(f"expected one native write at {pc:#x}")
    return effects[0]


def final_written_bytes(rows):
    """Fold every native store in program order, including overlapping stores."""
    written = {}
    for row in rows:
        for item in row["memory"]:
            if item["access"] & 2:
                for index in range(item["size"]):
                    written[item["address"] + index] = (item["after"] >> (8 * index)) & 255
    return written


def final_word(written, address, width):
    try:
        return int.from_bytes(bytes(written[address + index]
                                    for index in range(width)), "little")
    except KeyError as error:
        raise ValueError(f"result byte was never written: {error}") from error


def main():
    py_rows = records(PYTHON_SOURCE)[1]["rows"]
    js_rows = records(JS_SOURCE)[1]["rows"]
    x = z3.BitVec("X", 32)
    # Operand digits have already been read into registers at this cutpoint.
    arithmetic = replay(py_rows[73:79], PYTHON, {"rdi": z3.ZeroExt(32, x)})
    arithmetic_result = z3.Extract(31, 0, arithmetic.regs[8])
    arithmetic_proof = prove(z3.And(interval(x, 252, 256), guard(arithmetic),
                                    arithmetic_result != x + 5))
    arithmetic_guard = prove(z3.And(interval(x, 252, 256),
                                     z3.Not(guard(arithmetic))))
    y = z3.BitVec("Y", 32)
    gap = replay(py_rows[79:101], PYTHON, {"rcx": z3.ZeroExt(32, y)})
    gap_proof = prove(z3.And(interval(y, 257, 261), guard(gap),
                             gap.regs[8] != z3.ZeroExt(32, y)))
    gap_guard = prove(z3.And(interval(y, 257, 261), z3.Not(guard(gap))))
    # The allocator and all other live-ins remain fixed to the source witness.
    digit = replay(py_rows[101:116], PYTHON, {"rcx": z3.ZeroExt(32, y)})
    digit_write = effect_at(digit, 0x5E9853)
    digit_proof = prove(z3.And(interval(y, 257, 261), guard(digit),
                               digit_write["value"] != y))
    digit_guard = prove(z3.And(interval(y, 257, 261), z3.Not(guard(digit))))

    node = Path(shutil.which("node"))
    byte_results = []
    for start, stop, pc in ((187, 189, 0x1AB4145),
                            (189, 191, 0x1AB414F)):
        section = js_rows[start:stop]
        accesses = [item for row in section for item in row["memory"]
                    if item["access"] & 1 and item["size"] == 1]
        if len(accesses) != 1:
            raise ValueError("unexpected JS character read inventory")
        address = accesses[0]["address"]
        char = z3.BitVec(f"CHAR_{start}", 8)
        memory, _ = initial_memory(section)
        memory = z3.Store(memory, z3.BitVecVal(address, 64), char)
        model = replay(section, node, memory=memory)
        write = effect_at(model, pc)
        proof = prove(z3.And(z3.UGE(char, z3.BitVecVal(48, 8)),
                             z3.ULE(char, z3.BitVecVal(57, 8)), guard(model),
                             write["value"] != char))
        guard_proof = prove(z3.And(z3.UGE(char, z3.BitVecVal(48, 8)),
                                    z3.ULE(char, z3.BitVecVal(57, 8)),
                                    z3.Not(guard(model))))
        byte_results.append({"source_read_address": hex(address),
                             "write_pc": hex(pc), "source_byte": char.decl().name(),
                             "inequality_check": proof, "guard_exclusion_check": guard_proof,
                             "native_steps": len(section),
                             "pcode_operations": model.operation_count})
    suffix = replay(js_rows[204:208], node)
    suffix_write = effect_at(suffix, 0x1AB41F1)
    suffix_proof = prove(z3.And(guard(suffix), suffix_write["value"] != 53))
    suffix_guard = prove(z3.Not(guard(suffix)))

    observed_python = []
    trace_hashes = {}
    binary_hashes = {"python": sha256(PYTHON.read_bytes()).hexdigest(),
                     "javascript": sha256(node.read_bytes()).hexdigest()}
    for input_value in (252, 253, 254, 256):
        path = ARTIFACTS / f"python_holdout_{input_value}.json.gz"
        trace_hashes[path.name] = sha256(path.read_bytes()).hexdigest()
        meta, body, result = records(path)
        if meta["binary_sha256"] != binary_hashes["python"]:
            raise ValueError("Python trace executable differs from pinned binary")
        rows = body["rows"]
        written = final_written_bytes(rows)
        pointer = final_word(written, meta["output_slot"], 8)
        final_digit = final_word(written, pointer + 24, 4)
        if final_digit != input_value + 5 or result["output"] != input_value + 5:
            raise ValueError("Python projected value differs from observed output")
        observed_python.append({"input": input_value, "output": result["output"],
                                "final_digit_bytes": final_digit})
    observed_javascript = []
    for input_value, path in ((37, JS_SOURCE),
                              (38, ARTIFACTS / "js_string_full_38.json.gz")):
        trace_hashes[path.name] = sha256(path.read_bytes()).hexdigest()
        meta, body, result = records(path)
        if meta["binary_sha256"] != binary_hashes["javascript"]:
            raise ValueError("JavaScript trace executable differs from pinned binary")
        rows = body["rows"]
        char_address = rows[-1]["registers_after"]["rax"] - 1 + 16
        written = final_written_bytes(rows)
        projection = bytes(written[char_address + index]
                           for index in range(3)).decode("ascii")
        if projection != str(input_value) + "5" or result["output"] != projection:
            raise ValueError("JavaScript projected value differs from observed output")
        observed_javascript.append({"input": input_value, "output": result["output"],
                                    "written_ascii": projection})

    report = {
        "schema_version": 1,
        "source_sha256": {"python_trace": sha256(PYTHON_SOURCE.read_bytes()).hexdigest(),
                          "javascript_trace": sha256(JS_SOURCE.read_bytes()).hexdigest()},
        "binary_sha256": binary_hashes,
        "observed_trace_sha256": trace_hashes,
        "python": {"native_transition_steps": len(py_rows),
                   "native_transition_writes": 18,
                   "value_expression": "X + 5",
                   "domain": "cached input digit X in [252,256], fixed source cutpoint live-ins and observed paths",
                   "arithmetic": {"step_indices": [73, 79],
                                  "pcode_operations": arithmetic.operation_count,
                                  "guards": len(arithmetic.guards),
                                  "inequality_check": arithmetic_proof,
                                  "guard_exclusion_check": arithmetic_guard},
                   "value_transport": {"step_indices": [79, 101],
                                       "pcode_operations": gap.operation_count,
                                       "guards": len(gap.guards),
                                       "inequality_check": gap_proof,
                                       "guard_exclusion_check": gap_guard},
                   "digit_store": {"step_indices": [101, 116],
                                   "pc": hex(0x5E9853),
                                   "pcode_operations": digit.operation_count,
                                   "guards": len(digit.guards),
                                   "inequality_check": digit_proof,
                                   "guard_exclusion_check": digit_guard},
                   "observed_value_checks": observed_python},
        "javascript": {"native_transition_steps": len(js_rows),
                       "native_transition_writes": 30,
                       "value_expression": "two ASCII input digits followed by '5'",
                       "domain": "fixed source cutpoint live-ins, observed two-digit string path",
                       "character_copies": byte_results,
                       "suffix": {"step_indices": [204, 208],
                                  "pc": hex(0x1AB41F1),
                                  "pcode_operations": suffix.operation_count,
                                  "inequality_check": suffix_proof,
                                  "guard_exclusion_check": suffix_guard},
                       "observed_value_checks": observed_javascript},
        "limits": ["each proof begins at an internal observed native cutpoint",
                   "cutpoint reachability and arbitrary memory aliases are not proved here",
                   "the full native transition retains other register and memory effects",
                   "unobserved handler paths remain unknown"]}
    RESULT.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"python": [arithmetic_proof, digit_proof],
                      "javascript": [item["inequality_check"] for item in byte_results]
                      + [suffix_proof]}))


if __name__ == "__main__":
    main()
