"""Reduce frozen native path summaries to an input-level conditional formula.

Only the entry snapshot and output ABI below are R4VM-specific. The symbolic
P-code path projection lives in interpreter-expression/logic_projection.py.
No fixture source, case manifest, expected result or VM opcode table is read.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys

import z3

from analyze_r4vm import Analyzer, image_string, put

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "interpreter-expression"))
from logic_projection import (ProjectionUnknown, SymbolicState, bit,
                              compact_expression, compact_guard, concrete_address, project_path,
                              reduce_input_guard, reduce_input_value, reduced, require_inputs)
from pcode_transition_summary import FLAG_OFFSETS, REGISTER_OFFSETS


def entry_state(analyzer, program):
    concrete_registers, concrete_memory = analyzer.initial_state(program, 0)
    symbolic_input = z3.BitVec("X", 64)
    registers = {name: bit(value, 64) for name, value in concrete_registers.items()
                 if name != "eflags"}
    registers["rdx"] = symbolic_input
    flags = {bit_index: bit((concrete_registers["eflags"] >> bit_index) & 1, 8)
             for bit_index in FLAG_OFFSETS.values()}
    memory = {address: bit(value, 8) for address, value in concrete_memory.items()}
    for index in range(8):
        memory[concrete_registers["rsp"] + index] = reduced(
            z3.Extract(index * 8 + 7, index * 8, symbolic_input))
    return SymbolicState(registers, flags, memory)


def project_witness(analyzer, program, witness, budget=64):
    registers, memory = analyzer.initial_state(program, witness)
    symbolic = entry_state(analyzer, program)
    guards, used = [], []
    for _ in range(budget):
        matches = [(path, result) for path in analyzer.paths
                   if (result := path.apply(registers, memory, with_reads=True)) is not None]
        if len(matches) != 1:
            raise ProjectionUnknown(f"{len(matches)} native paths at VM PC {registers['rcx']}")
        path, (next_registers, effects, reads) = matches[0]
        path_guards, _ = project_path(path, symbolic, reads, effects,
                                      REGISTER_OFFSETS, FLAG_OFFSETS, {"X"})
        guards.extend(path_guards)
        used.append(path.record["id"])
        registers = next_registers
        for address, value, width in effects:
            put(memory, address, value, width)
        if path.record["kind"] == "next_fetch":
            continue
        if path.record["kind"] != "output":
            raise ProjectionUnknown("native path reaches an unmodeled call")
        status_ptr = concrete_address(symbolic.registers["rdi"], "output status")
        status = image_string(analyzer.binary, status_ptr)
        condition = reduced(z3.And(*guards))
        require_inputs(condition, {"X"})
        require_inputs(symbolic.registers["rcx"], {"X"})
        if not z3.is_true(z3.simplify(z3.substitute(
                condition, (z3.BitVec("X", 64), bit(witness, 64))))):
            raise ProjectionUnknown("path guard rejects its own witness")
        condition, guard_proved = reduce_input_guard(condition, z3.BitVec("X", 64), witness)
        result = {"status": status, "witnesses": [str(witness)],
                  "path_ids": used, "guard_smt": condition.sexpr(),
                  "guard": compact_guard(condition, z3.BitVec("X", 64)),
                  "guard_reduction_proved": guard_proved,
                  "vm_pc": compact_expression(symbolic.registers["rcx"]),
                  "vm_pc_smt": symbolic.registers["rcx"].sexpr()}
        count = concrete_address(symbolic.registers["r9"], "write count")
        base = concrete_address(symbolic.registers["r8"], "write log base")
        if count > budget:
            raise ProjectionUnknown("output write count exceeds transition budget")
        result["writes"] = []
        for index in range(count):
            write_slot = symbolic.read(base + 24 * index, 1)
            write_tag = symbolic.read(base + 24 * index + 16, 1)
            write_value, write_proved = reduce_input_value(
                symbolic.read(base + 24 * index + 8, 8), z3.BitVec("X", 64))
            result["writes"].append({
                "slot": compact_expression(write_slot), "slot_smt": write_slot.sexpr(),
                "value": compact_expression(write_value), "value_smt": write_value.sexpr(),
                "value_reduction_proved": write_proved,
                "tag": compact_expression(write_tag), "tag_smt": write_tag.sexpr()})
        if status == "ok":
            value, value_proved = reduce_input_value(symbolic.registers["rdx"],
                                                      z3.BitVec("X", 64))
            require_inputs(value, {"X"})
            result["value"] = compact_expression(value)
            result["value_smt"] = value.sexpr()
            result["value_reduction_proved"] = value_proved
        return result
    raise ProjectionUnknown("VM transition budget exceeded")


def project_program(analyzer, program, witnesses):
    cases = []
    for witness in witnesses:
        try:
            case = project_witness(analyzer, program, witness)
        except ProjectionUnknown as error:
            cases.append({"status": "unknown", "witnesses": [str(witness)],
                          "reason": str(error)})
            continue
        existing = next((item for item in cases
                         if item.get("path_ids") == case.get("path_ids") and
                         item.get("status") == case["status"] and
                         item.get("guard_smt") == case.get("guard_smt") and
                         item.get("value_smt") == case.get("value_smt") and
                         item.get("writes") == case.get("writes")), None)
        if existing is None:
            cases.append(case)
        else:
            existing["witnesses"].append(str(witness))
    return {"schema_version": 1, "kind": "conditional_input_logic_projection",
            "source": "frozen native P-code path summaries",
            "claim": "observed paths only; path guards and alias/frame completeness unproved",
            "binary_sha256": analyzer.summary["binary_sha256"],
            "program_sha256": sha256(program).hexdigest(), "input_sort": "BV64",
            "cases": cases}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("program", type=Path)
    parser.add_argument("--witness", type=int, nargs="+", default=[0, 9, -1])
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    analyzer = Analyzer()
    report = project_program(analyzer, args.program.read_bytes(), args.witness)
    rendered = json.dumps(report, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered)
    else:
        print(rendered, end="")


if __name__ == "__main__":
    main()
