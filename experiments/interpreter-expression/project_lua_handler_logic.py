"""Project an archived Lua handler summary onto a symbolic input value.

The boundary/input binding is a fixture adapter.  The path reduction is the
same logic_projection.project_path used for the small R4VM interpreter.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path

import z3

from apply_transition_summary import load_trace
from logic_projection import (ProjectionUnknown, SerializedCasePath,
                              SymbolicState, bit, compact_expression, compact_guard,
                              concrete_address, project_path, reduce_input_guard,
                              reduce_input_value, reduced)
from pcode_transition_summary import FLAG_OFFSETS, REGISTER_OFFSETS


ROOT = Path(__file__).resolve().parent


def project(summary_file, trace_file, binary_file):
    summary = json.loads(summary_file.read_text())
    if sha256(binary_file.read_bytes()).hexdigest() != summary["identity"]["executable_code_sha256"]:
        raise ValueError("Lua ELF differs from handler summary")
    entry_pc = int(summary["identity"]["entry_cutpoint"], 16)
    exit_pc = int(summary["identity"]["exit_cutpoint"], 16)
    entry, _ = load_trace(trace_file, entry_pc, exit_pc)
    path = SerializedCasePath(summary, REGISTER_OFFSETS, FLAG_OFFSETS)
    before = entry["registers"]
    snapshot = entry["entry_memory"]
    base = snapshot["base"]
    captured = bytes.fromhex(snapshot["bytes_hex"])
    if base != before["rbx"] or len(captured) < 16:
        raise ProjectionUnknown("Lua input binding is outside the captured VM stack")
    witness = int.from_bytes(captured[:8], "little")
    register_binding = before["rdx"] == witness
    input_symbol = z3.BitVec("X", 64)
    registers = {name: bit(before[name], 64) for name in REGISTER_OFFSETS.values()}
    if register_binding:
        registers["rdx"] = input_symbol
    flags = {bit_index: bit((before["eflags"] >> bit_index) & 1, 8)
             for bit_index in FLAG_OFFSETS.values()}
    memory = {base + offset: bit(value, 8) for offset, value in enumerate(captured)}
    for offset in range(8):
        memory[base + offset] = reduced(z3.Extract(offset * 8 + 7,
                                                   offset * 8, input_symbol))
    state = SymbolicState(registers, flags, memory)

    # Addresses are evaluated from the entry registers and instruction word.
    # A symbolic address is rejected by project_path instead of fixed to this
    # witness behind the user's back.
    bindings = [(path.decls[f"R_{name.upper()}"], bit(before[name], 64))
                for name in REGISTER_OFFSETS.values()
                if f"R_{name.upper()}" in path.decls]
    bindings.extend((path.decls[f"F_{bit_index}"], bit((before["eflags"] >> bit_index) & 1, 8))
                    for bit_index in FLAG_OFFSETS.values()
                    if f"F_{bit_index}" in path.decls)
    bindings.append((path.decls["W"], bit(before["r12"] & 0xFFFFFFFF, 32)))
    bindings.append((path.decls["M0"], z3.K(z3.BitVecSort(64), bit(0, 8))))
    def address(expr):
        return concrete_address(z3.substitute(expr, *bindings), "Lua boundary address")
    reads = [(address(expr), width) for expr, width in path.reads]
    effects = [(address(expr), 0, width) for expr, _, width in path.effects]
    guards, projected_effects = project_path(path, state, reads, effects,
                                             REGISTER_OFFSETS, FLAG_OFFSETS, {"X"})
    condition = reduced(z3.And(*guards))
    condition, guard_proved = reduce_input_guard(condition, input_symbol, witness)
    if not projected_effects or projected_effects[0][2] != 8:
        raise ProjectionUnknown("no 64-bit payload write in this handler path")
    value, value_proved = reduce_input_value(projected_effects[0][1], input_symbol)
    return {"schema_version": 1, "kind": "conditional_input_logic_projection",
            "scope": "one observed Lua VM handler path, not a full script return",
            "claim": "path guard and memory alias completeness unproved",
            "summary_sha256": sha256(summary_file.read_bytes()).hexdigest(),
            "trace_sha256": sha256(trace_file.read_bytes()).hexdigest(),
            "binary_sha256": summary["identity"]["executable_code_sha256"],
            "entry_cutpoint": hex(entry_pc), "exit_cutpoint": hex(exit_pc),
            "input_binding": ("entry R_RDX and 8-byte VM memory at entry R_RBX"
                              if register_binding else "8-byte VM memory at entry R_RBX"),
            "word": hex(before["r12"] & 0xFFFFFFFF),
            "witness": str(witness), "guard": compact_guard(condition, input_symbol),
            "guard_smt": condition.sexpr(), "guard_reduction_proved": guard_proved,
            "payload_write_address": hex(projected_effects[0][0]),
            "value": compact_expression(value), "value_smt": value.sexpr(),
            "value_reduction_proved": value_proved,
            "ordered_effects": len(projected_effects)}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--summary", type=Path, default=ROOT / "handler_summary_plus7.json")
    parser.add_argument("--trace", type=Path,
                        default=ROOT / "artifacts/lua_handler_plus7_x9.jsonl")
    parser.add_argument("--binary", type=Path, default=ROOT / "lua_interpreter_fixture")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = project(args.summary, args.trace, args.binary)
    rendered = json.dumps(report, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered)
    else:
        print(rendered, end="")


if __name__ == "__main__":
    main()
