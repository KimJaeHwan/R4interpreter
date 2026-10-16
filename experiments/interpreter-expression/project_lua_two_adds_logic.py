"""Compose the archived Lua handler and fetch bridge with symbolic VM input.

The fixture adapter identifies the initial VM stack, next bytecode word and
read-only dispatch table. The actual path substitutions use logic_projection.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path

import z3

from apply_transition_summary import concrete, declarations, expression
from compose_lua_two_adds import bind_bytes, bind_first_state, elf_bytes, entry_records
from logic_projection import (ProjectionUnknown, SerializedCasePath, SymbolicState,
                              bit, compact_expression, compact_guard, project_path,
                              reduce_input_guard, reduce_input_value, reduced)
from pcode_transition_summary import FLAG_OFFSETS, REGISTER_OFFSETS


ROOT = Path(__file__).resolve().parent


def project(handler_file, bridge_file, binary, bytecode, trace):
    handler = json.loads(handler_file.read_text())
    bridge = json.loads(bridge_file.read_text())
    digest = sha256(binary.read_bytes()).hexdigest()
    if digest != handler["identity"]["executable_code_sha256"] or digest != bridge["identity"]["executable_code_sha256"]:
        raise ValueError("Lua ELF differs from the frozen summaries")
    if sha256(handler_file.read_bytes()).hexdigest() != bridge["evidence"]["handler_summary_sha256"]:
        raise ValueError("fetch bridge was built from a different handler summary")
    first, observed_second = entry_records(trace, int(handler["identity"]["entry_cutpoint"], 16))
    before = first["registers"]
    snapshot = first["entry_memory"]
    base = snapshot["base"]
    captured = bytes.fromhex(snapshot["bytes_hex"])
    if base != before["rbx"] or int.from_bytes(captured[:8], "little") != before["rdx"]:
        raise ProjectionUnknown("initial VM input binding is not in captured memory")
    input_symbol = z3.BitVec("X", 64)
    registers = {name: bit(before[name], 64) for name in REGISTER_OFFSETS.values()}
    registers["rdx"] = input_symbol
    flags = {bit_index: bit((before["eflags"] >> bit_index) & 1, 8)
             for bit_index in FLAG_OFFSETS.values()}
    memory = {base + offset: bit(value, 8) for offset, value in enumerate(captured)}
    for offset in range(8):
        memory[base + offset] = reduced(z3.Extract(8 * offset + 7, 8 * offset, input_symbol))
    state = SymbolicState(registers, flags, memory)

    bridge_path = SerializedCasePath(bridge, REGISTER_OFFSETS, FLAG_OFFSETS)
    solver = z3.Solver()
    decls = declarations(bridge)
    bind_first_state(solver, decls, bridge, first)
    bridge_reads = bridge["case"]["reads"]
    code_read = bridge_reads[-2]
    table_read = bridge_reads[-1]
    code_address = concrete(solver, expression(code_read["address"], "BV64", decls))
    first_file_offset = bridge["adapter_evidence"]["first_instruction_file_offset"]
    second_file_offset = first_file_offset + 4 + code_address - before["r11"]
    if second_file_offset != bridge["adapter_evidence"]["second_instruction_file_offset"]:
        raise ProjectionUnknown("code read differs from mapped bytecode offset")
    chunk = bytecode.read_bytes()
    code_bytes = chunk[second_file_offset:second_file_offset + code_read["width"]]
    if len(code_bytes) != code_read["width"]:
        raise ProjectionUnknown("second bytecode word is outside file")
    bind_bytes(solver, decls["M0"], code_address, code_bytes)
    table_address = concrete(solver, expression(table_read["address"], "BV64", decls))
    table_bytes = elf_bytes(binary, table_address, table_read["width"])
    bind_bytes(solver, decls["M0"], table_address, table_bytes)
    dispatch_output = next(item for item in bridge["case"]["outputs"]
                           if item["name"] == "dispatch_target")
    dispatch_target = concrete(solver, expression(dispatch_output["expression"],
                                                  dispatch_output["sort"], decls))
    if dispatch_target != int(handler["identity"]["entry_cutpoint"], 16):
        raise ProjectionUnknown("fetch bridge dispatches outside the numeric handler")
    for offset, value in enumerate(code_bytes):
        state.memory[code_address + offset] = bit(value, 8)
    for offset, value in enumerate(table_bytes):
        state.memory[table_address + offset] = bit(value, 8)
    reads = [(concrete(solver, expression(item["address"], "BV64", decls)), item["width"])
             for item in bridge_reads]
    effects = [(concrete(solver, expression(item["address"], "BV64", decls)), 0, item["width"])
               for item in bridge["case"]["ordered_effects"]]
    for address, _, width in effects:
        if (address < code_address + len(code_bytes) and code_address < address + width or
                address < table_address + len(table_bytes) and table_address < address + width):
            raise ProjectionUnknown("handler write overlaps code or dispatch table")
    first_guards, first_effects = project_path(bridge_path, state, reads, effects,
                                               REGISTER_OFFSETS, FLAG_OFFSETS, {"X"})
    if not first_effects:
        raise ProjectionUnknown("first handler has no VM payload write")
    first_value, first_proved = reduce_input_value(first_effects[0][1], input_symbol)
    second_word = reduced(z3.Extract(31, 0, state.registers["r12"]))
    if not z3.is_bv_value(second_word) or second_word.as_long() != observed_second["registers"]["r12"] & 0xFFFFFFFF:
        raise ProjectionUnknown("symbolic fetch did not produce the observed second word")

    handler_path = SerializedCasePath(handler, REGISTER_OFFSETS, FLAG_OFFSETS)
    second_bindings = [(handler_path.decls[f"R_{name.upper()}"], value)
                       for name, value in state.registers.items()
                       if f"R_{name.upper()}" in handler_path.decls]
    second_bindings.extend((handler_path.decls[f"F_{bit_index}"], value)
                           for bit_index, value in state.flags.items()
                           if f"F_{bit_index}" in handler_path.decls)
    second_bindings.extend(((handler_path.decls["W"], second_word),
                            (handler_path.decls["M0"], z3.K(z3.BitVecSort(64), bit(0, 8)))))
    def second_address(expr):
        value = reduced(z3.substitute(expr, *second_bindings))
        if not z3.is_bv_value(value):
            raise ProjectionUnknown("second handler address depends on input value")
        return value.as_long()
    second_reads = [(second_address(expr), width) for expr, width in handler_path.reads]
    second_effects = [(second_address(expr), 0, width)
                      for expr, _, width in handler_path.effects]
    guards, effects = project_path(handler_path, state, second_reads, second_effects,
                                   REGISTER_OFFSETS, FLAG_OFFSETS, {"X"})
    if not effects or effects[0][2] != 8:
        raise ProjectionUnknown("second handler has no 64-bit payload write")
    value, proved = reduce_input_value(effects[0][1], input_symbol)
    condition, guard_proved = reduce_input_guard(reduced(z3.And(*(first_guards + guards))),
                                                 input_symbol, before["rdx"])
    return {"schema_version": 1, "kind": "conditional_input_logic_projection",
            "scope": "two Lua VM handlers and intervening native fetch/dispatch",
            "claim": "conditional observed path; later Lua return path and full CFG unproved",
            "binary_sha256": digest,
            "handler_summary_sha256": sha256(handler_file.read_bytes()).hexdigest(),
            "bridge_summary_sha256": sha256(bridge_file.read_bytes()).hexdigest(),
            "bytecode_sha256": sha256(chunk).hexdigest(),
            "trace_sha256": sha256(trace.read_bytes()).hexdigest(),
            "witness": str(before["rdx"]), "first_word": hex(before["r12"] & 0xFFFFFFFF),
            "second_word": hex(second_word.as_long()),
            "first_value": compact_expression(first_value),
            "first_value_smt": first_value.sexpr(), "first_reduction_proved": first_proved,
            "value": compact_expression(value), "value_smt": value.sexpr(),
            "value_reduction_proved": proved,
            "guard": compact_guard(condition, input_symbol), "guard_smt": condition.sexpr(),
            "guard_reduction_proved": guard_proved,
            "code_read_address": hex(code_address), "table_read_address": hex(table_address),
            "dispatch_target": hex(dispatch_target),
            "second_entry_word_matches_trace": True,
            "second_entry_snapshot_used_as_input": False}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--handler", type=Path, default=ROOT / "handler_summary_plus7.json")
    parser.add_argument("--bridge", type=Path, default=ROOT / "lua_handler_dispatch_bridge.json")
    parser.add_argument("--binary", type=Path, default=ROOT / "lua_interpreter_fixture")
    parser.add_argument("--bytecode", type=Path, default=ROOT / "lua_chunk_two_adds.luac")
    parser.add_argument("--trace", type=Path, default=ROOT / "artifacts/lua_two_adds_x9.jsonl")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = project(args.handler, args.bridge, args.binary, args.bytecode, args.trace)
    rendered = json.dumps(report, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered)
    else:
        print(rendered, end="")


if __name__ == "__main__":
    main()
