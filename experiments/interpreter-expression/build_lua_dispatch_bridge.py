"""Compose a frozen handler case with observed P-code fetch/decode/dispatch.

The first handler's output expressions seed the bridge replay. The next
handler's entry state is used only later, for differential validation.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path

import z3

from apply_transition_summary import declarations, expression
from pcode_transition_summary import (FLAG_OFFSETS, PathReplay, REGISTER_OFFSETS,
                                      load_observation, serialize_expr)


BRIDGE_PCS = [0x415B24, 0x415B27, 0x415B2B, 0x415B2E, 0x415B31]


def path_rows(path):
    records = [json.loads(line) for line in path.read_text().splitlines()]
    first = next(i for i, row in enumerate(records) if row.get("pc") == 0x4164B8)
    exit_index = next(i for i in range(first, len(records))
                      if records[i].get("pc") == 0x415B22)
    rows = records[exit_index + 1:exit_index + 1 + len(BRIDGE_PCS)]
    if [row["pc"] for row in rows] != BRIDGE_PCS:
        raise AssertionError("observed bridge differs from expected five instructions")
    if rows[-1]["next_pc"] != 0x4164B8:
        raise AssertionError("bridge does not dispatch to the numeric handler")
    return rows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("handler_summary", type=Path)
    parser.add_argument("bundle", type=Path)
    parser.add_argument("training_trace", type=Path)
    parser.add_argument("binary", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--bytecode-map", type=Path, required=True)
    args = parser.parse_args()
    handler = json.loads(args.handler_summary.read_text())
    bytecode_map = json.loads(args.bytecode_map.read_text())
    if bytecode_map["binary_sha256"] != sha256(args.binary.read_bytes()).hexdigest():
        raise ValueError("bytecode mapping binary differs from bridge binary")
    numeric_events = [event for event in bytecode_map["events"]
                      if event["numeric_opcode"] == 21 and
                      int(event["handler_entry_native_pc"], 16) == 0x4164B8]
    if len(numeric_events) != 2 or any(event["handler_entry_r11"] !=
                                       event["runtime_code_address"] + 4
                                       for event in numeric_events):
        raise AssertionError("bytecode mapping does not establish two handler words and R11 relation")
    decls = declarations(handler)
    outputs = {item["name"]: expression(item["expression"], item["sort"], decls)
               for item in handler["case"]["outputs"]}
    regs = {offset: outputs[f"R_{name.upper()}"] for offset, name in REGISTER_OFFSETS.items()}
    flags = {offset: outputs[f"F_{bit}"] for offset, bit in FLAG_OFFSETS.items()}
    memory = decls["M0"]
    for effect in handler["case"]["ordered_effects"]:
        address = expression(effect["address"], "BV64", decls)
        value = expression(effect["value"], f"BV{effect['width'] * 8}", decls)
        for index in range(effect["width"]):
            memory = z3.Store(memory, address + z3.BitVecVal(index, 64),
                              z3.Extract(index * 8 + 7, index * 8, value))
    rows = path_rows(args.training_trace)
    replay = PathReplay({}, rows, load_observation(args.bundle), regs, flags, memory)
    replay.run()
    if replay.effects or len(replay.reads) != 2 or len(replay.guards) != 1:
        raise AssertionError("bridge effects/read/branch shape changed")
    output_items = [{"name": "dispatch_target", "sort": "BV64",
                     "expression": serialize_expr(replay.successor)}]
    output_items += [{"name": f"R_{name.upper()}", "sort": "BV64",
                      "expression": serialize_expr(replay.regs[offset]),
                      "observed_binding": {"kind": "register", "name": name}}
                     for offset, name in REGISTER_OFFSETS.items()]
    output_items += [{"name": f"F_{bit}", "sort": "BV8",
                      "expression": serialize_expr(replay.flags[offset]),
                      "observed_binding": {"kind": "register_bit", "name": "eflags", "bit": bit}}
                     for offset, bit in FLAG_OFFSETS.items()]
    bridge_reads = [{"pc": item["pc"], "ordinal": item["ordinal"],
                     "address": serialize_expr(item["address"]), "width": item["width"],
                     "memory_version": len(handler["case"]["ordered_effects"]),
                     "value_expression": serialize_expr(item["value_expression"])}
                    for item in replay.reads]
    report = {
        "schema_version": "transition-summary-v0-candidate",
        "semantic_model": handler["semantic_model"],
        "identity": {"executable_code_sha256": sha256(args.binary.read_bytes()).hexdigest(),
                     "code_epoch": handler["identity"]["code_epoch"],
                     "entry_cutpoint": handler["identity"]["entry_cutpoint"],
                     "exit_cutpoint": hex(rows[-1]["next_pc"]),
                     "specialization_dependencies": ["numeric handler path", "five-instruction next-fetch bridge",
                                                     "static ELF dispatch table"]},
        "interface": {"inputs": handler["interface"]["inputs"],
                      "external_memory_bindings": ["bytecode image at runtime code base",
                                                   "ELF read-only dispatch table"]},
        "case": {"path_guard": handler["case"]["path_guard"] +
                               [serialize_expr(item["condition"]) for item in replay.guards],
                 "reads": handler["case"]["reads"] + bridge_reads,
                 "ordered_effects": handler["case"]["ordered_effects"],
                 "outputs": output_items,
                 "exit_kind": "dispatch_to_next_handler",
                 "uncovered": "other handler and dispatch CFG paths; external memory binding proof"},
        "adapter_evidence": {"bytecode_map_sha256": sha256(args.bytecode_map.read_bytes()).hexdigest(),
                             "first_instruction_file_offset": numeric_events[0]["file_byte_offset"],
                             "second_instruction_file_offset": numeric_events[1]["file_byte_offset"],
                             "r11_points_four_bytes_after_first_instruction": True,
                             "bridge_native_pcs": [hex(pc) for pc in BRIDGE_PCS]},
        "evidence": {"handler_summary_sha256": sha256(args.handler_summary.read_bytes()).hexdigest(),
                     "training_trace_sha256": sha256(args.training_trace.read_bytes()).hexdigest(),
                     "bridge_pcode_operations_replayed": replay.operation_count,
                     "validation_level": "candidate: observed bridge path, not all paths"},
    }
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"bridge_instructions": len(rows), "pcode_operations": replay.operation_count,
                      "bridge_reads": len(bridge_reads), "dispatch_target": hex(rows[-1]["next_pc"])}))


if __name__ == "__main__":
    main()
