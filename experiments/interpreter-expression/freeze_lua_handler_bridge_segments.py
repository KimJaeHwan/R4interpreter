"""Freeze Lua numeric handler and fetch/dispatch bridge as shared segments."""
from __future__ import annotations

from hashlib import sha256
import json

import z3

from apply_transition_summary import declarations, expression
from build_lua_dispatch_bridge import path_rows
from composed_native_transition import path_shape
from pcode_transition_summary import (FLAG_OFFSETS, PathReplay,
                                      REGISTER_OFFSETS, load_observation)
from prove_lua_full_flow import initial_memory


from pathlib import Path


ROOT = Path(__file__).resolve().parent
SOURCE_TRACE = ROOT / "artifacts/lua_two_adds_x9.jsonl"
HANDLER_SOURCE = ROOT / "handler_summary_plus7.json"
BUNDLE = ROOT / "artifacts/lua_bundle.tar.gz"
OUTPUT = ROOT / "lua_handler_bridge_composed_summary.json"


def source_handler_rows():
    rows = [json.loads(line) for line in SOURCE_TRACE.read_text().splitlines()]
    steps = [row for row in rows if row.get("type") == "step"]
    start = next(index for index, row in enumerate(steps) if row["pc"] == 0x4164B8)
    end = next(index for index in range(start, len(steps))
               if steps[index]["next_pc"] == 0x415B24)
    return steps[start:end + 1]


def identity(rows):
    return {"entry_pc": hex(rows[0]["pc"]), "next_pc": hex(rows[-1]["next_pc"]),
            "native_steps": len(rows), "path_shape_mode": "pc_next",
            "path_shape_sha256": path_shape(rows, "pc_next")}


def handler_segment(source, rows):
    case = source["case"]
    decls = declarations(source)
    def read_value(item):
        if item["memory_version"] != 0:
            raise ValueError("Lua handler has a read after a modeled write")
        address = expression(item["address"], "BV64", decls)
        bytes_read = [z3.Select(decls["M0"], address + z3.BitVecVal(i, 64))
                      for i in range(item["width"])]
        return z3.simplify(bytes_read[0] if len(bytes_read) == 1 else
                           z3.Concat(*reversed(bytes_read))).sexpr()
    outputs = [item for item in case["outputs"]
               if item["name"].startswith(("R_", "F_"))]
    if len(outputs) != 21 or len(case["ordered_effects"]) != 2:
        raise ValueError("Lua handler state/effect inventory changed")
    return {"label": "handler", "identity": identity(rows),
            "guard": z3.simplify(z3.And(*(expression(item, "Bool", decls)
                for item in case["path_guard"]))).sexpr(),
            "outputs": [{"name": item["name"], "sort": item["sort"],
                         "expression": item["expression"]} for item in outputs],
            "reads": [{"pc": item["pc"], "width": item["width"],
                       "address": item["address"],
                       "value": read_value(item)}
                      for item in case["reads"]],
            "effects": [{"kind": "Write", "pc": item["pc"],
                         "width": item["width"], "address": item["address"],
                         "value": item["value"]}
                        for item in case["ordered_effects"]],
            "successor": f"#x{rows[-1]['next_pc']:016x}",
            "evidence": {"source_summary_sha256": sha256(
                HANDLER_SOURCE.read_bytes()).hexdigest(),
                "source_pcode_operations_at_freeze": 0,
                "source_summary_pcode_operations": source["evidence"].get(
                    "pcode_operations_replayed")}}


def bridge_segment(rows):
    registers = {offset: z3.BitVec(f"R_{name.upper()}", 64)
                 for offset, name in REGISTER_OFFSETS.items()}
    flags = {offset: z3.BitVec(f"F_{bit}", 8)
             for offset, bit in FLAG_OFFSETS.items()}
    memory = z3.Array("M0", z3.BitVecSort(64), z3.BitVecSort(8))
    model = PathReplay(rows[0], rows, load_observation(BUNDLE),
                       registers, flags, memory, address_guards=False)
    model.run()
    if len(model.reads) != 2 or model.effects or model.successor is None:
        raise ValueError("Lua bridge read/write/successor inventory changed")
    native_reads = [(hex(row["pc"]), access["address"], access["size"],
                     access["before"])
                    for row in rows for access in row["memory"]
                    if access["access"] & 1]
    modeled_reads = [(item["pc"], item["observed_address"], item["width"],
                      item["observed"]) for item in model.reads]
    if modeled_reads != native_reads or any(
            access["access"] & 2 for row in rows for access in row["memory"]):
        raise ValueError("Lua bridge native/P-code memory inventory changed")
    bindings = [(registers[offset], z3.BitVecVal(rows[0]["registers"][name], 64))
                for offset, name in REGISTER_OFFSETS.items()]
    bindings += [(flags[offset], z3.BitVecVal(
        (rows[0]["registers"]["eflags"] >> bit) & 1, 8))
        for offset, bit in FLAG_OFFSETS.items()]
    bindings.append((memory, initial_memory(rows)[0]))
    if any(not z3.is_true(z3.simplify(z3.substitute(
            item["condition"], *bindings))) for item in model.guards):
        raise ValueError("Lua source bridge guard failed")
    for offset, name in REGISTER_OFFSETS.items():
        value = z3.simplify(z3.substitute(model.regs[offset], *bindings))
        if not z3.is_bv_value(value) or value.as_long() != rows[-1][
                "registers_after"][name]:
            raise ValueError(f"Lua source bridge register {name} differs")
    for offset, bit in FLAG_OFFSETS.items():
        value = z3.simplify(z3.substitute(model.flags[offset], *bindings))
        if not z3.is_bv_value(value) or value.as_long() != (
                rows[-1]["registers_after"]["eflags"] >> bit) & 1:
            raise ValueError(f"Lua source bridge flag {bit} differs")
    successor = z3.simplify(z3.substitute(model.successor, *bindings))
    if not z3.is_bv_value(successor) or successor.as_long() != rows[-1]["next_pc"]:
        raise ValueError("Lua source bridge successor differs")
    return {"label": "bridge", "identity": identity(rows),
            "guard": z3.simplify(z3.And(*(item["condition"]
                                           for item in model.guards))).sexpr(),
            "outputs": ([{"name": f"R_{name.upper()}", "sort": "BV64",
                          "expression": z3.simplify(model.regs[offset]).sexpr()}
                         for offset, name in REGISTER_OFFSETS.items()] +
                        [{"name": f"F_{bit}", "sort": "BV8",
                          "expression": z3.simplify(model.flags[offset]).sexpr()}
                         for offset, bit in FLAG_OFFSETS.items()]),
            "reads": [{"pc": item["pc"], "width": item["width"],
                       "address": z3.simplify(item["address"]).sexpr(),
                       "value": z3.simplify(item["value_expression"]).sexpr()}
                      for item in model.reads],
            "effects": [], "successor": z3.simplify(model.successor).sexpr(),
            "evidence": {"source_pcode_operations_at_freeze": model.operation_count,
                         "source_guards": len(model.guards),
                         "source_reads": len(model.reads)}}


def main():
    source = json.loads(HANDLER_SOURCE.read_text())
    binary = ROOT / "lua_interpreter_fixture"
    if sha256(binary.read_bytes()).hexdigest() != source[
            "identity"]["executable_code_sha256"]:
        raise ValueError("Lua handler binary changed")
    handler = source_handler_rows()
    bridge = path_rows(SOURCE_TRACE)
    if handler[-1]["next_pc"] != bridge[0]["pc"] or bridge[-1][
            "next_pc"] != handler[0]["pc"]:
        raise ValueError("Lua segment boundaries do not compose")
    inputs = ([{"name": f"R_{name.upper()}", "sort": "BV64"}
               for name in REGISTER_OFFSETS.values()] +
              [{"name": f"F_{bit}", "sort": "BV8"}
               for bit in FLAG_OFFSETS.values()] +
              [{"name": "M0", "sort": "Array(BV64,BV8)"},
               {"name": "W", "sort": "BV32", "binding":
                {"kind": "register_slice", "name": "r12", "low_bit": 0,
                 "width": 32}}])
    old_bridge = ROOT / "lua_handler_dispatch_bridge.json"
    old_binding = json.loads(old_bridge.read_text())["adapter_evidence"]
    report = {"schema_version": "composed-native-sequence-transition-v1",
              "engine": "lua", "binary_sha256": sha256(binary.read_bytes()).hexdigest(),
              "bytecode_sha256": sha256((ROOT / "lua_chunk_two_adds.luac").read_bytes()).hexdigest(),
              "interface": {"inputs": inputs},
              "composition": ["handler", "bridge", "handler"],
              "adapter_evidence": {
                  "first_instruction_file_offset": old_binding[
                      "first_instruction_file_offset"],
                  "second_instruction_file_offset": old_binding[
                      "second_instruction_file_offset"],
                  "prior_bridge_summary_sha256": sha256(
                      old_bridge.read_bytes()).hexdigest()},
              "segments": [handler_segment(source, handler),
                           bridge_segment(bridge)],
              "sources": {"trace_sha256": sha256(SOURCE_TRACE.read_bytes()).hexdigest(),
                          "bundle_sha256": sha256(BUNDLE.read_bytes()).hexdigest()},
              "limits": ["native first-read memory and path observation required",
                         "fixed numeric handler/dispatch path and static binary",
                         "other Lua bytecodes, exception and helper paths unknown"]}
    OUTPUT.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"segments": len(report["segments"]),
                      "bridge_pcode_operations": report["segments"][1][
                          "evidence"]["source_pcode_operations_at_freeze"],
                      "summary_sha256": sha256(OUTPUT.read_bytes()).hexdigest()}))


if __name__ == "__main__":
    main()
