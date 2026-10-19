"""Bind observed Lua branch-call bytecode words to native dispatch occurrences.

The pinned Lua adapter knows only the fetch/mask/indirect-jump instruction
sites. It does not use Lua opcode names or infer unseen bytecode execution.
"""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import struct

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
import pypcode

from build_common_program_representation import (LUA_BINARY, LUA_BYTECODE,
    ROOT, digest, lua_flow_trace)
from common_program_path_il import require
from cross_dispatch_pcode import read_vaddr
from prove_lua_full_flow import trace_records


OUTPUT = ROOT / "lua_branch_dispatch_map_v1.json"
FETCH = {0x4154A5: (0x4154AC, 0x4154AF),
         0x41553A: (0x415540, 0x415543),
         0x415B24: (0x415B2E, 0x415B31)}


def static_site_check():
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    ctx = pypcode.Context("x86:LE:64:default")
    checked = {}
    for fetch, (mask, dispatch) in FETCH.items():
        names = []
        translated = []
        for pc in (fetch, mask, dispatch):
            instruction = next(decoder.disasm(read_vaddr(LUA_BINARY, pc, pc + 15), pc))
            ops = [op for op in ctx.translate(bytes(instruction.bytes), base_address=pc,
                                              max_instructions=1).ops
                   if op.opcode.name != "IMARK"]
            translated.append(ops)
            names.append([op.opcode.name for op in ops])
        require("LOAD" in names[0] and "INT_AND" in names[1] and
                "BRANCHIND" in names[2] and
                any(op.opcode.name == "INT_AND" and
                    any(node.space.name == "const" and node.offset == 127
                        for node in op.inputs) for op in translated[1]),
                "Lua fetch/mask/dispatch shape changed")
        checked[hex(fetch)] = {"mask_pc": hex(mask),
                               "dispatch_pc": hex(dispatch)}
    return checked


def mapped_regions(events, bytecode):
    regions = []
    for event in events:
        address = event["runtime_code_address"]
        if not regions or abs(address - regions[-1][-1]["runtime_code_address"]) > 128:
            regions.append([])
        regions[-1].append(event)
    for number, region in enumerate(regions):
        runtime_base = min(item["runtime_code_address"] for item in region)
        anchor = min(region, key=lambda item: item["runtime_code_address"])
        needle = struct.pack("<I", anchor["raw_instruction_word"])
        candidates = [offset for offset in range(len(bytecode) - 3)
                      if bytecode[offset:offset + 4] == needle]
        bases = [base for base in candidates
                 if all(0 <= (at := base + item["runtime_code_address"] - runtime_base)
                        <= len(bytecode) - 4 and
                        bytecode[at:at + 4] ==
                        struct.pack("<I", item["raw_instruction_word"])
                        for item in region)]
        require(len(bases) == 1,
                f"Lua VM code region {number} has ambiguous bytecode file mapping")
        for item in region:
            delta = item["runtime_code_address"] - runtime_base
            require(delta % 4 == 0, "unaligned Lua bytecode cursor")
            item["vm_code_region"] = number
            item["index_from_min_observed_address"] = delta // 4
            item["file_byte_offset"] = bases[0] + delta
    return len(regions)


def extract(label):
    trace = lua_flow_trace(label)
    records = trace_records(trace)
    rows = [row for row in records if row.get("type") == "replay_step"]
    require(Path(records[0]["bytecode"]).name == LUA_BYTECODE.name,
            "wrong Lua branch-call fixture")
    bytecode = LUA_BYTECODE.read_bytes()
    events = []
    for position, row in enumerate(rows):
        if row["pc"] not in FETCH:
            continue
        mask_pc, dispatch_pc = FETCH[row["pc"]]
        access = [item for item in row["memory"]
                  if item["access"] & 1 and item["size"] == 4]
        require(len(access) == 1 and position + 4 < len(rows),
                "Lua fetch lacks one captured four-byte read")
        word = access[0]["before"] & 0xFFFFFFFF
        following = rows[position + 1:position + 4]
        require([item["step"] for item in following] ==
                list(range(row["step"] + 1, row["step"] + 4)) and
                [item["pc"] for item in following[-2:]] ==
                [mask_pc, dispatch_pc] and
                row["next_pc"] == following[0]["pc"] and
                all(a["next_pc"] == b["pc"]
                    for a, b in zip(following, following[1:])) and
                row["registers_after"]["r12"] & 0xFFFFFFFF == word,
                "Lua fetch-to-dispatch sequence changed")
        dispatch = following[-1]
        opcode = word & 0x7F
        table_reads = [item for item in dispatch["memory"]
                       if item["access"] & 1 and item["size"] == 8]
        require(dispatch["registers"]["rax"] == opcode and
                len(table_reads) == 1 and
                table_reads[0]["before"] == dispatch["next_pc"] and
                rows[position + 4]["pc"] == dispatch["next_pc"] and
                rows[position + 4]["step"] == dispatch["step"] + 1,
                "Lua opcode index or jump table target differs")
        events.append({"fetch_trace_step": row["step"],
            "dispatch_trace_step": dispatch["step"],
            "fetch_pc": hex(row["pc"]), "dispatch_pc": hex(dispatch_pc),
            "runtime_code_address": access[0]["address"],
            "raw_instruction_word": word, "numeric_opcode": opcode,
            "handler_entry_pc": hex(dispatch["next_pc"]),
            "jump_table_read_address": hex(table_reads[0]["address"])})
    require(events and len({item["dispatch_trace_step"] for item in events}) ==
            len(events) and
            {item["dispatch_trace_step"] for item in events} ==
            {row["step"] for row in rows if row["pc"] in
             {value[1] for value in FETCH.values()}},
            "captured Lua dispatch occurrence lacks a bytecode fetch")
    regions = mapped_regions(events, bytecode)
    return {"input_label": label, "trace_sha256": digest(trace),
            "bytecode_sha256": digest(LUA_BYTECODE),
            "observed_fetches": len(events), "vm_code_regions": regions,
            "events": events, "coverage": "captured replay_step windows only",
            "all_bytecodes_enumerated": False}


def build():
    sites = static_site_check()
    traces = [extract(label) for label in ("x0", "x9")]
    require(all(item["bytecode_sha256"] == digest(LUA_BYTECODE) and
                item["observed_fetches"] >= 6 for item in traces),
            "Lua branch-call dispatch evidence changed")
    called = [[event for event in item["events"]
               if event["handler_entry_pc"] == "0x4164b8"]
              for item in traces]
    require(all(len(events) == 1 and
                (events[0]["file_byte_offset"], events[0]["numeric_opcode"]) ==
                (111, 21) for events in called),
            "Lua branch-call numeric handler no longer shares the observed bytecode")
    return {"schema_version": "lua-branch-dispatch-map-v1",
        "binary_sha256": digest(LUA_BINARY),
        "bytecode_sha256": digest(LUA_BYTECODE),
        "static_fetch_sites": sites, "traces": traces,
        "claim": "observed bytecode word, low-seven-bit index register, table read and handler target agree in selected replay windows",
        "limits": ["no opcode-name or handler-semantic inference",
                   "index_from_min_observed_address is not a function-start bytecode index",
                   "static three-site shape does not by itself prove jump-table address arithmetic",
                   "uncaptured fetches and alternate paths remain unknown",
                   "mapping does not complete the long native-state gaps"]}


def validate(doc, canonical):
    require(doc["schema_version"] == "lua-branch-dispatch-map-v1" and
            doc["binary_sha256"] == digest(LUA_BINARY) and
            doc["bytecode_sha256"] == digest(LUA_BYTECODE) and
            doc["traces"] == canonical["traces"] and doc == canonical,
            "Lua dispatch evidence changed")


def negative_controls(doc):
    mutations = {
        "wrong_opcode_word": lambda d: d["traces"][0]["events"][0].update(
            raw_instruction_word=0),
        "wrong_handler_target": lambda d: d["traces"][0]["events"][0].update(
            handler_entry_pc="0xdeadbeef"),
        "wrong_bytecode_offset": lambda d: d["traces"][0]["events"][0].update(
            file_byte_offset=0),
        "wrong_fetch_occurrence": lambda d: d["traces"][0]["events"][0].update(
            fetch_trace_step=0),
        "foreign_bytecode": lambda d: d.update(bytecode_sha256="0" * 64),
    }
    outcomes = {}
    for name, mutation in mutations.items():
        changed = deepcopy(doc)
        mutation(changed)
        try:
            validate(changed, doc)
        except ValueError:
            outcomes[name] = "rejected"
        else:
            outcomes[name] = "unexpectedly_accepted"
    require(all(value == "rejected" for value in outcomes.values()),
            "altered Lua dispatch evidence was accepted")
    return outcomes


def main():
    doc = build()
    negatives = negative_controls(doc)
    reordered = [deepcopy(doc["traces"][0]["events"][1]),
                 deepcopy(doc["traces"][0]["events"][0])]
    require(mapped_regions(reordered, LUA_BYTECODE.read_bytes()) == 1 and
            [item["file_byte_offset"] for item in reordered] == [51, 47],
            "out-of-order observed addresses changed Lua file mapping")
    OUTPUT.write_text(json.dumps(doc, indent=2) + "\n")
    validate(json.loads(OUTPUT.read_text()), doc)
    print(json.dumps({"traces": {item["input_label"]: item["observed_fetches"]
        for item in doc["traces"]}, "negative_controls_rejected": len(negatives)}))


if __name__ == "__main__":
    main()
