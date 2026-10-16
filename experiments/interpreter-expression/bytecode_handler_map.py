"""Map observed Lua bytecode fetches to native VM dispatch targets.

The fetch/dispatch PCs below were identified from the binary's LOAD,
low-seven-bit mask, and BRANCHIND P-code pattern. This first probe does not
use Lua opcode names or source semantics.
"""

from __future__ import annotations

import csv
from hashlib import sha256
import json
from pathlib import Path
import struct
import sys
import tarfile


experiment = Path(__file__).resolve().parent
trace_path = Path(sys.argv[1]) if len(sys.argv) > 1 else experiment / "artifacts/lua_trace_x9.csv"
bundle_path = experiment / "artifacts/lua_bundle.tar.gz"
bytecode_path = experiment / "lua_chunk.luac"
if len(sys.argv) > 3:
    bytecode_path = Path(sys.argv[3])
binary_path = experiment / "lua_interpreter_fixture"
report_path = Path(sys.argv[2]) if len(sys.argv) > 2 else experiment / "bytecode_handler_map_x9.json"

# Native address of the 32-bit fetch, its address register, bit mask, dispatch.
fetch_sites = {
    0x4154A5: ("r12", 0x4154AC, 0x4154AF),
    0x41553A: ("rax", 0x415540, 0x415543),
    0x415B24: ("r15", 0x415B2E, 0x415B31),
}
with tarfile.open(bundle_path, "r:gz") as archive:
    member = next(member for member in archive if member.name.endswith("/function-000040.json"))
    vm_observation = json.load(archive.extractfile(member))
by_pc = {ins["address"]["byte_offset"]: ins for ins in vm_observation["instructions"]}
for fetch_pc, (_, mask_pc, dispatch_pc) in fetch_sites.items():
    if "LOAD" not in [op["opcode"] for op in by_pc[fetch_pc]["operations"]]:
        raise AssertionError(f"{fetch_pc:#x} is not a P-code LOAD")
    if not any(op["opcode"] == "INT_AND" and any(
            operand["kind_code"] == 1 and operand["byte_offset"] == 127
            for operand in op["inputs"]) for op in by_pc[mask_pc]["operations"]):
        raise AssertionError(f"{mask_pc:#x} does not mask the low seven bits")
    if "BRANCHIND" not in [op["opcode"] for op in by_pc[dispatch_pc]["operations"]]:
        raise AssertionError(f"{dispatch_pc:#x} is not a P-code BRANCHIND")

rows = list(csv.DictReader(trace_path.open(newline="")))
events = []
for position, row in enumerate(rows[:-1]):
    fetch_pc = int(row["rip"], 16)
    if fetch_pc not in fetch_sites:
        continue
    pointer_register, mask_pc, dispatch_pc = fetch_sites[fetch_pc]
    runtime_address = int(row[pointer_register], 16)
    if int(rows[position + 1]["rip"], 16) != int(row["next_rip"], 16):
        raise AssertionError("trace is not a contiguous execution")
    instruction_word = int(rows[position + 1]["r12"], 16) & 0xFFFFFFFF
    dispatch_position = next((index for index in range(position + 1, min(position + 9, len(rows)))
                              if int(rows[index]["rip"], 16) == dispatch_pc), None)
    if dispatch_position is None:
        raise AssertionError(f"fetch at {fetch_pc:#x} has no following dispatch")
    if not any(int(rows[index]["rip"], 16) == mask_pc
               for index in range(position + 1, dispatch_position)):
        raise AssertionError("no observed opcode mask between fetch and dispatch")
    dispatch = rows[dispatch_position]
    opcode_number = instruction_word & 0x7F
    if int(dispatch["rax"], 16) != opcode_number:
        raise AssertionError("dispatch index disagrees with low seven bytecode bits")
    events.append({
        "fetch_trace_step": position,
        "runtime_code_address": runtime_address,
        "raw_instruction_word": instruction_word,
        "numeric_opcode": opcode_number,
        "fetch_native_pc": f"{fetch_pc:#x}",
        "dispatch_native_pc": f"{dispatch_pc:#x}",
        "handler_entry_native_pc": dispatch["next_rip"],
        "handler_entry_r11": int(rows[dispatch_position + 1]["r11"], 16),
        "handler_first_trace_step": dispatch_position + 1,
    })

if len(events) < 3:
    raise AssertionError("too few bytecode fetches for the current fixture")
all_vm_indirect_dispatches = [int(row["rip"], 16) for row in rows
                              if int(row["rip"], 16) in by_pc and any(
                                  op["opcode"] == "BRANCHIND"
                                  for op in by_pc[int(row["rip"], 16)]["operations"])]
if sorted(all_vm_indirect_dispatches) != sorted(int(event["dispatch_native_pc"], 16)
                                                for event in events):
    raise AssertionError("an executed VM indirect dispatch has no bytecode fetch mapping")
runtime_base = events[0]["runtime_code_address"]
bytecode = bytecode_path.read_bytes()
first_three_words = b"".join(struct.pack("<I", row["raw_instruction_word"]) for row in events[:3])
file_start = bytecode.find(first_three_words)
if file_start < 0 or bytecode.count(first_three_words) != 1:
    raise AssertionError("fetched words do not uniquely identify the bytecode file sequence")

for index, event in enumerate(events):
    delta = event["runtime_code_address"] - runtime_base
    if delta < 0 or delta % 4:
        raise AssertionError("runtime bytecode positions are not aligned")
    bytecode_index = delta // 4
    file_offset = file_start + delta
    if file_offset + 4 > len(bytecode):
        raise AssertionError("runtime bytecode position is outside the file")
    if struct.unpack_from("<I", bytecode, file_offset)[0] != event["raw_instruction_word"]:
        raise AssertionError("runtime instruction word disagrees with the .luac file")
    end = events[index + 1]["fetch_trace_step"] if index + 1 < len(events) else len(rows)
    executed_pcs = [int(row["rip"], 16) for row in rows[event["handler_first_trace_step"]:end]]
    event["bytecode_index"] = bytecode_index
    event["file_byte_offset"] = file_offset
    event["executed_native_steps_until_next_fetch_or_return"] = len(executed_pcs)
    event["contains_observed_addition_pc"] = 0x417CE7 in executed_pcs
    del event["handler_first_trace_step"]

observed_indices = [event["bytecode_index"] for event in events]
report = {
    "binary_sha256": sha256(binary_path.read_bytes()).hexdigest(),
    "bytecode_sha256": sha256(bytecode).hexdigest(),
    "trace_sha256": sha256(trace_path.read_bytes()).hexdigest(),
    "bundle_archive_sha256": sha256(bundle_path.read_bytes()).hexdigest(),
    "bytecode_code_start_file_offset": file_start,
    "executed_bytecode_indices": observed_indices,
    "not_fetched_between_observed_indices": [index for index in range(min(observed_indices), max(observed_indices) + 1)
                                             if index not in observed_indices],
    "events": events,
    "conclusion": "observed bytecode words and numeric dispatch targets linked for one VM invocation; handler semantics and general input expression remain unproven",
}
report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
print(json.dumps(report, indent=2, ensure_ascii=False))
