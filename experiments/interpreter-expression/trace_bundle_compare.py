"""Compare one native instruction trace with the saved Ghidra Bundle."""

from __future__ import annotations

from collections import Counter
import csv
from hashlib import sha256
import json
from pathlib import Path
import sys
import tarfile


archive = Path(sys.argv[1])
trace = Path(sys.argv[2])
destination = Path(sys.argv[3])
with tarfile.open(archive, "r:gz") as bundle:
    instruction_by_pc = {}
    for member in bundle:
        if not member.name.rsplit("/", 1)[-1].startswith("function-"):
            continue
        if not member.name.endswith(".json"):
            continue
        data = json.load(bundle.extractfile(member))
        function_index = int(member.name.rsplit("/", 1)[-1][9:15])
        for instruction in data["instructions"]:
            pc = instruction["address"]["byte_offset"]
            instruction_by_pc.setdefault(pc, (function_index, instruction))

rows = list(csv.DictReader(trace.open(newline="")))
matched = Counter()
branch_results = Counter()
vm_steps = 0
for row in rows:
    pc = int(row["rip"], 16)
    found = instruction_by_pc.get(pc)
    if found is None:
        matched["outside_bundle"] += 1
        continue
    function_index, instruction = found
    matched["in_bundle"] += 1
    if function_index == 40:
        vm_steps += 1
    flow = instruction["flow_type"]
    if flow["is_conditional"]:
        next_pc = int(row["next_rip"], 16)
        fallthrough = instruction["fallthrough"]
        targets = {target["byte_offset"] for target in instruction["flow_targets"]}
        if fallthrough is not None and next_pc == fallthrough["byte_offset"]:
            branch_results["fallthrough"] += 1
        elif next_pc in targets:
            branch_results["target"] += 1
        else:
            branch_results["unmatched"] += 1

relation = None
if any(int(row["rip"], 16) == 0x4011A0 for row in rows):
    add_index = next(i for i, row in enumerate(rows) if int(row["rip"], 16) == 0x4011A0)
    add = rows[add_index]
    _, instruction = instruction_by_pc[0x4011A0]
    pcode_add_ordinals = [index for index, operation in enumerate(instruction["operations"])
                          if operation["opcode"] == "INT_ADD"]
    if len(pcode_add_ordinals) != 1 or (int(add["rdi"], 16) + 7) % 2**64 != int(rows[add_index + 1]["rax"], 16):
        raise AssertionError("ELF addition disagrees with trace and Bundle")
    relation = {
        "native_add_pc": "0x4011a0",
        "pcode_opcode": "INT_ADD",
        "pcode_ordinal": pcode_add_ordinals[0],
        "rdi_before": int(add["rdi"], 16),
        "rax_after": int(rows[add_index + 1]["rax"], 16),
        "result": "observed 64-bit add7 function",
    }
elif any(int(row["rip"], 16) == 0x417CE7 for row in rows):
    add_index = next(i for i, row in enumerate(rows) if int(row["rip"], 16) == 0x417CE7)
    add = rows[add_index]
    after_add = rows[add_index + 1]
    store = rows[add_index + 1]
    _, instruction = instruction_by_pc[0x417CE7]
    pcode_add_ordinals = [index for index, operation in enumerate(instruction["operations"])
                          if operation["opcode"] == "INT_ADD"]
    if len(pcode_add_ordinals) != 1 or int(after_add["rip"], 16) != 0x417CEA:
        raise AssertionError("expected executed addition did not match the Bundle")
    source = int(add["mem_rax_before"], 16)
    constant = int(add["r12"], 16)
    result = int(after_add["r12"], 16)
    stored = int(store["mem_rdx_after"], 16)
    if (source + constant) % 2**64 != result or result != stored:
        raise AssertionError("traced arithmetic/store disagrees with 64-bit P-code addition")
    relation = {
        "native_add_pc": "0x417ce7",
        "pcode_opcode": "INT_ADD",
        "pcode_ordinal": pcode_add_ordinals[0],
        "loaded_memory_value": source,
        "r12_before": constant,
        "r12_after": result,
        "store_pc": "0x417cea",
        "stored_memory_value": stored,
        "result": "observed local 64-bit addition; input provenance and guard not established",
    }

report = {
    "trace_sha256": sha256(trace.read_bytes()).hexdigest(),
    "bundle_archive_sha256": sha256(archive.read_bytes()).hexdigest(),
    "instruction_steps": len(rows),
    "unique_native_pcs": len({row["rip"] for row in rows}),
    "matched_steps": dict(matched),
    "vm_function_steps": vm_steps,
    "conditional_branches": dict(branch_results),
    "local_addition": relation,
    "scope": "one concrete execution; no symbolic Lua input expression or path guard claimed",
}
destination.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
print(json.dumps(report, ensure_ascii=False, indent=2))
