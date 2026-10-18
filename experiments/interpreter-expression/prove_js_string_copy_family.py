"""Check a shared byte-copy value rule across five observed V8 string paths.

The full native transitions remain length-specific. Each local P-code proof
holds other entry state fixed at its observed cutpoint and varies one byte.
"""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import shutil

import z3

from build_expanded_native_paths import ARTIFACTS, JS_SOURCE, records
from project_expanded_values import (effect_at, final_written_bytes, guard,
                                     prove, replay)
from prove_lua_full_flow import initial_memory
from prove_cross_full_flow import NativePathReplay, ROOT
from prove_cross_value_path import lifted_instructions
from pcode_transition_summary import FLAG_OFFSETS, REGISTER_OFFSETS


RESULT = ROOT / "js_string_copy_family_result.json"
SOURCE_PATHS = {1: ARTIFACTS / "js_string_full_9.json.gz",
                2: JS_SOURCE,
                3: ARTIFACTS / "js_string_full_251.json.gz",
                4: ARTIFACTS / "js_string_full_1000.json.gz",
                5: ARTIFACTS / "js_string_full_10000.json.gz"}
TARGET_VALUES = (0, 8, 9, 10, 37, 38, 99, 251, 252, 999, 1000, 1001,
                 1009, 10000)
COPY_PCS = {0x1AB4145, 0x1AB414F, 0x1AB4167}
SUFFIX_PC = 0x1AB41F1
PAIR_PCS = (0x1AB4140, 0x1AB4145, 0x1AB4149, 0x1AB414F)


def trace_for(value):
    return JS_SOURCE if value == 37 else ARTIFACTS / f"js_string_full_{value}.json.gz"


def character_addresses(rows):
    return (rows[0]["registers"]["rax"] - 1 + 16,
            rows[-1]["registers_after"]["rax"] - 1 + 16)


def result_writes(rows, destination, count):
    found = {}
    for index, row in enumerate(rows):
        for item in row["memory"]:
            if (item["access"] & 2 and item["size"] == 1 and
                    destination <= item["address"] < destination + count):
                position = item["address"] - destination
                found.setdefault(position, []).append((index, row, item))
    if set(found) != set(range(count)) or any(len(items) != 1 for items in found.values()):
        raise ValueError("result character has an absent or duplicate byte write")
    return {position: items[0] for position, items in found.items()}


def prove_symbolic_pair_block(node):
    """Prove the four-instruction two-byte copy with symbolic addresses."""
    rows = records(JS_SOURCE)[1]["rows"][187:191]
    if tuple(row["pc"] for row in rows) != PAIR_PCS:
        raise ValueError("two-character P-code block changed")
    source_base, destination_base, offset = [z3.BitVec(name, 64)
                                              for name in ("SRC", "DST", "OFFSET")]
    memory = z3.Array("PAIR_M0", z3.BitVecSort(64), z3.BitVecSort(8))
    before = rows[0]["registers"]
    special = {"r11": source_base, "r14": destination_base, "r12": offset}
    registers = {root: special.get(name, z3.BitVecVal(before[name], 64))
                 for root, name in REGISTER_OFFSETS.items()}
    flags = {root: z3.BitVecVal((before["eflags"] >> bit) & 1, 8)
             for root, bit in FLAG_OFFSETS.items()}
    model = NativePathReplay(rows[0], rows, lifted_instructions(node, rows),
                             register_symbols=registers, flag_symbols=flags,
                             memory_symbol=memory, address_guards=False)
    model.run()
    if len(model.reads) != 2 or len(model.effects) != 2 or model.guards:
        raise ValueError("two-character block effects changed")
    src = source_base + offset
    dst = destination_base + offset
    # The first store must not overwrite the second source before its read.
    nonalias = dst != src + 1
    read_proofs = []
    for position, item in enumerate(model.reads):
        if item["width"] != 1:
            raise ValueError("two-character block read width changed")
        read_proofs.append({"position": position,
                            "address_inequality": prove(item["address"] != src + position)})
    write_proofs = []
    for position, item in enumerate(model.effects):
        if item["width"] != 1:
            raise ValueError("two-character block write width changed")
        write_proofs.append({"position": position,
            "address_inequality": prove(item["address"] != dst + position),
            "byte_inequality": prove(z3.And(nonalias,
                item["value"] != z3.Select(memory, src + position)))})
    query_address = z3.BitVec("UNWRITTEN_ADDRESS", 64)
    frame = prove(z3.And(query_address != dst, query_address != dst + 1,
                         z3.Select(model.memory, query_address) !=
                         z3.Select(memory, query_address)))
    bases = prove(z3.Or(model.regs[152] != source_base,
                        model.regs[176] != destination_base,
                        model.regs[160] != offset))
    overlap = z3.Solver()
    overlap.set(timeout=30000)
    overlap.add(dst == src + 1,
                z3.Select(memory, src) != z3.Select(memory, src + 1),
                model.effects[1]["value"] != z3.Select(memory, src + 1))
    if overlap.check() != z3.sat:
        raise ValueError("expected overlapping-copy counterexample is absent")
    return {"pc_sequence": [hex(pc) for pc in PAIR_PCS],
            "native_steps": len(rows), "pcode_operations": model.operation_count,
            "input_symbols": ["SRC", "DST", "OFFSET", "PAIR_M0"],
            "alias_condition": "DST + OFFSET != SRC + OFFSET + 1 (mod 2^64)",
            "overlap_counterexample": "sat",
            "reads": read_proofs, "writes": write_proofs,
            "unwritten_memory_inequality": frame,
            "base_register_change": bases}


def prove_source(digits, path, node, binary_hash):
    meta, body, result = records(path)
    rows = body["rows"]
    source, destination = character_addresses(rows)
    if (meta["binary_sha256"] != binary_hash or
            len(str(meta["input"])) != digits or
            result["output"] != str(meta["input"]) + "5" or
            destination == source + 1):
        raise ValueError("source identity or output changed")
    writes = result_writes(rows, destination, digits + 1)
    copies = []
    for position in range(digits):
        index, row, item = writes[position]
        if index == 0 or row["pc"] not in COPY_PCS:
            raise ValueError("unrecognized character-copy store")
        previous = rows[index - 1]
        reads = [access for access in previous["memory"] if access["access"] & 1]
        if (len(reads) != 1 or reads[0]["size"] != 1 or
                reads[0]["address"] != source + position or
                item["address"] != destination + position):
            raise ValueError("character-copy read/write pair changed")
        section = rows[index - 1:index + 1]
        byte = z3.BitVec(f"C_{digits}_{position}", 8)
        memory, _ = initial_memory(section)
        memory = z3.Store(memory, z3.BitVecVal(source + position, 64), byte)
        model = replay(section, node, memory=memory)
        write = effect_at(model, row["pc"])
        equal = prove(z3.And(guard(model), write["value"] != byte))
        address = prove(z3.And(guard(model),
                               write["address"] != z3.BitVecVal(destination + position, 64)))
        guard_total = prove(z3.Not(guard(model)))
        copies.append({"position": position, "read_step": index - 1,
                       "write_step": index, "read_pc": hex(previous["pc"]),
                       "write_pc": hex(row["pc"]),
                       "pcode_operations": model.operation_count,
                       "byte_inequality": equal, "address_inequality": address,
                       "guard_exclusion": guard_total})
    suffix_index, suffix_row, _ = writes[digits]
    if suffix_row["pc"] != SUFFIX_PC:
        raise ValueError("suffix store changed")
    suffix_model = replay(rows[suffix_index:suffix_index + 1], node)
    suffix_effect = effect_at(suffix_model, SUFFIX_PC)
    suffix = {"step": suffix_index, "pc": hex(SUFFIX_PC),
              "byte_inequality": prove(z3.And(guard(suffix_model),
                                               suffix_effect["value"] != 53)),
              "address_inequality": prove(z3.And(guard(suffix_model),
                                                  suffix_effect["address"] !=
                                                  z3.BitVecVal(destination + digits, 64))),
              "guard_exclusion": prove(z3.Not(guard(suffix_model)))}
    reference = records(JS_SOURCE)[1]["rows"][187:191]
    reference_shape = [(row["pc"], row["bytes"]) for row in reference]
    pair_occurrences = []
    for position in range(0, digits - 1, 2):
        start = copies[position]["read_step"]
        end = copies[position + 1]["write_step"] + 1
        block = rows[start:end]
        if [(row["pc"], row["bytes"]) for row in block] != reference_shape:
            raise ValueError("observed pair differs from symbolic P-code template")
        pair_occurrences.append({"first_character": position,
                                 "step_indices": [start, end]})
    return {"trace": path.name, "trace_sha256": sha256(path.read_bytes()).hexdigest(),
            "input": meta["input"], "digits": digits,
            "native_steps": len(rows), "copy_pairs": copies, "suffix": suffix,
            "symbolic_pair_block_occurrences": pair_occurrences,
            "repeated_two_character_copy_block": (
                digits >= 4 and [item["write_pc"] for item in copies[:4]] ==
                ["0x1ab4145", "0x1ab414f", "0x1ab4145", "0x1ab414f"])}


def check_target(value, binary_hash):
    path = trace_for(value)
    meta, body, result = records(path)
    rows = body["rows"]
    source, destination = character_addresses(rows)
    digits = len(str(value))
    if (meta["binary_sha256"] != binary_hash or meta["input"] != value or
            meta["input_type"] != "string" or destination == source + 1):
        raise ValueError("target identity changed")
    writes = result_writes(rows, destination, digits + 1)
    for position in range(digits):
        index, row, _ = writes[position]
        if (row["pc"] not in COPY_PCS or index == 0 or
                not any(item["access"] & 1 and item["size"] == 1 and
                        item["address"] == source + position
                        for item in rows[index - 1]["memory"])):
            raise ValueError("target character-copy shape changed")
    if writes[digits][1]["pc"] != SUFFIX_PC:
        raise ValueError("target suffix shape changed")
    final = final_written_bytes(rows)
    output = bytes(final[destination + position]
                   for position in range(digits + 1)).decode("ascii")
    if output != str(value) + "5" or result["output"] != output:
        raise ValueError("target output bytes disagree")
    return {"input": value, "digits": digits, "output": output,
            "trace": path.name, "trace_sha256": sha256(path.read_bytes()).hexdigest(),
            "native_steps": len(rows)}


def main():
    node = Path(shutil.which("node"))
    binary_hash = sha256(node.read_bytes()).hexdigest()
    symbolic_pair_block = prove_symbolic_pair_block(node)
    sources = [prove_source(digits, path, node, binary_hash)
               for digits, path in SOURCE_PATHS.items()]
    targets = [check_target(value, binary_hash) for value in TARGET_VALUES]
    report = {"schema_version": 1, "binary_sha256": binary_hash,
              "symbolic_pair_block": symbolic_pair_block,
              "sources": sources, "target_value_checks": targets,
              "metrics": {"source_path_lengths": [1, 2, 3, 4, 5],
                          "local_copy_proofs": sum(len(item["copy_pairs"])
                                                   for item in sources),
                          "matching_pair_block_occurrences": sum(
                              len(item["symbolic_pair_block_occurrences"])
                              for item in sources),
                          "suffix_proofs": len(sources),
                          "observed_value_checks": len(targets)},
              "limits": ["complete native state/effect summaries cover only lengths one to four",
                         "five-digit full native transition remains unknown",
                         "copy proofs fix non-character cutpoint state and addresses",
                         "local copy proof covers observed one- to five-digit ASCII decimal string paths and Smi 5",
                         "no proof of arbitrary string length, aliasing, allocation or path reachability"]}
    RESULT.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report["metrics"]))


if __name__ == "__main__":
    main()
