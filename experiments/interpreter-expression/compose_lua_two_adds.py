"""Predict a second VM handler entry from the first entry and two summaries.

The second handler's traced entry is reserved for comparison. It supplies no
register, bytecode word or VM-memory value to the prediction.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import subprocess

from elftools.elf.elffile import ELFFile
import z3

from apply_transition_summary import apply, concrete, declarations, expression


def elf_bytes(path, address, width):
    with path.open("rb") as stream:
        elf = ELFFile(stream)
        for segment in elf.iter_segments():
            start = segment["p_vaddr"]
            if segment["p_type"] == "PT_LOAD" and start <= address and address + width <= start + segment["p_filesz"]:
                if segment["p_flags"] & 2:
                    raise ValueError("dispatch table is in a writable ELF segment")
                stream.seek(segment["p_offset"] + address - start)
                return stream.read(width)
    raise ValueError(f"static ELF has no bytes at {address:#x}/{width}")


def entry_records(path, entry_pc):
    records = [json.loads(line) for line in path.read_text().splitlines()]
    entries = [row for row in records if row.get("pc") == entry_pc]
    if len(entries) != 2:
        raise AssertionError("expected exactly two numeric handler entries")
    return entries


def bind_first_state(solver, decls, summary, entry):
    for item in summary["interface"]["inputs"]:
        binding = item["binding"]
        if binding["kind"] == "entry_memory":
            continue
        value = entry["registers"][binding["name"]]
        if binding["kind"] == "register_slice":
            value = (value >> binding["low_bit"]) & ((1 << binding["width"]) - 1)
        elif binding["kind"] == "register_bit":
            value = (value >> binding["bit"]) & 1
        elif binding["kind"] != "register":
            raise ValueError(f"unsupported input binding {binding['kind']}")
        solver.add(decls[item["name"]] == z3.BitVecVal(value, decls[item["name"]].size()))
    snapshot = entry["entry_memory"]
    base, content = snapshot["base"], bytes.fromhex(snapshot["bytes_hex"])
    for index, value in enumerate(content):
        solver.add(z3.Select(decls["M0"], z3.BitVecVal(base + index, 64)) ==
                   z3.BitVecVal(value, 8))
    return base, content


def bind_bytes(solver, memory, address, content):
    for index, value in enumerate(content):
        solver.add(z3.Select(memory, z3.BitVecVal(address + index, 64)) == z3.BitVecVal(value, 8))


def compose(handler, bridge, binary, bytecode, trace):
    if sha256(binary.read_bytes()).hexdigest() != bridge["identity"]["executable_code_sha256"]:
        raise ValueError("bridge executable identity mismatch")
    handler_digest = sha256((json.dumps(handler, indent=2) + "\n").encode()).hexdigest()
    if handler_digest != bridge["evidence"]["handler_summary_sha256"]:
        raise ValueError("bridge was built from a different handler summary")
    first_entry, observed_second_entry = entry_records(
        trace, int(handler["identity"]["entry_cutpoint"], 16))
    first_word_offset = bridge["adapter_evidence"]["first_instruction_file_offset"]
    chunk = bytecode.read_bytes()
    first_word = int.from_bytes(chunk[first_word_offset:first_word_offset + 4], "little")
    if first_entry["registers"]["r12"] & 0xFFFFFFFF != first_word:
        raise AssertionError("first runtime instruction differs from bytecode image")
    first_result = apply(handler, binary, trace, occurrence=0)
    if first_result["status"] != "differentially_validated":
        raise AssertionError("first handler summary did not apply")
    decls = declarations(bridge)
    solver = z3.Solver()
    base, first_memory = bind_first_state(solver, decls, bridge, first_entry)
    first_effect_count = len(handler["case"]["ordered_effects"])
    bridge_reads = [item for item in bridge["case"]["reads"]
                    if item["memory_version"] >= first_effect_count]
    if len(bridge_reads) != 2:
        raise AssertionError("bridge read contract changed")
    code_read = bridge_reads[0]
    code_address = concrete(solver, expression(code_read["address"], "BV64", decls))
    code_file_offset = first_word_offset + 4 + code_address - first_entry["registers"]["r11"]
    if code_file_offset < 0:
        raise ValueError("derived code read precedes bytecode image")
    if code_file_offset != bridge["adapter_evidence"]["second_instruction_file_offset"]:
        raise ValueError("derived code read conflicts with bytecode position map")
    code_bytes = chunk[code_file_offset:code_file_offset + code_read["width"]]
    if len(code_bytes) != code_read["width"]:
        raise ValueError("second word outside bytecode image")
    bind_bytes(solver, decls["M0"], code_address, code_bytes)
    table_read = bridge_reads[1]
    table_address = concrete(solver, expression(table_read["address"], "BV64", decls))
    for effect in first_result["predicted_effects"]:
        written = range(effect["address"], effect["address"] + effect["width"])
        if (written.start < code_address + len(code_bytes) and code_address < written.stop or
            written.start < table_address + table_read["width"] and table_address < written.stop):
            return {"status": "unknown(code or dispatch table modified)"}
    table_bytes = elf_bytes(binary, table_address, table_read["width"])
    bind_bytes(solver, decls["M0"], table_address, table_bytes)
    for guard in bridge["case"]["path_guard"]:
        if not concrete(solver, expression(guard, "Bool", decls)):
            return {"status": "unknown(outside conditional path)"}
    predicted = {item["name"]: concrete(solver, expression(item["expression"], item["sort"], decls))
                 for item in bridge["case"]["outputs"]}
    if predicted["dispatch_target"] != int(bridge["identity"]["exit_cutpoint"], 16):
        raise AssertionError("derived dispatch target misses handler entry")
    registers = {key[2:].lower(): value for key, value in predicted.items() if key.startswith("R_")}
    eflags = first_entry["registers"]["eflags"]
    for name, value in predicted.items():
        if name.startswith("F_"):
            bit = int(name[2:])
            eflags = (eflags & ~(1 << bit)) | (value << bit)
    registers["eflags"] = eflags
    if registers["rbx"] != base:
        raise AssertionError("VM stack base moved outside available snapshot")
    memory_after = bytearray(first_memory)
    for effect in first_result["predicted_effects"]:
        index = effect["address"] - base
        if index < 0 or index + effect["width"] > len(memory_after):
            raise ValueError("first effect outside captured VM memory")
        memory_after[index:index + effect["width"]] = effect["value"].to_bytes(effect["width"], "little")
    synthetic_entry = {"registers": registers,
                       "entry_memory": {"base": base, "bytes_hex": memory_after.hex()}}
    second_result = apply(handler, binary, trace, occurrence=1, entry_override=synthetic_entry)
    if second_result["status"] != "differentially_validated":
        raise AssertionError("second handler summary did not apply")
    for name in registers:
        if name != "eflags" and registers[name] != observed_second_entry["registers"][name]:
            raise AssertionError(f"predicted second-entry register {name} differs")
    for name, value in predicted.items():
        if name.startswith("F_") and value != (observed_second_entry["registers"]["eflags"] >> int(name[2:])) & 1:
            raise AssertionError(f"predicted second-entry flag {name} differs")
    if memory_after.hex() != observed_second_entry["entry_memory"]["bytes_hex"]:
        raise AssertionError("predicted second-entry VM memory differs")
    program_input = next(row["input"] for row in (json.loads(line) for line in trace.read_text().splitlines())
                         if row.get("type") == "meta")
    program_output = int(subprocess.check_output([str(binary), str(bytecode), str(program_input)],
                                                 text=True).strip())
    value = second_result["predicted_effects"][0]["value"]
    signed_value = value - (1 << 64) if value >> 63 else value
    if signed_value != program_output:
        raise AssertionError("composed payload differs from program output")
    return {"status": "differentially_validated", "input": program_input,
            "first_word": hex(first_word), "second_word": hex(int.from_bytes(code_bytes, "little")),
            "first_payload": first_result["predicted_effects"][0]["value"],
            "second_payload": value, "program_output": program_output,
            "first_destination": first_result["predicted_effects"][0]["address"],
            "second_destination": second_result["predicted_effects"][0]["address"],
            "predicted_second_entry_word": hex(registers["r12"] & 0xFFFFFFFF),
            "predicted_second_entry_matches_trace": True,
            "second_entry_snapshot_used_as_input": False,
            "bridge_code_read_address": code_address,
            "bridge_table_read_address": table_address}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("handler_summary", type=Path)
    parser.add_argument("bridge_summary", type=Path)
    parser.add_argument("binary", type=Path)
    parser.add_argument("bytecode", type=Path)
    parser.add_argument("trace", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    handler = json.loads(args.handler_summary.read_text())
    bridge = json.loads(args.bridge_summary.read_text())
    result = compose(handler, bridge, args.binary, args.bytecode, args.trace)
    result["handler_summary_sha256"] = sha256(args.handler_summary.read_bytes()).hexdigest()
    result["bridge_summary_sha256"] = sha256(args.bridge_summary.read_bytes()).hexdigest()
    result["trace_sha256"] = sha256(args.trace.read_bytes()).hexdigest()
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
