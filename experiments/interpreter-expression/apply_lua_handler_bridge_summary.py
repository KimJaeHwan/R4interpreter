"""Compose two Lua handler instances through a frozen dispatch segment."""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import subprocess

from compose_lua_two_adds import elf_bytes
from composed_native_transition import apply_segment, parse_segments
from pcode_transition_summary import FLAG_OFFSETS, REGISTER_OFFSETS
from prove_lua_full_flow import initial_memory


ROOT = Path(__file__).resolve().parent
SUMMARY = ROOT / "lua_handler_bridge_composed_summary.json"
RESULT = ROOT / "lua_handler_bridge_application_result.json"
INPUTS = {"x9": 9, "zero": 0, "one": 1, "minus_one": -1,
          "max": 9223372036854775807, "min": -9223372036854775808}


def native_rows(trace, summary):
    records = [json.loads(line) for line in trace.read_text().splitlines()]
    meta = next(row for row in records if row.get("type") == "meta")
    steps = [row for row in records if row.get("type") == "step"]
    first = next(index for index, row in enumerate(steps)
                 if hex(row["pc"]) == summary["segments"][0]["identity"]["entry_pc"])
    steps = steps[first:]
    if len(steps) != sum(next(segment["identity"]["native_steps"]
                             for segment in summary["segments"]
                             if segment["label"] == label)
                         for label in summary["composition"]):
        raise ValueError("Lua trace does not cover exactly two handler entries and bridge")
    return meta, steps


def static_bindings(summary, rows, binary, bytecode):
    first_offset = summary["adapter_evidence"]["first_instruction_file_offset"]
    second_offset = summary["adapter_evidence"]["second_instruction_file_offset"]
    chunk = bytecode.read_bytes()
    first_word = int.from_bytes(chunk[first_offset:first_offset + 4], "little")
    second_word = int.from_bytes(chunk[second_offset:second_offset + 4], "little")
    if rows[0]["registers"]["r12"] & 0xFFFFFFFF != first_word:
        return "unknown(first bytecode word)"
    handler_steps = summary["segments"][0]["identity"]["native_steps"]
    bridge = rows[handler_steps:handler_steps + summary["segments"][1][
        "identity"]["native_steps"]]
    reads = [access for row in bridge for access in row["memory"]
             if access["access"] & 1]
    if len(reads) != 2 or reads[0]["size"] != 4 or reads[1]["size"] != 8:
        return "unknown(dispatch read inventory)"
    code_offset = first_offset + 4 + reads[0]["address"] - rows[0][
        "registers"]["r11"]
    if code_offset != second_offset or reads[0]["before"] != second_word:
        return "unknown(second bytecode word)"
    if reads[1]["before"] != int.from_bytes(elf_bytes(
            binary, reads[1]["address"], 8), "little"):
        return "unknown(read-only dispatch table)"
    return None


def signed64(value):
    return value - (1 << 64) if value >> 63 else value


def apply(summary, decls, parsed, value, trace, binary, bytecode,
          rows_override=None):
    if (summary.get("schema_version") != "composed-native-sequence-transition-v1" or
            summary.get("engine") != "lua" or
            sha256(binary.read_bytes()).hexdigest() != summary["binary_sha256"] or
            sha256(bytecode.read_bytes()).hexdigest() != summary["bytecode_sha256"] or
            summary.get("composition") != ["handler", "bridge", "handler"]):
        return {"input": value, "status": "unknown(summary/code identity)"}
    meta, recorded_rows = native_rows(trace, summary)
    rows = recorded_rows if rows_override is None else rows_override
    if meta.get("input") != value:
        return {"input": value, "status": "unknown(input identity)"}
    reason = static_bindings(summary, rows, binary, bytecode)
    if reason:
        return {"input": value, "status": reason}
    first = rows[0]["registers"]
    state = {name: first[name] for name in REGISTER_OFFSETS.values()}
    flags = {bit: (first["eflags"] >> bit) & 1 for bit in FLAG_OFFSETS.values()}
    memory, initial_byte_count = initial_memory(rows)
    stages = []
    cursor = 0
    for label in summary["composition"]:
        segment = parsed[label]
        width = segment["identity"]["native_steps"]
        applied, reason = apply_segment(label, segment, rows[cursor:cursor + width],
                                        summary, decls, state, flags, memory)
        if reason:
            return {"input": value, "status": reason,
                    "completed_stages": [stage["label"] for stage in stages]}
        state, flags, memory, evidence = applied
        stages.append(evidence)
        cursor += width
        if label == "handler" and len(stages) == 1:
            code_reads = [access for row in rows[
                width:width + parsed["bridge"]["identity"]["native_steps"]]
                for access in row["memory"] if access["access"] & 1]
            for effect in evidence["predicted_effects"]:
                for read in code_reads:
                    if (effect["address"] < read["address"] + read["size"] and
                            read["address"] < effect["address"] + effect["width"]):
                        return {"input": value,
                                "status": "unknown(code or dispatch table modified)"}
    if cursor != len(rows):
        return {"input": value, "status": "unknown(unconsumed Lua path)"}
    first_effect = stages[0]["predicted_effects"][0]
    second_effect = stages[2]["predicted_effects"][0]
    output = signed64(second_effect["value"])
    actual_output = int(subprocess.check_output(
        [str(binary), str(bytecode), str(value)], text=True).strip())
    if output != actual_output:
        return {"input": value, "status": "unknown(program output)"}
    return {"input": value, "status": "differentially_validated",
            "first_payload": signed64(first_effect["value"]),
            "second_payload": output, "program_output": actual_output,
            "first_destination": first_effect["address"],
            "second_destination": second_effect["address"],
            "initial_read_bytes": initial_byte_count,
            "native_steps": len(rows), "target_pcode_operations_replayed": 0,
            "source_pcode_operations_replayed_at_application": 0,
            "second_entry_state_used_as_input": False,
            "stages": [{key: stage[key] for key in (
                "label", "native_steps", "reads_checked", "ordered_writes_checked",
                "outputs_checked")} for stage in stages]}


def main():
    summary = json.loads(SUMMARY.read_text())
    decls, parsed = parse_segments(summary, {"handler", "bridge"})
    binary = ROOT / "lua_interpreter_fixture"
    bytecode = ROOT / "lua_chunk_two_adds.luac"
    cases = []
    for name, value in INPUTS.items():
        trace = ROOT / "artifacts" / f"lua_two_adds_{name}.jsonl"
        item = apply(summary, decls, parsed, value, trace, binary, bytecode)
        item["trace"] = trace.name
        item["trace_sha256"] = sha256(trace.read_bytes()).hexdigest()
        cases.append(item)
    trace = ROOT / "artifacts/lua_two_adds_x9.jsonl"
    _, source_rows = native_rows(trace, summary)
    bad_effect = deepcopy(source_rows)
    write = next(access for row in bad_effect for access in row["memory"]
                 if access["access"] & 2)
    write["after"] ^= 1
    bad_path = deepcopy(source_rows)
    bad_path[23]["next_pc"] += 1
    bad_second_entry = deepcopy(source_rows)
    second_index = (summary["segments"][0]["identity"]["native_steps"] +
                    summary["segments"][1]["identity"]["native_steps"])
    bad_second_entry[second_index]["registers"]["rdx"] ^= 1
    probes = {"wrong_native_write": apply(summary, decls, parsed, 9,
        trace, binary, bytecode, bad_effect)["status"],
        "wrong_bridge_path": apply(summary, decls, parsed, 9,
        trace, binary, bytecode, bad_path)["status"],
        "wrong_second_entry_snapshot": apply(summary, decls, parsed, 9,
        trace, binary, bytecode, bad_second_entry)["status"]}
    if (any(item["status"] != "differentially_validated" for item in cases) or
            any(not item.startswith("unknown(") for item in probes.values())):
        raise ValueError("unexpected Lua frozen segment applicability")
    report = {"schema_version": 1,
              "summary_sha256": sha256(SUMMARY.read_bytes()).hexdigest(),
              "cases": cases, "negative_probes": probes,
              "metrics": {"targets": len(cases),
                          "full_native_transitions_matched": len(cases),
                          "target_pcode_operations_replayed": 0,
                          "source_pcode_operations_replayed_at_application": 0},
              "limits": ["target native path and first-read memory supplied by trace",
                         "first handler input state supplied by trace",
                         "fixed numeric path and bytecode image; alternative paths unknown"]}
    RESULT.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report["metrics"]))


if __name__ == "__main__":
    main()
