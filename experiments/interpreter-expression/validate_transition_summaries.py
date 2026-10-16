"""Differentially validate frozen summaries on independent boundary traces."""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import subprocess
import tempfile

from apply_transition_summary import apply


ROOT = Path(__file__).resolve().parent
ARTIFACTS = ROOT / "artifacts"
CASES = {"x9": 9, "zero": 0, "one": 1, "minus_one": -1,
         "max_minus_11": 9223372036854775796,
         "max_minus_7": 9223372036854775800,
         "max": 9223372036854775807,
         "min": -9223372036854775808}
NATIVE_CASES = {"x9": 9, "zero": 0, "one": 1,
                "max_minus_7": 18446744073709551608,
                "max": 18446744073709551615}


def signed64(value):
    value &= (1 << 64) - 1
    return value - (1 << 64) if value >> 63 else value


def main():
    lua_path = ROOT / "handler_summary_plus7.json"
    native_path = ROOT / "native_summary_add7.json"
    lua_summary = json.loads(lua_path.read_text())
    native_summary = json.loads(native_path.read_text())
    report = {"schema_version": "transition-summary-validation-v0",
              "lua_summary_sha256": sha256(lua_path.read_bytes()).hexdigest(),
              "native_summary_sha256": sha256(native_path.read_bytes()).hexdigest(),
              "lua": [], "native": []}
    for increment in (7, 11):
        bytecode = ROOT / ("lua_chunk.luac" if increment == 7 else "lua_chunk_plus11.luac")
        word = int.from_bytes(bytecode.read_bytes()[47:51], "little")
        assert word & 127 == 21
        for name, x in CASES.items():
            trace = ARTIFACTS / f"lua_handler_plus{increment}_{name}.jsonl"
            entry = next(row for row in (json.loads(line) for line in trace.read_text().splitlines())
                         if row.get("pc") == 0x4164B8)
            assert entry["registers"]["r12"] & 0xFFFFFFFF == word
            outcome = apply(lua_summary, ROOT / "lua_interpreter_fixture", trace)
            expected = signed64(x + increment)
            observed_output = subprocess.check_output(
                [str(ROOT / "lua_interpreter_fixture"), str(bytecode), str(x)], text=True).strip()
            actual = int(observed_output)
            predicted = signed64(outcome["predicted_effects"][0]["value"])
            assert outcome["status"] == "differentially_validated"
            assert predicted == actual == expected
            assert outcome["predicted_effects"][1]["value"] == 3
            report["lua"].append({"bytecode": bytecode.name, "input": x,
                                  "instruction_word": hex(word), "handler_entry": hex(entry["pc"]),
                                  "trace_sha256": sha256(trace.read_bytes()).hexdigest(),
                                  "predicted_signed_payload": predicted,
                                  "observed_program_output": actual,
                                  "predicted_tag": 3,
                                  "next_code_pointer": outcome["outputs"][0]["value"],
                                  "native_steps": outcome["native_steps_within_summary"]})
    for name, x in NATIVE_CASES.items():
        trace = ARTIFACTS / f"elf_transition_{name}.jsonl"
        outcome = apply(native_summary, ROOT / "elf_expression_fixture", trace)
        actual = int(subprocess.check_output([str(ROOT / "elf_expression_fixture"), str(x)],
                                             text=True).strip())
        predicted = outcome["outputs"][0]["value"]
        assert outcome["status"] == "differentially_validated"
        assert predicted == actual == (x + 7) & ((1 << 64) - 1)
        report["native"].append({"input": x,
                                 "trace_sha256": sha256(trace.read_bytes()).hexdigest(),
                                 "predicted_return": predicted,
                                 "observed_program_output": actual})
    source = ARTIFACTS / "lua_handler_plus11_x9.jsonl"
    records = [json.loads(line) for line in source.read_text().splitlines()]
    entry = next(row for row in records if row.get("pc") == 0x4164B8)
    memory = bytearray.fromhex(entry["entry_memory"]["bytes_hex"])
    original_tag = memory[8]
    assert original_tag == 3
    memory[8] = 4
    entry["entry_memory"]["bytes_hex"] = memory.hex()
    with tempfile.TemporaryDirectory() as directory:
        modified = Path(directory) / "tag4.jsonl"
        modified.write_text("\n".join(json.dumps(row) for row in records) + "\n")
        outcome = apply(lua_summary, ROOT / "lua_interpreter_fixture", modified)
    assert outcome["status"] == "unknown(outside conditional path)"
    report["synthetic_out_of_path_tag"] = {"original": original_tag, "changed_to": 4,
                                           "status": outcome["status"]}
    report["counts"] = {"lua": len(report["lua"]), "native": len(report["native"]),
                        "lua_nontraining": len(report["lua"]) - 1,
                        "native_nontraining": len(report["native"]) - 1}
    (ROOT / "transition_summary_validation.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report["counts"]))


if __name__ == "__main__":
    main()
