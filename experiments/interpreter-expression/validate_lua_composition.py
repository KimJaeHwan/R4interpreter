"""Differentially check the frozen two-handler composition on six inputs."""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import tempfile

from apply_transition_summary import apply
from compose_lua_two_adds import compose


ROOT = Path(__file__).resolve().parent
INPUTS = {"x9": 9, "zero": 0, "one": 1, "minus_one": -1,
          "max": 9223372036854775807, "min": -9223372036854775808}


def main():
    handler_path = ROOT / "handler_summary_plus7.json"
    bridge_path = ROOT / "lua_handler_dispatch_bridge.json"
    handler = json.loads(handler_path.read_text())
    bridge = json.loads(bridge_path.read_text())
    bytecode = ROOT / "lua_chunk_two_adds.luac"
    binary = ROOT / "lua_interpreter_fixture"
    report = {"schema_version": "vm-two-handler-composition-validation-v0",
              "handler_summary_sha256": sha256(handler_path.read_bytes()).hexdigest(),
              "bridge_summary_sha256": sha256(bridge_path.read_bytes()).hexdigest(),
              "bytecode_sha256": sha256(bytecode.read_bytes()).hexdigest(),
              "cases": []}
    for name, value in INPUTS.items():
        trace = ROOT / "artifacts" / f"lua_two_adds_{name}.jsonl"
        result = compose(handler, bridge, binary, bytecode, trace)
        standalone = apply(handler, binary, trace, occurrence=1)
        assert result["status"] == "differentially_validated" and result["input"] == value
        assert standalone["status"] == "differentially_validated"
        assert standalone["predicted_effects"][0]["value"] == result["second_payload"]
        assert standalone["predicted_effects"][0]["address"] == result["second_destination"]
        assert result["second_entry_snapshot_used_as_input"] is False
        assert result["second_destination"] - result["first_destination"] == 16
        report["cases"].append({"name": name, **result,
                                "standalone_second_entry_summary_matches": True,
                                "trace_sha256": sha256(trace.read_bytes()).hexdigest()})
    changed = bytearray(bytecode.read_bytes())
    second_offset = bridge["adapter_evidence"]["second_instruction_file_offset"]
    changed[second_offset] &= 0x80  # Synthetic second opcode with another dispatch index.
    with tempfile.TemporaryDirectory() as directory:
        synthetic = Path(directory) / "changed_second_word.luac"
        synthetic.write_bytes(changed)
        outside = compose(handler, bridge, binary, synthetic,
                          ROOT / "artifacts/lua_two_adds_x9.jsonl")
    assert outside["status"] == "unknown(outside conditional path)"
    report["synthetic_other_dispatch"] = {"second_word": hex(int.from_bytes(changed[second_offset:second_offset + 4], "little")),
                                          "status": outside["status"]}
    report["counts"] = {"composed_inputs": len(report["cases"]),
                        "independent_inputs": len(report["cases"]) - 1,
                        "synthetic_outside_path": 1}
    (ROOT / "lua_composition_validation.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report["counts"]))


if __name__ == "__main__":
    main()
