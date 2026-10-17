"""Assemble a guarded Lua branch/call observation from native and P-code evidence.

The Lua source is not read here. Full-script guards remain candidates; local
branch, call-argument and arithmetic reductions have separate P-code proofs.
"""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parent
MASK = (1 << 64) - 1
CASES = [("0", 0), ("9", 9), ("minus1", -1), ("max", (1 << 63) - 1)]


def signed(value):
    value &= MASK
    return value - (1 << 64) if value >> 63 else value


def main():
    binary = ROOT / "lua_interpreter_fixture"
    bytecode = ROOT / "lua_branch_call.luac"
    records = []
    for name, value in CASES:
        map_name = "-1" if name == "minus1" else name
        map_path = ROOT / f"lua_branch_call_map_{map_name}.json"
        mapping = json.loads(map_path.read_text())
        handler_name = f"x{name}" if name in ("0", "9") else name
        logic = json.loads((ROOT / f"lua_branch_call_handler_logic_{handler_name}.json").read_text())
        validation = json.loads((ROOT / f"lua_branch_call_handler_validation_{handler_name}.json").read_text())
        if mapping["vm_code_regions"] != 2:
            raise ValueError("expected caller and callee bytecode regions")
        if mapping["binary_sha256"] != sha256(binary.read_bytes()).hexdigest() or \
                mapping["bytecode_sha256"] != sha256(bytecode.read_bytes()).hexdigest():
            raise ValueError("binary or bytecode identity mismatch")
        caller = [e for e in mapping["events"] if e["vm_code_region"] == 0]
        callee = [e for e in mapping["events"] if e["vm_code_region"] == 1]
        if [e["bytecode_index"] for e in callee] != [0, 2] or \
                not callee[0]["contains_observed_addition_pc"]:
            raise ValueError("callee handler path changed")
        if logic["value"] != "X + 5" or not logic["value_reduction_proved"]:
            raise ValueError("callee P-code value reduction missing")
        if validation["status"] != "differentially_validated":
            raise ValueError("callee summary differential validation failed")
        entry_value = int(logic["witness"])
        handler_value = signed(validation["predicted_effects"][0]["value"])
        if handler_value != signed(entry_value + 5):
            raise ValueError("handler projection and observed effect differ")
        actual = int(subprocess.check_output([str(binary), str(bytecode), str(value)], text=True))
        if actual != handler_value:
            raise ValueError("observed script return differs from handler payload")
        records.append({"input": str(value), "caller_bytecode_indices": [e["bytecode_index"] for e in caller],
                        "callee_bytecode_indices": [e["bytecode_index"] for e in callee],
                        "callee_entry_value": str(signed(entry_value)),
                        "callee_payload": str(handler_value), "script_return": str(actual),
                        "native_vm_instructions": sum(e["executed_native_steps_until_next_fetch_or_return"]
                                                      for e in mapping["events"]),
                        "map_sha256": sha256(map_path.read_bytes()).hexdigest(),
                        "handler_trace_sha256": validation["trace_sha256"]})
    zero, nonzero = records[0], records[1:]
    if zero["caller_bytecode_indices"] != [0, 1, 2, 3, 5, 6, 7] or any(
            row["caller_bytecode_indices"] != [0, 1, 2, 3, 9, 10, 11] for row in nonzero):
        raise ValueError("observed branch classes changed")
    if zero["callee_entry_value"] != "5" or any(
            row["callee_entry_value"] != row["input"] for row in nonzero):
        raise ValueError("observed argument binding changed")
    local_path = ROOT / "lua_branch_local_input.json"
    local = json.loads(local_path.read_text())
    if local["binary_sha256"] != sha256(binary.read_bytes()).hexdigest() or \
            local["bytecode_sha256"] != sha256(bytecode.read_bytes()).hexdigest():
        raise ValueError("local VM boundary proof targets another fixture")
    if [(path["guard"], path["callee_input"]) for path in local["paths"]] != [
            ("X_local == 0", "5"), ("X_local != 0", "X_local")]:
        raise ValueError("local VM branch/call relation changed")
    if any(path["guard_equivalence"] != "unsat" or
           path["branch_operand_equivalence"] != "unsat" or
           path["callee_input_equivalence"] != "unsat" for path in local["paths"]):
        raise ValueError("local VM boundary proof missing")
    report = {"schema_version": 1, "format": "guarded_input_relation",
              "engine": "lua_5_4_fixture", "source": "branch_and_called_lua_function",
              "scope": "observed_full_script_paths", "input": "X:BV64",
              "binary_sha256": sha256(binary.read_bytes()).hexdigest(),
              "program_sha256": sha256(bytecode.read_bytes()).hexdigest(),
              "observed_samples": len(records), "records": records,
              "local_vm_boundary": {
                  "input": "X_local:BV64", "entry_native_pc": local["entry_native_pc"],
                  "evidence_sha256": sha256(local_path.read_bytes()).hexdigest(),
                  "paths": [{"guard": path["guard"], "guard_proven": True,
                             "callee_input": path["callee_input"], "callee_input_proven": True}
                            for path in local["paths"]]},
              "paths": [
                  {"guard": "X == 0", "guard_proven": False,
                   "status": "observed_return", "value": "10", "value_proven": False,
                   "handler_value": "callee_input + 5", "handler_value_proven": True,
                   "observed_inputs": [zero["input"]]},
                  {"guard": "X != 0", "guard_proven": False,
                   "status": "observed_return", "value": "X + 5", "value_proven": False,
                   "handler_value": "callee_input + 5", "handler_value_proven": True,
                   "observed_inputs": [row["input"] for row in nonzero]}],
              "limits": "The local VM source-to-callee relation and arithmetic handler reduction are conditional on their captured entry states. CLI X to X_local and final return composition are not proved for all X."}
    (ROOT / "lua_branch_call_relation.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"samples": len(records), "observed_paths": 2,
                      "local_vm_boundary_proved": True,
                      "callee_value_proved": True, "full_script_guard_proved": False}))


if __name__ == "__main__":
    main()
