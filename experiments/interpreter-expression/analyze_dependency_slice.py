"""Retain address inputs and path-control inputs around observed result slices.

This is an obligation inventory: the native path, guards, and all non-value
effects stay in the existing certificates. It does not delete instructions.
"""
from collections import Counter
from hashlib import sha256
import json

from common_native_slice import caller_slice, lanes
from prove_cross_full_flow import JAVASCRIPT, PYTHON, load_trace
from prove_lua_full_flow import trace_records
from run_integrated_pipeline import (ARTIFACTS, BRANCH_INPUT, ROOT,
                                     lua_value_rows)


OUTPUT = ROOT / "address_control_slice_result.json"
BASELINE = ROOT / "integrated_native_slice_42.json"


def main():
    baseline = json.loads(BASELINE.read_text())
    lua_path = ARTIFACTS / "integrated_lua_branch_42.jsonl"
    python_path = ARTIFACTS / "integrated_python_branch_42.json.gz"
    javascript_path = ARTIFACTS / "integrated_js_branch_42.json.gz"
    _, python_rows, python_summary = load_trace(
        python_path, "python", BRANCH_INPUT, PYTHON)
    _, javascript_rows, _ = load_trace(
        javascript_path, "javascript", BRANCH_INPUT, JAVASCRIPT)
    subjects = {
        "lua": (lua_value_rows(trace_records(lua_path)),
                lanes("register", 160, 8, 0), lua_path),
        "python": (python_rows,
                   lanes("memory", python_summary["exit_registers"]["r15"] - 8,
                         8, 0), python_path),
        "javascript": (javascript_rows, lanes("register", 0, 8, 0),
                       javascript_path)}
    result = {}
    for engine, (rows, sink, path) in subjects.items():
        selected, debts, live, _, _, selected_steps, audit = caller_slice(
            rows, sink, include_address_control=True)
        original = baseline["engines"][engine]
        if len(selected) < len(original["selected_operations"]) or \
                audit["selected_address_dependencies"] == 0 or \
                audit["retained_control_operations"] == 0:
            raise ValueError(f"{engine} address/control obligations were lost")
        old = {(row["step"], row["ordinal"], row["opcode"])
               for row in original["selected_operations"]}
        new = {(row["step"], row["ordinal"], row["opcode"])
               for row in selected}
        if not old <= new:
            raise ValueError(f"{engine} original value dependencies were dropped")
        result[engine] = {"trace_sha256": sha256(path.read_bytes()).hexdigest(),
            "native_steps_in_interval": len(rows),
            "raw_dynamic_pcode_operations": audit["raw_dynamic_pcode_operations"],
            "baseline_value_pcode_operations": len(old),
            "address_control_pcode_operations": len(selected),
            "selected_native_steps": selected_steps,
            "selected_address_dependencies": audit["selected_address_dependencies"],
            "retained_control_operations": audit["retained_control_operations"],
            "selected_opcode_counts": dict(sorted(Counter(
                item["opcode"] for item in selected).items())),
            "entry_live_byte_lanes": len(live),
            "debts": debts[:20], "debt_count": len(debts),
            "excluded_effect_counts": audit["excluded_counts"],
            "scope": "concrete address and recorded path control closure; no effect erasure"}
    OUTPUT.write_text(json.dumps({"schema_version": 1,
        "baseline_sha256": sha256(BASELINE.read_bytes()).hexdigest(),
        "engines": result,
        "limits": ["observed native address mapping still chooses LOAD/STORE targets",
                   "unknown aliasing writes and unmodeled effects remain obligations",
                   "recorded conditional, indirect and return inputs are retained; direct constant targets are not value dependencies",
                   "entry live byte lanes are external state requirements"]},
        indent=2) + "\n")
    print(json.dumps({engine: {"selected": item["address_control_pcode_operations"],
                                "control": item["retained_control_operations"],
                                "debts": item["debt_count"]}
                      for engine, item in result.items()}))


if __name__ == "__main__":
    main()
