"""Compare broad caller slices with path-sensitive local-control inventories."""
from collections import Counter
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path

import pypcode

from common_native_slice import caller_slice, lanes
from common_observed_transition import shape
from discover_dispatch_intervals import candidates, choose_summary
from observed_pcode_schedule import schedule
from prove_cross_full_flow import JAVASCRIPT, PYTHON, load_trace
from prove_lua_full_flow import trace_records
from run_integrated_pipeline import ROOT, lua_value_rows


ARTIFACTS = ROOT / "artifacts"
OUTPUT = ROOT / "observed_dependency_audit_result.json"


def compact(rows, sink, path):
    selected, debts, live, _, _, selected_steps, audit = caller_slice(
        rows, sink, include_address_control=True, strict_schedule=True)
    groups = Counter(item["reason"] for item in debts)
    local_families = Counter(item.get("instruction", "").split(" ", 1)[0]
        for item in debts if item["reason"].startswith("unsupported instruction-local"))
    return {"trace_sha256": sha256(path.read_bytes()).hexdigest(),
        "interval_native_steps": len(rows),
        "raw_pcode_operations": audit["raw_dynamic_pcode_operations"],
        "selected_pcode_operations": len(selected),
        "selected_native_steps": selected_steps,
        "observed_cmov_guards_checked": len(audit["supported_local_guards"]),
        "observed_skipped_pcode_operations": audit["skipped_observed_pcode_operations"],
        "unsupported_local_control_steps": audit["unsupported_local_control_steps"],
        "debt_count": len(debts), "debts_by_reason": dict(groups),
        "unsupported_local_instruction_families": dict(local_families),
        "debt_examples": debts[:8],
        "entry_live_byte_lanes": len(live),
        "syntactic_debt_free": audit["syntactic_debt_free"],
        "retained_control_operations": audit["retained_control_operations"],
        "excluded_control_counts": {key: value for key, value in
                                    audit["excluded_counts"].items()
                                    if key.startswith("control_or_")},
        "cmov_guard_examples": audit["supported_local_guards"][:4]}


def one_cmov_negative(rows):
    ctx = pypcode.Context("x86:LE:64:default")
    cases = {}
    for row in (row for row in rows if row["instruction"].startswith("cmov")):
        operations = [op for op in ctx.translate(bytes.fromhex(row["bytes"]),
            base_address=row["pc"], max_instructions=1).ops
            if op.opcode.name != "IMARK"]
        selected, evidence, reason = schedule(row, operations)
        if evidence is None or reason is not None:
            raise ValueError("control source CMOV did not resolve")
        destination = row["instruction"].split(" ", 1)[1].split(",", 1)[0]
        if len(selected) < len(operations) and "skipped_destination" not in cases:
            changed = deepcopy(row)
            changed["registers_after"][destination] ^= 1
            cases["skipped_destination"] = (row, changed, operations)
            changed = deepcopy(row)
            changed["next_pc"] += 1
            cases["wrong_fallthrough"] = (row, changed, operations)
            flag = next((bit for bit in (0, 2, 6, 7, 11)
                         if f"F_{bit}" in evidence["guard_smt2"]), None)
            if flag is None:
                raise ValueError("CMOV guard has no modeled flag input")
            changed = deepcopy(row)
            changed["registers"]["eflags"] ^= 1 << flag
            cases["altered_input_flag"] = (row, changed, operations)
        if len(selected) == len(operations) and "executed_destination" not in cases:
            changed = deepcopy(row)
            changed["registers_after"][destination] ^= 1
            cases["executed_destination"] = (row, changed, operations)
        if len(cases) == 4:
            break
    if len(cases) != 4:
        raise ValueError("CMOV negative controls need both execution paths")
    rejected = {}
    for name, (row, changed, operations) in cases.items():
        _, evidence, reason = schedule(changed, operations)
        if evidence is not None or reason is None:
            raise ValueError(f"{name} CMOV mutation was admitted")
        rejected[name] = {"pc": hex(row["pc"]), "status": "unknown",
                          "reason": reason}
    return rejected


def main():
    common = json.loads((ROOT / "common_three_engine_transitions.json").read_text())
    lua_path = ARTIFACTS / "integrated_lua_branch_42.jsonl"
    py_path = ARTIFACTS / "integrated_python_branch_42.json.gz"
    js_path = ARTIFACTS / "integrated_js_branch_42.json.gz"
    py_meta, py_rows, py_summary = load_trace(py_path, "python", 42, PYTHON)
    _, js_rows, _ = load_trace(js_path, "javascript", 42, JAVASCRIPT)
    full = {
        "lua": compact(lua_value_rows(trace_records(lua_path)),
                       lanes("register", 160, 8, 0), lua_path),
        "python": compact(py_rows,
            lanes("memory", py_summary["exit_registers"]["r15"] - 8, 8, 0),
            py_path),
        "javascript": compact(js_rows, lanes("register", 0, 8, 0), js_path)}
    fresh = {}
    for engine, binary, path in (
            ("python", PYTHON, ARTIFACTS / "next_boundary_py_43.json.gz"),
            ("javascript", JAVASCRIPT,
             ARTIFACTS / "next_boundary_js_43.json.gz")):
        _, rows, _ = load_trace(path, engine, 43, binary)
        identity = choose_summary(common, engine)["identity"]
        matching = [item for item in candidates(rows)
                    if item["native_steps"] == identity["native_steps"] and
                    shape(rows[item["begin"]:item["end_exclusive"]],
                          identity["path_shape_mode"]) ==
                    identity["path_shape_sha256"]]
        if len(matching) != 1:
            raise ValueError("fresh numerical interval absent from candidate list")
        boundary = matching[0]
        segment = rows[boundary["begin"]:boundary["end_exclusive"]]
        sink = (lanes("memory", segment[-1]["registers_after"]["r15"] - 8,
                      8, 0) if engine == "python" else
                lanes("register", 0, 8, 0))
        fresh[engine] = compact(segment, sink, path)
    controls = {"cmov": one_cmov_negative(py_rows)}
    OUTPUT.write_text(json.dumps({"schema_version": 1,
        "full_caller_intervals": full, "fresh_dispatch_intervals": fresh,
        "negative_controls": controls,
        "scope": "observed P-code dependency inventory; a zero debt count does not prove alias independence or effect removability",
        "remaining": "unsupported JS REP/atomic local flow, AVX-512 CALLOTHER and access-mode-zero rows remain unknown"},
        indent=2) + "\n")
    print(json.dumps({engine: {"debt_count": result["debt_count"],
        "cmov_guards": result["observed_cmov_guards_checked"]}
        for engine, result in full.items()}))


if __name__ == "__main__":
    main()
