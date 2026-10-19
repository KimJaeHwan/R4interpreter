"""Generate observed dispatch-to-dispatch candidates without entry/exit PCs.

An indirect branch is a candidate delimiter, not proof of a VM handler. A
frozen full-transition summary and adapter must separately admit the window.
"""
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path

import pypcode

from common_observed_transition import apply_case, shape
from prove_cross_full_flow import (CACHE_BASE, JAVASCRIPT, PYTHON,
                                   load_trace, verify_cache)


ROOT = Path(__file__).resolve().parent
ARTIFACTS = ROOT / "artifacts"
SUMMARY = ROOT / "common_three_engine_transitions.json"
OUTPUT = ROOT / "dispatch_interval_discovery_result.json"
TRACE_CASES = (("python", 42, "integrated_python_branch_42.json.gz"),
               ("javascript", 42, "integrated_js_branch_42.json.gz"),
               ("python", 43, "next_boundary_py_43.json.gz"),
               ("javascript", 43, "next_boundary_js_43.json.gz"),
               ("python", 252, "next_boundary_py_252.json.gz"))


def digest(path):
    return sha256(path.read_bytes()).hexdigest()


def pcode_names(ctx, cache, row):
    key = row["pc"], row["bytes"]
    if key not in cache:
        cache[key] = tuple(op.opcode.name for op in ctx.translate(
            bytes.fromhex(row["bytes"]), base_address=row["pc"],
            max_instructions=1).ops if op.opcode.name != "IMARK")
    return cache[key]


def candidates(rows):
    if not rows or any(left["next_pc"] != right["pc"]
                       for left, right in zip(rows, rows[1:])):
        raise ValueError("dispatch candidate trace is discontinuous")
    ctx, cache = pypcode.Context("x86:LE:64:default"), {}
    dispatch = [index for index, row in enumerate(rows)
                if "BRANCHIND" in pcode_names(ctx, cache, row)]
    found = []
    for left, right in zip(dispatch, dispatch[1:]):
        if left + 1 >= right or rows[left]["next_pc"] != rows[left + 1]["pc"]:
            continue
        segment = rows[left + 1:right + 1]
        found.append({"begin": left + 1, "end_exclusive": right + 1,
            "entry_predecessor": left, "entry_pc": hex(segment[0]["pc"]),
            "exit_pc": hex(segment[-1]["next_pc"]),
            "native_steps": len(segment),
            "internal_indirect_calls": sum("CALLIND" in
                pcode_names(ctx, cache, row) for row in segment)})
    return found


def choose_summary(common, engine):
    kinds = {"python": "python_cached_int", "javascript": "guard_only"}
    cases = [case for case in common["cases"] if case["engine"] == engine and
             case["preconditions"]["kind"] == kinds[engine] and
             case["identity"]["entry_pc"] != case["identity"]["next_pc"]]
    if len(cases) != 1:
        raise ValueError("numeric summary selection is ambiguous")
    return cases[0]


def admitted(common, case, engine, witness, meta, rows, segment):
    binary = PYTHON if engine == "python" else JAVASCRIPT
    if engine == "python":
        cache_hash = verify_cache(meta)
        adapter = {"input": witness,
            "runtime_cache_sha256_at_entry": cache_hash,
            "runtime_cache_sha256_at_exit": cache_hash,
            "left_pointer": meta["entry_value_address"],
            "right_pointer": CACHE_BASE + 10 * 32,
            "output_slot": segment[-1]["registers_after"]["r15"] - 8}
    else:
        adapter = None
    return apply_case(common, case, binary, segment, adapter)


def run_case(common, engine, witness, filename):
    path = ARTIFACTS / filename
    binary = PYTHON if engine == "python" else JAVASCRIPT
    meta, rows, _ = load_trace(path, engine, witness, binary)
    case = choose_summary(common, engine)
    all_candidates = candidates(rows)
    identity = case["identity"]
    shape_matches = [item for item in all_candidates
        if item["native_steps"] == identity["native_steps"] and
        shape(rows[item["begin"]:item["end_exclusive"]],
              identity["path_shape_mode"]) == identity["path_shape_sha256"]]
    if not shape_matches:
        return {"engine": engine, "input": witness,
            "trace_sha256": digest(path), "candidate_count": len(all_candidates),
            "shape_matches": 0, "status": "unknown(different dispatch interval)",
            "same_entry_different_length": [item["native_steps"]
                for item in all_candidates
                if item["entry_pc"] == identity["entry_pc"]]}
    if len(shape_matches) != 1:
        raise ValueError(f"{engine} frozen interval is absent or ambiguous")
    boundary = shape_matches[0]
    segment = rows[boundary["begin"]:boundary["end_exclusive"]]
    verdict = admitted(common, case, engine, witness, meta, rows, segment)
    if verdict["status"] != "differentially_validated":
        raise ValueError(f"{engine} discovered boundary failed effects: {verdict}")
    changed = deepcopy(segment)
    changed[-1]["next_pc"] ^= 1
    wrong_end = admitted(common, case, engine, witness, meta, rows, changed)
    if not wrong_end["status"].startswith("unknown("):
        raise ValueError("changed discovered successor was admitted")
    wrong_write = None
    if case["effects"]:
        changed = deepcopy(segment)
        access = next(access for row in changed for access in row["memory"]
                      if access["access"] & 2)
        access["after"] ^= 1
        wrong_write = admitted(common, case, engine, witness, meta, rows, changed)
        if not wrong_write["status"].startswith("unknown("):
            raise ValueError("changed discovered write was admitted")
    changed = deepcopy(segment)
    first_read = next(access for row in changed for access in row["memory"]
                      if access["access"] & 1)
    first_read["address"] ^= 1
    wrong_read = admitted(common, case, engine, witness, meta, rows, changed)
    if not wrong_read["status"].startswith("unknown("):
        raise ValueError("changed discovered read address was admitted")
    changed_rows = deepcopy(rows)
    changed_rows[boundary["entry_predecessor"]]["bytes"] = "90"
    source_edge_matches = [item for item in candidates(changed_rows)
        if item["native_steps"] == identity["native_steps"] and
        shape(changed_rows[item["begin"]:item["end_exclusive"]],
              identity["path_shape_mode"]) == identity["path_shape_sha256"]]
    if source_edge_matches:
        raise ValueError("changed dispatch edge retained a frozen boundary")
    return {"engine": engine, "input": witness,
        "trace_sha256": digest(path), "candidate_count": len(all_candidates),
        "shape_matches": len(shape_matches), "status": verdict["status"],
        "boundary": boundary,
        "guard_count": len(case["condition"]),
        "reads_checked": verdict["reads_checked"],
        "ordered_writes_checked": verdict["ordered_writes_checked"],
        "outputs_checked": verdict["outputs_checked"],
        "wrong_successor": wrong_end["status"],
        "wrong_write": wrong_write["status"] if wrong_write else None,
        "wrong_read_address": wrong_read["status"],
        "wrong_dispatch_edge": "unknown(no matching delimiter pair)",
        "target_pcode_steps_replayed": verdict["target_pcode_steps_replayed"]}


def main():
    common = json.loads(SUMMARY.read_text())
    results = [run_case(common, *case) for case in TRACE_CASES]
    expected_status = ["differentially_validated"] * 4 + [
        "unknown(different dispatch interval)"]
    if [row["status"] for row in results] != expected_status:
        raise ValueError("fresh dispatch regression verdict changed")
    OUTPUT.write_text(json.dumps({"schema_version": 1,
        "summary_sha256": digest(SUMMARY), "cases": results,
        "candidate_rule": "consecutive observed P-code BRANCHIND edges; no fixed native entry or exit PC",
        "admission_rule": "unique exact frozen path shape followed by full guard, state, read, ordered-write, successor validation",
        "limits": "candidate edges can be unrelated indirect branches; unknown handlers and alternate exits are not inferred"},
        indent=2) + "\n")
    print(json.dumps({"matched": sum(row["status"] ==
        "differentially_validated" for row in results),
        "unknown": sum(row["status"].startswith("unknown(") for row in results),
        "candidates": {f"{row['engine']}_{row['input']}": row["candidate_count"]
                       for row in results}}))


if __name__ == "__main__":
    main()
