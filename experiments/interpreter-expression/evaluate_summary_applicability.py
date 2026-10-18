"""Apply common guard/effect/unknown rules to the two bounded summaries."""
from __future__ import annotations

from copy import deepcopy
import gzip
from hashlib import sha256
import json
from pathlib import Path

from prove_cross_full_flow import (CACHE_BASE, PYTHON, ROOT, load_trace,
                                   verify_cache)
from prove_js_summary_reuse import (SUMMARY as JS_SUMMARY, TRACE as JS_TRACE,
                                    check_second_site, prefix)
from prove_python_value_reuse import (SUMMARY as PY_SUMMARY, TARGET as PY_TARGET,
                                      add_segment, apply_value_summary)


RESULT = ROOT / "summary_applicability_result.json"


def outcome(status):
    if status == "differentially_validated" or status == "applied":
        return "applied"
    if status.startswith("unknown("):
        return "unknown"
    raise ValueError(f"unexpected summary result {status}")


def main():
    js = json.loads(JS_SUMMARY.read_text())
    py = json.loads(PY_SUMMARY.read_text())
    with gzip.open(JS_TRACE, "rt") as stream:
        js_records = [json.loads(line) for line in stream]
    second = prefix(js_records[2]["rows"])
    if (js["evidence"]["source_trace_sha256"] != sha256(JS_TRACE.read_bytes()).hexdigest() or
            js["identity"]["binary_sha256"] != js_records[0]["binary_sha256"]):
        raise ValueError("stale JavaScript summary evidence")
    py_meta, py_rows, _ = load_trace(PY_TARGET, "python", 0, PYTHON)
    cache_hash = verify_cache(py_meta)
    py_add, py_return = add_segment(py_rows)
    if (py["evidence"]["binary_sha256"] != py_meta["binary_sha256"] or
            py["evidence"]["cache_sha256"] != cache_hash):
        raise ValueError("stale Python summary evidence")
    # These values come from the recorded PyLong operands, and the independent
    # numeric-reuse experiment checks their cache layout and provenance.
    py_reuse = json.loads((ROOT / "python_numeric_value_reuse_result.json").read_text())
    if (py_reuse["summary_sha256"] != sha256(PY_SUMMARY.read_bytes()).hexdigest() or
            py_reuse["target_trace_sha256"] != sha256(PY_TARGET.read_bytes()).hexdigest()):
        raise ValueError("stale Python target operand evidence")
    x, y = [item["value"] for item in py_reuse["target_input"]]

    wrong_js_code = deepcopy(second)
    wrong_js_code[0]["bytes"] = "90"
    unexpected_js_write = deepcopy(second)
    unexpected_js_write[-1]["memory"].append({"address": 0x1000, "size": 8,
                                               "access": 2, "before": 0, "after": 1})
    extra_js_read = deepcopy(second)
    extra_js_read[-1]["memory"].append({"address": 0x1000, "size": 1,
                                        "access": 1, "before": 5, "after": 5})
    wrong_js_state = deepcopy(second)
    wrong_js_state[-1]["registers_after"]["r8"] ^= 1
    missing_js_output = deepcopy(js)
    missing_js_output["case"]["outputs"] = [
        item for item in missing_js_output["case"]["outputs"]
        if item["binding"] != "r8"]
    bad_js_effect = deepcopy(js)
    bad_js_effect["case"]["ordered_effects"] = [{"unproved": "memory write"}]
    js_cases = {
        "valid_prefix": check_second_site(js, second),
        "wrong_code": check_second_site(js, wrong_js_code),
        "unexpected_write": check_second_site(js, unexpected_js_write),
        "extra_read": check_second_site(js, extra_js_read),
        "wrong_state": check_second_site(js, wrong_js_state),
        "missing_register_output": check_second_site(missing_js_output, second),
        "unproved_effect_contract": check_second_site(bad_js_effect, second),
        "full_handler": check_second_site(js, js_records[2]["rows"])
    }
    py_cases = {
        "valid_numeric_value": apply_value_summary(py, x, y, cache_hash),
        "below_domain": apply_value_summary(py, 4, y, cache_hash),
        "wrong_operand": apply_value_summary(py, x, 6, cache_hash),
        "wrong_cache": apply_value_summary(py, x, y, "wrong-cache-digest"),
        "full_transition": apply_value_summary(py, x, y, cache_hash,
                                               mode="transition")
    }
    for cases, positive in ((js_cases, "valid_prefix"),
                            (py_cases, "valid_numeric_value")):
        if outcome(cases[positive]["status"]) != "applied" or any(
                outcome(case["status"]) != "unknown"
                for name, case in cases.items() if name != positive):
            raise ValueError("applicability policy accepted an unsupported case")
    output_slot = py_return["registers"]["r15"] - 8
    effects = [{"step_in_segment": index, "pc": hex(row["pc"]),
                "address": hex(access["address"]), "width": access["size"],
                "role": "result_slot" if access["address"] == output_slot else
                        "unmodeled_native_effect"}
               for index, row in enumerate(py_add) for access in row["memory"]
               if access["access"] & 2]
    if sum(item["role"] == "result_slot" for item in effects) != 1 or len(effects) != 12:
        raise ValueError("Python native effect inventory changed")
    if any(int(item["address"], 16) < CACHE_BASE + 262 * 32 and
           int(item["address"], 16) + item["width"] > CACHE_BASE
           for item in effects):
        raise ValueError("target unexpectedly modified the small-int cache")
    report = {"status": "bounded cross-engine summary applicability policy",
        "policy": {"value": "apply only when identity, guard, type and required read footprint match",
                   "transition": "apply only when the summary covers all ordered effects and the continuation",
                   "unknown": "return unknown on unsupported path, state, code, read, write, or effect"},
        "javascript": {"summary_sha256": sha256(JS_SUMMARY.read_bytes()).hexdigest(),
                       "cases": js_cases,
                       "proved_scope": "11-step arithmetic prefix; zero native writes"},
        "python": {"summary_sha256": sha256(PY_SUMMARY.read_bytes()).hexdigest(),
                   "cases": py_cases,
                   "native_effect_inventory": effects,
                   "modeled_result_writes": 1,
                   "unmodeled_native_writes": len(effects) - 1},
        "limits": ["all positive cases use saved concrete target traces",
                   "unknown does not establish behavior of a skipped path"]}
    RESULT.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"js": {k: v["status"] for k, v in js_cases.items()},
                      "python": {k: v["status"] for k, v in py_cases.items()},
                      "python_unmodeled_writes": len(effects) - 1}))


if __name__ == "__main__":
    main()
