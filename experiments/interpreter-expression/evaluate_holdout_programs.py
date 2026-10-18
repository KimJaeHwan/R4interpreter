"""Grade unused JS/Python programs with saved, bounded value summaries."""
from __future__ import annotations

import gzip
from hashlib import sha256
import json
import subprocess

from cross_dispatch_pcode import read_vaddr
from prove_cross_full_flow import CACHE_BASE, PYTHON, ROOT, load_trace, verify_cache
from prove_js_summary_reuse import SUMMARY as JS_SUMMARY, check_second_site
from prove_python_value_reuse import (SOURCE as PY_SOURCE, SUMMARY as PY_SUMMARY,
                                      add_segment, apply_value_summary, cache_value,
                                      observed_operands)


INPUTS = (37, 251, 252)
RESULT = ROOT / "summary_holdout_result.json"


def read_gzip_json(path):
    with gzip.open(path, "rt") as stream:
        return [json.loads(line) for line in stream]


def grade_js(summary):
    cases = []
    fixture_hash = sha256((ROOT / "js_holdout_fixture.js").read_bytes()).hexdigest()
    for value in INPUTS:
        path = ROOT / f"artifacts/js_holdout_{value}.json.gz"
        meta, payload, observed = read_gzip_json(path)
        rows = payload["rows"]
        if (meta["input"] != value or meta["fixture_sha256"] != fixture_hash or
                meta["binary_sha256"] != summary["identity"]["binary_sha256"] or
                observed["output"] != value + 5):
            raise ValueError("JavaScript holdout provenance or oracle changed")
        application = check_second_site(summary, rows)
        status = application["status"]
        predicted = (int(application["predicted_tagged_result"], 16) >> 32
                     if status == "differentially_validated" else None)
        if predicted is not None and predicted != observed["output"]:
            raise ValueError("JavaScript holdout produced an incorrect prediction")
        cases.append({"input": value, "oracle_output": observed["output"],
                      "status": status, "prediction": predicted,
                      "trace_sha256": sha256(path.read_bytes()).hexdigest(),
                      "native_steps": len(rows), "target_pcode_steps_replayed": 0})
    return cases


def grade_python(summary):
    source_meta, source_rows, _ = load_trace(PY_SOURCE, "python", 9, PYTHON)
    cache_hash = verify_cache(source_meta)
    if (summary["evidence"]["binary_sha256"] != source_meta["binary_sha256"] or
            summary["evidence"]["source_trace_sha256"] !=
            sha256(PY_SOURCE.read_bytes()).hexdigest() or
            summary["evidence"]["cache_sha256"] != cache_hash):
        raise ValueError("Python summary does not match its source native proof")
    cache = read_vaddr(PYTHON, CACHE_BASE, CACHE_BASE + 262 * 32)
    source_add, _ = add_segment(source_rows)
    source_path_shape = [(row["pc"], row["bytes"], row["next_pc"])
                         for row in source_add]
    fixture_hash = sha256((ROOT / "python_holdout_fixture.py").read_bytes()).hexdigest()
    cases = []
    for value in INPUTS:
        if value == 252:
            oracle_path = ROOT / "artifacts/python_holdout_252.stdout.txt"
            oracle = json.loads(oracle_path.read_text())["result"]
            regenerated = json.loads(subprocess.check_output(
                [str(PYTHON), "-I", "-S", str(ROOT / "python_holdout_fixture.py"),
                 str(value), "-"], text=True, timeout=30))["result"]
            application = apply_value_summary(summary, value, 5, cache_hash)
            if oracle != regenerated or oracle != 257 or \
                    not application["status"].startswith("unknown("):
                raise ValueError("out-of-domain Python holdout was misclassified")
            cases.append({"input": value, "oracle_output": oracle,
                          "status": application["status"], "prediction": None,
                          "trace_sha256": None, "native_steps": None,
                          "target_pcode_steps_replayed": 0,
                          "oracle_stdout_sha256": sha256(oracle_path.read_bytes()).hexdigest(),
                          "fixture_sha256": fixture_hash,
                          "binary_sha256": source_meta["binary_sha256"],
                          "oracle_regenerated_with_pinned_fixture": True,
                          "note": "program output only; no native trace outside proved path"})
            continue
        path = ROOT / f"artifacts/python_holdout_{value}.json.gz"
        meta, payload, observed = read_gzip_json(path)
        rows = payload["rows"]
        if (meta["input"] != value or meta["fixture_sha256"] != fixture_hash or
                meta["binary_sha256"] != source_meta["binary_sha256"] or
                meta["runtime_cache_sha256_at_entry"] != cache_hash or
                meta["runtime_cache_sha256_at_exit"] != cache_hash or
                observed["output"] != value + 5 or
                [(row["pc"], row["bytes"], row["next_pc"]) for row in rows] !=
                source_path_shape):
            raise ValueError("Python holdout path or oracle differs from source")
        if any(access["access"] & 2 and
               access["address"] < CACHE_BASE + 262 * 32 and
               access["address"] + access["size"] > CACHE_BASE
               for row in rows for access in row["memory"]):
            raise ValueError("Python holdout trace writes the small-int cache")
        inputs = observed_operands(rows, cache)
        if [item["value"] for item in inputs] != [value, 5]:
            raise ValueError("Python holdout input objects differ")
        application = apply_value_summary(summary, value, 5, cache_hash)
        if application["status"] != "applied":
            raise ValueError("in-domain Python holdout was not applicable")
        slot = meta["output_slot"]
        writes = [access for row in rows for access in row["memory"]
                  if access["address"] == slot and access["size"] == 8 and
                  access["access"] & 2]
        if len(writes) != 1:
            raise ValueError("Python holdout result slot write is ambiguous")
        output_value = cache_value(cache, writes[0]["after"])
        if output_value != application["value"] or output_value != observed["output"]:
            raise ValueError("Python holdout numeric prediction is wrong")
        other_writes = sum(bool(access["access"] & 2) for row in rows
                           for access in row["memory"]) - 1
        cases.append({"input": value, "oracle_output": observed["output"],
                      "status": application["status"],
                      "prediction": application["value"],
                      "trace_sha256": sha256(path.read_bytes()).hexdigest(),
                      "native_steps": len(rows), "target_pcode_steps_replayed": 0,
                      "unmodeled_native_writes": other_writes})
    return cases


def summarize(cases):
    applied = sum(case["prediction"] is not None for case in cases)
    unknown = sum(case["status"].startswith("unknown(") for case in cases)
    mismatch = sum(case["prediction"] is not None and
                   case["prediction"] != case["oracle_output"] for case in cases)
    return {"cases": len(cases), "applied": applied, "unknown": unknown,
            "mismatch": mismatch, "applied_correct": applied - mismatch,
            "native_steps_recorded": sum(case["native_steps"] or 0 for case in cases),
            "target_pcode_steps_replayed": sum(case["target_pcode_steps_replayed"]
                                               for case in cases)}


def main():
    js = json.loads(JS_SUMMARY.read_text())
    py = json.loads(PY_SUMMARY.read_text())
    js_cases = grade_js(js)
    py_cases = grade_python(py)
    js_metrics, py_metrics = summarize(js_cases), summarize(py_cases)
    if any(metric["applied"] != 2 or metric["unknown"] != 1 or metric["mismatch"]
           for metric in (js_metrics, py_metrics)):
        raise ValueError("holdout grade did not match the proved domain")
    report = {"status": "new-program value-summary holdout evaluation",
        "javascript": {"fixture": "js_holdout_fixture.js",
                       "summary_sha256": sha256(JS_SUMMARY.read_bytes()).hexdigest(),
                       "cases": js_cases, "metrics": js_metrics},
        "python": {"fixture": "python_holdout_fixture.py",
                   "summary_sha256": sha256(PY_SUMMARY.read_bytes()).hexdigest(),
                   "cases": py_cases, "metrics": py_metrics},
        "limits": ["two fresh programs on fixed Node and CPython binaries",
                   "Python out-of-domain case has an oracle output but no native trace",
                   "correctness count excludes unknown cases and does not prove unobserved paths"]}
    RESULT.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"javascript": js_metrics, "python": py_metrics}))


if __name__ == "__main__":
    main()
