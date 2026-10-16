"""Grade analyzer sample results without treating missing results as passes."""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path

from build_cases import EXPECTED


def grade(expected_case, expected_sample, actual):
    if actual is None:
        return "not_run", "no analyzer result"
    status = actual.get("status")
    wanted = expected_sample["expected"]
    if status == "unknown":
        if not actual.get("reason"):
            return "fail", "unknown requires a reason"
        return ("accepted_unknown" if expected_case["analysis_policy"] == "unknown_allowed"
                else "uncovered"), actual["reason"]
    if wanted["status"] != "ok":
        if status == "error" and actual.get("runtime_status") == wanted["status"]:
            return "pass", "matching runtime error"
        return "fail", "numeric result or incorrect error on an error path"
    if status != "computed":
        return "fail", "expected computed, unknown, or matching error status"
    if str(actual.get("result")) != wanted["result"]:
        return "fail", "wrong result"
    if expected_case["analysis_target"] == "transition":
        if "pc" not in actual or "writes" not in actual:
            return "partial", "missing next PC or ordered writes"
        if actual["pc"] != wanted["pc"] or actual["writes"] != wanted["writes"]:
            return "fail", "next PC or ordered writes disagree"
    return "pass", "expected output and required effects match"


def compare(expected, analysis):
    if analysis.get("schema_version") != 1 or not isinstance(analysis.get("results"), list):
        raise ValueError("analysis input must have schema_version 1 and results list")
    lookup = {}
    for item in analysis["results"]:
        key = (item["id"], str(item["input"]))
        if key in lookup:
            raise ValueError(f"duplicate analyzer result {key}")
        lookup[key] = item
    grades = []
    known = set()
    for case in expected["cases"]:
        for sample in case["samples"]:
            key = (case["id"], sample["input"])
            known.add(key)
            category, reason = grade(case, sample, lookup.get(key))
            grades.append({"id": key[0], "input": key[1],
                           "partition": sample["partition"],
                           "grade": category, "reason": reason})
    extra = sorted(lookup.keys() - known)
    if extra:
        raise ValueError(f"analyzer results refer to unknown samples: {extra}")
    return {"schema_version": 1, "total": len(grades),
            "counts": dict(sorted(Counter(item["grade"] for item in grades).items())),
            "holdout_counts": dict(sorted(Counter(item["grade"] for item in grades
                                                  if item["partition"] == "holdout").items())),
            "grades": grades}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("analysis_results", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = compare(json.loads(EXPECTED.read_text()), json.loads(args.analysis_results.read_text()))
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"total": report["total"], "counts": report["counts"],
                      "holdout_counts": report["holdout_counts"]}))
    raise SystemExit(any(item["grade"] == "fail" for item in report["grades"]))


if __name__ == "__main__":
    main()
