"""Evaluate projected formulas on the separate R4VM benchmark samples.

This file belongs to the grading side. The projection tools do not import it
or read expected/cases.expected.json.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

import z3

from analyze_r4vm import signed64, ROOT

sys.path.insert(0, str(ROOT.parent / "interpreter-expression"))
from apply_transition_summary import expression


def evaluate(source, sort, input_value):
    symbol = z3.BitVec("X", 64)
    expr = expression(source, sort, {"X": symbol})
    result = z3.simplify(z3.substitute(expr, (symbol, z3.BitVecVal(input_value, 64))))
    if sort == "Bool" and (z3.is_true(result) or z3.is_false(result)):
        return z3.is_true(result)
    if z3.is_bv_value(result):
        return result.as_long()
    raise ValueError(f"projection did not reduce for input {input_value}: {result}")


def predict(cases, input_value):
    matches = [item for item in cases if item["status"] != "unknown"
               and evaluate(item["guard_smt"], "Bool", input_value)]
    if len(matches) != 1:
        return {"status": "unknown", "reason": f"{len(matches)} projected guards match"}
    case = matches[0]
    answer = {"status": case["status"],
              "pc": evaluate(case["vm_pc_smt"], "BV64", input_value),
              "writes": [
                  {"slot": evaluate(write["slot_smt"], "BV8", input_value),
                   "value": str(signed64(evaluate(write["value_smt"], "BV64", input_value))),
                   "tag": evaluate(write["tag_smt"], "BV8", input_value)}
                  for write in case["writes"]]}
    if case["status"] == "ok":
        answer["result"] = str(signed64(evaluate(case["value_smt"], "BV64", input_value)))
    else:
        answer["result"] = None
    return answer


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--projection", type=Path,
                        default=ROOT / "results/input-logic-projection.json")
    parser.add_argument("--expected", type=Path,
                        default=ROOT / "expected/cases.expected.json")
    parser.add_argument("--output", type=Path,
                        default=ROOT / "results/input-logic-grade.json")
    args = parser.parse_args()
    projection = json.loads(args.projection.read_text())
    expected = json.loads(args.expected.read_text())
    rows = []
    for case in expected["cases"]:
        if case["engine"] != "r4vm":
            continue
        projected = projection["r4vm_programs"][case["id"]]
        if projected["program_sha256"] != case["program_sha256"]:
            raise ValueError(f"program hash changed for {case['id']}")
        for sample in case["samples"]:
            value = int(sample["input"])
            actual = predict(projected["cases"], value)
            target = sample["expected"]
            if actual == target:
                grade = "pass"
            elif actual["status"] == "unknown" and case["analysis_policy"] == "unknown_allowed":
                grade = "accepted_unknown"
            else:
                grade = "fail"
            rows.append({"id": case["id"], "input": sample["input"],
                         "partition": sample["partition"], "grade": grade,
                         "predicted": actual, "expected": target})
    report = {"schema_version": 1, "projection": str(args.projection), "results": rows,
              "counts": {name: sum(row["grade"] == name for row in rows)
                         for name in ("pass", "accepted_unknown", "fail")}}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report["counts"]))


if __name__ == "__main__":
    main()
