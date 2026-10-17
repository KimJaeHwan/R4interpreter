"""Grade projected path formulas and statuses against independent samples."""
from __future__ import annotations

import json

from build_control_cases import EXPECTED, MASK, SUITE, signed


PROJECTION = SUITE / "pcode-projection.json"


def accepts(guard, value):
    if guard == "true":
        return True
    if guard == "X == 0":
        return value == 0
    if guard == "X != 0":
        return value != 0
    raise ValueError(f"unsupported guard display: {guard}")


def evaluate(formula, value):
    if formula.startswith("X + "):
        return str(signed((value + int(formula[4:])) & MASK))
    if formula.startswith("X - "):
        return str(signed((value - int(formula[4:])) & MASK))
    if formula == "X":
        return str(signed(value))
    return str(int(formula))


def main():
    projected = {case["id"]: case for case in
                 json.loads(PROJECTION.read_text())["cases"]}
    rows = []
    for case in json.loads(EXPECTED.read_text())["cases"]:
        for sample in case["samples"]:
            value = int(sample["input"])
            paths = [path for path in projected[case["id"]]["paths"]
                     if accepts(path["guard"], value)]
            wanted = sample["expected"]
            valid = (len(paths) == 1 and paths[0]["runtime_status"] == wanted["status"]
                     and paths[0]["output_pc"] == wanted["pc"])
            if valid:
                formula = paths[0]["formula"]
                valid = (formula is None if wanted["result"] is None else
                         formula is not None and evaluate(formula, value) == wanted["result"])
            rows.append({"id": case["id"], "input": sample["input"],
                         "grade": "pass" if valid else "fail"})
    report = {"schema_version": 1, "samples": len(rows),
              "passed": sum(row["grade"] == "pass" for row in rows), "rows": rows}
    (SUITE / "pcode-grade.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"samples": report["samples"], "passed": report["passed"]}))
    raise SystemExit(report["passed"] != report["samples"])


if __name__ == "__main__":
    main()
