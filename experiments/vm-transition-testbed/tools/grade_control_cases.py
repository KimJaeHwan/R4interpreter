"""Compare CALL/RET analysis with independently generated output and fetch path."""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path

from build_control_cases import EXPECTED, SUITE


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("analysis", type=Path)
    parser.add_argument("--output", type=Path, default=SUITE / "grade.json")
    args = parser.parse_args()
    expected = json.loads(EXPECTED.read_text())
    analysis = json.loads(args.analysis.read_text())
    lookup = {(item["id"], str(item["input"])): item
              for item in analysis["results"]}
    rows = []
    for case in expected["cases"]:
        for sample in case["samples"]:
            key = case["id"], sample["input"]
            actual = lookup.get(key)
            wanted = sample["expected"]
            if actual is None:
                reason = "missing prediction"
            elif actual["status"] == "unknown":
                reason = actual["reason"]
            else:
                actual_status = ("ok" if actual["status"] == "computed"
                                 else actual.get("runtime_status"))
                result = actual.get("result") if actual_status == "ok" else None
                projection = {"status": actual_status, "result": result,
                              "pc": actual.get("pc"), "writes": actual.get("writes")}
                reason = ("" if projection == wanted and
                          actual["angr_evidence"]["vm_fetch_trace"] == sample["fetch_trace"]
                          else "output, PC, writes, or fetch trace mismatch")
            rows.append({"id": key[0], "input": key[1],
                         "grade": "pass" if not reason else "fail", "reason": reason})
    report = {"schema_version": 1, "counts": dict(Counter(x["grade"] for x in rows)),
              "rows": rows}
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report["counts"]))
    raise SystemExit(any(row["grade"] == "fail" for row in rows))


if __name__ == "__main__":
    main()
