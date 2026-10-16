"""Benchmark harness: feed only program bytes and input to the analyzer."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from analyze_r4vm import Analyzer
from build_cases import MANIFEST, PROGRAMS, ROOT


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=ROOT / "reports/current-r4vm-analysis.json")
    args = parser.parse_args()
    analyzer = Analyzer()
    manifest = json.loads(MANIFEST.read_text())
    results = []
    for case in manifest["cases"]:
        if case["engine"] != "r4vm":
            continue
        program = (PROGRAMS / f"{case['id']}.r4vm").read_bytes()
        for sample in case["samples"]:
            prediction = analyzer.analyze(program, int(sample["input"]))
            results.append({"id": case["id"], "input": sample["input"], **prediction})
    report = {"schema_version": 1, "analysis_kind": "frozen_native_pcode_paths",
              "results": results}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"samples": len(results),
                      "computed": sum(r["status"] == "computed" for r in results),
                      "error": sum(r["status"] == "error" for r in results),
                      "unknown": sum(r["status"] == "unknown" for r in results)}))


if __name__ == "__main__":
    main()
