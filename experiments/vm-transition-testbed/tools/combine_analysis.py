"""Combine independently produced VM and prior Lua predictions for grading."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from build_cases import ROOT


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("r4vm", type=Path)
    parser.add_argument("lua", type=Path)
    parser.add_argument("--output", type=Path, default=ROOT / "results/combined-analysis.json")
    args = parser.parse_args()
    results = []
    seen = set()
    for label, path in (("r4vm_frozen_pcode_paths", args.r4vm),
                        ("prior_lua_path_summaries", args.lua)):
        report = json.loads(path.read_text())
        if report["schema_version"] != 1:
            raise ValueError(f"unsupported report schema: {path}")
        for row in report["results"]:
            key = row["id"], str(row["input"])
            if key in seen:
                raise ValueError(f"duplicate case/input: {key}")
            seen.add(key)
            results.append({**row, "analysis_method": label})
    combined = {"schema_version": 1, "provenance":
                "R4VM frozen Low P-code paths plus previously validated Lua path summaries",
                "results": results}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(combined, indent=2) + "\n")
    print(f"combined {len(results)} predictions")


if __name__ == "__main__":
    main()
