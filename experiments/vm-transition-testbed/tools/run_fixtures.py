"""Execute built fixtures and compare them with manifest-derived expected JSON."""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import subprocess

from build_cases import EXPECTED, ROOT


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", type=Path, default=ROOT / "reports/fixture-check.json")
    args = parser.parse_args()
    expected = json.loads(EXPECTED.read_text())
    manifest = json.loads((ROOT / "manifests/cases.json").read_text())
    failures = []
    checks = []
    for case in expected["cases"]:
        binary = ROOT / manifest["engines"][case["engine"]]["binary"]
        program = ROOT / case["program"]
        if not binary.is_file() or not program.is_file():
            raise FileNotFoundError(f"missing fixture for {case['id']}; run tools/build_cases.py")
        if sha256(program.read_bytes()).hexdigest() != case["program_sha256"]:
            raise AssertionError(f"program digest differs from expected data: {case['id']}")
        for sample in case["samples"]:
            command = [str(binary), str(program), sample["input"]]
            completed = subprocess.run(command, capture_output=True, text=True, check=True)
            if case["engine"] == "r4vm":
                observed = json.loads(completed.stdout)
            else:
                observed = {"status": "ok", "result": completed.stdout.strip(),
                            "pc": None, "writes": None}
            wanted = sample["expected"]
            passed = observed == wanted
            checks.append({"id": case["id"], "input": sample["input"],
                           "pass": passed, "observed": observed if not passed else None})
            if not passed:
                failures.append({"id": case["id"], "input": sample["input"],
                                 "expected": wanted, "observed": observed})
    result = {"schema_version": 1, "expected_sha256": sha256(EXPECTED.read_bytes()).hexdigest(),
              "cases": len(expected["cases"]), "samples": len(checks),
              "passed": sum(item["pass"] for item in checks), "failed": len(failures),
              "failures": failures}
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({key: result[key] for key in ("cases", "samples", "passed", "failed")}))
    raise SystemExit(bool(failures))


if __name__ == "__main__":
    main()
