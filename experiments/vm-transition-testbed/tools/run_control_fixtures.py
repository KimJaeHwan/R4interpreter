"""Check the CALL/RET native ELF against the independent case oracle."""
from __future__ import annotations

import json
import subprocess

from build_control_cases import BINARY, EXPECTED, PROGRAMS, SUITE


def main():
    expected = json.loads(EXPECTED.read_text())
    failed = []
    count = 0
    for case in expected["cases"]:
        program = PROGRAMS / f"{case['id']}.r4vm"
        for sample in case["samples"]:
            output = subprocess.check_output(
                [str(BINARY.resolve()), str(program.resolve()), sample["input"]],
                text=True)
            observed = json.loads(output)
            count += 1
            if observed != sample["expected"]:
                failed.append({"id": case["id"], "input": sample["input"],
                               "observed": observed, "expected": sample["expected"]})
    result = {"schema_version": 1, "samples": count, "passed": count - len(failed),
              "failed": failed}
    (SUITE / "fixture-grade.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"samples": count, "passed": result["passed"],
                      "failed": len(failed)}))
    raise SystemExit(bool(failed))


if __name__ == "__main__":
    main()
