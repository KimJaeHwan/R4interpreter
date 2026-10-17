"""Measure VM program length, path growth, and bounded unknown outcomes."""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import logging
from pathlib import Path
import subprocess
import sys
import time

import angr

from angr_from_execute_abi import explore, predict, symbol_address
from build_frames_cases import BINARY, MASK, SUITE, encode, oracle


def cases():
    results = []
    for count in (4, 16, 48, 60):
        words = [{"op": "addi", "dst": 1, "src": 0, "imm": 1}]
        words += [{"op": "addi", "dst": 1, "src": 1, "imm": 1}
                  for _ in range(count - 1)]
        words += [{"op": "halt", "src": 1}]
        results.append((f"straight_{count}", words, 64))
    for bits in (2, 3, 4, 5, 6, 7):
        words = [{"op": "move", "dst": 1, "src": 0}]
        for bit in range(bits):
            words += [{"op": "andi", "dst": 2, "src": 0, "imm": 1 << bit},
                      {"op": "brz", "src": 2, "imm": 1},
                      {"op": "movi", "dst": 3, "imm": bit}]
        words += [{"op": "halt", "src": 1}]
        results.append((f"independent_bits_{bits}", words, 64))
    bits = 5
    words = [{"op": "move", "dst": 1, "src": 0}]
    for bit in range(bits):
        words += [{"op": "andi", "dst": 2, "src": 0, "imm": 1 << bit},
                  {"op": "brz", "src": 2, "imm": 1},
                  {"op": "movi", "dst": 3, "imm": bit}]
    words += [{"op": "halt", "src": 1}]
    results.append(("independent_bits_5_limit8", words, 8))
    return results


def one(name):
    selected = next((row for row in cases() if row[0] == name), None)
    if selected is None:
        raise ValueError(name)
    _, words, max_live = selected
    program = encode(words)
    program_file = SUITE / "scale-programs" / f"{name}.r4vm"
    program_file.parent.mkdir(parents=True, exist_ok=True)
    program_file.write_bytes(program)
    sample_values = (0, 9, 31)
    native_matches = []
    for value in sample_values:
        expected = oracle(words, value)
        expected.pop("fetch_trace")
        observed = json.loads(subprocess.check_output(
            [str(BINARY), str(program_file), str(value)], text=True))
        native_matches.append(observed == expected)
    if not all(native_matches):
        raise ValueError("concrete ELF and independent oracle differ")
    project = angr.Project(str(BINARY), auto_load_libs=False)
    entry, output = (symbol_address(project, name) for name in ("execute", "output"))
    start = time.perf_counter()
    report = {"id": name, "words": len(words), "max_live_states_limit": max_live,
              "program_sha256": sha256(program).hexdigest(),
              "native_oracle_samples": len(sample_values)}
    try:
        completed, x, stats = explore(project, program, entry, output,
                                      max_native_steps=6000,
                                      max_live_states=max_live,
                                      observe_fetch_memory=True)
        grades = []
        for value in sample_values:
            predicted = predict(project, completed, x, value)
            wanted = oracle(words, value)
            expected_fetch = wanted.pop("fetch_trace")
            observed = {"status": predicted.get("runtime_status", "ok"),
                        "result": predicted.get("result"), "pc": predicted.get("pc"),
                        "writes": predicted.get("writes")}
            grades.append(observed == wanted and
                          predicted["angr_evidence"]["vm_fetch_trace"] == expected_fetch)
        report.update({"status": "proved", "samples_matched": sum(grades),
                       "guard_coverage_proved": True, **stats})
    except (ValueError, KeyError, angr.errors.AngrError) as error:
        report.update({"status": "unknown", "reason": str(error),
                       "guard_coverage_proved": False})
    report["seconds"] = round(time.perf_counter() - start, 3)
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--case")
    args = parser.parse_args()
    logging.getLogger("angr").setLevel(logging.CRITICAL)
    if args.case:
        print(json.dumps(one(args.case)))
        return
    results = []
    for name, words, max_live in cases():
        start = time.perf_counter()
        try:
            process = subprocess.run([sys.executable, __file__, "--case", name],
                                     capture_output=True, text=True, timeout=45,
                                     check=True)
            results.append(json.loads(process.stdout))
        except subprocess.TimeoutExpired:
            results.append({"id": name, "words": len(words),
                            "max_live_states_limit": max_live,
                            "status": "unknown", "reason": "45-second case timeout",
                            "seconds": round(time.perf_counter() - start, 3),
                            "guard_coverage_proved": False})
        except (subprocess.CalledProcessError, json.JSONDecodeError) as error:
            results.append({"id": name, "words": len(words),
                            "max_live_states_limit": max_live,
                            "status": "error", "reason": str(error),
                            "seconds": round(time.perf_counter() - start, 3),
                            "guard_coverage_proved": False})
    report = {"schema_version": 1, "kind": "scale_and_path_budget",
              "binary_sha256": sha256(BINARY.read_bytes()).hexdigest(),
              "limits": {"native_steps": 6000, "total_states": 128,
                         "per_case_seconds": 45}, "cases": results}
    (SUITE / "scale-results.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(results, indent=2))
    if any(row["status"] == "error" for row in results):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
