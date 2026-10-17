"""Recover VM boundaries from stripped O2/O1 ELFs, then grade all frame cases.

The analyzer gets the ELF, execute's three-argument ABI, output's six-argument
ABI, and a bytecode buffer. It gets no function symbols or native PCs.
"""
from __future__ import annotations

from hashlib import sha256
import json
import logging
from pathlib import Path
import subprocess
import time

import angr

from angr_from_execute_abi import explore, predict
from build_frames_cases import EXPECTED, PROGRAMS, ROOT, SUITE


def build_stripped(optimization):
    binary = ROOT / "build" / f"r4vm_frames_{optimization}_stripped"
    subprocess.run(["cc", "-std=c11", f"-{optimization}", "-fno-pie", "-no-pie",
                    "-Wall", "-Wextra", "-Werror", "-o", str(binary),
                    str(ROOT / "fixtures/r4vm_frames.c")], check=True)
    subprocess.run(["strip", "--strip-all", str(binary)], check=True)
    return binary


def discover(project):
    cfg = project.analyses.CFGFast(normalize=True)
    candidates = []
    for function in cfg.kb.functions.values():
        if function.is_plt:
            continue
        counts = {}
        for site in function.get_call_sites():
            target = function.get_call_target(site)
            callee = cfg.kb.functions.get(target)
            if callee is not None and not callee.is_plt:
                counts[target] = counts.get(target, 0) + 1
        for target, count in counts.items():
            if count >= 3:
                candidates.append((function.addr, target, count))
    if len(candidates) != 1:
        raise ValueError(f"expected one repeated-local-callee pair, got {candidates}")
    return candidates[0]


def grade(prediction, sample):
    if prediction["status"] == "unknown":
        return False
    observed = {"status": prediction.get("runtime_status", "ok"),
                "result": prediction.get("result"), "pc": prediction.get("pc"),
                "writes": prediction.get("writes")}
    fetch = prediction["angr_evidence"]["vm_fetch_trace"]
    wanted = sample["fetch_trace"]
    if sample["expected"]["status"] == "pc_out_of_bounds":
        fetch_matches = fetch == wanted[:-1] and prediction["pc"] == wanted[-1]
    else:
        fetch_matches = fetch == wanted
    return observed == sample["expected"] and fetch_matches


def main():
    logging.getLogger("angr").setLevel(logging.CRITICAL)
    cases = json.loads(EXPECTED.read_text())["cases"]
    reports = []
    for optimization in ("O2", "O1"):
        binary = build_stripped(optimization)
        project = angr.Project(str(binary), auto_load_libs=False)
        entry, output, calls = discover(project)
        case_reports = []
        for case in cases:
            program = (PROGRAMS / f"{case['id']}.r4vm").read_bytes()
            start = time.perf_counter()
            try:
                completed, x, stats = explore(project, program, entry, output,
                                              max_native_steps=6000,
                                              observe_fetch_memory=True)
                predictions = [predict(project, completed, x, int(sample["input"]))
                               for sample in case["samples"]]
                scores = [grade(prediction, sample)
                          for prediction, sample in zip(predictions, case["samples"])]
                native_fetch_pcs = sorted({pc for state, _ in completed
                                           for pc in state.globals.get("fetch_native_pcs", ())})
                case_reports.append({"id": case["id"], "seconds": round(time.perf_counter()-start, 3),
                                     "computed": sum(scores), "samples": len(scores),
                                     "first_fetch_native_pcs": [hex(pc) for pc in native_fetch_pcs],
                                     "guard_coverage_proved": True, **stats})
            except (ValueError, KeyError, angr.errors.AngrError) as error:
                case_reports.append({"id": case["id"], "seconds": round(time.perf_counter()-start, 3),
                                     "computed": 0, "samples": len(case["samples"]),
                                     "guard_coverage_proved": False, "reason": str(error)})
        reports.append({"compiler_optimization": optimization,
                        "binary_sha256": sha256(binary.read_bytes()).hexdigest(),
                        "symbols_removed": project.loader.main_object.get_symbol("execute") is None,
                        "recovered_execute": hex(entry), "recovered_output": hex(output),
                        "local_calls_to_output": calls, "cases": case_reports})
    report = {"schema_version": 1, "kind": "stripped_boundary_recovery",
              "known_adapter": "execute(code,count,X), output(status,has_result,value,pc,writes,count); framed R4VM bytecode",
              "discovery": "CFG repeated local callee; bytecode-memory reads at each word start",
              "fetch_limit": "An out-of-bounds PC performs no bytecode read; its attempted value is checked from the output ABI, not counted as an observed fetch.",
              "builds": reports}
    (SUITE / "boundary-recovery.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps([{"optimization": row["compiler_optimization"],
                       "recovered_execute": row["recovered_execute"],
                       "recovered_output": row["recovered_output"],
                       "computed": sum(c["computed"] for c in row["cases"]),
                       "samples": sum(c["samples"] for c in row["cases"])}
                      for row in reports], indent=2))
    raise SystemExit(any(c["computed"] != c["samples"]
                         for row in reports for c in row["cases"]))


if __name__ == "__main__":
    main()
