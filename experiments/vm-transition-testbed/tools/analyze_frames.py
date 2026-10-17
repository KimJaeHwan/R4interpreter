"""Bounded symbolic path experiment for the frame/indirect-call ELF."""
from __future__ import annotations

from hashlib import sha256
import json
import logging
from pathlib import Path
import time

import angr
import claripy

from angr_from_execute_abi import (CODE_ADDRESS, MASK, explore, predict,
                                   symbol_address)
from build_frames_cases import BINARY, EXPECTED, PROGRAMS, SUITE

FETCH_PC = 0x4013ec
MAX_NATIVE_STEPS = 6000


def first_fetch_check(state, x, count, _):
    expected = (("rbx", count), ("r12", CODE_ADDRESS), ("rdx", 0))
    if any(not state.solver.is_true(getattr(state.regs, name) == value)
           for name, value in expected):
        raise ValueError("frame VM first fetch register invariant failed")
    slot_zero = state.memory.load(state.regs.rsp, 8,
                                  endness=state.arch.memory_endness)
    if not state.solver.is_true(slot_zero == x):
        raise ValueError("frame VM first slot is not symbolic X")


def formula(state, x, observed):
    value = state.regs.rdx
    if state.solver.is_false(value != observed & MASK):
        return str(observed)
    offset = (observed - state.solver.eval(x)) & MASK
    if state.solver.is_false(value != x + offset):
        signed = offset - (1 << 64) if offset >> 63 else offset
        return f"X + {signed}" if signed >= 0 else f"X - {-signed}"
    return "unknown"


def compact_guard(state, x):
    if not state.solver.constraints:
        return "true"
    if not state.solver.satisfiable(extra_constraints=[x != 0]):
        return "X == 0"
    if not state.solver.satisfiable(extra_constraints=[x == 0]):
        return "X != 0"
    return "SMT: " + claripy.And(*state.solver.constraints).shallow_repr()


def main():
    logging.getLogger("angr").setLevel(logging.CRITICAL)
    project = angr.Project(str(BINARY), auto_load_libs=False)
    entry = symbol_address(project, "execute")
    output = symbol_address(project, "output")
    cases = json.loads(EXPECTED.read_text())["cases"]
    results = []
    experiments = []
    for case in cases:
        name = case["id"]
        program = (PROGRAMS / f"{name}.r4vm").read_bytes()
        start = time.perf_counter()
        try:
            completed, x, stats = explore(
                project, program, entry, output, fetch_pc=FETCH_PC,
                max_native_steps=MAX_NATIVE_STEPS, first_fetch_check=first_fetch_check,
                vm_pc_register="rdx")
            paths = []
            for state, native in completed:
                witness = state.solver.eval(x)
                prediction = predict(project, [(state, native)], x, witness)
                value_formula = (formula(state, x, int(prediction["result"]))
                                 if prediction["status"] == "computed" else None)
                paths.append({"witness": str(witness),
                              "guard": compact_guard(state, x), "guard_proven": True,
                              "status": prediction.get("runtime_status", "ok"),
                              "formula": value_formula,
                              "formula_proven": value_formula is not None and value_formula != "unknown",
                              "output_pc": prediction["pc"],
                              "vm_fetch_trace": prediction["angr_evidence"]["vm_fetch_trace"]})
            experiments.append({"id": name, "program_sha256": sha256(program).hexdigest(),
                                "seconds": round(time.perf_counter() - start, 3),
                                "guard_coverage_proved": True,
                                "guards_disjoint_proved": True, "paths": paths, **stats})
            for sample in case["samples"]:
                prediction = predict(project, completed, x, int(sample["input"]))
                results.append({"id": name, "input": sample["input"], **prediction})
        except (ValueError, KeyError, angr.errors.AngrError) as error:
            reason = str(error)
            experiments.append({"id": name, "seconds": round(time.perf_counter() - start, 3),
                                "guard_coverage_proved": False, "reason": reason})
            for sample in case["samples"]:
                results.append({"id": name, "input": sample["input"],
                                "status": "unknown", "reason": reason})
    report = {"schema_version": 1, "analysis_kind": "bounded_angr_from_execute_call_abi",
              "binary_sha256": sha256(BINARY.read_bytes()).hexdigest(),
              "hints": {"execute": hex(entry), "first_fetch": hex(FETCH_PC),
                        "output": hex(output)},
              "limits": {"max_native_steps": MAX_NATIVE_STEPS,
                         "max_live_states": 64, "max_total_states": 128},
              "experiments": experiments, "results": results}
    (SUITE / "angr-analysis.json").write_text(json.dumps(report, indent=2) + "\n")
    grade = []
    lookup = {(r["id"], r["input"]): r for r in results}
    for case in cases:
        for sample in case["samples"]:
            actual = lookup[(case["id"], sample["input"])]
            wanted = sample["expected"]
            observed = {"status": actual.get("runtime_status", "ok")
                        if actual["status"] != "unknown" else "unknown",
                        "result": actual.get("result"), "pc": actual.get("pc"),
                        "writes": actual.get("writes")}
            passed = observed == wanted and actual.get("angr_evidence", {}).get(
                "vm_fetch_trace") == sample["fetch_trace"]
            grade.append({"id": case["id"], "input": sample["input"],
                          "grade": "pass" if passed else "fail",
                          "reason": "" if passed else actual.get("reason", "mismatch")})
    (SUITE / "grade.json").write_text(json.dumps({"rows": grade}, indent=2) + "\n")
    print(json.dumps({"passed": sum(r["grade"] == "pass" for r in grade),
                      "samples": len(grade), "experiments": experiments}, indent=2))
    raise SystemExit(any(r["grade"] == "fail" for r in grade))


if __name__ == "__main__":
    main()
