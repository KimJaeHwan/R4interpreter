"""Use bounded angr exploration for R4VM cases the frozen P-code paths miss.

The ELF, program bytes and a previously observed execute cutpoint baseline are
inputs. This file does not read the manifest or expected results. A result is
computed only when all explored states reach the output boundary and exactly
one output state accepts the requested input with uniquely determined output.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import logging
from pathlib import Path
import sys

import angr
import claripy

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))

from analyze_r4vm import image_string, signed64  # noqa: E402
from capture_native_paths import LOOP_PC, OUTPUT_PC, OPAQUE_PC  # noqa: E402
from probe_angr_add import angr_entry  # noqa: E402
from train_r4vm import BINARY, PROGRAMS, SUMMARIES  # noqa: E402


MAX_NATIVE_STEPS = 600
MAX_LIVE_STATES = 64
MAX_TOTAL_STATES = 128


def explore(project, summary, program):
    initial, symbol, _ = angr_entry(project, summary, program, 0)
    active = [(initial, ())]
    completed = []
    max_live = 1
    for depth in range(MAX_NATIVE_STEPS):
        next_active = []
        for state, path in active:
            if state.addr == OUTPUT_PC:
                completed.append((state, path))
                continue
            successors = state.step(num_inst=1)
            if successors.unconstrained_successors:
                raise ValueError(f"unconstrained successor at {state.addr:#x}")
            if not successors.successors:
                raise ValueError(f"no feasible successor at {state.addr:#x}")
            next_active.extend((item, path + (state.addr,))
                               for item in successors.successors)
        active = next_active
        max_live = max(max_live, len(active))
        if len(active) > MAX_LIVE_STATES or len(active) + len(completed) > MAX_TOTAL_STATES:
            raise ValueError("symbolic state budget exceeded")
        if not active:
            break
    else:
        raise ValueError("native instruction budget exceeded")
    if not completed:
        raise ValueError("no output state reached")
    for state, _ in completed:
        for constraint in state.solver.constraints:
            if constraint.variables - symbol.variables:
                raise ValueError("path guard depends on an unbound symbolic input")
    return completed, symbol, {"completed_paths": len(completed),
                               "max_live_states": max_live, "depth": depth}


def eval_unique(state, expression, symbol, input_value):
    if expression.variables - symbol.variables:
        raise ValueError(f"unbound output symbols: {sorted(expression.variables - symbol.variables)}")
    binding = symbol == claripy.BVV(input_value & ((1 << 64) - 1), 64)
    values = state.solver.eval_upto(expression, 2, extra_constraints=[binding])
    if len(values) != 1:
        raise ValueError("output value is not uniquely determined")
    return values[0]


def formula_if_addition(state, expression, symbol):
    """Prove a constant or X + constant under this path's guard."""
    witness = state.solver.eval(symbol)
    observed = eval_unique(state, expression, symbol, witness)
    constant = claripy.BVV(observed, 64)
    if not state.solver.satisfiable(extra_constraints=[expression != constant]):
        return str(signed64(observed))
    offset = (observed - witness) & ((1 << 64) - 1)
    candidate = symbol + claripy.BVV(offset, 64)
    if state.solver.satisfiable(extra_constraints=[expression != candidate]):
        return None
    signed = signed64(offset)
    return f"X + {signed}" if signed >= 0 else f"X - {-signed}"


def predict(completed, symbol, program, input_value):
    binding = symbol == claripy.BVV(input_value & ((1 << 64) - 1), 64)
    accepted = [(state, path) for state, path in completed
                if state.solver.satisfiable(extra_constraints=[binding])]
    if len(accepted) != 1:
        raise ValueError(f"{len(accepted)} output paths accept this input")
    state, path = accepted[0]
    output_args = {name: eval_unique(state, getattr(state.regs, name), symbol, input_value)
                   for name in ("rdi", "rsi", "rdx", "rcx", "r8", "r9")}
    status = image_string(BINARY, output_args["rdi"])
    if output_args["rsi"] != 1 or output_args["r9"] > 64:
        raise ValueError("unsupported output ABI state")
    if status != "ok":
        raise ValueError(f"non-numeric output status: {status}")
    base = output_args["r8"]
    writes = []
    for index in range(output_args["r9"]):
        address = base + 24 * index
        slot = eval_unique(state, state.memory.load(address, 1), symbol, input_value)
        value = eval_unique(state, state.memory.load(address + 8, 8,
                            endness=state.arch.memory_endness), symbol, input_value)
        tag = eval_unique(state, state.memory.load(address + 16, 1), symbol, input_value)
        writes.append({"slot": slot, "value": str(signed64(value)), "tag": tag})
    return {"status": "computed", "result": str(signed64(output_args["rdx"])),
            "pc": output_args["rcx"], "writes": writes,
            "angr_evidence": {"native_instructions": len(path),
                              "visited_helper": OPAQUE_PC in path,
                              "path_constraints": len(state.solver.constraints),
                              "result_formula": formula_if_addition(state, state.regs.rdx, symbol)}}


def branch_probe(project, summary):
    program = (PROGRAMS / "VMT007.r4vm").read_bytes()
    completed, symbol, stats = explore(project, summary, program)
    paths = []
    for state, native_path in completed:
        paths.append({"native_instructions": len(native_path),
                      "guard": [str(item) for item in state.solver.constraints],
                      "result_formula": formula_if_addition(state, state.regs.rdx, symbol),
                      "example_0": state.solver.satisfiable(extra_constraints=[symbol == 0]),
                      "example_9": state.solver.satisfiable(extra_constraints=[symbol == 9])})
    guards = [claripy.And(*state.solver.constraints) for state, _ in completed]
    solver = claripy.Solver()
    covers_all_inputs = not solver.satisfiable(extra_constraints=[claripy.Not(claripy.Or(*guards))])
    pairwise_disjoint = all(
        not solver.satisfiable(extra_constraints=[claripy.And(left, right)])
        for index, left in enumerate(guards) for right in guards[index + 1:])
    return {"program_sha256": sha256(program).hexdigest(), "stats": stats,
            "paths": paths, "guards_cover_all_X": covers_all_inputs,
            "guards_pairwise_disjoint": pairwise_disjoint,
            "input_0": predict(completed, symbol, program, 0),
            "input_9": predict(completed, symbol, program, 9)}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline", type=Path, default=ROOT / "reports/current-r4vm-analysis.json")
    parser.add_argument("--output", type=Path, default=ROOT / "reports/angr-fallback-r4vm.json")
    args = parser.parse_args()
    logging.getLogger("angr").setLevel(logging.CRITICAL)
    summary = json.loads(SUMMARIES.read_text())
    if sha256(BINARY.read_bytes()).hexdigest() != summary["binary_sha256"]:
        raise ValueError("ELF differs from archived baseline")
    baseline = json.loads(args.baseline.read_text())
    if baseline.get("schema_version") != 1 or not isinstance(baseline.get("results"), list):
        raise ValueError("invalid baseline analysis report")
    project = angr.Project(str(BINARY), auto_load_libs=False)
    cache = {}
    results = []
    improvements = []
    for original in baseline["results"]:
        if original["status"] != "unknown":
            results.append(original)
            continue
        name = original["id"]
        program = (PROGRAMS / f"{name}.r4vm").read_bytes()
        try:
            if name not in cache:
                cache[name] = explore(project, summary, program)
            completed, symbol, stats = cache[name]
            prediction = predict(completed, symbol, program, int(original["input"]))
            prediction["angr_evidence"].update(stats)
            prediction["angr_evidence"]["baseline_reason"] = original["reason"]
            results.append({"id": name, "input": original["input"], **prediction})
            improvements.append({"id": name, "input": original["input"],
                                 "result": prediction["result"], "pc": prediction["pc"]})
        except (ValueError, KeyError, angr.errors.AngrError) as error:
            results.append({**original, "angr_fallback_reason": str(error)})
    report = {"schema_version": 1,
              "analysis_kind": "frozen_native_pcode_paths_with_bounded_angr_fallback",
              "initial_state": "previously observed execute cutpoint baseline",
              "native_execution_or_ptrace": False,
              "limits": {"max_native_steps": MAX_NATIVE_STEPS,
                         "max_live_states": MAX_LIVE_STATES},
              "results": results, "improvements": improvements,
              "branch_probe": branch_probe(project, summary)}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"samples": len(results),
                      "computed": sum(row["status"] == "computed" for row in results),
                      "unknown": sum(row["status"] == "unknown" for row in results),
                      "improvements": improvements,
                      "branch_paths": len(report["branch_probe"]["paths"])}, indent=2))


if __name__ == "__main__":
    main()
