"""Explore the R4VM ELF from execute's call ABI without a trace snapshot.

The engine sees only the ELF, program bytes, and symbolic input. The manifest
supplies benchmark inputs to main(), while expected results stay in the grader.
This fixture-specific adapter identifies execute, output, and the first fetch.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import logging
from pathlib import Path

import angr
import claripy

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "manifests/cases.json"
PROGRAMS = ROOT / "generated/programs"
BINARY = ROOT / "build/r4vm"
FETCH_PC = 0x401410
CODE_ADDRESS = 0x50000000
MAX_NATIVE_STEPS = 1200
MAX_LIVE_STATES = 64
MAX_TOTAL_STATES = 128
MASK = (1 << 64) - 1


def signed64(value):
    value &= MASK
    return value - (1 << 64) if value >> 63 else value


def symbol_address(project, name):
    symbol = project.loader.main_object.get_symbol(name)
    if symbol is None:
        raise ValueError(f"missing function symbol: {name}")
    return symbol.rebased_addr


def initial_state(project, program, entry):
    if program[:4] != b"R4VM" or len(program) < 8 or len(program) != 8 + 4 * program[5]:
        raise ValueError("invalid R4VM program framing")
    x = claripy.BVS("X", 64)
    state = project.factory.call_state(entry, CODE_ADDRESS, program[5], x,
                                       ret_addr=0xDEADBEEF)
    state.memory.store(CODE_ADDRESS, program)
    return state, x


def check_first_fetch(state, x, count, slot_offset):
    """Check the fixture ABI's initialized loop state before exploring it."""
    expected = (("r10", count), ("r11", CODE_ADDRESS), ("rcx", 0))
    if any(not state.solver.is_true(getattr(state.regs, name) == value)
           for name, value in expected):
        raise ValueError("execute prologue did not establish the expected fetch state")
    slot_zero = state.memory.load(state.regs.rsp + slot_offset, 8,
                                  endness=state.arch.memory_endness)
    if not state.solver.is_true(slot_zero == x):
        raise ValueError("execute prologue did not initialize VM slot zero from X")


def explore(project, program, entry, output, fetch_pc=FETCH_PC,
            slot_offset=0, max_native_steps=MAX_NATIVE_STEPS,
            first_fetch_states=None):
    state, x = initial_state(project, program, entry)
    active = [(state, ())]
    completed = []
    first_fetch_depth = None
    max_live = 1
    for depth in range(max_native_steps):
        next_active = []
        for state, path in active:
            if state.addr == fetch_pc:
                if first_fetch_depth is None:
                    check_first_fetch(state, x, program[5], slot_offset)
                    first_fetch_depth = depth
                    if first_fetch_states is not None:
                        first_fetch_states.append(state.copy())
                if not state.solver.unique(state.regs.rcx):
                    raise ValueError("symbolic VM PC at fetch")
                state.globals["vm_fetch_trace"] = (
                    state.globals.get("vm_fetch_trace", ()) +
                    (state.solver.eval(state.regs.rcx),))
            if state.addr == output:
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
    if first_fetch_depth is None or not completed:
        raise ValueError("fetch or output boundary was not reached")
    for state, _ in completed:
        for guard in state.solver.constraints:
            if guard.variables - x.variables:
                raise ValueError("path guard depends on an unbound symbolic input")
    guards = [claripy.And(*state.solver.constraints) for state, _ in completed]
    solver = claripy.Solver()
    if solver.satisfiable(extra_constraints=[claripy.Not(claripy.Or(*guards))]):
        raise ValueError("completed output paths do not cover all X")
    if any(solver.satisfiable(extra_constraints=[claripy.And(left, right)])
           for index, left in enumerate(guards) for right in guards[index + 1:]):
        raise ValueError("completed output paths overlap")
    return completed, x, {"first_fetch_native_instructions": first_fetch_depth,
                          "completed_paths": len(completed),
                          "max_live_states": max_live, "max_depth": depth}


def eval_unique(state, expression, x, input_value):
    if expression.variables - x.variables:
        raise ValueError(f"unbound output symbols: {sorted(expression.variables - x.variables)}")
    values = state.solver.eval_upto(expression, 2,
                                   extra_constraints=[x == (input_value & MASK)])
    if len(values) != 1:
        raise ValueError("output value is not uniquely determined")
    return values[0]


def image_string(project, address):
    raw = project.loader.memory.load(address, 64)
    if b"\0" not in raw:
        raise ValueError("unterminated output status")
    return raw.split(b"\0", 1)[0].decode("ascii")


def predict(project, completed, x, input_value):
    accepted = [(state, path) for state, path in completed
                if state.solver.satisfiable(extra_constraints=[x == (input_value & MASK)])]
    if len(accepted) != 1:
        raise ValueError(f"{len(accepted)} output paths accept this input")
    state, path = accepted[0]
    args = {name: eval_unique(state, getattr(state.regs, name), x, input_value)
            for name in ("rdi", "rsi", "rdx", "rcx", "r8", "r9")}
    status = image_string(project, args["rdi"])
    helper = project.loader.main_object.get_symbol("opaque_add")
    evidence = {"native_instructions": len(path),
                "path_constraints": len(state.solver.constraints),
                "vm_fetch_trace": list(state.globals.get("vm_fetch_trace", ())),
                "visited_helper": helper is not None and helper.rebased_addr in path}
    if args["r9"] > 64:
        raise ValueError("unsupported output ABI state")
    writes = []
    for index in range(args["r9"]):
        address = args["r8"] + 24 * index
        slot = eval_unique(state, state.memory.load(address, 1), x, input_value)
        value = eval_unique(state, state.memory.load(address + 8, 8,
                            endness=state.arch.memory_endness), x, input_value)
        tag = eval_unique(state, state.memory.load(address + 16, 1), x, input_value)
        writes.append({"slot": slot, "value": str(signed64(value)), "tag": tag})
    if status != "ok":
        if args["rsi"] != 0:
            raise ValueError("error output unexpectedly has a numeric result")
        return {"status": "error", "runtime_status": status,
                "pc": args["rcx"], "writes": writes, "angr_evidence": evidence}
    if args["rsi"] != 1:
        raise ValueError("successful output lacks a numeric result")
    return {"status": "computed", "result": str(signed64(args["rdx"])),
            "pc": args["rcx"], "writes": writes, "angr_evidence": evidence}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--control-flow", action="store_true",
                        help="analyze the separate CALL/RET fixture")
    parser.add_argument("--output", type=Path,
                        default=ROOT / "reports/angr-from-execute-abi.json")
    args = parser.parse_args()
    logging.getLogger("angr").setLevel(logging.CRITICAL)
    if args.control_flow:
        binary = ROOT / "build/r4vm_control"
        manifest = ROOT / "control-flow/cases.json"
        programs = ROOT / "control-flow/programs"
        fetch_pc, slot_offset, max_steps = 0x40141D, 0x10, 2500
    else:
        binary, manifest, programs = BINARY, MANIFEST, PROGRAMS
        fetch_pc, slot_offset, max_steps = FETCH_PC, 0, MAX_NATIVE_STEPS
    project = angr.Project(str(binary), auto_load_libs=False)
    entry = symbol_address(project, "execute")
    output = symbol_address(project, "output")
    cases = json.loads(manifest.read_text())["cases"]
    results = []
    experiments = []
    for case in cases:
        if not args.control_flow and case["engine"] != "r4vm":
            continue
        name = case["id"]
        program = (programs / f"{name}.r4vm").read_bytes()
        samples = (case["samples"] if args.control_flow
                   else [sample["input"] for sample in case["samples"]])
        try:
            completed, x, stats = explore(project, program, entry, output,
                                         fetch_pc, slot_offset, max_steps)
            experiments.append({"id": name, "program_sha256": sha256(program).hexdigest(),
                                **stats})
            for sample in samples:
                value = int(sample)
                try:
                    prediction = predict(project, completed, x, value)
                except ValueError as error:
                    prediction = {"status": "unknown", "reason": str(error)}
                results.append({"id": name, "input": sample, **prediction})
        except (ValueError, KeyError, angr.errors.AngrError) as error:
            experiments.append({"id": name, "reason": str(error)})
            results.extend({"id": name, "input": sample,
                            "status": "unknown", "reason": str(error)}
                           for sample in samples)
    report = {"schema_version": 1,
              "analysis_kind": "bounded_angr_from_execute_call_abi",
              "initial_state": "execute call ABI; no recorded register or stack snapshot",
              "hints": {"execute": hex(entry), "first_fetch": hex(fetch_pc),
                        "output": hex(output), "code_address": hex(CODE_ADDRESS)},
              "binary_sha256": sha256(binary.read_bytes()).hexdigest(),
              "native_execution_or_ptrace": False,
              "limits": {"max_native_steps": max_steps,
                         "max_live_states": MAX_LIVE_STATES,
                         "max_total_states": MAX_TOTAL_STATES},
              "experiments": experiments, "results": results}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"samples": len(results),
                      "computed": sum(row["status"] == "computed" for row in results),
                      "error": sum(row["status"] == "error" for row in results),
                      "unknown": sum(row["status"] == "unknown" for row in results),
                      "experiments": experiments}, indent=2))


if __name__ == "__main__":
    main()
