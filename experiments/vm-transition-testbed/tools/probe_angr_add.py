"""Compare angr symbolic execution with a P-code transition for R4VM ADD.

This experiment uses the archived cutpoint baseline, but not native path traces
to choose successors. angr and the P-code replay independently follow the ELF.
The one VEX scratch write described below is fixture-specific, not a general
cross-IR normalization rule.
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
import z3

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT.parent / "interpreter-expression"))

from analyze_r4vm import TransitionPath  # noqa: E402
from capture_native_paths import LOOP_PC, OUTPUT_PC, OPAQUE_PC  # noqa: E402
from logic_projection import project_path, compact_expression, reduce_input_value  # noqa: E402
from pcode_transition_summary import FLAG_OFFSETS, REGISTER_OFFSETS  # noqa: E402
from project_r4vm_logic import entry_state as symbolic_entry_state  # noqa: E402
from static_pcode_step import derive_step, elf_memory, entry_state  # noqa: E402
from train_r4vm import BINARY, BUNDLE, PROGRAMS, SUMMARIES, bundle_instructions  # noqa: E402


CASES = (("VMT001", 9), ("VMT002", 9))
MAX_INSTRUCTIONS = 120
MAX_STATES = 32


class BaselineAdapter:
    def __init__(self, summary):
        self.summary = summary

    def initial_state(self, program, input_value):
        return entry_state(self.summary, program, input_value)


def on_memory_write(state):
    address = state.inspect.attrs.mem_write_address
    value = state.inspect.attrs.mem_write_expr
    width = state.inspect.attrs.mem_write_length
    state.globals["write_events"] = state.globals.get("write_events", ()) + (
        (state.addr, address, value, width),)


def angr_entry(project, summary, program, input_value):
    registers, memory = entry_state(summary, program, input_value)
    state = project.factory.blank_state(addr=LOOP_PC)
    symbolic_input = claripy.BVS("X", 64)
    for name, value in registers.items():
        if name != "eflags":
            setattr(state.regs, name, symbolic_input if name == "rdx" else claripy.BVV(value, 64))
    state.regs.eflags = claripy.BVV(registers["eflags"], 64)
    # The first native instruction overwrites condition flags. Initialize all
    # VEX flag inputs so no unconstrained flag symbol enters the experiment.
    for name in ("cc_op", "cc_dep1", "cc_dep2", "cc_ndep"):
        setattr(state.regs, name, claripy.BVV(0, 64))
    stack = summary["baseline"]["stack"]
    state.memory.store(stack["base"], bytes.fromhex(stack["bytes_hex"]))
    state.memory.store(summary["baseline"]["code_base"], program)
    state.memory.store(registers["rsp"], symbolic_input, endness=project.arch.memory_endness)
    state.inspect.b("mem_write", when=angr.BP_BEFORE, action=on_memory_write)
    state.globals["write_events"] = ()
    return state, symbolic_input, registers


def explore_one_step(initial):
    pending = [(initial, ())]
    completed = []
    max_live = 1
    for _ in range(MAX_INSTRUCTIONS):
        next_pending = []
        for state, path in pending:
            if path and state.addr in (LOOP_PC, OUTPUT_PC, OPAQUE_PC):
                completed.append((state, path))
                continue
            successors = state.step(num_inst=1)
            if successors.unconstrained_successors:
                raise ValueError(f"unconstrained native successor at {state.addr:#x}")
            if not successors.successors:
                raise ValueError(f"no feasible native successor at {state.addr:#x}")
            for successor in successors.successors:
                next_pending.append((successor, path + (state.addr,)))
        pending = next_pending
        max_live = max(max_live, len(pending))
        if len(pending) + len(completed) > MAX_STATES:
            raise ValueError("symbolic state budget exceeded")
        if not pending:
            break
    else:
        raise ValueError("native instruction budget exceeded")
    return completed, max_live


def prove_equal(angr_expr, pcode_expr, angr_input_name, constraints):
    if angr_expr.variables - {angr_input_name}:
        raise ValueError(f"unexpected angr symbolic inputs: {sorted(angr_expr.variables)}")
    expected = z3.substitute(pcode_expr,
                             (z3.BitVec("X", 64), z3.BitVec(angr_input_name, 64)))
    actual = claripy.backends.z3.convert(angr_expr)
    solver = z3.Solver()
    solver.set(timeout=5000)
    solver.add(*(claripy.backends.z3.convert(item) for item in constraints))
    solver.add(actual != expected)
    answer = solver.check()
    if answer == z3.unknown:
        raise ValueError("cross-IR equivalence check timed out")
    return answer == z3.unsat


def concrete_address(state, expr):
    if not state.solver.unique(expr):
        raise ValueError(f"symbolic write address: {expr}")
    return state.solver.eval(expr)


def assess_case(project, summary, instructions, image, name, input_value):
    program = (PROGRAMS / f"{name}.r4vm").read_bytes()
    pcode_step, candidate = derive_step(summary, instructions, image, program,
                                        input_value, [name, input_value])
    path = TransitionPath(candidate)
    registers, memory = entry_state(summary, program, input_value)
    witness = path.apply(registers, memory, with_reads=True)
    if witness is None:
        raise ValueError("P-code path rejects its witness")
    _, concrete_effects, concrete_reads = witness
    projected = symbolic_entry_state(BaselineAdapter(summary), program)
    pcode_guards, projected_effects = project_path(
        path, projected, concrete_reads, concrete_effects,
        REGISTER_OFFSETS, FLAG_OFFSETS, {"X"})

    initial, symbolic_input, _ = angr_entry(project, summary, program, input_value)
    completed, max_live = explore_one_step(initial)
    if len(completed) != 1:
        raise ValueError(f"expected one completed ADD path, got {len(completed)}")
    state, native_path = completed[0]
    if state.addr != LOOP_PC:
        raise ValueError(f"ADD did not reach next fetch: {state.addr:#x}")
    if [hex(pc) for pc in native_path] != candidate["native_path"]:
        raise ValueError("angr and P-code native paths differ")
    angr_input_name = next(iter(symbolic_input.variables))
    constraints = state.solver.constraints
    raw_writes = []
    for pc, addr, value, width in state.globals["write_events"]:
        concrete_width = (state.solver.eval(width) if not isinstance(width, int) else width)
        raw_writes.append((pc, concrete_address(state, addr), concrete_width, value))

    matched, unmatched = [], []
    cursor = 0
    for expected, (pcode_addr, pcode_value, pcode_width) in zip(pcode_step.effects,
                                                                projected_effects):
        expected_key = (int(expected["pc"], 16), pcode_addr, pcode_width)
        while cursor < len(raw_writes) and raw_writes[cursor][:3] != expected_key:
            unmatched.append(raw_writes[cursor])
            cursor += 1
        if cursor == len(raw_writes):
            raise ValueError(f"P-code write absent from angr events: {expected_key}")
        pc, address, width, angr_value = raw_writes[cursor]
        matched.append({"pc": hex(pc), "address": hex(address), "width": width,
                        "equivalent_for_all_X": prove_equal(angr_value, pcode_value,
                                                            angr_input_name, constraints)})
        cursor += 1
    unmatched.extend(raw_writes[cursor:])

    # VEX implements a register-only BT by spilling r12 to rsp-0x120 and
    # restoring rsp. Ghidra P-code and the native instruction have no STORE.
    # This one exception is recorded, never hidden as a VM state write.
    scratch = [(pc, address, width) for pc, address, width, _ in unmatched]
    bt_block = project.factory.block(0x401573, num_inst=1)
    bt_instruction = bt_block.capstone.insns[0]
    pcode_bt_store_count = sum(op["opcode"] == "STORE"
                               for op in instructions[0x401573]["operations"])
    vex_bt_store_count = sum(type(statement).__name__ == "Store"
                             for statement in bt_block.vex.statements)
    rsp_restored = state.solver.unique(state.regs.rsp) and state.solver.eval(state.regs.rsp) == registers["rsp"]
    known_scratch = (scratch == [(0x401573, registers["rsp"] - 0x120, 8)]
                     and bt_instruction.mnemonic == "bt" and "[" not in bt_instruction.op_str
                     and pcode_bt_store_count == 0 and vex_bt_store_count == 1
                     and rsp_restored)
    angr_slot = state.memory.load(registers["rsp"], 8, endness=project.arch.memory_endness)
    pcode_slot = projected.read(registers["rsp"], 8)
    reduced_slot, reduction_proved = reduce_input_value(pcode_slot, z3.BitVec("X", 64))
    return {"program": name, "input": input_value,
            "program_sha256": sha256(program).hexdigest(),
            "native_instructions": len(native_path),
            "native_path_equal": True,
            "completed_states": len(completed), "max_live_states": max_live,
            "angr_path_constraints": len(constraints),
            "pcode_nontrivial_input_guards": len(pcode_guards),
            "ordered_write_matches": matched,
            "all_write_values_equivalent": all(item["equivalent_for_all_X"] for item in matched),
            "raw_angr_writes": len(raw_writes), "pcode_writes": len(projected_effects),
            "unmatched_angr_writes": [{"pc": hex(pc), "address": hex(address),
                                        "width": width} for pc, address, width, _ in unmatched],
            "unmatched_writes_are_known_vex_bt_scratch": known_scratch,
            "bt_ir_evidence": {"native_instruction": f"{bt_instruction.mnemonic} {bt_instruction.op_str}",
                               "ghidra_pcode_store_count": pcode_bt_store_count,
                               "vex_store_count": vex_bt_store_count,
                               "rsp_restored": rsp_restored},
            "slot0_equivalent_for_all_X": prove_equal(angr_slot, pcode_slot,
                                                      angr_input_name, constraints),
            "slot0_formula_pcode": compact_expression(reduced_slot),
            "slot0_formula_reduction_proved": reduction_proved,
            "next_vm_pc_equivalent": prove_equal(state.regs.rcx, projected.registers["rcx"],
                                                 angr_input_name, constraints),
            "next_vm_pc": state.solver.eval(state.regs.rcx),
            "angr_version": angr.__version__}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=ROOT / "reports/angr-add-probe.json")
    args = parser.parse_args()
    logging.getLogger("angr").setLevel(logging.CRITICAL)
    summary = json.loads(SUMMARIES.read_text())
    if sha256(BINARY.read_bytes()).hexdigest() != summary["binary_sha256"]:
        raise ValueError("ELF differs from archived baseline")
    if sha256(BUNDLE.read_bytes()).hexdigest() != summary["bundle_sha256"]:
        raise ValueError("Bundle differs from archived baseline")
    project = angr.Project(str(BINARY), auto_load_libs=False)
    instructions, image = bundle_instructions(), elf_memory(BINARY)
    cases = [assess_case(project, summary, instructions, image, name, value)
             for name, value in CASES]
    report = {"schema_version": 1,
              "method": "angr native VEX step versus Ghidra Bundle P-code step",
              "entry_cutpoint": hex(LOOP_PC),
              "initial_state": "previously observed register/stack baseline; X and stack slot symbolic",
              "native_execution_or_ptrace": False,
              "claim": "ADD one-step path and outputs under this baseline, not all-handler coverage",
              "cases": cases}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps([{"program": row["program"], "path": row["native_instructions"],
                       "states": row["completed_states"],
                       "formula": row["slot0_formula_pcode"],
                       "writes_equivalent": row["all_write_values_equivalent"],
                       "scratch_write": row["unmatched_writes_are_known_vex_bt_scratch"]}
                      for row in cases], indent=2))


if __name__ == "__main__":
    main()
