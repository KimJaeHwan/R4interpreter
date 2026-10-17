"""Compose path-specific P-code steps from a trace-free angr execute entry.

angr selects complete symbolic native paths. For each path, a concrete witness
feeds Ghidra Low P-code replay; the common projection engine carries symbolic
X, memory versions, guards, and writes across VM fetch boundaries. Each result
is checked against the independently explored angr output state.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import logging
from pathlib import Path
import sys
import tarfile

import angr
import claripy
import z3

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT.parent / "interpreter-expression"))

from analyze_r4vm import TransitionPath  # noqa: E402
from angr_from_execute_abi import (CODE_ADDRESS, explore, image_string,
                                   symbol_address)  # noqa: E402
from build_control_cases import BINARY, MANIFEST, PROGRAMS, SUITE  # noqa: E402
from logic_projection import SymbolicState, project_path  # noqa: E402
from pcode_transition_summary import FLAG_OFFSETS, REGISTER_OFFSETS  # noqa: E402
from static_pcode_step import StaticStep, elf_memory  # noqa: E402
from train_r4vm import compact_path  # noqa: E402


BUNDLE = SUITE / "r4vm_control_bundle.tar.gz"
FETCH_PC = 0x40141D
SLOT_OFFSET = 0x10
MASK = (1 << 64) - 1


def bundle_instructions():
    with tarfile.open(BUNDLE, "r:gz") as archive:
        manifest = json.load(archive.extractfile(next(
            m for m in archive if m.name.endswith("/manifest.json"))))
        original = next(m for m in manifest["members"] if m["id"] == "original")
        if original["sha256"] != sha256(BINARY.read_bytes()).hexdigest():
            raise ValueError("P-code Bundle belongs to a different ELF")
        function = json.load(archive.extractfile(next(
            m for m in archive if m.name.endswith("/function-000000.json"))))
    instructions = {row["address"]["byte_offset"]: row
                    for row in function["instructions"]}
    if FETCH_PC not in instructions:
        raise ValueError("fetch boundary absent from P-code Bundle")
    return instructions


def prove_equal(left, right, guard):
    solver = z3.Solver()
    solver.set(timeout=5000)
    solver.add(guard, left != right)
    verdict = solver.check()
    if verdict == z3.unknown:
        raise ValueError("cross-IR proof timed out")
    return verdict == z3.unsat


def prove_guard_equal(left, right):
    solver = z3.Solver()
    solver.set(timeout=5000)
    solver.add(z3.Xor(left, right))
    verdict = solver.check()
    if verdict == z3.unknown:
        raise ValueError("guard proof timed out")
    return verdict == z3.unsat


def compact_addition(expr, x, guard, witness, observed):
    if prove_equal(expr, z3.BitVecVal(observed, 64), guard):
        value = observed - (1 << 64) if observed >> 63 else observed
        return str(value)
    offset = (observed - witness) & MASK
    if prove_equal(expr, x + z3.BitVecVal(offset, 64), guard):
        signed = offset - (1 << 64) if offset >> 63 else offset
        return f"X + {signed}" if signed >= 0 else f"X - {-signed}"
    return None


def project_one(project, program, output_state, native_path, first_state,
                x, instructions, image, output_pc):
    witness = output_state.solver.eval(x)
    concrete = first_state.copy()
    concrete.solver.add(x == witness)
    convert = claripy.backends.z3.convert
    registers = {name: concrete.solver.eval(getattr(concrete.regs, name))
                 for name in REGISTER_OFFSETS.values()}
    registers["eflags"] = concrete.solver.eval(concrete.regs.eflags)
    sp = registers["rsp"]
    stack = concrete.solver.eval(concrete.memory.load(sp - 0x200, 0x900),
                                 cast_to=bytes)
    memory = dict(image)
    memory.update({CODE_ADDRESS + index: byte for index, byte in enumerate(program)})
    memory.update({sp - 0x200 + index: byte for index, byte in enumerate(stack)})
    projected = SymbolicState(
        {name: convert(getattr(first_state.regs, name))
         for name in REGISTER_OFFSETS.values()},
        {offset: convert(claripy.Extract(bit, bit, first_state.regs.eflags))
         for offset, bit in FLAG_OFFSETS.items()}, {})
    fetches = list(output_state.globals["vm_fetch_trace"])
    selected_native = []
    all_guards = []
    steps = []
    for index, vm_pc in enumerate(fetches):
        if registers["rcx"] != vm_pc:
            raise ValueError(f"P-code VM PC differs before fetch {index}")
        replay = StaticStep(registers, memory, instructions,
                            loop_pc=FETCH_PC, output_pc=output_pc)
        replay.run_step(budget=250)
        selected_native.extend(replay.native_path)
        record = compact_path(replay, replay.exit_kind,
                              tuple(replay.native_path), [vm_pc, witness])
        path = TransitionPath(record)
        reads = [(row["observed_address"], row["width"]) for row in replay.reads]
        for address, width in reads:
            for byte_address in range(address, address + width):
                if byte_address not in projected.memory:
                    projected.memory[byte_address] = convert(
                        first_state.memory.load(byte_address, 1))
        effects = [(row["observed_address"], row["observed"], row["width"])
                   for row in replay.effects]
        guards, projected_effects = project_path(
            path, projected, reads, effects,
            REGISTER_OFFSETS, FLAG_OFFSETS, x.variables)
        all_guards.extend(guards)
        registers = {name: replay.regs_concrete[offset]
                     for offset, name in REGISTER_OFFSETS.items()}
        registers["eflags"] = sum((replay.flags_concrete[offset] & 1) << bit
                                  for offset, bit in FLAG_OFFSETS.items())
        steps.append({"vm_pc": vm_pc, "next_vm_pc": registers["rcx"],
                      "boundary": replay.exit_kind,
                      "native_instructions": len(replay.native_path),
                      "pcode_operations": replay.operation_count,
                      "ordered_native_writes": len(projected_effects),
                      "slot2_value_store_roots": [
                          f'op:{instructions[int(effect["pc"], 16)]["address"]["space_id"]:x}:'
                          f'{int(effect["pc"], 16):x}:{effect["ordinal"]}:STORE'
                          for effect in replay.effects
                          if effect["observed_address"] == sp + SLOT_OFFSET + 2 * 16
                          and effect["width"] == 8],
                      "nontrivial_guards": len(guards)})
        if index + 1 < len(fetches):
            if replay.exit_kind != "next_fetch" or registers["rcx"] != fetches[index + 1]:
                raise ValueError("P-code next fetch differs from angr")
        elif replay.exit_kind != "output":
            raise ValueError("P-code path did not reach output")
    suffix = native_path[native_path.index(FETCH_PC):]
    native_match = (suffix[:len(selected_native)] == tuple(selected_native)
                    and len(suffix) == len(selected_native) + 1)
    if not native_match:
        raise ValueError("P-code replay and angr native paths differ")
    pcode_guard = z3.And(*all_guards)
    angr_guard = convert(claripy.And(*output_state.solver.constraints))
    guard_equal = prove_guard_equal(pcode_guard, angr_guard)
    if not guard_equal:
        raise ValueError("P-code and angr input path guards differ")
    args_equal = {}
    for name in ("rdi", "rsi", "rdx", "rcx", "r8", "r9"):
        args_equal[name] = prove_equal(projected.registers[name],
                                      convert(getattr(output_state.regs, name)),
                                      pcode_guard)
    if not all(args_equal.values()):
        raise ValueError(f"P-code output arguments differ: {args_equal}")
    count = registers["r9"]
    if count > 64:
        raise ValueError("write count exceeds fixture capacity")
    write_equal = []
    for index in range(count):
        for offset, width in ((0, 1), (8, 8), (16, 1)):
            address = registers["r8"] + index * 24 + offset
            for byte_address in range(address, address + width):
                if byte_address not in projected.memory:
                    projected.memory[byte_address] = convert(
                        first_state.memory.load(byte_address, 1))
            lhs = projected.read(address, width)
            rhs = convert(output_state.memory.load(address, width,
                          endness=project.arch.memory_endness))
            write_equal.append(prove_equal(lhs, rhs, pcode_guard))
    if not all(write_equal):
        raise ValueError("P-code and angr ordered write-log values differ")
    x_z3 = z3.BitVec(next(iter(x.variables)), 64)
    formula = (compact_addition(projected.registers["rdx"], x_z3,
                                pcode_guard, witness, registers["rdx"])
               if registers["rsi"] == 1 else None)
    if prove_guard_equal(pcode_guard, z3.BoolVal(True)):
        guard_text = "true"
    elif prove_guard_equal(pcode_guard, x_z3 == 0):
        guard_text = "X == 0"
    elif prove_guard_equal(pcode_guard, x_z3 != 0):
        guard_text = "X != 0"
    else:
        guard_text = str(z3.simplify(pcode_guard))
    return {"witness": str(witness - (1 << 64) if witness >> 63 else witness),
            "guard": guard_text, "guard_smt": str(z3.simplify(pcode_guard)),
            "guard_equal_to_angr": guard_equal,
            "runtime_status": image_string(project, registers["rdi"]),
            "formula": formula, "output_pc": registers["rcx"],
            "write_count": registers["r9"],
            "vm_fetch_trace": fetches, "native_pcs": [hex(pc) for pc in selected_native],
            "steps": steps,
            "native_path_equal": native_match,
            "output_args_equal": args_equal,
            "write_fields_equal": len(write_equal),
            "all_write_fields_equal": all(write_equal)}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path,
                        default=SUITE / "pcode-projection.json")
    args = parser.parse_args()
    logging.getLogger("angr").setLevel(logging.CRITICAL)
    project = angr.Project(str(BINARY), auto_load_libs=False)
    entry = symbol_address(project, "execute")
    output = symbol_address(project, "output")
    instructions = bundle_instructions()
    image = elf_memory(BINARY)
    cases = []
    for case in json.loads(MANIFEST.read_text())["cases"]:
        program = (PROGRAMS / f"{case['id']}.r4vm").read_bytes()
        initial_fetch = []
        completed, x, stats = explore(project, program, entry, output,
                                     FETCH_PC, SLOT_OFFSET, 2500, initial_fetch)
        if len(initial_fetch) != 1:
            raise ValueError("expected one execute prologue state")
        paths = []
        for state, native_path in completed:
            paths.append(project_one(project, program, state, native_path,
                                     initial_fetch[0], x, instructions, image, output))
        cases.append({"id": case["id"], "program_sha256": sha256(program).hexdigest(),
                      "exploration": stats, "paths": paths})
    report = {"schema_version": 1,
              "method": "angr path selection; Ghidra Low P-code replay and shared projection",
              "binary_sha256": sha256(BINARY.read_bytes()).hexdigest(),
              "bundle_sha256": sha256(BUNDLE.read_bytes()).hexdigest(),
              "cases": cases}
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"cases": len(cases), "paths": sum(len(c["paths"]) for c in cases),
                      "steps": sum(len(p["steps"]) for c in cases for p in c["paths"]),
                      "formulas": [(c["id"], [p["formula"] for p in c["paths"]])
                                   for c in cases]}, indent=2))


if __name__ == "__main__":
    main()
