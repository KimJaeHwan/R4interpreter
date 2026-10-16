"""Apply frozen native P-code path summaries to a new VM program and input.

This module reads no case manifest, expected results, or VM opcode table.  The
only target-specific adapter is the execute-loop entry/exit state projection.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys

import z3
from elftools.elf.elffile import ELFFile

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "interpreter-expression"))
from apply_transition_summary import concrete, expression
from pcode_transition_summary import FLAG_OFFSETS, REGISTER_OFFSETS

from train_r4vm import BINARY, SUMMARIES


MASK = (1 << 64) - 1


def signed64(value):
    value &= MASK
    return value - (1 << 64) if value >> 63 else value


def put(memory, address, value, width):
    for index in range(width):
        memory[address + index] = (value >> (8 * index)) & 255


def get(memory, address, width):
    return sum(memory[address + index] << (8 * index) for index in range(width))


def image_string(binary: Path, address: int):
    with binary.open("rb") as stream:
        elf = ELFFile(stream)
        for segment in elf.iter_segments():
            if segment["p_type"] != "PT_LOAD":
                continue
            start = segment["p_vaddr"]
            contents = segment.data()
            if start <= address < start + len(contents):
                data = contents[address - start:]
                return data.split(b"\0", 1)[0].decode("ascii")
    raise ValueError(f"output status pointer not in ELF image: {address:#x}")


class TransitionPath:
    def __init__(self, record):
        self.record = record
        self.decls = {f"R_{name.upper()}": z3.BitVec(f"R_{name.upper()}", 64)
                      for name in REGISTER_OFFSETS.values()}
        self.decls.update({f"F_{bit}": z3.BitVec(f"F_{bit}", 8)
                           for bit in FLAG_OFFSETS.values()})
        self.decls["M0"] = z3.Array("M0", z3.BitVecSort(64), z3.BitVecSort(8))
        self.decls["W"] = z3.BitVec("W", 32)
        self.decls["V_XMM0"] = z3.BitVec("V_XMM0", 128)
        self.guards = [expression(s, "Bool", self.decls) for s in record["guards"]]
        self.reads = [(expression(r["address"], "BV64", self.decls), r["width"])
                      for r in record["reads"]]
        self.effects = [(expression(e["address"], "BV64", self.decls),
                         expression(e["value"], f"BV{e['width'] * 8}", self.decls),
                         e["width"]) for e in record["effects"]]
        self.registers = {int(offset): expression(expr, "BV64", self.decls)
                          for offset, expr in record["registers"].items()}
        self.flags = {int(offset): expression(expr, "BV8", self.decls)
                      for offset, expr in record["flags"].items()}

    def apply(self, registers, memory):
        solver = z3.Solver()
        for offset, name in REGISTER_OFFSETS.items():
            solver.add(self.decls[f"R_{name.upper()}"] == z3.BitVecVal(registers[name], 64))
        solver.add(self.decls["W"] == z3.BitVecVal(registers["r12"] & 0xFFFFFFFF, 32))
        for offset, bit in FLAG_OFFSETS.items():
            solver.add(self.decls[f"F_{bit}"] ==
                       z3.BitVecVal((registers["eflags"] >> bit) & 1, 8))
        bound = set()
        try:
            for addr_expr, width in self.reads:
                address = concrete(solver, addr_expr)
                for index in range(width):
                    byte_addr = address + index
                    if byte_addr in bound or byte_addr not in memory:
                        continue
                    solver.add(z3.Select(self.decls["M0"], z3.BitVecVal(byte_addr, 64)) ==
                               z3.BitVecVal(memory[byte_addr], 8))
                    bound.add(byte_addr)
            if not all(concrete(solver, guard) for guard in self.guards):
                return None
            effects = [(concrete(solver, addr), concrete(solver, value), width)
                       for addr, value, width in self.effects]
            next_registers = dict(registers)
            for offset, name in REGISTER_OFFSETS.items():
                next_registers[name] = concrete(solver, self.registers[offset])
            for offset, bit in FLAG_OFFSETS.items():
                value = concrete(solver, self.flags[offset])
                next_registers["eflags"] = ((next_registers["eflags"] & ~(1 << bit)) |
                                            (value << bit))
            return next_registers, effects
        except (ValueError, KeyError, AssertionError, z3.Z3Exception):
            return None


class Analyzer:
    def __init__(self, binary=BINARY, summaries=SUMMARIES):
        self.binary = Path(binary)
        self.summary = json.loads(Path(summaries).read_text())
        if sha256(self.binary.read_bytes()).hexdigest() != self.summary["binary_sha256"]:
            raise ValueError("ELF hash differs from frozen transition summaries")
        self.paths = [TransitionPath(row) for row in self.summary["paths"]]

    def initial_state(self, program: bytes, x: int):
        if program[:4] != b"R4VM" or len(program) < 8 or len(program) != 8 + 4 * program[5]:
            raise ValueError("invalid R4VM program framing")
        baseline = self.summary["baseline"]
        registers = dict(baseline["entry_registers"])
        stack = baseline["stack"]
        memory = {stack["base"] + index: byte
                  for index, byte in enumerate(bytes.fromhex(stack["bytes_hex"]))}
        code_base = baseline["code_base"]
        memory.update({code_base + index: byte for index, byte in enumerate(program)})
        registers["r10"] = program[5]
        registers["rdx"] = x & MASK
        put(memory, registers["rsp"], x & MASK, 8)
        return registers, memory

    def analyze(self, program: bytes, x: int):
        registers, memory = self.initial_state(program, x)
        used = []
        for _ in range(64):
            matches = []
            for path in self.paths:
                result = path.apply(registers, memory)
                if result is not None:
                    matches.append((path, result))
            if len(matches) != 1:
                return {"status": "unknown", "reason":
                        f"{len(matches)} supported native paths match at VM PC {registers['rcx']}" ,
                        "path_ids": used}
            path, (registers, effects) = matches[0]
            used.append(path.record["id"])
            for address, value, width in effects:
                put(memory, address, value, width)
            if path.record["kind"] == "next_fetch":
                continue
            if path.record["kind"] != "output":
                return {"status": "unknown", "reason": "native path reaches an unmodeled call",
                        "path_ids": used}
            runtime_status = image_string(self.binary, registers["rdi"])
            if runtime_status != "ok":
                return {"status": "error", "runtime_status": runtime_status,
                        "path_ids": used}
            count = registers["r9"]
            if count > 64 or registers["rsi"] != 1:
                return {"status": "unknown", "reason": "unsupported output ABI state",
                        "path_ids": used}
            base = registers["r8"]
            writes = [{"slot": get(memory, base + 24 * index, 1),
                       "value": str(signed64(get(memory, base + 24 * index + 8, 8))),
                       "tag": get(memory, base + 24 * index + 16, 1)}
                      for index in range(count)]
            return {"status": "computed", "result": str(signed64(registers["rdx"])),
                    "pc": registers["rcx"], "writes": writes, "path_ids": used}
        return {"status": "unknown", "reason": "64 VM transition budget exceeded",
                "path_ids": used}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("program", type=Path)
    parser.add_argument("input", type=int)
    parser.add_argument("--binary", type=Path, default=BINARY)
    parser.add_argument("--summaries", type=Path, default=SUMMARIES)
    args = parser.parse_args()
    print(json.dumps(Analyzer(args.binary, args.summaries).analyze(args.program.read_bytes(), args.input)))


if __name__ == "__main__":
    main()
