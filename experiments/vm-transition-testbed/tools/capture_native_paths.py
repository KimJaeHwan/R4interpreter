"""Capture native execute-loop paths for P-code transition extraction.

The fixed addresses below are cutpoint hints for the current ELF build.  The
trace is training evidence, never a result for a graded input.
"""
from __future__ import annotations

import argparse
import ctypes
import json
import os
from pathlib import Path
import signal
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM, X86_REG_INVALID
from elftools.elf.elffile import ELFFile

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "interpreter-expression"))
from trace_input_provenance import (
    CONT, PEEKTEXT, POKETEXT, SETREGS, SINGLESTEP, TRACEME,
    getregs, peek, ptrace, reg_value,
)


LOOP_PC = 0x401410
OUTPUT_PC = 0x401310
OPAQUE_PC = 0x4012F0
MAX_STEPS = 1000
REG_NAMES = "rax rbx rcx rdx rsi rdi rbp rsp r8 r9 r10 r11 r12 r13 r14 r15 eflags".split()


def snapshot(pid, address, size):
    data = bytearray()
    for offset in range(0, size, 8):
        width = min(8, size - offset)
        value = peek(pid, address + offset, width)
        if value is None:
            raise RuntimeError(f"unreadable snapshot at {address + offset:#x}")
        data += value.to_bytes(width, "little")
    return data.hex()


def registers(regs):
    return {name: getattr(regs, name) for name in REG_NAMES}


def read_operand(pid, address, size):
    if size <= 8:
        return peek(pid, address, size)
    if size == 16:
        low, high = peek(pid, address, 8), peek(pid, address + 8, 8)
        return None if low is None or high is None else low | (high << 64)
    raise ValueError(f"unsupported memory operand size {size}")


def memory_operands(insn, regs):
    if insn.mnemonic == "lea":
        return []
    result = []
    for operand in insn.operands:
        if operand.type != X86_OP_MEM or operand.mem.segment != X86_REG_INVALID:
            continue
        mem = operand.mem
        base = reg_value(insn, mem.base, regs) if mem.base != X86_REG_INVALID else 0
        index = reg_value(insn, mem.index, regs) if mem.index != X86_REG_INVALID else 0
        if base is None or index is None or operand.size not in (1, 2, 4, 8, 16):
            continue
        result.append(((base + index * mem.scale + mem.disp) & ((1 << 64) - 1),
                       operand.size, operand.access))
    return result


def trace(binary: Path, program: Path, input_value: int):
    with binary.open("rb") as stream:
        section = ELFFile(stream).get_section_by_name(".text")
        text_start, text_bytes = section["sh_addr"], section.data()
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    child = os.fork()
    if child == 0:
        ptrace(TRACEME, 0)
        os.execv(str(binary), [str(binary), str(program), str(input_value)])
    try:
        _, status = os.waitpid(child, 0)
        if not os.WIFSTOPPED(status):
            raise RuntimeError("child did not stop at entry")
        original = ptrace(PEEKTEXT, child, LOOP_PC)
        ptrace(POKETEXT, child, LOOP_PC, (original & ~255) | 0xCC)
        ptrace(CONT, child)
        _, status = os.waitpid(child, 0)
        if not os.WIFSTOPPED(status):
            raise RuntimeError("execute-loop breakpoint missed")
        start = getregs(child)
        if start.rip != LOOP_PC + 1:
            raise RuntimeError(f"unexpected breakpoint at {start.rip:#x}")
        ptrace(POKETEXT, child, LOOP_PC, original)
        start.rip = LOOP_PC
        ptrace(SETREGS, child, 0, ctypes.addressof(start))
        program_bytes = program.read_bytes()
        result = {"binary": str(binary), "program": str(program), "seed_input": input_value,
                  "entry_registers": registers(start),
                  "stack": {"base": start.rsp, "bytes_hex": snapshot(child, start.rsp, 0x640)},
                  "code": {"base": start.r11, "bytes_hex": snapshot(child, start.r11, len(program_bytes))},
                  "segments": []}
        rows = []
        for step in range(MAX_STEPS):
            before = getregs(child)
            pc = before.rip
            if pc == LOOP_PC and rows:
                result["segments"].append({"kind": "next_fetch", "rows": rows})
                rows = []
            code = (text_bytes[pc - text_start:pc - text_start + 15]
                    if text_start <= pc < text_start + len(text_bytes) else b"")
            decoded = list(decoder.disasm(code, pc, count=1))
            if not decoded:
                raise RuntimeError(f"no instruction at {pc:#x}")
            insn = decoded[0]
            if insn.mnemonic == "call":
                target = int(insn.op_str, 16)
                if target in (OUTPUT_PC, OPAQUE_PC):
                    result["segments"].append({"kind": "output" if target == OUTPUT_PC else "opaque_call",
                                               "rows": rows, "exit_registers": registers(before)})
                    break
                raise RuntimeError(f"unmodeled call at {pc:#x} -> {target:#x}")
            accesses = memory_operands(insn, before)
            old = [read_operand(child, address, size) for address, size, _ in accesses]
            ptrace(SINGLESTEP, child)
            _, status = os.waitpid(child, 0)
            if not os.WIFSTOPPED(status):
                raise RuntimeError(f"child exited at native step {step}")
            after = getregs(child)
            new = [read_operand(child, address, size) for address, size, _ in accesses]
            rows.append({"type": "step", "pc": pc, "next_pc": after.rip,
                         "instruction": f"{insn.mnemonic} {insn.op_str}".strip(),
                         "registers": registers(before), "registers_after": registers(after),
                         "memory": [{"address": address, "size": size, "access": access,
                                     "before": was, "after": now}
                                    for (address, size, access), was, now in zip(accesses, old, new)]})
        else:
            raise RuntimeError("native trace hit step limit")
        return result
    finally:
        try:
            os.kill(child, signal.SIGKILL)
            os.waitpid(child, 0)
        except ProcessLookupError:
            pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    parser.add_argument("program", type=Path)
    parser.add_argument("input", type=int)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    result = trace(args.binary.resolve(), args.program.resolve(), args.input)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result) + "\n")
    print(json.dumps({"segments": len(result["segments"]),
                      "native_instructions": sum(len(s["rows"]) for s in result["segments"]),
                      "stop": result["segments"][-1]["kind"]}))


if __name__ == "__main__":
    main()
