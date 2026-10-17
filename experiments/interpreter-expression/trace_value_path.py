"""Single-step a real small-integer handler path after a fixture sync point.

This records all native instructions, visible memory operands, and concrete
register states for later Ghidra SLEIGH P-code replay. Other paths retain an
explicit early-exit reason. Addresses are pinned to the two saved ELFs.
"""
from __future__ import annotations

import argparse
import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import signal

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from elftools.elf.elffile import ELFFile

from trace_input_provenance import (CONT, PEEKTEXT, POKETEXT, SETREGS,
                                    SINGLESTEP, TRACEME, getregs, memory_operands,
                                    peek, ptrace)


TARGETS = {"python": (0x56227C, 0x571000),
           "javascript": (0x1BB7780, 0x1BB7E00)}
REG_NAMES = "rax rbx rcx rdx rsi rdi rbp rsp r8 r9 r10 r11 r12 r13 r14 r15 eflags".split()


def registers(regs):
    return {name: getattr(regs, name) for name in REG_NAMES}


def decode_compact_python_int(pid, address):
    tag = peek(pid, address + 16, 8)
    digit = peek(pid, address + 24, 4)
    if tag is None or digit is None or tag > 15:
        return None
    return (1 - (tag & 3)) * digit


def signed_32(word):
    value = (word >> 32) & 0xFFFFFFFF
    return value - (1 << 32) if value & (1 << 31) else value


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("engine", choices=tuple(TARGETS))
    parser.add_argument("binary", type=Path)
    parser.add_argument("marker", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("arguments", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    args.marker.unlink(missing_ok=True)
    binary = args.binary.resolve()
    start, end = TARGETS[args.engine]
    with binary.open("rb") as handle:
        elf = ELFFile(handle)
        section = elf.get_section_by_name(".text")
        text_start, text_bytes = section["sh_addr"], section.data()
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    stdout_path = args.output.with_suffix(".stdout.txt")
    child = os.fork()
    if child == 0:
        ptrace(TRACEME, 0)
        with stdout_path.open("w") as stream:
            os.dup2(stream.fileno(), 1)
            os.execv(str(binary), [str(binary), *args.arguments])
    try:
        status = os.waitpid(child, 0)[1]
        if not os.WIFSTOPPED(status):
            raise RuntimeError("child failed at exec")
        ptrace(CONT, child)
        status = os.waitpid(child, 0)[1]
        if not os.WIFSTOPPED(status) or os.WSTOPSIG(status) != signal.SIGSTOP:
            raise RuntimeError(f"fixture sync missing: {status:#x}")
        marker = json.loads(args.marker.read_text())
        runtime_cache_sha256 = None
        if args.engine == "python":
            cache = b"".join(peek(child, 0xA42A10 + offset, 8).to_bytes(8, "little")
                             for offset in range(0, 262 * 32, 8))
            runtime_cache_sha256 = sha256(cache).hexdigest()
        original = ptrace(PEEKTEXT, child, start)
        ptrace(POKETEXT, child, start, (original & ~255) | 0xCC)
        paths = []
        ptrace(CONT, child)
        while True:
            status = os.waitpid(child, 0)[1]
            if os.WIFEXITED(status):
                exit_code = os.WEXITSTATUS(status)
                break
            if os.WIFSIGNALED(status):
                raise RuntimeError(f"child killed by {os.WTERMSIG(status)}")
            if os.WSTOPSIG(status) != signal.SIGTRAP:
                ptrace(CONT, child, 0, os.WSTOPSIG(status))
                continue
            regs = getregs(child)
            if regs.rip != start + 1:
                raise RuntimeError(f"unexpected native trap {regs.rip:#x}")
            ptrace(POKETEXT, child, start, original)
            regs.rip = start
            ptrace(SETREGS, child, 0, ctypes.addressof(regs))
            entry = registers(regs)
            if args.engine == "python":
                code_pointer = peek(child, regs.rbx, 8)
                if code_pointer != marker["code_pointers"]["addFive"]:
                    # Restore the breakpoint after stepping the first instruction.
                    ptrace(SINGLESTEP, child)
                    os.waitpid(child, 0)
                    ptrace(POKETEXT, child, start, (original & ~255) | 0xCC)
                    ptrace(CONT, child)
                    continue
                left_address = peek(child, regs.r15 - 16, 8)
                right_address = peek(child, regs.r15 - 8, 8)
                entry_values = {"left": decode_compact_python_int(child, left_address),
                                "right": decode_compact_python_int(child, right_address),
                                "left_address": hex(left_address), "right_address": hex(right_address),
                                "code_pointer": hex(code_pointer)}
                return_address = 0x56173B  # addFive's next RETURN_VALUE handler
            else:
                immediate = peek(child, regs.r12 + regs.r9 + 1, 1)
                if immediate is not None and immediate & 0x80:
                    immediate -= 256
                entry_values = {"accumulator_tagged": hex(regs.rax),
                                "accumulator_smi": signed_32(regs.rax) if not regs.rax & 1 else None,
                                "immediate": immediate,
                                "bytecode_address": hex(regs.r12 + regs.r9)}
                return_address = None
            rows = []
            reason = "instruction limit"
            for index in range(1500):
                before = getregs(child)
                pc = before.rip
                if index and (args.engine == "javascript" and not start <= pc < end or
                              args.engine == "python" and pc == return_address):
                    reason = "next bytecode handler" if pc == return_address else "left handler range"
                    break
                if not text_start <= pc < text_start + len(text_bytes):
                    reason = "left ELF text"
                    break
                decoded = list(decoder.disasm(text_bytes[pc-text_start:pc-text_start+15], pc, count=1))
                if not decoded:
                    reason = "undecodable instruction"
                    break
                insn = decoded[0]
                accesses = memory_operands(insn, before)
                before_memory = [peek(child, address, size) for address, size, _ in accesses]
                ptrace(SINGLESTEP, child)
                step_status = os.waitpid(child, 0)[1]
                if not os.WIFSTOPPED(step_status) or os.WSTOPSIG(step_status) != signal.SIGTRAP:
                    raise RuntimeError(f"native single step failed at {pc:#x}: {step_status:#x}")
                after = getregs(child)
                after_memory = [peek(child, address, size) for address, size, _ in accesses]
                rows.append({"type": "step", "step": index, "pc": pc, "next_pc": after.rip,
                             "instruction": f"{insn.mnemonic} {insn.op_str}".strip(),
                             "registers": registers(before), "registers_after": registers(after),
                             "memory": [{"address": address, "size": size, "access": access,
                                         "before": old, "after": new}
                                        for (address, size, access), old, new in
                                        zip(accesses, before_memory, after_memory)]})
            final = getregs(child)
            if args.engine == "python":
                result_address = peek(child, final.r15 - 8, 8)
                numeric_result = decode_compact_python_int(child, result_address) if \
                    reason == "next bytecode handler" and result_address else None
            else:
                numeric_result = signed_32(final.rax) if not final.rax & 1 else None
            paths.append({"entry_registers": entry, "entry_values": entry_values,
                          "rows": rows, "exit_pc": hex(final.rip),
                          "exit_registers": registers(final), "exit_reason": reason,
                          "result_compact_integer": numeric_result})
            if len(paths) > 200:
                raise RuntimeError("too many arithmetic helper visits")
            ptrace(POKETEXT, child, start, (original & ~255) | 0xCC)
            ptrace(CONT, child)
        if exit_code:
            raise RuntimeError(f"fixture exited with {exit_code}")
        report = {"engine": args.engine, "binary_sha256": sha256(binary.read_bytes()).hexdigest(),
                  "entry_pc": hex(start), "marker": marker, "paths": paths,
                  "runtime_cache_sha256_at_sync": runtime_cache_sha256,
                  "stdout_sha256": sha256(stdout_path.read_bytes()).hexdigest()}
        args.output.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps({"engine": args.engine, "paths": len(paths),
                          "path_lengths": [len(path["rows"]) for path in paths]}))
    finally:
        try:
            os.kill(child, signal.SIGKILL)
        except ProcessLookupError:
            pass


if __name__ == "__main__":
    main()
