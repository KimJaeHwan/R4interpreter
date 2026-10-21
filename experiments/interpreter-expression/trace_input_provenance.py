"""Trace actual x86 memory operands from run_lua_chunk to its first VM add.

Run in the experiment venv (capstone, pyelftools). The child is the saved,
fixed-address ELF. A distinct input value makes equality-based candidate
filtering useful; a candidate is not, by itself, a taint proof.
"""
from __future__ import annotations

import argparse
from collections import deque
import ctypes
import errno
import json
import os
import signal
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_AC_READ, CS_AC_WRITE
from capstone.x86 import X86_OP_MEM, X86_REG_INVALID, X86_REG_RIP
from elftools.elf.elffile import ELFFile


LIBC = ctypes.CDLL(None, use_errno=True)
LIBC.ptrace.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
LIBC.ptrace.restype = ctypes.c_long
TRACEME, PEEKTEXT, PEEKDATA, PEEKUSER, POKETEXT, POKEDATA, POKEUSER, CONT, SINGLESTEP, GETREGS, SETREGS = 0, 1, 2, 3, 4, 5, 6, 7, 9, 12, 13
MASK = (1 << 64) - 1
DEBUG_REGISTERS_OFFSET = 848  # offsetof(struct user, u_debugreg), Linux x86-64.


class Regs(ctypes.Structure):
    _fields_ = [(n, ctypes.c_ulonglong) for n in (
        "r15 r14 r13 r12 rbp rbx r11 r10 r9 r8 rax rcx rdx rsi rdi orig_rax "
        "rip cs eflags rsp ss fs_base gs_base ds es fs gs").split()]


def ptrace(request, pid, address=0, data=0):
    ctypes.set_errno(0)
    result = LIBC.ptrace(request, pid, ctypes.c_void_p(address), ctypes.c_void_p(data))
    if result == -1 and ctypes.get_errno():
        raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))
    return result & MASK


def getregs(pid):
    regs = Regs()
    ptrace(GETREGS, pid, 0, ctypes.addressof(regs))
    return regs


def debug_register(pid, index, value=None):
    offset = DEBUG_REGISTERS_OFFSET + 8 * index
    return ptrace(PEEKUSER if value is None else POKEUSER, pid, offset, 0 if value is None else value)


def set_write_watch(pid, address=None):
    debug_register(pid, 7, 0)
    debug_register(pid, 6, 0)
    if address is not None:
        if address & 7:
            raise ValueError("8-byte hardware write watch requires an aligned address")
        debug_register(pid, 0, address)
        debug_register(pid, 7, 0x90001)  # local DR0, write-only, 8-byte length.


def peek(pid, address, size):
    try:
        return sum((ptrace(PEEKDATA, pid, address + offset) &
                    ((1 << (8 * min(8, size - offset))) - 1)) << (offset * 8)
                   for offset in range(0, size, 8))
    except OSError as error:
        if error.errno in (errno.EIO, errno.EFAULT):
            return None
        raise


def reg_value(insn, reg_id, regs):
    name = insn.reg_name(reg_id)
    if name == "rip":
        return insn.address + insn.size
    aliases = {"eax": "rax", "ebx": "rbx", "ecx": "rcx", "edx": "rdx",
               "esi": "rsi", "edi": "rdi", "ebp": "rbp", "esp": "rsp"}
    for index in range(8, 16):
        aliases[f"r{index}d"] = f"r{index}"
    name = aliases.get(name, name)
    return getattr(regs, name, None)


def memory_operands(insn, regs):
    if insn.mnemonic == "lea" or insn.mnemonic.startswith("nop"):
        return []
    result = []
    for operand in insn.operands:
        if operand.type != X86_OP_MEM:
            continue
        mem = operand.mem
        if mem.segment != X86_REG_INVALID:
            continue
        base = reg_value(insn, mem.base, regs) if mem.base != X86_REG_INVALID else 0
        index = reg_value(insn, mem.index, regs) if mem.index != X86_REG_INVALID else 0
        if base is None or index is None or operand.size not in (1, 2, 4, 8, 16, 32, 64):
            continue
        address = (base + index * mem.scale + mem.disp) & MASK
        result.append((address, operand.size, operand.access))
    # x86 CALL/RET touch the stack even though Capstone exposes no explicit
    # memory operand for their direct forms. Ghidra P-code models these bytes.
    if insn.mnemonic.startswith(("call", "push")):
        result.append(((regs.rsp - 8) & MASK, 8, CS_AC_WRITE))
    elif insn.mnemonic.startswith(("ret", "pop")):
        result.append((regs.rsp, 8, CS_AC_READ))
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    parser.add_argument("bytecode", type=Path)
    parser.add_argument("input", type=int)
    parser.add_argument("output", type=Path)
    parser.add_argument("--limit", type=int, default=2_000_000)
    parser.add_argument("--markers-only", action="store_true",
                        help="record selected path sites only (useful for input zero)")
    parser.add_argument("--capture-handler", action="store_true",
                        help="record every step from 0x4164b8 through 0x415b22")
    parser.add_argument("--capture-bridge", action="store_true",
                        help="record every step from 0x417e50 through callee entry 0x4164b8")
    parser.add_argument("--capture-full-flow", action="store_true",
                        help="audit native writes from run_lua_chunk entry through main printf call")
    parser.add_argument("--hardware-watch", action="store_true",
                        help="with --capture-full-flow, watch live 8-byte slots for any intervening write")
    parser.add_argument("--handler-count", type=int, default=1,
                        help="number of 0x4164b8 handler exits to capture, including intervening steps")
    parser.add_argument("--snapshot-bytes", type=int, default=256,
                        help="bytes to capture at handler entry from RBX")
    parser.add_argument("--snapshot-addresses", type=Path,
                        help="JSON list of byte addresses to read at --snapshot-pc")
    parser.add_argument("--snapshot-pc", type=lambda value: int(value, 0),
                        help="native PC where requested byte addresses are read once")
    parser.add_argument("--override-word-pc", type=lambda value: int(value, 0),
                        help="native PC where one 8-byte read is replaced before execution")
    parser.add_argument("--override-word-value", type=lambda value: int(value, 0),
                        help="replacement unsigned 64-bit word for --override-word-pc")
    args = parser.parse_args()
    if args.hardware_watch and not args.capture_full_flow:
        parser.error("--hardware-watch requires --capture-full-flow")
    if (args.snapshot_addresses is None) != (args.snapshot_pc is None):
        parser.error("--snapshot-addresses and --snapshot-pc must be used together")
    if (args.override_word_pc is None) != (args.override_word_value is None):
        parser.error("--override-word-pc and --override-word-value must be used together")
    if args.override_word_value is not None and not 0 <= args.override_word_value <= MASK:
        parser.error("override word must be an unsigned 64-bit value")
    snapshot_addresses = []
    if args.snapshot_addresses is not None:
        raw = json.loads(args.snapshot_addresses.read_text())
        if (not isinstance(raw, list) or len(raw) > 10000 or
                any(not isinstance(item, (int, str)) for item in raw)):
            parser.error("snapshot addresses must be a JSON list of at most 10000 addresses")
        snapshot_addresses = [int(item, 0) if isinstance(item, str) else item for item in raw]
        if len(snapshot_addresses) != len(set(snapshot_addresses)) or any(
                address < 0 or address > MASK for address in snapshot_addresses):
            parser.error("snapshot addresses must be unique BV64 byte addresses")
    with args.binary.open("rb") as handle:
        elf = ELFFile(handle)
        text = elf.get_section_by_name(".text")
        text_start = text["sh_addr"]
        text_bytes = text.data()
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    instruction_cache = {}
    child = os.fork()
    if child == 0:
        ptrace(TRACEME, 0)
        os.execv(str(args.binary), [str(args.binary), str(args.bytecode), str(args.input)])
    try:
        _, status = os.waitpid(child, 0)
        if not os.WIFSTOPPED(status):
            raise RuntimeError("child failed before entry")
        start = 0x401490
        original = ptrace(PEEKTEXT, child, start)
        ptrace(POKETEXT, child, start, (original & ~0xFF) | 0xCC)
        ptrace(CONT, child)
        _, status = os.waitpid(child, 0)
        if not os.WIFSTOPPED(status):
            raise RuntimeError("entry breakpoint missed")
        regs = getregs(child)
        if regs.rip != start + 1:
            raise RuntimeError(f"unexpected breakpoint: {regs.rip:#x}")
        ptrace(POKETEXT, child, start, original)
        regs.rip = start
        ptrace(SETREGS, child, 0, ctypes.addressof(regs))
        if args.hardware_watch:
            set_write_watch(child, (regs.rsp - 8) & MASK)
        input_word = args.input & MASK
        count = 0
        candidates = 0
        capturing = False
        full_suffix_capturing = False
        bridge_prefix = deque(maxlen=32)
        full_prefix = deque(maxlen=384)
        watch_state = None
        watch_events = []
        watch_intervals = []
        watch_self_check_passed = False
        source_reads_seen = 0
        snapshot_captured = False
        override_applied = False
        captured_handlers = 0
        markers = {0x401490, 0x40149B, 0x4014B3, 0x4014B6,
                   0x402A00, 0x402A04, 0x402A07, 0x403300,
                   0x411B50, 0x411B54, 0x416EA1, 0x416EA7,
                   0x415440, 0x4164B8, 0x4164D0, 0x4164D7,
                   0x4164E5, 0x4164E9, 0x4164EC,
                   0x417CE4, 0x417CE7, 0x417CEA}
        if args.capture_full_flow:
            markers.update({0x4014EE, 0x4014F3, 0x4014FF, 0x401504,
                            0x401528, 0x401532, 0x401537, 0x401542,
                            0x40154C, 0x40155B, 0x401377, 0x40137E,
                            0x401381, 0x401388})
        with args.output.open("w") as out:
            out.write(json.dumps({"type": "meta", "input": args.input, "input_word": input_word,
                                  "binary": str(args.binary), "bytecode": str(args.bytecode)}) + "\n")
            for count in range(args.limit):
                before = getregs(child)
                pc = before.rip
                if args.snapshot_pc == pc and not snapshot_captured:
                    snapshot_captured = True
                    out.write(json.dumps({"type": "entry_snapshot", "step": count,
                                          "pc": pc,
                                          "bytes": {hex(address): peek(child, address, 1)
                                                    for address in snapshot_addresses}}) + "\n")
                if args.capture_handler and pc == 0x4164B8:
                    capturing = True
                if args.capture_bridge and pc == 0x417E50:
                    capturing = True
                    for buffered in bridge_prefix:
                        out.write(json.dumps(buffered) + "\n")
                if args.capture_full_flow and pc in (0x417CEA, 0x40154C):
                    if pc == 0x417CEA:
                        for buffered in full_prefix:
                            out.write(json.dumps(buffered) + "\n")
                    full_suffix_capturing = True
                if pc not in instruction_cache:
                    if text_start <= pc < text_start + len(text_bytes):
                        code = text_bytes[pc - text_start: pc - text_start + 15]
                    else:
                        try:
                            code = b"".join(ptrace(PEEKTEXT, child, pc + offset).to_bytes(8, "little")
                                            for offset in (0, 8))
                        except OSError:
                            code = b""
                    decoded = list(decoder.disasm(code, pc, count=1))
                    instruction_cache[pc] = decoded[0] if decoded else None
                insn = instruction_cache[pc]
                accesses = [] if insn is None else memory_operands(insn, before)
                if args.override_word_pc == pc and not override_applied:
                    source_reads = [(address, size) for address, size, access in accesses
                                    if access & CS_AC_READ and size == 8]
                    if len(source_reads) != 1:
                        raise RuntimeError("override PC must have exactly one 8-byte read")
                    address, _ = source_reads[0]
                    old_word = peek(child, address, 8)
                    if old_word is None:
                        raise RuntimeError("override source word is unreadable")
                    ptrace(POKEDATA, child, address, args.override_word_value)
                    override_applied = True
                    out.write(json.dumps({"type": "input_override", "step": count,
                                          "pc": pc, "address": address,
                                          "before": old_word,
                                          "after": args.override_word_value}) + "\n")
                reads = [(a, n, access, peek(child, a, n)) for a, n, access in accesses]
                entry_memory = None
                if (args.capture_handler or args.capture_bridge) and pc == 0x4164B8:
                    snapshot = bytearray()
                    for offset in range(0, args.snapshot_bytes, 8):
                        size = min(8, args.snapshot_bytes - offset)
                        word = peek(child, before.rbx + offset, size)
                        if word is None:
                            raise RuntimeError(f"unreadable handler entry memory at +{offset}")
                        snapshot.extend(word.to_bytes(size, "little"))
                    entry_memory = {"base": before.rbx, "bytes_hex": snapshot.hex()}
                ptrace(SINGLESTEP, child)
                _, status = os.waitpid(child, 0)
                if not os.WIFSTOPPED(status):
                    raise RuntimeError(f"child exited at step {count}: {status:#x}")
                after = getregs(child)
                if args.hardware_watch and count == 0:
                    if pc != 0x401490 or not debug_register(child, 6) & 1:
                        raise RuntimeError("hardware watch self-check failed on entry push")
                    watch_self_check_passed = True
                    set_write_watch(child)
                if args.hardware_watch and watch_state is not None and debug_register(child, 6) & 1:
                    watch_events.append({"step": count, "pc": hex(pc),
                                         "phase": watch_state[0],
                                         "address": hex(watch_state[1])})
                    debug_register(child, 6, 0)
                writes = [(a, n, access, peek(child, a, n)) for a, n, access in accesses]
                if args.hardware_watch:
                    if pc in (0x411B50, 0x416EA1, 0x40154C):
                        if pc == 0x416EA1 and watch_state is not None and \
                                watch_state[0] == "copied_vm_source":
                            source_reads_seen += 1
                        if watch_state is not None and (pc != 0x416EA1 or
                                                        args.input == 0 or source_reads_seen >= 2):
                            phase, address, start_step = watch_state
                            watch_intervals.append({"phase": phase, "address": hex(address),
                                                    "start_step": start_step, "end_step": count})
                            set_write_watch(child)
                            watch_state = None
                    if pc in (0x402A04, 0x411B54, 0x401542):
                        if watch_state is not None:
                            raise RuntimeError("previous hardware watch interval did not end")
                        source = next((item for item in accesses if item[2] & CS_AC_WRITE and item[1] == 8), None)
                        if source is None:
                            raise RuntimeError(f"missing 8-byte watch source at {pc:#x}")
                        phase = {0x402A04: "initial_lua_slot", 0x411B54: "copied_vm_source",
                                 0x401542: "native_return_stack"}[pc]
                        watch_state = (phase, source[0], count)
                        set_write_watch(child, source[0])
                hits = []
                for (a, n, access, old), (_, _, _, new) in zip(reads, writes):
                    if n == 8 and (old == input_word or new == input_word):
                        hits.append({"address": a, "size": n, "access": access,
                                     "before": old, "after": new})
                has_write = any(access & CS_AC_WRITE for _, _, access in accesses)
                if (capturing or full_suffix_capturing or
                        (hits and not args.markers_only) or pc in markers or
                        args.capture_bridge or args.capture_full_flow):
                    candidates += bool(hits)
                    record = {"type": "step", "step": count, "pc": pc, "next_pc": after.rip,
                              "instruction": None if insn is None else f"{insn.mnemonic} {insn.op_str}".strip(),
                              "registers": {name: getattr(before, name) for name in
                                            "rax rbx rcx rdx rsi rdi rbp rsp r8 r9 r10 r11 r12 r13 r14 r15 eflags".split()},
                              "registers_after": {name: getattr(after, name) for name in
                                                  "rax rbx rcx rdx rsi rdi rbp rsp r8 r9 r10 r11 r12 r13 r14 r15 eflags".split()},
                              "memory": [{"address": a, "size": n, "access": access,
                                          "before": old, "after": new}
                                         for (a, n, access, old), (_, _, _, new) in zip(reads, writes)],
                              "candidate_input_words": hits}
                    if entry_memory is not None:
                        record["entry_memory"] = entry_memory
                    if args.capture_full_flow and not full_suffix_capturing:
                        full_prefix.append({**record, "type": "replay_step"})
                    if args.capture_full_flow and not full_suffix_capturing and pc not in markers:
                        record = {"type": "write", "step": count, "pc": pc,
                                  "next_pc": after.rip, "instruction": record["instruction"],
                                  "memory": [m for m in record["memory"] if m["access"] & CS_AC_WRITE]}
                    if args.capture_bridge and not capturing:
                        bridge_prefix.append(record)
                    elif (not args.capture_full_flow or full_suffix_capturing or
                          pc in markers or has_write):
                        out.write(json.dumps(record) + "\n")
                if args.capture_full_flow and pc == 0x401542:
                    full_suffix_capturing = False
                if args.capture_bridge and pc == 0x4164B8:
                    break
                if args.capture_full_flow and pc == 0x401388:
                    break
                if args.capture_handler:
                    if capturing and pc == 0x415B22:
                        captured_handlers += 1
                        if captured_handlers >= args.handler_count:
                            break
                elif not args.capture_full_flow and pc == 0x417CEA:
                    break
            else:
                raise RuntimeError(f"VM target not reached within {args.limit} steps")
            out.write(json.dumps({"type": "summary", "steps": count + 1,
                                  "input_word_access_steps": candidates,
                                  "stopped_after_vm_add_store": pc == 0x417CEA,
                                  "stopped_before_printf_call": pc == 0x401388,
                                  "stop_pc": pc,
                                  "captured_handlers": captured_handlers,
                                  "hardware_watch_enabled": args.hardware_watch,
                                  "hardware_watch_self_check_passed": watch_self_check_passed,
                                  "hardware_watch_events": watch_events,
                                  "hardware_watch_intervals": watch_intervals,
                                  "source_override_applied": override_applied}) + "\n")
            if args.override_word_value is not None and not override_applied:
                raise RuntimeError("source override PC was never reached")
        print(f"steps={count + 1} input_word_access_steps={candidates} output={args.output}")
    finally:
        try:
            os.kill(child, signal.SIGKILL)
            os.waitpid(child, 0)
        except ProcessLookupError:
            pass


if __name__ == "__main__":
    main()
