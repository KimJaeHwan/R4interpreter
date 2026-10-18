"""Single-step branchCall from entry through its caller's next dispatch.

This is a path inventory and memory-access audit, not a general interpreter
control-flow proof. Both executable addresses and the JS bytecode signature
are pinned to the saved fixture and two interpreter binaries.
"""
from __future__ import annotations

import argparse
import ctypes
import gzip
from hashlib import sha256
import json
import os
from pathlib import Path
import signal

from capstone import Cs, CS_AC_WRITE, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import (X86_OP_MEM, X86_REG_DS, X86_REG_ES, X86_REG_FS,
                         X86_REG_GS, X86_REG_INVALID)

from trace_input_provenance import (CONT, PEEKTEXT, POKETEXT, SETREGS,
                                    SINGLESTEP, TRACEME, getregs, memory_operands,
                                    reg_value, debug_register,
                                    peek, ptrace)


START = {"python": 0x565038, "javascript": 0x1BA8D40}
RETURN = {"python": 0x56173B, "javascript": 0x1BC6F40}
JS_BRANCH_CODE = bytes.fromhex("0c740300a30d1903ce0d05cd69f9f801b31903ce69f90303b3")
REG_NAMES = "rax rbx rcx rdx rsi rdi rbp rsp r8 r9 r10 r11 r12 r13 r14 r15 eflags fs_base gs_base".split()


def registers(regs):
    return {name: getattr(regs, name) for name in REG_NAMES}


def read_bytes(pid, address, size):
    parts = []
    for offset in range(0, size, 8):
        word = peek(pid, address + offset, 8)
        if word is None:
            return None
        parts.append(word.to_bytes(8, "little"))
    return b"".join(parts)[:size]


def observed_memory_operands(insn, regs):
    result = memory_operands(insn, regs)
    # Some Capstone builds label the destination of an SSE memory move as a
    # read. The first operand is the x86 destination; its P-code is STORE.
    if (insn.mnemonic in ("movups", "movaps", "movdqu", "movdqa") and
            insn.operands and insn.operands[0].type == X86_OP_MEM):
        result = [(address, size, CS_AC_WRITE) for address, size, _ in result]
    if insn.mnemonic == "leave":
        result.append((regs.rbp, 8, 1))
    for operand in insn.operands:
        if operand.type != X86_OP_MEM or operand.mem.segment not in (
                X86_REG_DS, X86_REG_ES, X86_REG_FS, X86_REG_GS):
            continue
        mem = operand.mem
        segment = (regs.fs_base if mem.segment == X86_REG_FS else
                   regs.gs_base if mem.segment == X86_REG_GS else 0)
        base = reg_value(insn, mem.base, regs) if mem.base != X86_REG_INVALID else 0
        index = reg_value(insn, mem.index, regs) if mem.index != X86_REG_INVALID else 0
        result.append(((segment + base + index * mem.scale + mem.disp) & ((1 << 64) - 1),
                       operand.size, operand.access))
    return result


def install_watches(pid, watches):
    """Install up to four aligned 8-byte hardware access watches."""
    debug_register(pid, 7, 0)
    mask = 0
    for index, item in watches.items():
        address = item["address"]
        if not 0 <= index < 4 or address & 7:
            raise ValueError("unaligned or unavailable x86 debug watchpoint")
        debug_register(pid, index, address)
        mask |= 1 << (index * 2)
        mask |= (11 if item.get("mode") == "read_write" else 9) << (16 + index * 4)
    debug_register(pid, 6, 0)
    debug_register(pid, 7, mask)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("engine", choices=tuple(START))
    parser.add_argument("binary", type=Path)
    parser.add_argument("marker", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("arguments", nargs=argparse.REMAINDER)
    parser.add_argument("--limit", type=int, default=250000)
    parser.add_argument("--count-only", action="store_true")
    parser.add_argument("--watch-bridge", action="store_true")
    parser.add_argument("--through-return", action="store_true")
    args = parser.parse_args()
    args.marker.unlink(missing_ok=True)
    binary = args.binary.resolve()
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
            raise RuntimeError("child did not stop at exec")
        ptrace(CONT, child)
        status = os.waitpid(child, 0)[1]
        if not os.WIFSTOPPED(status) or os.WSTOPSIG(status) != signal.SIGSTOP:
            raise RuntimeError("fixture sync missing")
        marker = json.loads(args.marker.read_text())
        runtime_cache_sha256 = (sha256(read_bytes(child, 0xA42A10, 262 * 32)).hexdigest()
                                if args.engine == "python" else None)
        start = START[args.engine]
        original = ptrace(PEEKTEXT, child, start)
        ptrace(POKETEXT, child, start, (original & ~255) | 0xCC)
        ptrace(CONT, child)
        while True:
            status = os.waitpid(child, 0)[1]
            if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                raise RuntimeError("child exited before branchCall entry")
            if os.WSTOPSIG(status) != signal.SIGTRAP:
                ptrace(CONT, child, 0, os.WSTOPSIG(status))
                continue
            regs = getregs(child)
            if regs.rip != start + 1:
                raise RuntimeError(f"unexpected trap {regs.rip:#x}")
            ptrace(POKETEXT, child, start, original)
            regs.rip = start
            ptrace(SETREGS, child, 0, ctypes.addressof(regs))
            if args.engine == "python":
                selected = peek(child, regs.rbx, 8) == marker["code_pointers"]["branchCall"]
            else:
                selected = read_bytes(child, regs.r12 + regs.r9, len(JS_BRANCH_CODE)) == JS_BRANCH_CODE
            if selected:
                break
            ptrace(SINGLESTEP, child)
            status = os.waitpid(child, 0)[1]
            if not os.WIFSTOPPED(status) or os.WSTOPSIG(status) != signal.SIGTRAP:
                raise RuntimeError("breakpoint step failed")
            ptrace(POKETEXT, child, start, (original & ~255) | 0xCC)
            ptrace(CONT, child)
        entry = registers(getregs(child))
        if args.engine == "python":
            target_code = marker["code_pointers"]["branchCall"]
            entry_value_address = peek(child, entry["rbx"] + 0x48, 8)
            entry_value = peek(child, entry_value_address + 24, 4)
        else:
            target_code = entry["r12"] + entry["r9"]
            entry_value_address = entry["rbp"] + 0x18
            entry_value = peek(child, entry_value_address, 8)
        decoder = Cs(CS_ARCH_X86, CS_MODE_64)
        decoder.detail = True
        steps = 0
        visits = []
        end = None
        final_return_seen = False
        function_return_raw = None
        previous_pc = None
        watches = {}
        watch_intervals = []
        watch_read_events = []
        bridge_phase = "source"
        if args.watch_bridge:
            if args.engine == "python":
                watches[1] = {"address": entry_value_address + 16, "label": "input_pyint_tag",
                              "start_step": 0, "mode": "read_write"}
                watches[2] = {"address": entry_value_address + 24, "label": "input_pyint_digit",
                              "start_step": 0, "mode": "read_write"}
                watches[3] = {"address": entry["rbx"] + 0x48, "label": "parent_local",
                              "start_step": 0}
                bridge_source = entry["rbx"] + 0x60
            else:
                watches[1] = {"address": entry_value_address, "label": "parent_parameter",
                              "start_step": 0, "mode": "read_write"}
                bridge_source = None
            install_watches(child, watches)
        with gzip.open(args.output, "wt") as stream:
            stream.write(json.dumps({"type": "meta", "engine": args.engine,
                "binary_sha256": sha256(binary.read_bytes()).hexdigest(),
                "marker": marker, "entry_registers": entry,
                "runtime_cache_sha256_at_sync": runtime_cache_sha256,
                "entry_value_address": entry_value_address,
                "entry_value_raw": entry_value,
                "target_code": target_code}) + "\n")
            for steps in range(args.limit):
                before = getregs(child)
                pc = before.rip
                if steps and pc == RETURN[args.engine]:
                    if args.engine == "python":
                        selected = peek(child, before.rbx, 8) == target_code
                    else:
                        selected = before.r12 + before.r9 == target_code + 24 or \
                            before.r12 + before.r9 == target_code + 16
                    if selected:
                        function_return_raw = (peek(child, before.r15 - 8, 8)
                                               if args.engine == "python" else before.rax)
                        final_return_seen = True
                        if not args.through_return:
                            end = before
                            break
                        if args.watch_bridge:
                            for index, item in list(watches.items()):
                                watch_intervals.append({**item, "end_step": steps,
                                                        "read_pc": None})
                                del watches[index]
                            install_watches(child, watches)
                if args.through_return and final_return_seen and (
                        args.engine == "python" and previous_pc == 0x5617BA and
                        before.rbx != entry["rbx"] or
                        args.engine == "javascript" and pc == 0x1A0A652 and
                        before.r12 + before.r9 != target_code and
                        before.r12 + before.r9 != target_code + 16 and
                        before.r12 + before.r9 != target_code + 24):
                    end = before
                    break
                raw = read_bytes(child, pc, 16)
                if raw is None:
                    raise RuntimeError(f"cannot read executable byte at {pc:#x}")
                decoded = list(decoder.disasm(raw, pc, count=1))
                if not decoded:
                    raise RuntimeError(f"cannot decode {pc:#x}")
                insn = decoded[0]
                accesses = observed_memory_operands(insn, before)
                old = [] if args.count_only else [peek(child, address, size)
                                                   for address, size, _ in accesses]
                ptrace(SINGLESTEP, child)
                status = os.waitpid(child, 0)[1]
                if not os.WIFSTOPPED(status) or os.WSTOPSIG(status) != signal.SIGTRAP:
                    raise RuntimeError(f"single step failed at {pc:#x}: {status:#x}")
                after = getregs(child)
                if args.watch_bridge:
                    hit_mask = debug_register(child, 6) & 15
                    if hit_mask:
                        for index, item in watches.items():
                            if not hit_mask & (1 << index):
                                continue
                            allowed = ({"input_pyint_tag": {0x5A8256, 0x5E973F},
                                        "input_pyint_digit": {0x5A8289, 0x5E9769},
                                        "parent_call_argument": {0x56036C},
                                        "parent_parameter": {0x1BBFF8D, 0x1BBDB12},
                                        "child_parameter": ({0x5612BF} if args.engine == "python"
                                                            else {0x1BA8D09})}
                                       .get(item["label"], set()))
                            if item.get("mode") == "read_write" and pc in allowed:
                                watch_read_events.append({"step": steps, "pc": hex(pc),
                                                          "label": item["label"]})
                            else:
                                raise RuntimeError(f"hardware watch hit at step {steps} "
                                                   f"{pc:#x}: {item['label']}")
                    debug_register(child, 6, 0)
                new = [] if args.count_only else [peek(child, address, size)
                                                   for address, size, _ in accesses]
                if args.watch_bridge:
                    if args.engine == "python":
                        if bridge_phase == "source" and any(
                                address == bridge_source and size == 8 and
                                after_value == (0xA42B50 if entry_value == 0 else 0xA42BD0)
                                for (address, size, _), after_value in zip(accesses, new)):
                            watches[0] = {"address": bridge_source, "label": "parent_call_argument",
                                          "start_step": steps + 1, "mode": "read_write"}
                            bridge_phase = "source_watch"
                            install_watches(child, watches)
                        elif bridge_phase == "source_watch" and pc == 0x56036C:
                            item = watches.pop(0)
                            watch_intervals.append({**item, "end_step": steps, "read_pc": hex(pc)})
                            bridge_phase = "child_store"
                            install_watches(child, watches)
                        elif bridge_phase == "child_store" and pc == 0x56036F:
                            destination = next(address for address, size, _ in accesses if size == 8)
                            watches[0] = {"address": destination, "label": "child_parameter",
                                          "start_step": steps + 1, "mode": "read_write"}
                            bridge_phase = "child_watch"
                            install_watches(child, watches)
                        elif bridge_phase == "child_watch" and pc == 0x5612BF and any(
                                address == watches[0]["address"] for address, _, _ in accesses):
                            item = watches.pop(0)
                            watch_intervals.append({**item, "end_step": steps, "read_pc": hex(pc)})
                            bridge_phase = "done"
                            install_watches(child, watches)
                    else:
                        if bridge_phase == "source" and pc == 0x1BBDB33:
                            destination = next(address for address, size, _ in accesses if size == 8)
                            watches[0] = {"address": destination, "label": "child_parameter",
                                          "start_step": steps + 1, "mode": "read_write"}
                            bridge_phase = "child_watch"
                            install_watches(child, watches)
                        elif bridge_phase == "child_watch" and pc == 0x1BA8D09 and any(
                                address == watches[0]["address"] for address, _, _ in accesses):
                            item = watches.pop(0)
                            watch_intervals.append({**item, "end_step": steps, "read_pc": hex(pc)})
                            bridge_phase = "done"
                            install_watches(child, watches)
                if pc in (0x56227C, 0x1BB7780, 0x56173B, 0x1BC6F40):
                    visits.append({"step": steps, "pc": hex(pc), "registers": registers(before)})
                if not args.count_only:
                    stream.write(json.dumps({"type": "step", "step": steps,
                        "pc": pc, "next_pc": after.rip, "bytes": raw[:insn.size].hex(),
                        "instruction": f"{insn.mnemonic} {insn.op_str}".strip(),
                        "registers": registers(before), "registers_after": registers(after),
                        "memory": [{"address": address, "size": size, "access": access,
                                    "before": was, "after": now}
                                   for (address, size, access), was, now in
                                   zip(accesses, old, new)]}) + "\n")
                previous_pc = pc
            if end is None:
                raise RuntimeError(f"return cutpoint not reached within {args.limit} steps")
            if args.watch_bridge and bridge_phase != "done":
                raise RuntimeError(f"bridge watch incomplete: {bridge_phase}")
            for item in watches.values():
                watch_intervals.append({**item, "end_step": steps, "read_pc": None})
            if args.watch_bridge:
                install_watches(child, {})
            output = (peek(child, end.r15 - 8, 8) if args.engine == "python"
                      else end.rax)
            stream.write(json.dumps({"type": "summary", "steps": steps,
                "exit_pc": hex(end.rip), "exit_registers": registers(end),
                "output_raw": output, "function_return_raw": function_return_raw,
                "through_return": args.through_return, "visits": visits,
                "hardware_watch_enabled": args.watch_bridge,
                "hardware_watch_intervals": watch_intervals,
                "hardware_watch_events": [],
                "hardware_read_events": watch_read_events}) + "\n")
        print(json.dumps({"engine": args.engine, "steps": steps,
                          "entry_value": entry_value, "output_raw": output,
                          "visits": visits}))
    finally:
        try:
            os.kill(child, signal.SIGKILL)
        except ProcessLookupError:
            pass


if __name__ == "__main__":
    main()
