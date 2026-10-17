"""Trace concrete native interpreter dispatches in fixed CPython/Node ELFs.

The fixture stops itself after writing a marker. We then install software
breakpoints on CPython's bytecode jump sites, or V8's interpreter entry and
its actual dispatch-table handler targets. No opcode semantics are encoded.
"""
from __future__ import annotations

import argparse
from collections import Counter
import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import signal
import subprocess

from elftools.elf.elffile import ELFFile

from trace_input_provenance import (CONT, PEEKTEXT, POKETEXT, SETREGS,
                                    SINGLESTEP, TRACEME, getregs, peek, ptrace)


PYTHON_EVAL_START = 0x5611E0
NODE_ENTRY_DISPATCH = 0x1A0A652
MASK64 = (1 << 64) - 1


def python_jump_sites(binary):
    output = subprocess.check_output(["objdump", "-d", "--start-address=0x5611e0",
                                      "--stop-address=0x571000", str(binary)], text=True)
    sites = {}
    for line in output.splitlines():
        match = re.search(r"^\s*([0-9a-f]+):.*\bjmp\s+\*0x([0-9a-f]+)\(,%rax,8\)", line)
        if match:
            sites[int(match.group(1), 16)] = int(match.group(2), 16)
    table, count = Counter(sites.values()).most_common(1)[0]
    selected = {pc for pc, address in sites.items() if address == table}
    if count < 100 or table != 0x8659A0:
        raise RuntimeError("CPython native bytecode dispatch layout changed")
    return selected, table


def wait(child):
    return os.waitpid(child, 0)[1]


def patch_byte(child, address, byte):
    word = ptrace(PEEKTEXT, child, address)
    ptrace(POKETEXT, child, address, (word & ~255) | byte)


def install(child, breakpoints, address):
    if address not in breakpoints:
        breakpoints[address] = ptrace(PEEKTEXT, child, address) & 255
        patch_byte(child, address, 0xCC)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("engine", choices=("python", "javascript"))
    parser.add_argument("executable", type=Path)
    parser.add_argument("marker", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("arguments", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    args.marker.unlink(missing_ok=True)
    binary = args.executable.resolve()
    with binary.open("rb") as handle:
        elf = ELFFile(handle)
        executable_ranges = [(segment["p_vaddr"], segment["p_vaddr"] + segment["p_memsz"])
                             for segment in elf.iter_segments()
                             if segment["p_type"] == "PT_LOAD" and segment["p_flags"] & 1]
    stdout_path = args.output.with_suffix(".stdout.txt")
    argv = [str(binary), *args.arguments]
    python_sites, python_table = python_jump_sites(binary) if args.engine == "python" else (set(), None)
    child = os.fork()
    if child == 0:
        ptrace(TRACEME, 0)
        with stdout_path.open("w") as stream:
            os.dup2(stream.fileno(), 1)
            os.execv(str(binary), argv)
    try:
        status = wait(child)
        if not os.WIFSTOPPED(status):
            raise RuntimeError("child did not stop at exec")
        ptrace(CONT, child)
        status = wait(child)
        if not os.WIFSTOPPED(status) or os.WSTOPSIG(status) != signal.SIGSTOP:
            raise RuntimeError(f"fixture did not stop at native sync: {status:#x}")
        marker = json.loads(args.marker.read_text())
        breakpoints = {}
        for site in (python_sites if args.engine == "python" else {NODE_ENTRY_DISPATCH}):
            install(child, breakpoints, site)
        node_handler_table = None
        node_handlers = set()
        rows = []
        ptrace(CONT, child)
        while True:
            status = wait(child)
            if os.WIFEXITED(status):
                exit_code = os.WEXITSTATUS(status)
                break
            if os.WIFSIGNALED(status):
                raise RuntimeError(f"child killed by signal {os.WTERMSIG(status)}")
            if os.WIFSTOPPED(status) and os.WSTOPSIG(status) != signal.SIGTRAP:
                ptrace(CONT, child, 0, os.WSTOPSIG(status))
                continue
            regs = getregs(child)
            pc = regs.rip - 1
            if pc not in breakpoints:
                raise RuntimeError(f"unexpected SIGTRAP PC {regs.rip:#x}")
            if args.engine == "python":
                executable_object = peek(child, regs.rbx, 8)
                code_name = next((name for name, address in marker["code_pointers"].items()
                                  if address == executable_object), None)
                byte_address = regs.rbp
                byte = peek(child, byte_address, 1)
                row = {"native_pc": hex(pc), "byte_address": hex(byte_address),
                       "fetched_byte": byte, "opcode_register": regs.rax & 255,
                       "handler_address": hex(peek(child, python_table + (regs.rax & 255) * 8, 8)),
                       "code_name": code_name}
            else:
                if pc == NODE_ENTRY_DISPATCH and node_handler_table is None:
                    node_handler_table = regs.r15
                    for opcode in range(256):
                        address = peek(child, node_handler_table + opcode * 8, 8)
                        if address is not None and address != pc and any(
                                start <= address < end for start, end in executable_ranges):
                            node_handlers.add(address)
                    for address in node_handlers:
                        install(child, breakpoints, address)
                byte_address = (regs.r12 + regs.r9) & MASK64
                byte = peek(child, byte_address, 1)
                table_target = (peek(child, node_handler_table + byte * 8, 8)
                                if byte is not None and node_handler_table is not None else None)
                row = {"native_pc": hex(pc), "byte_address": hex(byte_address),
                       "fetched_byte": byte,
                       "kind": "entry_dispatch" if pc == NODE_ENTRY_DISPATCH else "handler_entry",
                       "handler_address": hex(regs.rcx) if pc == NODE_ENTRY_DISPATCH else hex(pc),
                       "table_handler_address": None if table_target is None else hex(table_target),
                       "dispatch_table_match": table_target == (regs.rcx if pc == NODE_ENTRY_DISPATCH else pc)}
                if pc == NODE_ENTRY_DISPATCH and byte != (regs.r10 & 255):
                    raise RuntimeError("native fetched byte differs from dispatch register")
            rows.append(row)
            if len(rows) > 200000:
                raise RuntimeError("native dispatch observation exceeded 200000 hits")
            patch_byte(child, pc, breakpoints[pc])
            regs.rip = pc
            ptrace(SETREGS, child, 0, ctypes.addressof(regs))
            ptrace(SINGLESTEP, child)
            step_status = wait(child)
            if not os.WIFSTOPPED(step_status) or os.WSTOPSIG(step_status) != signal.SIGTRAP:
                raise RuntimeError(f"single step at breakpoint failed: {step_status:#x}")
            patch_byte(child, pc, 0xCC)
            ptrace(CONT, child)
        if exit_code != 0:
            raise RuntimeError(f"fixture exited with {exit_code}")
        report = {"engine": args.engine, "executable_sha256": sha256(binary.read_bytes()).hexdigest(),
                  "breakpoint_count": len(breakpoints), "marker": marker,
                  "hit_count": len(rows), "events": rows, "exit_code": exit_code,
                  "stdout_sha256": sha256(stdout_path.read_bytes()).hexdigest()}
        args.output.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps({"engine": args.engine, "hits": len(rows),
                          "target_hits": sum(bool(row.get("code_name")) for row in rows),
                          "handler_count": len(node_handlers)}))
    finally:
        try:
            os.kill(child, signal.SIGKILL)
        except ProcessLookupError:
            pass


if __name__ == "__main__":
    main()
