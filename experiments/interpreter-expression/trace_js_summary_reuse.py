"""Capture two AddSmi paths at distinct bytecode offsets in one JS function."""
from __future__ import annotations

import argparse
import ctypes
import gzip
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import signal

from capstone import Cs, CS_ARCH_X86, CS_MODE_64

from trace_cross_full_flow import observed_memory_operands, read_bytes, registers
from trace_input_provenance import (CONT, PEEKTEXT, POKETEXT, SETREGS,
                                    SINGLESTEP, TRACEME, getregs, peek, ptrace)


ADD_HANDLER = 0x1BB7780
ENTRY_DISPATCH = 0x1A0A652
END_JUMP = 0x1BB77F1
BYTECODE = bytes.fromhex("0b034b0500ce4b0501b3")


def wait_stopped(child, expected):
    status = os.waitpid(child, 0)[1]
    if not os.WIFSTOPPED(status) or os.WSTOPSIG(status) != expected:
        raise RuntimeError(f"unexpected child status {status:#x}")


def step(child):
    ptrace(SINGLESTEP, child)
    wait_stopped(child, signal.SIGTRAP)
    return getregs(child)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=int)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    binary = Path(shutil.which("node"))
    fixture = Path(__file__).with_name("js_summary_reuse_fixture.js")
    marker = args.output.with_suffix(".marker.json")
    stdout = args.output.with_suffix(".stdout.txt")
    marker.unlink(missing_ok=True)
    child = os.fork()
    if child == 0:
        ptrace(TRACEME, 0)
        with stdout.open("w") as stream:
            os.dup2(stream.fileno(), 1)
            os.execv(str(binary), [str(binary), "--jitless", "--no-warnings",
                                   "--print-bytecode", "--print-bytecode-filter=twoAdds",
                                   str(fixture), str(args.input), str(marker)])
    try:
        wait_stopped(child, signal.SIGTRAP)
        ptrace(CONT, child)
        wait_stopped(child, signal.SIGSTOP)
        if json.loads(marker.read_text())["phase"] != "ready":
            raise RuntimeError("fixture sync marker missing")
        dispatch_original = ptrace(PEEKTEXT, child, ENTRY_DISPATCH)
        ptrace(POKETEXT, child, ENTRY_DISPATCH,
               (dispatch_original & ~255) | 0xCC)
        ptrace(CONT, child)
        wait_stopped(child, signal.SIGTRAP)
        dispatch_regs = getregs(child)
        if dispatch_regs.rip != ENTRY_DISPATCH + 1:
            raise RuntimeError("interpreter dispatch breakpoint was missed")
        ptrace(POKETEXT, child, ENTRY_DISPATCH, dispatch_original)
        dispatch_regs.rip = ENTRY_DISPATCH
        ptrace(SETREGS, child, 0, ctypes.addressof(dispatch_regs))
        step(child)
        original = ptrace(PEEKTEXT, child, ADD_HANDLER)
        ptrace(POKETEXT, child, ADD_HANDLER, (original & ~255) | 0xCC)
        decoder = Cs(CS_ARCH_X86, CS_MODE_64)
        decoder.detail = True
        paths = []
        pending_entry = False
        with gzip.open(args.output, "wt") as stream:
            stream.write(json.dumps({"type": "meta", "engine": "javascript",
                "input": args.input, "binary_sha256": sha256(binary.read_bytes()).hexdigest(),
                "fixture_sha256": sha256(fixture.read_bytes()).hexdigest(),
                "handler_pc": ADD_HANDLER, "bytecode_signature": BYTECODE.hex()}) + "\n")
            while len(paths) < 2:
                if pending_entry:
                    before = getregs(child)
                    if before.rip != ADD_HANDLER:
                        raise RuntimeError("chained AddSmi entry was lost")
                    pending_entry = False
                else:
                    ptrace(CONT, child)
                    wait_stopped(child, signal.SIGTRAP)
                    before = getregs(child)
                    if before.rip != ADD_HANDLER + 1:
                        raise RuntimeError(f"unexpected breakpoint {before.rip:#x}")
                    ptrace(POKETEXT, child, ADD_HANDLER, original)
                    before.rip = ADD_HANDLER
                    ptrace(SETREGS, child, 0, ctypes.addressof(before))
                offset = 2 if not paths else 6
                code_address = before.r12 + before.r9
                if read_bytes(child, code_address - offset, len(BYTECODE)) != BYTECODE:
                    step(child)
                    ptrace(POKETEXT, child, ADD_HANDLER, (original & ~255) | 0xCC)
                    continue
                if peek(child, before.r15 + 0x4B * 8, 8) != ADD_HANDLER:
                    raise RuntimeError("AddSmi dispatch table mismatch")
                rows = []
                for index in range(500):
                    before = getregs(child)
                    pc = before.rip
                    raw = read_bytes(child, pc, 16)
                    decoded = list(decoder.disasm(raw, pc, count=1))
                    if not decoded:
                        raise RuntimeError(f"cannot disassemble {pc:#x}")
                    insn = decoded[0]
                    accesses = observed_memory_operands(insn, before)
                    old = [peek(child, address, size) for address, size, _ in accesses]
                    after = step(child)
                    new = [peek(child, address, size) for address, size, _ in accesses]
                    rows.append({"type": "step", "step": index, "pc": pc,
                        "next_pc": after.rip, "bytes": raw[:insn.size].hex(),
                        "instruction": f"{insn.mnemonic} {insn.op_str}".strip(),
                        "registers": registers(before), "registers_after": registers(after),
                        "memory": [{"address": address, "size": size, "access": access,
                                    "before": was, "after": now}
                                   for (address, size, access), was, now in
                                   zip(accesses, old, new)]})
                    if pc in (0x1BB780C, END_JUMP):
                        break
                else:
                    raise RuntimeError("AddSmi handler did not reach its dispatch jump")
                path = {"type": "path", "bytecode_offset": offset,
                        "bytecode_address": code_address, "entry_smi":
                        rows[0]["registers"]["rax"] >> 32,
                        "exit_smi": rows[-1]["registers_after"]["rax"] >> 32,
                        "rows": rows}
                paths.append(path)
                stream.write(json.dumps(path) + "\n")
                pending_entry = rows[-1]["next_pc"] == ADD_HANDLER
                if not pending_entry:
                    ptrace(POKETEXT, child, ADD_HANDLER, (original & ~255) | 0xCC)
            ptrace(POKETEXT, child, ADD_HANDLER, original)
            ptrace(CONT, child)
            status = os.waitpid(child, 0)[1]
            if not os.WIFEXITED(status) or os.WEXITSTATUS(status):
                raise RuntimeError(f"fixture did not exit cleanly: {status:#x}")
            result = json.loads(stdout.read_text().splitlines()[-1])
            if result["result"] != args.input + 10:
                raise RuntimeError("fixture output mismatch")
            stream.write(json.dumps({"type": "summary", "paths": len(paths),
                                     "output": result["result"]}) + "\n")
        print(json.dumps({"input": args.input,
                          "paths": [(p["bytecode_offset"], len(p["rows"]),
                                     p["entry_smi"], p["exit_smi"]) for p in paths]}))
    finally:
        try:
            os.kill(child, signal.SIGKILL)
        except ProcessLookupError:
            pass


if __name__ == "__main__":
    main()
