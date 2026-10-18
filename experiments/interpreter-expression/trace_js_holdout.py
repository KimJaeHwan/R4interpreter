"""Capture the bounded AddSmi prefix in a different JS program."""
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
from trace_js_summary_reuse import wait_stopped


ROOT = Path(__file__).resolve().parent
FIXTURE = ROOT / "js_holdout_fixture.js"
BOUNDARY = ROOT / "js_boundary_discovery_result.json"


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
    boundary = json.loads(BOUNDARY.read_text())["prefix"]
    entry_pc = int(boundary["entry_pc"], 16)
    end_pc = int(boundary["end_branch_pc"], 16)
    marker = args.output.with_suffix(".marker.json")
    stdout = args.output.with_suffix(".stdout.txt")
    marker.unlink(missing_ok=True)
    child = os.fork()
    if child == 0:
        ptrace(TRACEME, 0)
        with stdout.open("w") as stream:
            os.dup2(stream.fileno(), 1)
            os.execv(str(binary), [str(binary), "--jitless", "--no-warnings",
                                   str(FIXTURE), str(args.input), str(marker)])
    try:
        wait_stopped(child, signal.SIGTRAP)
        ptrace(CONT, child)
        wait_stopped(child, signal.SIGSTOP)
        if json.loads(marker.read_text())["phase"] != "ready":
            raise RuntimeError("holdout fixture did not synchronize")
        original = ptrace(PEEKTEXT, child, entry_pc)
        ptrace(POKETEXT, child, entry_pc, (original & ~255) | 0xCC)
        decoder = Cs(CS_ARCH_X86, CS_MODE_64)
        decoder.detail = True
        for attempt in range(100):
            ptrace(CONT, child)
            wait_stopped(child, signal.SIGTRAP)
            before = getregs(child)
            if before.rip != entry_pc + 1:
                raise RuntimeError("unexpected breakpoint before holdout AddSmi")
            ptrace(POKETEXT, child, entry_pc, original)
            before.rip = entry_pc
            ptrace(SETREGS, child, 0, ctypes.addressof(before))
            if (before.rax == args.input << 32 and
                    read_bytes(child, before.r12 + before.r9, 2) == bytes([0x4B, 5])):
                break
            step(child)
            ptrace(POKETEXT, child, entry_pc, (original & ~255) | 0xCC)
        else:
            raise RuntimeError("holdout AddSmi site was not found")
        rows = []
        for index in range(boundary["native_steps"]):
            before = getregs(child)
            pc = before.rip
            raw = read_bytes(child, pc, 16)
            decoded = list(decoder.disasm(raw, pc, count=1))
            if not decoded:
                raise RuntimeError("cannot disassemble holdout native instruction")
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
        if rows[-1]["pc"] != end_pc or \
                hex(rows[-1]["next_pc"]) != boundary["exit_pc"]:
            raise RuntimeError("holdout prefix reached a different cutpoint")
        ptrace(CONT, child)
        status = os.waitpid(child, 0)[1]
        if not os.WIFEXITED(status) or os.WEXITSTATUS(status):
            raise RuntimeError("holdout fixture did not exit cleanly")
        actual = json.loads(stdout.read_text().splitlines()[-1])["result"]
        if actual != args.input + 5:
            raise RuntimeError("holdout JavaScript program output changed")
        with gzip.open(args.output, "wt") as stream:
            stream.write(json.dumps({"type": "meta", "input": args.input,
                "binary_sha256": sha256(binary.read_bytes()).hexdigest(),
                "fixture_sha256": sha256(FIXTURE.read_bytes()).hexdigest()}) + "\n")
            stream.write(json.dumps({"type": "path", "rows": rows}) + "\n")
            stream.write(json.dumps({"type": "summary", "output": actual}) + "\n")
        print(json.dumps({"input": args.input, "output": actual,
                          "prefix_steps": len(rows), "breakpoint_attempts": attempt + 1}))
    finally:
        try:
            os.kill(child, signal.SIGKILL)
        except ProcessLookupError:
            pass


if __name__ == "__main__":
    main()
