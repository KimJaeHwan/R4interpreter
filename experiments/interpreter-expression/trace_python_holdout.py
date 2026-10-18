"""Capture cached-input CPython BINARY_OP, including an uncached-result path."""
from __future__ import annotations

import argparse
import ctypes
import gzip
from hashlib import sha256
import json
import os
from pathlib import Path
import signal

from capstone import Cs, CS_ARCH_X86, CS_MODE_64

from prove_cross_full_flow import CACHE_BASE, PYTHON
from trace_cross_full_flow import observed_memory_operands, read_bytes, registers
from trace_input_provenance import (CONT, PEEKTEXT, POKETEXT, SETREGS,
                                    SINGLESTEP, TRACEME, getregs, peek, ptrace)
from trace_js_summary_reuse import wait_stopped


ROOT = Path(__file__).resolve().parent
FIXTURE = ROOT / "python_holdout_fixture.py"
HANDLER = 0x56227C
NEXT_HANDLER = 0x56173B


def step(child):
    ptrace(SINGLESTEP, child)
    wait_stopped(child, signal.SIGTRAP)
    return getregs(child)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=int)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    if not 5 <= args.input <= 252:
        raise ValueError("native holdout tracer covers cached inputs and one allocation boundary")
    marker = args.output.with_suffix(".marker.json")
    stdout = args.output.with_suffix(".stdout.txt")
    marker.unlink(missing_ok=True)
    child = os.fork()
    if child == 0:
        ptrace(TRACEME, 0)
        with stdout.open("w") as stream:
            os.dup2(stream.fileno(), 1)
            os.execv(str(PYTHON), [str(PYTHON), "-I", "-S", str(FIXTURE),
                                    str(args.input), str(marker)])
    try:
        wait_stopped(child, signal.SIGTRAP)
        ptrace(CONT, child)
        wait_stopped(child, signal.SIGSTOP)
        if json.loads(marker.read_text())["phase"] != "ready":
            raise RuntimeError("Python holdout fixture did not synchronize")
        original = ptrace(PEEKTEXT, child, HANDLER)
        ptrace(POKETEXT, child, HANDLER, (original & ~255) | 0xCC)
        decoder = Cs(CS_ARCH_X86, CS_MODE_64)
        decoder.detail = True
        wanted_left = CACHE_BASE + (args.input + 5) * 32
        wanted_right = CACHE_BASE + (5 + 5) * 32
        for attempt in range(100):
            ptrace(CONT, child)
            wait_stopped(child, signal.SIGTRAP)
            before = getregs(child)
            if before.rip != HANDLER + 1:
                raise RuntimeError("unexpected breakpoint before Python BINARY_OP")
            ptrace(POKETEXT, child, HANDLER, original)
            before.rip = HANDLER
            ptrace(SETREGS, child, 0, ctypes.addressof(before))
            observed_left = peek(child, before.r15 - 16, 8)
            if (peek(child, before.r15 - 8, 8) == wanted_right and
                    observed_left == wanted_left):
                wanted_left = observed_left
                break
            step(child)
            ptrace(POKETEXT, child, HANDLER, (original & ~255) | 0xCC)
        else:
            raise RuntimeError("holdout integer BINARY_OP was not found")
        cache_size = 262 * 32
        cache_hash_at_entry = sha256(read_bytes(child, CACHE_BASE, cache_size)).hexdigest()
        rows = []
        for index in range(500):
            before = getregs(child)
            if index and before.rip == NEXT_HANDLER:
                break
            pc = before.rip
            raw = read_bytes(child, pc, 16)
            decoded = list(decoder.disasm(raw, pc, count=1))
            if not decoded:
                raise RuntimeError("cannot disassemble Python holdout step")
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
        else:
            raise RuntimeError("Python holdout did not reach next handler")
        output_slot = getregs(child).r15 - 8
        cache_hash_at_exit = sha256(read_bytes(child, CACHE_BASE, cache_size)).hexdigest()
        if cache_hash_at_exit != cache_hash_at_entry or any(
                access["access"] & 2 and access["address"] < CACHE_BASE + cache_size and
                access["address"] + access["size"] > CACHE_BASE
                for row in rows for access in row["memory"]):
            raise RuntimeError("holdout native path modified the small-int cache")
        ptrace(CONT, child)
        status = os.waitpid(child, 0)[1]
        if not os.WIFEXITED(status) or os.WEXITSTATUS(status):
            raise RuntimeError("Python holdout fixture did not exit cleanly")
        actual = json.loads(stdout.read_text().splitlines()[-1])["result"]
        if actual != args.input + 5:
            raise RuntimeError("Python holdout program output changed")
        with gzip.open(args.output, "wt") as stream:
            stream.write(json.dumps({"type": "meta", "input": args.input,
                "binary_sha256": sha256(PYTHON.read_bytes()).hexdigest(),
                "fixture_sha256": sha256(FIXTURE.read_bytes()).hexdigest(),
                "runtime_cache_sha256_at_entry": cache_hash_at_entry,
                "runtime_cache_sha256_at_exit": cache_hash_at_exit,
                "left_pointer": wanted_left, "right_pointer": wanted_right,
                "output_slot": output_slot}) + "\n")
            stream.write(json.dumps({"type": "path", "rows": rows}) + "\n")
            stream.write(json.dumps({"type": "summary", "output": actual}) + "\n")
        print(json.dumps({"input": args.input, "output": actual,
                          "handler_steps": len(rows), "breakpoint_attempts": attempt + 1}))
    finally:
        try:
            os.kill(child, signal.SIGKILL)
        except ProcessLookupError:
            pass


if __name__ == "__main__":
    main()
