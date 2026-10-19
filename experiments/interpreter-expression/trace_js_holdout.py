"""Capture AddSmi numeric paths or alternate-type prefixes in separate programs."""
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
import pypcode

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
    parser.add_argument("--full-handler", action="store_true")
    parser.add_argument("--string", action="store_true")
    parser.add_argument("--bigint-error", action="store_true")
    args = parser.parse_args()
    if args.string and args.bigint_error:
        raise ValueError("choose one alternate input type")
    binary = Path(shutil.which("node"))
    fixture = (ROOT / "js_bigint_error_fixture.js" if args.bigint_error else
               ROOT / "js_string_holdout_fixture.js" if args.string else FIXTURE)
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
                                   str(fixture), str(args.input), str(marker)])
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
        pcode = pypcode.Context("x86:LE:64:default") if args.full_handler else None
        for attempt in range(100):
            ptrace(CONT, child)
            wait_stopped(child, signal.SIGTRAP)
            before = getregs(child)
            if before.rip != entry_pc + 1:
                raise RuntimeError("unexpected breakpoint before holdout AddSmi")
            ptrace(POKETEXT, child, entry_pc, original)
            before.rip = entry_pc
            ptrace(SETREGS, child, 0, ctypes.addressof(before))
            valid_type = (bool(before.rax & 1) if args.string or args.bigint_error
                          else before.rax == args.input << 32)
            if (valid_type and
                    read_bytes(child, before.r12 + before.r9, 2) == bytes([0x4B, 5])):
                break
            step(child)
            ptrace(POKETEXT, child, entry_pc, (original & ~255) | 0xCC)
        else:
            raise RuntimeError("holdout AddSmi site was not found")
        string_snapshot = None
        if args.string:
            string_address = before.rax - 1
            input_ascii = str(args.input).encode("ascii")
            observed_length = peek(child, string_address + 12, 4)
            observed_bytes = read_bytes(child, string_address + 16,
                                        len(input_ascii))
            if observed_length != len(input_ascii) or observed_bytes != input_ascii:
                raise RuntimeError("entry string object differs from fixture input")
            string_snapshot = {"object_address": string_address,
                               "length": observed_length,
                               "ascii_hex": observed_bytes.hex(),
                               "cutpoint_pc": entry_pc}
        rows = []
        for index in range(500 if args.full_handler else boundary["native_steps"]):
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
            if args.full_handler and index + 1 >= boundary["native_steps"] and any(
                    op.opcode.name == "BRANCHIND" for op in pcode.translate(
                        raw[:insn.size], base_address=pc,
                        max_instructions=1).ops):
                break
        else:
            if args.full_handler:
                raise RuntimeError("holdout handler did not reach indirect dispatch")
        if (not (args.string or args.bigint_error) and
                (rows[boundary["native_steps"] - 1]["pc"] != end_pc or
                 hex(rows[boundary["native_steps"] - 1]["next_pc"]) != boundary["exit_pc"])):
            raise RuntimeError("holdout prefix reached a different cutpoint")
        ptrace(CONT, child)
        status = os.waitpid(child, 0)[1]
        if not os.WIFEXITED(status) or os.WEXITSTATUS(status):
            raise RuntimeError("holdout fixture did not exit cleanly")
        output = json.loads(stdout.read_text().splitlines()[-1])
        actual = output.get("error") if args.bigint_error else output["result"]
        expected = ("TypeError" if args.bigint_error else
                    str(args.input) + "5" if args.string else args.input + 5)
        if actual != expected:
            raise RuntimeError("holdout JavaScript program output changed")
        with gzip.open(args.output, "wt") as stream:
            stream.write(json.dumps({"type": "meta", "input": args.input,
                "binary_sha256": sha256(binary.read_bytes()).hexdigest(),
                "fixture_sha256": sha256(fixture.read_bytes()).hexdigest(),
                "input_type": ("bigint" if args.bigint_error else
                               "string" if args.string else "number"),
                "full_handler": args.full_handler,
                **({"input_object_snapshot": string_snapshot}
                   if string_snapshot is not None else {})}) + "\n")
            stream.write(json.dumps({"type": "path", "rows": rows}) + "\n")
            stream.write(json.dumps({"type": "summary",
                                     "error" if args.bigint_error else "output": actual}) + "\n")
        print(json.dumps({"input": args.input, "output": actual,
                          "native_steps": len(rows),
                          "next_handler": hex(rows[-1]["next_pc"]),
                          "breakpoint_attempts": attempt + 1}))
    finally:
        try:
            os.kill(child, signal.SIGKILL)
        except ProcessLookupError:
            pass


if __name__ == "__main__":
    main()
