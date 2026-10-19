"""Single-step the two Lua allocator failure returns and the later success."""
import argparse
import ctypes
import gzip
from hashlib import sha256
import json
import os
from pathlib import Path
import signal
import subprocess

from capstone import Cs, CS_ARCH_X86, CS_MODE_64

from trace_cross_full_flow import observed_memory_operands, read_bytes, registers
from trace_input_provenance import (CONT, PEEKTEXT, POKETEXT, SETREGS,
    SINGLESTEP, TRACEME, getregs, peek, ptrace)
from trace_js_summary_reuse import wait_stopped


ROOT = Path(__file__).resolve().parent
BINARY = ROOT / "lua_pool_failure_retry_fixture"
OUTPUT = ROOT / "artifacts/next_lua_allocator_96.json.gz"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--length", type=int, choices=(94, 95, 96), default=96)
    parser.add_argument("--output", type=Path, default=OUTPUT)
    args = parser.parse_args()
    output = args.output
    request = 24 + args.length + 1
    symbols = subprocess.check_output(["nm", "-n", str(BINARY)], text=True)
    entry = next(int(line.split()[0], 16) for line in symbols.splitlines()
                 if line.split()[-1] == "allocator")
    storage = next(int(line.split()[0], 16) for line in symbols.splitlines()
                   if line.split()[-1] == "storage")
    owned_addresses = {name: next(int(line.split()[0], 16)
                    for line in symbols.splitlines() if line.split()[-1] == name)
                    for name in ("live", "generation", "live_extent")}

    def owned_state(pid):
        return {name: peek(pid, address, 8 if name == "live_extent" else 4)
                for name, address in owned_addresses.items()}
    stdout = output.with_suffix(".stdout.jsonl")
    child = os.fork()
    if child == 0:
        ptrace(TRACEME, 0)
        with stdout.open("w") as stream:
            os.dup2(stream.fileno(), 1)
            env = {key: value for key, value in os.environ.items()
                   if not key.startswith("LD_")}
            env["R4_TRACE_STOP"] = "1"
            os.execve(str(BINARY), [str(BINARY), str(args.length)], env)
    try:
        wait_stopped(child, signal.SIGTRAP)
        ptrace(CONT, child)
        wait_stopped(child, signal.SIGSTOP)
        original = ptrace(PEEKTEXT, child, entry)
        decoder = Cs(CS_ARCH_X86, CS_MODE_64)
        decoder.detail = True
        calls = []
        skipped = 0
        while True:
            ptrace(POKETEXT, child, entry, (original & ~255) | 0xCC)
            ptrace(CONT, child)
            _, status = os.waitpid(child, 0)
            if os.WIFEXITED(status):
                if os.WEXITSTATUS(status):
                    raise RuntimeError("Lua allocator fixture exited with an error")
                break
            if not os.WIFSTOPPED(status) or os.WSTOPSIG(status) != signal.SIGTRAP:
                raise RuntimeError(f"unexpected Lua allocator wait {status:#x}")
            before = getregs(child)
            if before.rip != entry + 1:
                raise RuntimeError("allocator breakpoint missed")
            ptrace(POKETEXT, child, entry, original)
            before.rip = entry
            ptrace(SETREGS, child, 0, ctypes.addressof(before))
            target_allocation = before.rsi == 0 and before.rcx in (105, request)
            target_release = before.rsi == storage and before.rcx == 0
            if not (target_allocation or target_release):
                skipped += 1
                ptrace(SINGLESTEP, child)
                wait_stopped(child, signal.SIGTRAP)
                continue
            owned_before = owned_state(child)
            return_pc = peek(child, before.rsp, 8)
            rows = []
            for index in range(200):
                state = getregs(child)
                if index and state.rip == return_pc:
                    break
                raw = read_bytes(child, state.rip, 16)
                insn = next(decoder.disasm(raw, state.rip, count=1), None)
                if insn is None:
                    raise RuntimeError("cannot disassemble Lua allocator path")
                accesses = observed_memory_operands(insn, state)
                old = [peek(child, address, size)
                       for address, size, _ in accesses]
                ptrace(SINGLESTEP, child)
                wait_stopped(child, signal.SIGTRAP)
                after = getregs(child)
                new = [peek(child, address, size)
                       for address, size, _ in accesses]
                rows.append({"step": index, "pc": state.rip,
                    "next_pc": after.rip, "bytes": raw[:insn.size].hex(),
                    "instruction": f"{insn.mnemonic} {insn.op_str}".strip(),
                    "registers": registers(state), "registers_after": registers(after),
                    "memory": [{"address": address, "size": size, "access": mode,
                                "before": was, "after": now}
                        for (address, size, mode), was, now in zip(accesses, old, new)]})
            else:
                raise RuntimeError("allocator call exceeded 200 native steps")
            calls.append({"request": before.rcx, "old_extent": before.rdx,
                          "pointer": before.rsi, "return_raw": state.rax,
                          "owned_state_before": owned_before,
                          "owned_state_after": owned_state(child),
                          "rows": rows})
        fixture = [json.loads(line) for line in stdout.read_text().splitlines()]
        if (len(calls) != 6 or [call["return_raw"] == 0 for call in calls] !=
                [False, True, True, True, False, True] or
                [call["request"] for call in calls] !=
                [105, request, request, 0, request, 0] or
                [item["kind"] for item in fixture if item["type"] == "event"] !=
                ["Allocate", "AllocationFailed", "AllocationFailed", "Free",
                 "Allocate", "Free"]):
            raise ValueError("allocator failure/success observation changed")
        with gzip.open(output, "wt") as stream:
            json.dump({"schema_version": 1,
                "binary_sha256": sha256(BINARY.read_bytes()).hexdigest(),
                "source_sha256": sha256(BINARY.with_suffix(".c").read_bytes()).hexdigest(),
                "retry_length": args.length,
                "entry_pc": entry, "skipped_other_allocator_calls": skipped,
                "calls": calls, "fixture_records": fixture}, stream)
        stdout.unlink()
        print(json.dumps({"failure_calls": 2, "success_calls": 2,
                          "release_calls": 2,
                          "native_steps": [len(call["rows"]) for call in calls],
                          "skipped_other_allocator_calls": skipped}))
    finally:
        try:
            os.kill(child, signal.SIGKILL)
        except ProcessLookupError:
            pass


if __name__ == "__main__":
    main()
