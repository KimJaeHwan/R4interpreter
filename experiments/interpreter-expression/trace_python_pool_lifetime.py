"""Trace every controlled allocator state transition used by real PyLongs."""
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
BINARY = ROOT / "python_pool_lifetime_fixture"
LIBRARY = Path("/usr/lib/x86_64-linux-gnu/libpython3.13.so.1.0")


def loaded_python_library(pid):
    expected = LIBRARY.resolve()
    metadata = expected.stat()
    matches = []
    for line in Path(f"/proc/{pid}/maps").read_text().splitlines():
        fields = line.split(maxsplit=5)
        if len(fields) != 6 or "libpython3.13.so.1.0" not in fields[5]:
            continue
        path = Path(fields[5]).resolve()
        major, minor = (int(part, 16) for part in fields[3].split(":"))
        if (path != expected or int(fields[4]) != metadata.st_ino or
                major != os.major(metadata.st_dev) or
                minor != os.minor(metadata.st_dev)):
            raise RuntimeError("mapped libpython differs from the pinned library")
        matches.append(fields)
    if not matches:
        raise RuntimeError("pinned libpython is absent from child mappings")
    return {"path": str(expected), "device": matches[0][3],
            "inode": int(matches[0][4]),
            "sha256": sha256(expected.read_bytes()).hexdigest(),
            "mapping_count": len(matches)}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("value", type=int)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    symbols = subprocess.check_output(["nm", "-n", str(BINARY)], text=True)
    entry = next(int(line.split()[0], 16) for line in symbols.splitlines()
                 if line.split()[-1] == "r4_pool_transition")
    stdout = args.output.with_suffix(".stdout.jsonl")
    child = os.fork()
    if child == 0:
        ptrace(TRACEME, 0)
        with stdout.open("w") as stream:
            os.dup2(stream.fileno(), 1)
            env = {key: value for key, value in os.environ.items()
                   if not key.startswith("LD_")}
            env["R4_TRACE_STOP"] = "1"
            os.execve(str(BINARY), [str(BINARY), str(args.value)], env)
    try:
        wait_stopped(child, signal.SIGTRAP)
        ptrace(CONT, child)
        wait_stopped(child, signal.SIGSTOP)
        loaded_library = loaded_python_library(child)
        original = ptrace(PEEKTEXT, child, entry)
        decoder = Cs(CS_ARCH_X86, CS_MODE_64)
        decoder.detail = True
        calls = []
        while True:
            ptrace(POKETEXT, child, entry, (original & ~255) | 0xCC)
            ptrace(CONT, child)
            _, status = os.waitpid(child, 0)
            if os.WIFEXITED(status):
                if os.WEXITSTATUS(status):
                    raise RuntimeError(f"fixture exit {os.WEXITSTATUS(status)}")
                break
            if not os.WIFSTOPPED(status) or os.WSTOPSIG(status) != signal.SIGTRAP:
                raise RuntimeError(f"unexpected fixture wait {status}")
            before = getregs(child)
            if before.rip != entry + 1:
                raise RuntimeError("unexpected pool breakpoint")
            ptrace(POKETEXT, child, entry, original)
            before.rip = entry
            ptrace(SETREGS, child, 0, ctypes.addressof(before))
            state_address, slot, operation = before.rdi, before.rsi, before.rdx
            initial = read_bytes(child, state_address, 40).hex()
            return_pc = peek(child, before.rsp, 8)
            rows = []
            for index in range(100):
                before = getregs(child)
                if index and before.rip == return_pc:
                    break
                raw = read_bytes(child, before.rip, 16)
                insn = next(decoder.disasm(raw, before.rip, count=1))
                accesses = observed_memory_operands(insn, before)
                old = [peek(child, address, size) for address, size, _ in accesses]
                ptrace(SINGLESTEP, child)
                wait_stopped(child, signal.SIGTRAP)
                after = getregs(child)
                new = [peek(child, address, size) for address, size, _ in accesses]
                rows.append({"step": index, "pc": before.rip,
                    "next_pc": after.rip, "bytes": raw[:insn.size].hex(),
                    "instruction": f"{insn.mnemonic} {insn.op_str}".strip(),
                    "registers": registers(before), "registers_after": registers(after),
                    "memory": [{"address": address, "size": size, "access": mode,
                                "before": was, "after": now}
                        for (address, size, mode), was, now in zip(accesses, old, new)]})
            else:
                raise RuntimeError("pool helper did not return")
            calls.append({"slot": slot, "operation": operation,
                "state_address": state_address, "state_before": initial,
                "state_after": read_bytes(child, state_address, 40).hex(),
                "return_value": getregs(child).rax, "rows": rows})
        records = [json.loads(line) for line in stdout.read_text().splitlines()]
        if len(calls) != 10 or records[-1].get("errors") != 0:
            raise RuntimeError("incomplete controlled allocator history")
        report = {"schema_version": 1, "input": args.value,
            "binary_sha256": sha256(BINARY.read_bytes()).hexdigest(),
            "fixture_source_sha256": sha256(BINARY.with_suffix(".c").read_bytes()).hexdigest(),
            "python_library_sha256": loaded_library["sha256"],
            "loaded_python_library": loaded_library,
            "helper_entry": entry, "calls": calls, "fixture_records": records}
        with gzip.open(args.output, "wt") as stream:
            json.dump(report, stream)
        stdout.unlink()
        print(json.dumps({"input": args.value, "helper_calls": len(calls),
                          "native_steps": sum(len(c["rows"]) for c in calls)}))
    finally:
        try:
            os.kill(child, signal.SIGKILL)
        except ProcessLookupError:
            pass


if __name__ == "__main__":
    main()
