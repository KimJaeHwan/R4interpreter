"""Observe the CPython allocation failure and exception check cutpoints.

This deliberately leaves the libpython interval between cutpoints opaque.
"""
import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import signal

from trace_input_provenance import (CONT, PEEKTEXT, POKETEXT, SETREGS,
    SINGLESTEP, TRACEME, getregs, ptrace)
from trace_js_summary_reuse import wait_stopped
from trace_python_pool_lifetime import BINARY, ROOT, loaded_python_library


CUTPOINTS = (("allocator_failure_branch", 0x4015ee),
             ("allocator_null_return", 0x401609),
             ("pylong_return", 0x40134f),
             ("exception_check_call", 0x4013bb),
             ("exception_check_return", 0x4013c0))
OUT = ROOT / "python_exception_boundary_result.json"
PINNED_BINARY_SHA256 = "525077da1068f5087ceea522ab11fb37f5086df5" \
                       "4d160d4e3abeb8721290a8b7"
PINNED_LIBPYTHON_SHA256 = "362412239e5c87cbcd67c720f368ebf414632bf" \
                          "ad3e0f30d1e3e95db9cc60b55"


def digest(path):
    return sha256(path.read_bytes()).hexdigest()


def read_word(pid, address):
    return ptrace(PEEKTEXT, pid, address)


def breakpoint(pid, address):
    original = read_word(pid, address)
    ptrace(POKETEXT, pid, address, (original & ~255) | 0xcc)
    ptrace(CONT, pid)
    wait_stopped(pid, signal.SIGTRAP)
    regs = getregs(pid)
    if regs.rip != address + 1:
        raise ValueError(f"unexpected exception cutpoint at {regs.rip:#x}")
    ptrace(POKETEXT, pid, address, original)
    regs.rip = address
    ptrace(SETREGS, pid, 0, ctypes.addressof(regs))
    return regs


def run(value, output):
    if digest(BINARY) != PINNED_BINARY_SHA256:
        raise ValueError("pinned Python fixture binary changed")
    stdout = output.with_suffix(".stdout.jsonl")
    child = os.fork()
    if child == 0:
        ptrace(TRACEME, 0)
        with stdout.open("w") as stream:
            os.dup2(stream.fileno(), 1)
            env = {key: item for key, item in os.environ.items()
                   if not key.startswith("LD_")}
            env["R4_TRACE_STOP"] = "1"
            os.execve(str(BINARY), [str(BINARY), str(value)], env)
    try:
        wait_stopped(child, signal.SIGTRAP)
        ptrace(CONT, child)
        wait_stopped(child, signal.SIGSTOP)
        library = loaded_python_library(child)
        if library["sha256"] != PINNED_LIBPYTHON_SHA256:
            raise ValueError("pinned libpython changed")
        points = []
        for label, address in CUTPOINTS:
            regs = breakpoint(child, address)
            points.append({"label": label, "pc": address,
                           "rax": regs.rax, "rsp": regs.rsp,
                           "pool_live_mask": read_word(child, 0x4050e0),
                           "target_calls": read_word(child, 0x4040cc) & 0xffffffff})
            ptrace(SINGLESTEP, child)
            wait_stopped(child, signal.SIGTRAP)
        ptrace(CONT, child)
        _, status = os.waitpid(child, 0)
        if not os.WIFEXITED(status) or os.WEXITSTATUS(status):
            raise ValueError(f"Python exception fixture exit {status:#x}")
        records = [json.loads(line) for line in stdout.read_text().splitlines()]
        failure = [row for row in records if row.get("kind") == "AllocationFailed"]
        if (len(failure) != 1 or failure[0]["live_after"] != 15 or
                records[-1]["errors"] != 0 or
                [row["pool_live_mask"] for row in points] != [15] * 5 or
                [row["target_calls"] for row in points] != [1] * 5 or
                points[1]["rax"] != 0 or points[2]["rax"] != 0 or
                points[3]["rax"] != 0 or points[4]["rax"] == 0):
            raise ValueError("CPython failure-to-exception observation changed")
        stdout.unlink()
        return {"input": value, "binary_sha256": digest(BINARY),
                "source_sha256": digest(BINARY.with_suffix(".c")),
                "libpython_sha256": library["sha256"],
                "cutpoints": points,
                "failure_event": failure[0],
                "status": "observed_cutpoints_only"}
    finally:
        try:
            os.kill(child, signal.SIGKILL)
        except ProcessLookupError:
            pass


def main():
    cases = [run(value, ROOT / "artifacts" /
                 f"next_python_exception_{value}.json")
             for value in (1073741824, 1073743000)]
    OUT.write_text(json.dumps({"schema_version": 1, "cases": cases,
        "boundary": "allocator failure, PyLong NULL, and PyErr_Occurred non-NULL are observed; intervening libpython instructions and exception identity are not summarized or proved"},
        indent=2) + "\n")
    print(json.dumps({"cases": len(cases),
                      "cutpoints": sum(len(case["cutpoints"]) for case in cases)}))


if __name__ == "__main__":
    main()
