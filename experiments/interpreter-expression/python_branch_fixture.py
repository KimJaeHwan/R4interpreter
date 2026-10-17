"""Evaluation fixture for the cross-interpreter branch/call experiment.

The analyzer consumes the collected bytecode/native observations, not this
source as an opcode semantics table. Run with CPython 3.13, -I -S.
"""
from __future__ import annotations

import argparse
import dis
from hashlib import sha256
import json
import os
from pathlib import Path
import sys


def addFive(value):
    return value + 5


def branchCall(value):
    if value == 0:
        return addFive(5)
    return addFive(value)


class Effectful:
    def __init__(self):
        self.calls = 0

    def __eq__(self, other):
        self.calls += 1
        return False

    def __add__(self, other):
        self.calls += 1
        return 6


def opcode_trace(path):
    names = {"branchCall", "addFive"}
    rows = []

    def record(frame, event, arg):
        if frame.f_code.co_name not in names:
            return None
        if event == "call":
            frame.f_trace_opcodes = True
            rows.append({"function": frame.f_code.co_name, "event": "call"})
            return record
        if event == "line":
            # CPython 3.13 requires this reset before delivering opcode events.
            frame.f_trace_opcodes = True
        if event == "opcode":
            rows.append({"function": frame.f_code.co_name, "event": "opcode",
                         "offset": frame.f_lasti})
        elif event == "return":
            rows.append({"function": frame.f_code.co_name, "event": "return",
                         "offset": frame.f_lasti})
        elif event == "exception":
            rows.append({"function": frame.f_code.co_name, "event": "exception",
                         "offset": frame.f_lasti})
        return record

    return record, rows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("input")
    parser.add_argument("--mode", choices=("integer", "object"), default="integer")
    parser.add_argument("--trace", type=Path)
    parser.add_argument("--mark", type=Path)
    parser.add_argument("--native-sync", action="store_true")
    args = parser.parse_args()
    value = int(args.input, 10) if args.mode == "integer" else Effectful()
    if args.mark:
        args.mark.write_text(json.dumps({
            "code_pointers": {name: id(fn.__code__) for name, fn in
                              (("branchCall", branchCall), ("addFive", addFive))},
            "bytecode_sha256": {name: sha256(fn.__code__.co_code).hexdigest() for name, fn in
                                (("branchCall", branchCall), ("addFive", addFive))},
        }))
    if args.native_sync:
        os.kill(os.getpid(), 19)  # SIGSTOP: parent installs a native breakpoint.
    rows = []
    if args.trace:
        hook, rows = opcode_trace(args.trace)
        sys.settrace(hook)
    try:
        result = branchCall(value)
    finally:
        sys.settrace(None)
    if args.trace:
        instructions = {
            name: [{"offset": row.offset, "opname": row.opname,
                    "opcode_byte": fn.__code__.co_code[row.offset],
                    "argrepr": row.argrepr} for row in dis.get_instructions(fn)]
            for name, fn in (("branchCall", branchCall), ("addFive", addFive))}
        args.trace.write_text(json.dumps({"instructions": instructions,
                                           "events": rows}, indent=2) + "\n")
    print(json.dumps({"result": result,
                      "effects": value.calls if args.mode == "object" else 0}))


if __name__ == "__main__":
    main()
