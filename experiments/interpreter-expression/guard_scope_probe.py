"""Measure the observed VM path guard and held-out formula agreement."""
from __future__ import annotations

import csv
from hashlib import sha256
import json
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parent
CASES = [
    (0, "x0", False), (9, "x9", False),
    (1, "one", True), (-1, "minus_one", True),
    (9223372036854775800, "max_minus_7", True),
    (9223372036854775801, "max_minus_6", True),
    (9223372036854775807, "max", True),
    (-9223372036854775808, "min", True),
]


def signed(value):
    value &= (1 << 64) - 1
    return value - (1 << 64) if value & (1 << 63) else value


def main():
    baseline = None
    results = []
    for x, name, held_out in CASES:
        trace = ROOT / "artifacts" / f"lua_trace_{name}.csv"
        rows = list(csv.DictReader(trace.open(newline="")))
        path = [(row["rip"], row["next_rip"]) for row in rows]
        if baseline is None:
            baseline = path
        path_equal = path == baseline
        addition = [row for row in rows if int(row["rip"], 16) == 0x417CE7]
        store = [row for row in rows if int(row["rip"], 16) == 0x417CEA]
        assert len(addition) == len(store) == 1
        operand = int(addition[0]["mem_rax_before"], 16)
        constant = int(addition[0]["r12"], 16)
        observed_word = int(store[0]["mem_rdx_after"], 16)
        output = subprocess.run([str(ROOT / "lua_interpreter_fixture"),
                                 str(ROOT / "lua_chunk.luac"), str(x)],
                                check=True, capture_output=True, text=True).stdout.strip()
        expected = signed(x + 7)
        assert operand == (x & ((1 << 64) - 1))
        assert constant == 7
        assert observed_word == ((x + 7) & ((1 << 64) - 1))
        assert int(output) == expected
        assert path_equal
        results.append({"input": x, "held_out": held_out,
                        "trace_sha256": sha256(trace.read_bytes()).hexdigest(),
                        "vm_steps": len(rows), "same_pc_and_successor_sequence_as_x0": path_equal,
                        "vm_operand_signed": signed(operand), "vm_immediate": constant,
                        "vm_stored_result_signed": signed(observed_word),
                        "program_output": int(output), "expression_expected": expected})
    report = {
        "binary_sha256": sha256((ROOT / "lua_interpreter_fixture").read_bytes()).hexdigest(),
        "bytecode_sha256": sha256((ROOT / "lua_chunk.luac").read_bytes()).hexdigest(),
        "candidate_formula": "signed64((X + 7) mod 2^64)",
        "observed_guard": "this ELF and bytecode, integer input accepted by strtoll, same first VM PC/successor sequence",
        "cases": results,
        "scope": "finite validation only; unobserved inputs and paths are unknown",
    }
    target = ROOT / "guard_scope_result.json"
    target.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({"cases": len(results), "held_out": sum(r["held_out"] for r in results),
                      "same_path": all(r["same_pc_and_successor_sequence_as_x0"] for r in results)}, indent=2))


if __name__ == "__main__":
    main()
