"""Prove local Lua VM branch and callee input from one pre-branch source read.

X_local is the 8-byte value first read at native PC 0x416ea1. All other
entry registers, flags, and first-read memory are fixed to the path witness.
This is a conditional VM boundary theorem, not a CLI-to-script theorem.
"""
from __future__ import annotations

from hashlib import sha256
import json

import z3
from z3.z3util import get_vars

from pcode_transition_summary import FLAG_OFFSETS, REGISTER_OFFSETS, PathReplay
from project_lua_call_bridge import BINARY, BUNDLE, BYTECODE, END, MASK, ROOT, load_instructions, output_word

SOURCE_PC = 0x416EA1
BRANCH_PC = 0x417E50
BRANCH_LOAD_PC = 0x417E54


def selected_path(trace):
    records = [json.loads(line) for line in trace.read_text().splitlines()]
    cut = next(i for i, row in enumerate(records) if row.get("pc") == BRANCH_PC)
    start = max(i for i, row in enumerate(records[:cut]) if row.get("pc") == SOURCE_PC)
    end = next(i for i in range(cut, len(records)) if records[i].get("pc") == END)
    rows = records[start:end]
    if any(row["type"] != "step" for row in rows):
        raise ValueError("local input path contains non-step records")
    if any(left["next_pc"] != right["pc"] or left["step"] + 1 != right["step"]
           for left, right in zip(rows, rows[1:] + [records[end]])):
        raise ValueError("local input path is not contiguous")
    return rows, records[end]


def initial_memory(rows, x):
    sources = [access for access in rows[0]["memory"] if access["access"] & 1]
    if len(sources) != 1 or sources[0]["size"] != 8 or sources[0]["before"] is None:
        raise ValueError("expected one 8-byte source read at local entry")
    source = sources[0]["address"]
    written = set()
    initial = {}
    for row in rows:
        for access in row["memory"]:
            address, size, mode = access["address"], access["size"], access["access"]
            if mode & 1:
                if access["before"] is None:
                    raise ValueError("unreadable first-read memory")
                for i in range(size):
                    byte = (address + i) & MASK
                    if byte not in written:
                        value = (access["before"] >> (8 * i)) & 255
                        if byte in initial and initial[byte] != value:
                            raise ValueError("first-read memory changed without modeled write")
                        initial[byte] = value
            if mode & 2:
                written.update((address + i) & MASK for i in range(size))
    memory = z3.K(z3.BitVecSort(64), z3.BitVecVal(0, 8))
    for address, value in initial.items():
        if not source <= address < source + 8:
            memory = z3.Store(memory, z3.BitVecVal(address, 64), z3.BitVecVal(value, 8))
    for i in range(8):
        address = (source + i) & MASK
        if initial.get(address) != (sources[0]["before"] >> (8 * i)) & 255:
            raise ValueError("source byte lacks its first-read witness")
        memory = z3.Store(memory, z3.BitVecVal(address, 64),
                          z3.Extract(8 * i + 7, 8 * i, x))
    return memory, source, sources[0]["before"], len(initial)


def prove_unsat(*conditions):
    solver = z3.Solver()
    solver.set(timeout=30000)
    solver.add(*conditions)
    verdict = solver.check()
    if verdict != z3.unsat:
        raise ValueError(f"proof failed: expected UNSAT, got {verdict}")


def prove_path(label, expected, x):
    trace = ROOT / f"artifacts/lua_branch_bridge_{label}.jsonl"
    rows, callee = selected_path(trace)
    memory, source, witness, initial_bytes = initial_memory(rows, x)
    entry = rows[0]["registers"]
    replay = PathReplay(
        rows[0], rows, load_instructions(row["pc"] for row in rows),
        register_symbols={offset: z3.BitVecVal(entry[name], 64)
                          for offset, name in REGISTER_OFFSETS.items()},
        flag_symbols={offset: z3.BitVecVal((entry["eflags"] >> bit) & 1, 8)
                      for offset, bit in FLAG_OFFSETS.items()},
        memory_symbol=memory)
    replay.run()
    guard = z3.simplify(z3.And(*(item["condition"] for item in replay.guards)))
    candidate_guard = x == 0 if label == "x0" else x != 0
    prove_unsat(z3.Xor(guard, candidate_guard))
    solver = z3.Solver()
    solver.add(guard)
    if solver.check() != z3.sat:
        raise ValueError("local path guard is empty")
    source_reads = [read for read in replay.reads if read["pc"] == hex(SOURCE_PC)]
    if not source_reads or source_reads[0]["observed_address"] != source:
        raise ValueError("source read not modeled at entry")
    branch_reads = [read for read in replay.reads if read["pc"] == hex(BRANCH_LOAD_PC)]
    if len(branch_reads) != 1:
        raise ValueError("expected one branch operand read")
    prove_unsat(guard, branch_reads[0]["value_expression"] != x)
    if label == "x9":
        if len(source_reads) != 2 or source_reads[1]["observed_address"] != source:
            raise ValueError("call argument does not reread the same source address")
        second_source_step = next(row["step"] for row in rows[1:] if row["pc"] == SOURCE_PC)
        for effect, effect_step in zip(replay.effects, replay.effect_steps):
            if effect_step >= second_source_step:
                continue
            overlaps = z3.Or(*(effect["address"] + z3.BitVecVal(i, 64) ==
                               z3.BitVecVal(source + j, 64)
                               for i in range(effect["width"]) for j in range(8)))
            prove_unsat(guard, overlaps)
        prove_unsat(guard, source_reads[1]["value_expression"] != x)
    callee_base = callee["entry_memory"]["base"]
    observed = int.from_bytes(bytes.fromhex(callee["entry_memory"]["bytes_hex"])[:8], "little")
    if observed != expected or replay.regs_concrete[24] != callee_base:
        raise ValueError("callee entry witness changed")
    result = z3.simplify(output_word(replay.memory, callee_base))
    if {str(var) for var in get_vars(guard) + get_vars(result)} - {"X_local"}:
        raise ValueError("unexpected symbolic live-in")
    candidate_result = z3.BitVecVal(5, 64) if label == "x0" else x
    prove_unsat(guard, result != candidate_result)
    if z3.simplify(z3.substitute(result, (x, z3.BitVecVal(witness, 64)))).as_long() != observed:
        raise ValueError("callee entry value disagrees with witness")
    return {"path": label, "source_address_witness": hex(source),
            "source_value_witness": str(witness), "callee_value_witness": str(observed),
            "native_instructions": len(rows), "pcode_operations": replay.operation_count,
            "pcode_reads": len(replay.reads), "pcode_writes": len(replay.effects),
            "initial_memory_bytes": initial_bytes,
            "guard": "X_local == 0" if label == "x0" else "X_local != 0",
            "branch_operand": "X_local", "callee_input": "5" if label == "x0" else "X_local",
            "guard_equivalence": "unsat", "branch_operand_equivalence": "unsat",
            "callee_input_equivalence": "unsat",
            "source_reread_equivalence": "unsat" if label == "x9" else None,
            "source_intervening_write_alias": "unsat" if label == "x9" else None,
            "trace_sha256": sha256(trace.read_bytes()).hexdigest()}


def main():
    x = z3.BitVec("X_local", 64)
    paths = [prove_path("x0", 5, x), prove_path("x9", 9, x)]
    report = {"schema_version": 1, "kind": "conditional_local_source_to_callee_input",
              "entry_native_pc": hex(SOURCE_PC), "callee_native_pc": hex(END),
              "interface": "X_local is the 8-byte value read at entry [R8]; other entry registers, flags and first-read memory bytes are fixed per path witness",
              "binary_sha256": sha256(BINARY.read_bytes()).hexdigest(),
              "bytecode_sha256": sha256(BYTECODE.read_bytes()).hexdigest(),
              "bundle_sha256": sha256(BUNDLE.read_bytes()).hexdigest(),
              "paths": paths, "pathwise_guard_equivalence_proved": True,
              "external_input_binding_proved": False, "full_script_output_proved": False}
    (ROOT / "lua_branch_local_input.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"paths": [(path["guard"], path["callee_input"])
                                  for path in paths], "external_input_binding_proved": False}))


if __name__ == "__main__":
    main()
