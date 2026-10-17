"""Replay one observed native branch-to-callee path with symbolic VM payload.

This experiment starts at the *native* equality cutpoint. It proves the
callee's entry slot as a function of that cutpoint's payload, conditional on
the recorded non-input machine state and path. The CLI input-to-payload edge
and final return remain separate obligations.
"""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import tarfile

import z3
from z3.z3util import get_vars

from pcode_transition_summary import FLAG_OFFSETS, REGISTER_OFFSETS, PathReplay

ROOT = Path(__file__).resolve().parent
BUNDLE = ROOT / "artifacts/lua_bundle.tar.gz"
BINARY = ROOT / "lua_interpreter_fixture"
BYTECODE = ROOT / "lua_branch_call.luac"
START = 0x417E50
END = 0x4164B8
MASK = (1 << 64) - 1


def load_path(path):
    records = [json.loads(line) for line in path.read_text().splitlines()]
    start = next(i for i, row in enumerate(records) if row.get("pc") == START)
    end = next(i for i in range(start, len(records)) if records[i].get("pc") == END)
    rows = records[start:end]
    if not rows or any(row["type"] != "step" for row in rows):
        raise ValueError("bridge trace has no complete step path")
    if any(a["next_pc"] != b["pc"] for a, b in zip(rows, rows[1:] + [records[end]])):
        raise ValueError("bridge trace is not contiguous")
    if records[end].get("entry_memory") is None:
        raise ValueError("callee entry snapshot was not captured")
    return rows, records[end]


def load_instructions(wanted, bundle=BUNDLE):
    wanted = set(wanted)
    found = {}
    with tarfile.open(bundle, "r:gz") as archive:
        for member in archive:
            if "/function-" not in member.name or not member.name.endswith(".json"):
                continue
            observation = json.load(archive.extractfile(member))
            for ins in observation["instructions"]:
                pc = ins["address"]["byte_offset"]
                if pc in wanted:
                    found[pc] = ins
    if set(found) != set(wanted):
        raise ValueError(f"Bundle misses native instructions: {sorted(set(wanted) - set(found))}")
    return found


def entry_memory(rows, y, argument, label):
    """Seed first reads; preserve the branch and call operands independently."""
    value_address = rows[0]["registers"]["rdx"]
    argument_reads = [access for row in rows for access in row["memory"]
                      if row["pc"] == 0x416EA1 and access["access"] & 1]
    if label == "x9" and (len(argument_reads) != 1 or argument_reads[0]["size"] != 8):
        raise ValueError("expected one 8-byte call argument source read")
    argument_address = argument_reads[0]["address"] if argument_reads else None
    if argument_address is not None:
        argument_step = next(i for i, row in enumerate(rows) if row["pc"] == 0x416EA1)
        if any(access["access"] & 2 and
               access["address"] < argument_address + 8 and
               argument_address < access["address"] + access["size"]
               for row in rows[:argument_step] for access in row["memory"]):
            raise ValueError("call argument source was written before its first read")
    written = set()
    initial = {}
    for row in rows:
        for access in row["memory"]:
            address, size, mode = access["address"], access["size"], access["access"]
            if mode & 1:
                if access["before"] is None:
                    raise ValueError(f"unreadable entry memory at {address:#x}")
                for index in range(size):
                    byte_address = (address + index) & MASK
                    if byte_address not in written:
                        value = (access["before"] >> (8 * index)) & 255
                        if byte_address in initial and initial[byte_address] != value:
                            raise ValueError("first-read memory value changed without a write")
                        initial[byte_address] = value
            if mode & 2:
                written.update((address + index) & MASK for index in range(size))
    payload_reads = [access for row in rows for access in row["memory"]
                     if row["pc"] == 0x417E54 and access["address"] == value_address]
    if len(payload_reads) != 1 or payload_reads[0]["size"] != 8:
        raise ValueError("expected one initial 8-byte payload read")
    witness = payload_reads[0]["before"]
    for index in range(8):
        address = (value_address + index) & MASK
        if initial.get(address) != (witness >> (8 * index)) & 255:
            raise ValueError("symbolic payload is not backed by the first-read snapshot")
    memory = z3.K(z3.BitVecSort(64), z3.BitVecVal(0, 8))
    for address, value in initial.items():
        if (not value_address <= address < value_address + 8 and
                not (argument_address is not None and argument_address <= address < argument_address + 8)):
            memory = z3.Store(memory, z3.BitVecVal(address, 64), z3.BitVecVal(value, 8))
    for index in range(8):
        memory = z3.Store(memory, z3.BitVecVal((value_address + index) & MASK, 64),
                          z3.Extract(index * 8 + 7, index * 8, y))
    if argument_address is not None:
        for index in range(8):
            address = (argument_address + index) & MASK
            if initial.get(address) != (argument_reads[0]["before"] >> (8 * index)) & 255:
                raise ValueError("call argument is not backed by first-read memory")
            memory = z3.Store(memory, z3.BitVecVal(address, 64),
                              z3.Extract(index * 8 + 7, index * 8, argument))
    return memory, witness, len(initial), argument_reads[0]["before"] if argument_reads else None


def output_word(memory, address):
    return z3.Concat(*(z3.Select(memory, z3.BitVecVal(address + index, 64))
                       for index in reversed(range(8))))


def prove_one(label, expected, y, argument):
    trace = ROOT / f"artifacts/lua_branch_bridge_{label}.jsonl"
    rows, callee = load_path(trace)
    instructions = load_instructions(row["pc"] for row in rows)
    memory, witness, initial_bytes, argument_witness = entry_memory(rows, y, argument, label)
    if rows[0]["registers"]["r12"] != 0x7F00BD:
        raise ValueError("caller cutpoint bytecode word changed")
    registers = rows[0]["registers"]
    replay = PathReplay(
        rows[0], rows, instructions,
        register_symbols={offset: z3.BitVecVal(registers[name], 64)
                          for offset, name in REGISTER_OFFSETS.items()},
        flag_symbols={offset: z3.BitVecVal((registers["eflags"] >> bit) & 1, 8)
                      for offset, bit in FLAG_OFFSETS.items()},
        memory_symbol=memory, address_guards=True)
    replay.run()
    callee_base = callee["entry_memory"]["base"]
    callee_observed = int.from_bytes(bytes.fromhex(callee["entry_memory"]["bytes_hex"])[:8], "little")
    if callee_observed != expected:
        raise ValueError("callee input witness changed")
    if replay.regs_concrete[next(offset for offset, name in REGISTER_OFFSETS.items()
                                 if name == "rbx")] != callee_base:
        raise ValueError("projected callee VM slot address differs from trace")
    result = z3.simplify(output_word(replay.memory, callee_base))
    if {str(variable) for variable in get_vars(result)} - {"Y", "A"}:
        raise ValueError("callee input depends on uncaptured symbolic state")
    guard = z3.simplify(z3.And(*(item["condition"] for item in replay.guards)))
    if {str(variable) for variable in get_vars(guard)} - {"Y", "A"}:
        raise ValueError("bridge guard depends on uncaptured symbolic state")
    solver = z3.Solver()
    solver.set(timeout=30000)
    solver.add(guard, y == z3.BitVecVal(witness, 64))
    if argument_witness is not None:
        solver.add(argument == z3.BitVecVal(argument_witness, 64))
    if solver.check() != z3.sat:
        raise ValueError("bridge guard rejects its concrete witness")
    substitutions = [(y, z3.BitVecVal(witness, 64))]
    if argument_witness is not None:
        substitutions.append((argument, z3.BitVecVal(argument_witness, 64)))
    if z3.simplify(z3.substitute(result, *substitutions)).as_long() != callee_observed:
        raise ValueError("projected callee input differs from observed snapshot")
    candidate_guard = y == 0 if label == "x0" else y != 0
    solver = z3.Solver()
    solver.set(timeout=30000)
    solver.add(z3.Xor(guard, candidate_guard))
    guard_verdict = str(solver.check())
    if guard_verdict != "unsat":
        raise ValueError(f"bridge guard equality unproved: {guard_verdict}")
    candidate_value = z3.BitVecVal(5, 64) if label == "x0" else argument
    solver = z3.Solver()
    solver.set(timeout=30000)
    solver.add(guard, result != candidate_value)
    value_verdict = str(solver.check())
    if value_verdict != "unsat":
        raise ValueError(f"callee input equality unproved: {value_verdict}")
    return {"label": label, "witness_cutpoint_payload": str(witness),
            "witness_argument_source": None if argument_witness is None else str(argument_witness),
            "witness_callee_input": str(callee_observed),
            "native_instructions": len(rows),
            "pcode_operations": replay.operation_count,
            "pcode_reads": len(replay.reads), "pcode_writes": len(replay.effects),
            "initial_memory_bytes": initial_bytes,
            "guard": "Y == 0" if label == "x0" else "Y != 0",
            "guard_equivalence_solver_result": guard_verdict,
            "callee_input": "5" if label == "x0" else "A",
            "callee_input_equivalence_solver_result": value_verdict,
            "guard_smt": guard.sexpr(), "callee_input_smt": result.sexpr(),
            "trace_sha256": sha256(trace.read_bytes()).hexdigest()}


def main():
    y = z3.BitVec("Y", 64)
    argument = z3.BitVec("A", 64)
    paths = [prove_one("x0", 5, y, argument), prove_one("x9", 9, y, argument)]
    report = {"schema_version": 1, "kind": "conditional_native_cutpoint_to_callee_input",
              "entry_native_pc": hex(START), "callee_native_pc": hex(END),
              "interface": "Y is the 8-byte value at entry RDX; A is the separate 8-byte call argument read at 0x416ea1 on x9. Other entry registers, flags, and first-read memory bytes are fixed per concrete path",
              "binary_sha256": sha256(BINARY.read_bytes()).hexdigest(),
              "bytecode_sha256": sha256(BYTECODE.read_bytes()).hexdigest(),
              "bundle_sha256": sha256(BUNDLE.read_bytes()).hexdigest(),
              "paths": paths,
              "external_input_binding_proved": False,
              "full_script_output_proved": False}
    (ROOT / "lua_branch_call_bridge.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"paths": [(row["label"], row["guard_equivalence_solver_result"],
                                  row["callee_input_equivalence_solver_result"])
                                 for row in paths]}))


if __name__ == "__main__":
    main()
