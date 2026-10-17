"""Prove the observed Lua VM equality branch from a native cutpoint.

The external CLI input is not bound here. Y denotes the 8 bytes at the
RDX-addressed VM value when native PC 0x417e50 is reached. Every instruction
from that cutpoint through native CBRANCH 0x415f30 is replayed as Ghidra Low
P-code; no Lua opcode/source meaning is consulted.
"""
from __future__ import annotations

import csv
from hashlib import sha256
import json
from pathlib import Path
import tarfile

import z3

from pcode_transition_summary import FLAG_OFFSETS, REGISTER_OFFSETS, PathReplay

ROOT = Path(__file__).resolve().parent
BUNDLE = ROOT / "artifacts/lua_bundle.tar.gz"
BINARY = ROOT / "lua_interpreter_fixture"
BYTECODE = ROOT / "lua_branch_call.luac"
PATH_PCS = (0x417E50, 0x417E52, 0x417E54, 0x417E57, 0x417E5B,
            0x415F25, 0x415F29, 0x415F2D, 0x415F30)
MASK = (1 << 64) - 1


def instructions():
    with tarfile.open(BUNDLE, "r:gz") as archive:
        data = json.load(archive.extractfile(next(
            member for member in archive
            if member.name.endswith("/function-000040.json"))))
    found = {row["address"]["byte_offset"]: row
             for row in data["instructions"] if row["address"]["byte_offset"] in PATH_PCS}
    if set(found) != set(PATH_PCS):
        raise ValueError("Lua Bundle does not cover the selected native cutpoint path")
    if [op["opcode"] for op in found[0x417E54]["operations"]].count("LOAD") != 1:
        raise ValueError("expected exactly one payload load")
    if "CBRANCH" not in [op["opcode"] for op in found[0x415F30]["operations"]]:
        raise ValueError("selected native exit is not a P-code conditional branch")
    return found


def selected_rows(csv_path):
    with csv_path.open(newline="") as stream:
        source = list(csv.DictReader(stream))
    positions = [i for i, row in enumerate(source) if int(row["rip"], 16) in PATH_PCS]
    if len(positions) != len(PATH_PCS):
        raise ValueError("selected cutpoint PCs are absent or repeated")
    if [int(source[i]["rip"], 16) for i in positions] != list(PATH_PCS):
        raise ValueError("selected native path order changed")
    if any(b != a + 1 for a, b in zip(positions, positions[1:])):
        raise ValueError("trace has unmodeled native instructions inside the cutpoint path")
    rows = []
    for index in positions:
        before, after = source[index:index + 2]
        if int(before["next_rip"], 16) != int(after["rip"], 16):
            raise ValueError("native register snapshots are not contiguous")
        pc = int(before["rip"], 16)
        registers = {name: int(before[name], 16)
                     for name in (*REGISTER_OFFSETS.values(), "eflags")}
        registers_after = {name: int(after[name], 16)
                           for name in (*REGISTER_OFFSETS.values(), "eflags")}
        memory = []
        if pc == 0x417E54:
            address = registers["rdx"]
            value = int(before["mem_rdx_before"], 16)
            if value != int(before["mem_rdx_after"], 16):
                raise ValueError("payload compare unexpectedly wrote memory")
            memory.append({"address": address, "size": 8, "access": 1,
                           "before": value, "after": value})
        rows.append({"type": "step", "pc": pc,
                     "next_pc": int(before["next_rip"], 16),
                     "registers": registers,
                     "registers_after": registers_after, "memory": memory})
    if rows[0]["registers"]["r12"] != 0x7F00BD:
        raise ValueError("different fetched word at native cutpoint")
    if rows[0]["registers"]["rax"] != 0:
        raise ValueError("different equality constant at native cutpoint")
    return rows


def prove_one(csv_path, expected_exit, bundle_instructions, y):
    rows = selected_rows(csv_path)
    entry = rows[0]["registers"]
    address = entry["rdx"]
    memory = z3.K(z3.BitVecSort(64), z3.BitVecVal(0, 8))
    for byte in range(8):
        memory = z3.Store(memory, z3.BitVecVal((address + byte) & MASK, 64),
                          z3.Extract(byte * 8 + 7, byte * 8, y))
    replay = PathReplay(
        rows[0], rows, bundle_instructions,
        register_symbols={offset: z3.BitVecVal(entry[name], 64)
                          for offset, name in REGISTER_OFFSETS.items()},
        flag_symbols={offset: z3.BitVecVal((entry["eflags"] >> bit) & 1, 8)
                      for offset, bit in FLAG_OFFSETS.items()},
        memory_symbol=memory)
    replay.run()
    if rows[-1]["next_pc"] != expected_exit:
        raise ValueError("native branch exit changed")
    if not replay.reads or len(replay.reads) != 1 or replay.reads[0]["observed_address"] != address:
        raise ValueError("unexpected P-code memory footprint")
    if replay.effects:
        raise ValueError("cutpoint branch unexpectedly writes memory")
    guard = z3.simplify(z3.And(*(item["condition"] for item in replay.guards)))
    solver = z3.Solver()
    solver.add(guard)
    if solver.check() != z3.sat:
        raise ValueError("selected branch has no symbolic input witness")
    candidate = y == 0 if expected_exit == 0x415D51 else y != 0
    solver = z3.Solver()
    solver.add(z3.Xor(guard, candidate))
    if solver.check() != z3.unsat:
        raise ValueError("P-code path condition differs from equality guard")
    return guard, {"witness_input": str(replay.reads[0]["observed"]),
                   "native_exit": hex(expected_exit),
                   "selected_native_instructions": len(rows),
                   "pcode_operations_replayed": replay.operation_count,
                   "pcode_payload_reads": len(replay.reads),
                   "pcode_writes": len(replay.effects),
                   "branch_evidence": [{"pc": item["pc"], "kind": item["kind"],
                                        "target": item["target"]} for item in replay.guards],
                   "guard_smt": guard.sexpr(),
                   "candidate_smt_inequivalence": "unsat",
                   "trace_sha256": sha256(csv_path.read_bytes()).hexdigest()}


def main():
    bundle_instructions = instructions()
    y = z3.BitVec("Y", 64)
    zero, zero_report = prove_one(ROOT / "artifacts/lua_branch_call_0.csv",
                                  0x415D51, bundle_instructions, y)
    nonzero, nonzero_report = prove_one(ROOT / "artifacts/lua_branch_call_9.csv",
                                        0x415F36, bundle_instructions, y)
    solver = z3.Solver()
    solver.add(z3.Not(z3.Or(zero, nonzero)))
    if solver.check() != z3.unsat:
        raise ValueError("the two local branch guards do not cover all Y")
    solver = z3.Solver()
    solver.add(zero, nonzero)
    if solver.check() != z3.unsat:
        raise ValueError("the two local branch guards overlap")
    report = {"schema_version": 1, "kind": "conditional_native_cutpoint_guard_proof",
              "binary_sha256": sha256(BINARY.read_bytes()).hexdigest(),
              "bytecode_sha256": sha256(BYTECODE.read_bytes()).hexdigest(),
              "bundle_sha256": sha256(BUNDLE.read_bytes()).hexdigest(),
              "entry_native_pc": hex(PATH_PCS[0]),
              "interface": "Y:BV64 is the 8-byte value at entry RDX; entry registers, flags and the fetched word are fixed to each captured path's state",
              "paths": [{"guard": "Y == 0", "guard_proven": True, **zero_report},
                        {"guard": "Y != 0", "guard_proven": True, **nonzero_report}],
              "local_coverage_proved": True, "local_disjointness_proved": True,
              "external_input_binding_proved": False,
              "full_script_output_proved": False,
              "limits": "Conditional on reaching native PC 0x417e50 with the recorded non-input state and [RDX]=Y. Earlier path admission, CLI X to Y, VM call argument and return are outside this proof."}
    (ROOT / "lua_branch_cutpoint_guard.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"local_guards": [path["guard"] for path in report["paths"]],
                      "local_coverage_proved": True, "external_input_binding_proved": False,
                      "pcode_operations": [path["pcode_operations_replayed"] for path in report["paths"]]}))


if __name__ == "__main__":
    main()
