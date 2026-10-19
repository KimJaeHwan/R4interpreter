"""Replay CPython caller prefix around one explicitly opaque libc vector call.

The main executable's bytes are lifted from the pinned ELF. The libc call is
an observed effect cutpoint, not a proven symbolic memset contract.
"""
from __future__ import annotations

from hashlib import sha256
import json

import z3

from common_program_path_il import require
from pcode_transition_summary import Dual, FLAG_OFFSETS, REGISTER_OFFSETS, bv
from probe_python_remaining_scope import TRACES
from probe_unseen_python_path import PYTHON, ROOT
from prove_cross_full_flow import NativePathReplay, load_trace
from prove_cross_value_path import lifted_instructions


RESULT = ROOT / "python_connected_prefix_result.json"
OPAQUE_START = 513
OPAQUE_END = 525
NUMERIC_START = 683


class IndirectMemoryTargetReplay(NativePathReplay):
    def read(self, node):
        if node["kind_code"] == 4 and self.current_opcode in ("BRANCHIND", "CALLIND"):
            address = node["byte_offset"]
            if any(item["address"] == address and item["size"] == node["byte_size"]
                   and item["access"] & 1 for item in self.current_row["memory"]):
                return self.load(Dual(bv(address, 64), address), node["byte_size"])
        return super().read(node)


def first_read_memory(rows, input_address, witness, x):
    first = {}
    written = set()
    for row in rows:
        for access in row["memory"]:
            address, size = access["address"], access["size"]
            if access["access"] & 1:
                for offset in range(size):
                    point = address + offset
                    if point not in written:
                        byte = (access["before"] >> (8 * offset)) & 255
                        if point in first:
                            require(first[point] == byte,
                                    "first-read byte changed without observed write")
                        first[point] = byte
            if access["access"] & 2:
                written.update(address + offset for offset in range(size))
            elif access["before"] != access["after"]:
                written.update(address + offset for offset in range(size)
                               if (access["before"] >> (offset * 8)) & 255 !=
                                  (access["after"] >> (offset * 8)) & 255)
    digit = input_address + 24
    require([first.get(digit + offset) for offset in range(4)] ==
            [(witness >> (8 * offset)) & 255 for offset in range(4)],
            "entry digit not available in first-read memory")
    memory = z3.K(z3.BitVecSort(64), z3.BitVecVal(0, 8))
    for address, byte in first.items():
        memory = z3.Store(memory, z3.BitVecVal(address, 64), z3.BitVecVal(byte, 8))
    for offset in range(4):
        memory = z3.Store(memory, z3.BitVecVal(digit + offset, 64),
                          z3.Extract(offset * 8 + 7, offset * 8, x))
    return memory, len(first)


def verify_base_frame(rows):
    expected = {name: rows[0]["registers"][name]
                for name in ("fs_base", "gs_base")}
    require(all(all(row[phase][name] == expected[name]
                    for name in expected for phase in ("registers", "registers_after"))
                for row in rows),
            "FS/GS base changed inside P-code prefix or external call")


def replay(rows, memory, register_symbols=None):
    before = rows[0]["registers"]
    model = IndirectMemoryTargetReplay(rows[0], rows, lifted_instructions(PYTHON, rows),
        register_symbols={offset: (register_symbols or {}).get(name,
                           z3.BitVecVal(before[name], 64))
                          for offset, name in REGISTER_OFFSETS.items()},
        flag_symbols={offset: z3.BitVecVal((before["eflags"] >> bit) & 1, 8)
                      for offset, bit in FLAG_OFFSETS.items()},
        memory_symbol=memory, address_guards=True)
    model.run()
    guard = z3.And(*(item["condition"] for item in model.guards))
    return model, guard


def prove_witness(model, guard, rows, x, witness):
    end = rows[-1]["registers_after"]
    native_writes = [(hex(row["pc"]), access["address"], access["size"],
                      access["after"])
                     for row in rows for access in row["memory"]
                     if access["access"] & 2]
    modeled_writes = [(item["pc"], item["observed_address"], item["width"],
                       item["observed"]) for item in model.effects]
    require(modeled_writes == native_writes,
            "P-code native writes differ in order, address, size or value")
    mismatches = [item["value_expression"] !=
                  z3.BitVecVal(item["observed"], item["width"] * 8)
                  for item in model.reads]
    mismatches += [item["value"] !=
                   z3.BitVecVal(item["observed"], item["width"] * 8)
                   for item in model.effects]
    mismatches += [model.regs[offset] != z3.BitVecVal(end[name], 64)
                   for offset, name in REGISTER_OFFSETS.items()]
    mismatches += [model.flags[offset] !=
                   z3.BitVecVal((end["eflags"] >> bit) & 1, 8)
                   for offset, bit in FLAG_OFFSETS.items()]
    solver = z3.Solver()
    solver.set(timeout=30000)
    solver.add(x == z3.BitVecVal(witness, 32),
               z3.Or(z3.Not(guard), *mismatches))
    require(solver.check() == z3.unsat,
            "computed P-code guard/read/write/end state differs at witness")
    return {"native_steps": len(rows), "pcode_operations": model.operation_count,
            "modeled_reads": len(model.reads), "ordered_writes": len(model.effects),
            "guard_terms": len(model.guards),
            "observed_witness_full_model_check": "unsat"}


def verify_entry(model, next_row, x, witness):
    mismatches = [model.regs[offset] !=
                  z3.BitVecVal(next_row["registers"][name], 64)
                  for offset, name in REGISTER_OFFSETS.items()]
    mismatches += [model.flags[offset] !=
                   z3.BitVecVal((next_row["registers"]["eflags"] >> bit) & 1, 8)
                   for offset, bit in FLAG_OFFSETS.items()]
    solver = z3.Solver()
    solver.set(timeout=30000)
    solver.add(x == witness, z3.Or(*mismatches))
    require(solver.check() == z3.unsat,
            "computed prefix state differs at external call entry")
    require(model.rows[0]["registers"]["fs_base"] ==
            next_row["registers"]["fs_base"] and
            model.rows[0]["registers"]["gs_base"] ==
            next_row["registers"]["gs_base"],
            "segment-base frame changed before external call")


def apply_opaque_observation(memory, rows, x, witness):
    effects = []
    reads = []
    for row in rows:
        for access in row["memory"]:
            address, size = access["address"], access["size"]
            if access["access"] & 1:
                reads += [z3.Select(memory, z3.BitVecVal(address + offset, 64)) !=
                          z3.BitVecVal((access["before"] >> (offset * 8)) & 255, 8)
                          for offset in range(size)]
            if access["access"] & 2 or access["before"] != access["after"]:
                changed = [offset for offset in range(size)
                           if (access["before"] >> (offset * 8)) & 255 !=
                              (access["after"] >> (offset * 8)) & 255]
                effects.append({"step": row["step"], "pc": hex(row["pc"]),
                                "address": address, "size": size,
                                "changed_byte_offsets": changed,
                                "write_flag": bool(access["access"] & 2)})
                for offset in (range(size) if access["access"] & 2 else changed):
                    memory = z3.Store(memory, z3.BitVecVal(address + offset, 64),
                        z3.BitVecVal((access["after"] >> (offset * 8)) & 255, 8))
    require(len(effects) == 1 and effects[0]["step"] == 523 and
            not effects[0]["write_flag"] and effects[0]["size"] == 64,
            "external vector memory effect changed")
    solver = z3.Solver()
    solver.set(timeout=30000)
    solver.add(x == witness, z3.Or(*reads))
    require(solver.check() == z3.unsat,
            "external call read differs from computed incoming memory")
    # This is an exact-witness check. No value is inferred for another input
    # or a different libc implementation.
    return memory, effects, len(reads)


def one(value, meta, rows):
    require(len(rows) > NUMERIC_START and rows[OPAQUE_START]["pc"] > 0x7F0000000000 and
            rows[OPAQUE_END]["pc"] == 0x56004D and
            rows[NUMERIC_START]["pc"] == 0x56227C,
            "prefix cutpoints changed")
    verify_base_frame(rows[:NUMERIC_START])
    x = z3.BitVec(f"connected_prefix_X_{value}", 32)
    memory, first_bytes = first_read_memory(rows[:NUMERIC_START],
                                             meta["entry_value_address"], value, x)
    before, before_guard = replay(rows[:OPAQUE_START], memory)
    first = prove_witness(before, before_guard, rows[:OPAQUE_START], x, value)
    verify_entry(before, rows[OPAQUE_START], x, value)
    opaque = rows[OPAQUE_START:OPAQUE_END]
    require(opaque[0]["registers"] == rows[OPAQUE_START - 1]["registers_after"] and
            opaque[-1]["registers_after"] == rows[OPAQUE_END]["registers"] and
            all(a["next_pc"] == b["pc"] and a["registers_after"] == b["registers"]
                for a, b in zip(opaque, opaque[1:])),
            "external cutpoint trace is discontinuous")
    call = rows[OPAQUE_START - 2]
    ret = opaque[-1]
    require(call["pc"] == 0x560048 and ret["instruction"].startswith("ret") and
            ret["next_pc"] == 0x56004D and
            ret["registers_after"]["rsp"] == call["registers"]["rsp"] and
            all(ret["registers_after"][name] == call["registers"][name]
                for name in ("rbx", "rbp", "r12", "r13", "r14", "r15",
                             "fs_base", "gs_base")),
            "observed external call/return frame changed")
    carried, effects, read_bytes = apply_opaque_observation(before.memory,
                                                             opaque, x, value)
    after_symbols = {name: z3.BitVecVal(number, 64)
                     for name, number in rows[OPAQUE_END]["registers"].items()
                     if name in REGISTER_OFFSETS.values()}
    after, after_guard = replay(rows[OPAQUE_END:NUMERIC_START],
                                carried, after_symbols)
    second = prove_witness(after, after_guard,
                           rows[OPAQUE_END:NUMERIC_START], x, value)
    require(rows[NUMERIC_START - 1]["registers_after"] ==
            rows[NUMERIC_START]["registers"],
            "computed prefix and numeric interval cutpoint differ")
    return {"input": value, "trace_sha256": sha256(TRACES[value].read_bytes()).hexdigest(),
            "first_read_environment_bytes": first_bytes,
            "before_external": first,
            "external_call": {"native_steps": len(opaque),
                              "entry_step": OPAQUE_START, "exit_step": OPAQUE_END,
                              "semantics": "opaque observed libc vector call",
                              "observed_effects": effects,
                              "read_operand_bytes": read_bytes,
                              "call_return_frame": "observed ABI-preserved registers and RSP",
                              "post_state_source": "observed trace, not computed from libc contract"},
            "after_external": second,
            "numeric_entry_step": NUMERIC_START,
            "complete_symbolic_prefix": False}


def main():
    cases = []
    for value in (251, 252, 254):
        meta, rows, _ = load_trace(TRACES[value], "python", value, PYTHON)
        cases.append(one(value, meta, rows))
    result = {"schema_version": "python-connected-prefix-v1",
              "binary_sha256": sha256(PYTHON.read_bytes()).hexdigest(),
              "cases": cases,
              "scope": "all non-libc caller-prefix native steps P-code replayed at observed witness; libc call opaque",
              "limits": ["external libc vector call post-state is observed, not symbolically derived",
                         "unexplored prefix branches and exception exits remain open",
                         "first-read environment bytes are target-trace supplied"]}
    RESULT.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"cases": len(cases),
                      "before_external_steps": cases[0]["before_external"]["native_steps"],
                      "opaque_steps": cases[0]["external_call"]["native_steps"],
                      "after_external_steps": cases[0]["after_external"]["native_steps"]}))


if __name__ == "__main__":
    main()
