"""Freeze and prove the native controlled-pool helper, under its ABI invariant."""
import gzip
from hashlib import sha256
import json

import z3

from composed_native_transition import path_shape
from pcode_transition_summary import FLAG_OFFSETS, REGISTER_OFFSETS
from prove_cross_full_flow import NativePathReplay, ROOT
from prove_cross_value_path import lifted_instructions
from trace_python_pool_lifetime import BINARY

SOURCE = ROOT / "artifacts/python_pool_source.json.gz"
OUTPUT = ROOT / "pool_native_transition_summary.json"
PROOF = ROOT / "pool_native_refinement_result.json"


def load64(memory, address):
    return z3.Concat(*reversed([z3.Select(memory, address + i) for i in range(8)]))


def store64(memory, address, value):
    for index in range(8):
        memory = z3.Store(memory, address + index,
                          z3.Extract(index * 8 + 7, index * 8, value))
    return memory


def unsat(*conditions):
    solver = z3.Solver()
    solver.set(timeout=60000)
    solver.add(*conditions)
    verdict = solver.check()
    if verdict != z3.unsat:
        raise ValueError(f"native pool refinement failed: {verdict}; {solver.reason_unknown()}")
    return "unsat"


def make_segment(call, label):
    rows = call["rows"]
    regs = {offset: z3.BitVec(f"R_{name.upper()}", 64)
            for offset, name in REGISTER_OFFSETS.items()}
    flags = {offset: z3.BitVec(f"F_{bit}", 8)
             for offset, bit in FLAG_OFFSETS.items()}
    memory = z3.Array("M0", z3.BitVecSort(64), z3.BitVecSort(8))
    model = NativePathReplay(rows[0], rows, lifted_instructions(BINARY, rows),
        register_symbols=regs, flag_symbols=flags,
        memory_symbol=memory, address_guards=False)
    model.run()
    if rows[-1]["instruction"] != "ret":
        raise ValueError("pool helper must end with a modeled near return")
    successor = load64(model.memory, model.regs[32] - 8)
    segment = {"label": label,
        "logical_effect": {"schema_version": "common-lifetime-effect-v1",
            "kind": "Allocate" if label == "allocate" else "Free",
            "cutpoint": "helper_return", "required_native_label": label,
            "required_return": {"register": "rax", "value": 1},
            "address_space_id": "native_virtual",
            "domain_id": "controlled_obj_pool",
            "resource_binding": {"kind": "register_index", "register": "rsi",
                                 "prefix": "pool_slot_"},
            "requested_extent": 32},
        "identity": {"entry_pc": hex(rows[0]["pc"]),
            "next_pc": hex(rows[-1]["next_pc"]), "native_steps": len(rows),
            "path_shape_mode": "pc_bytes_next",
            "path_shape_sha256": path_shape(rows, "pc_bytes_next")},
        "guard": z3.simplify(z3.And(*(g["condition"] for g in model.guards))).sexpr(),
        "outputs": ([{"name": f"R_{name.upper()}", "sort": "BV64",
            "expression": z3.simplify(model.regs[offset]).sexpr()}
            for offset, name in REGISTER_OFFSETS.items()] +
            [{"name": f"F_{bit}", "sort": "BV8",
              "expression": z3.simplify(model.flags[offset]).sexpr()}
             for offset, bit in FLAG_OFFSETS.items()]),
        "reads": [{"pc": r["pc"], "width": r["width"],
            "address": z3.simplify(r["address"]).sexpr(),
            "value": z3.simplify(r["value_expression"]).sexpr()}
            for r in model.reads],
        "effects": [{"kind": "Write", "pc": e["pc"], "width": e["width"],
            "address": z3.simplify(e["address"]).sexpr(),
            "value": z3.simplify(e["value"]).sexpr()} for e in model.effects],
        "successor": z3.simplify(successor).sexpr(),
        "evidence": {"source_pcode_operations": model.operation_count}}
    base, stack = regs[56], regs[32]
    live = load64(memory, base)
    guard = z3.And(*(g["condition"] for g in model.guards))
    abi = z3.And(z3.ULE(base, (1 << 64) - 41),
        z3.ULE(stack, (1 << 64) - 9),
        z3.Or(z3.ULE(base + 40, stack), z3.ULE(stack + 8, base)),
        load64(memory, stack) == rows[-1]["next_pc"], z3.ULE(live, 15))
    checks = []
    for slot in range(4):
        bit = z3.BitVecVal(1 << slot, 64)
        generation = load64(memory, base + 8 + slot * 8)
        operation = 1 if label == "allocate" else 2
        common = z3.And(abi, regs[48] == slot, regs[16] == operation)
        pre = z3.And(common, (live & bit) == 0, generation != (1 << 64) - 1
                     ) if operation == 1 else z3.And(common, (live & bit) != 0)
        next_live = live | bit if operation == 1 else live & ~bit
        expected = store64(memory, base + 8 + slot * 8, generation + 1
                           ) if operation == 1 else memory
        expected = store64(expected, base, next_live)
        checks.append({"slot": slot,
            "guard_counterexample": unsat(pre, z3.Not(guard)),
            "full_memory_refinement_counterexample": unsat(pre, model.memory != expected),
            "return_counterexample": unsat(pre, model.regs[0] != 1),
            "partition_counterexample": unsat(pre, z3.UGT(load64(model.memory, base), 15)),
            "generation_counterexample": unsat(pre,
                load64(model.memory, base + 8 + slot * 8) !=
                (generation + 1 if operation == 1 else generation))})
        if operation == 1:
            checks[-1]["new_generation_not_greater"] = unsat(pre,
                z3.ULE(load64(model.memory, base + 8 + slot * 8), generation))
            checks[-1]["overflow_admitted"] = unsat(common,
                (live & bit) == 0, generation == (1 << 64) - 1, guard)
            checks[-1]["already_live_admitted"] = unsat(common, (live & bit) != 0, guard)
        else:
            checks[-1]["already_free_admitted"] = unsat(common, (live & bit) == 0, guard)
    return segment, checks


def main():
    with gzip.open(SOURCE, "rt") as stream:
        source = json.load(stream)
    if source["binary_sha256"] != sha256(BINARY.read_bytes()).hexdigest():
        raise ValueError("pool fixture changed")
    segments, proofs = [], {}
    for operation, label in ((1, "allocate"), (2, "release")):
        call = next(c for c in source["calls"] if c["operation"] == operation)
        segment, proof = make_segment(call, label)
        segments.append(segment)
        proofs[label] = proof
    summary = {"schema_version": "controlled-pool-native-v1",
        "logical_effect_schema_version": "common-lifetime-effect-v1",
        "binary_sha256": source["binary_sha256"],
        "source_trace_sha256": sha256(SOURCE.read_bytes()).hexdigest(),
        "interface": {"inputs": (
            [{"name": f"R_{name.upper()}", "sort": "BV64"}
             for name in REGISTER_OFFSETS.values()] +
            [{"name": f"F_{bit}", "sort": "BV8"} for bit in FLAG_OFFSETS.values()] +
            [{"name": "M0", "sort": "Array(BV64,BV8)"}])},
        "segments": segments,
        "assumptions": ["four-slot pool ledger, exact helper ABI and static code",
            "state range does not wrap or overlap the return stack word",
            "valid live-mask partition and successful operation preconditions"],
        "limits": ["proof covers controlled helper; hook/CPython binding is observed",
                   "default CPython allocator ownership is not proved"]}
    OUTPUT.write_text(json.dumps(summary, indent=2) + "\n")
    PROOF.write_text(json.dumps({"schema_version": 1, "proofs": proofs,
        "summary_sha256": sha256(OUTPUT.read_bytes()).hexdigest(),
        "scope": "conditional native helper refinement; full byte-memory frame included"
        }, indent=2) + "\n")
    print(json.dumps({"segments": len(segments),
                      "proved_slot_cases": sum(map(len, proofs.values()))}))


if __name__ == "__main__":
    main()
