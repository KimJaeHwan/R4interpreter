"""Replay observed CPython and Ignition integer paths with SLEIGH P-code.

The output is deliberately a conditional native-path claim. All unobserved
branches, Python object layouts, and JavaScript non-Smi paths stay unknown.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import shutil

import pypcode
import z3

from cross_dispatch_pcode import read_vaddr
from pcode_transition_summary import FLAG_OFFSETS, REGISTER_OFFSETS, PathReplay
from prove_lua_full_flow import initial_memory


ROOT = Path(__file__).resolve().parent
MASK = (1 << 64) - 1


def varnode(node):
    kinds = {"const": 1, "register": 2, "unique": 3, "ram": 4}
    return {"kind_code": kinds[node.space.name], "byte_offset": node.offset,
            "byte_size": node.size}


def lifted_instructions(binary, rows):
    ctx = pypcode.Context("x86:LE:64:default")
    result = {}
    for row in rows:
        pc = row["pc"]
        ops = ctx.translate(read_vaddr(binary, pc, pc + 15),
                            base_address=pc, max_instructions=1).ops
        result[pc] = {"operations": [
            {"opcode": op.opcode.name, "inputs": [varnode(n) for n in op.inputs],
             "output": varnode(op.output) if op.output is not None else None,
             "output_present": op.output is not None}
            for op in ops if op.opcode.name != "IMARK"]}
    return result


def small_int_memory(rows, address, witness, symbol):
    memory, count = initial_memory(rows)
    digit_address = address + 24
    # The same object may be visited more than once. Confirm each first-read
    # byte before replacing only the object's 32-bit digit field.
    reads = [m for row in rows for m in row["memory"] if m["access"] & 1 and
             m["address"] <= digit_address and
             digit_address + 4 <= m["address"] + m["size"]]
    if not reads:
        raise ValueError("Python input digit was never read")
    for read in reads:
        got = (read["before"] >> (8 * (digit_address - read["address"]))) & 0xFFFFFFFF
        if got != witness:
            raise ValueError("Python input digit witness changed")
    for index in range(4):
        memory = z3.Store(memory, z3.BitVecVal(digit_address + index, 64),
                          z3.Extract(index * 8 + 7, index * 8, symbol))
    return memory, count


def prove_unsat(*conditions):
    solver = z3.Solver()
    solver.set(timeout=30000)
    solver.add(*conditions)
    verdict = solver.check()
    if verdict != z3.unsat:
        raise ValueError(f"proof failed: {verdict}")
    return "unsat"


def prove_sat(*conditions):
    solver = z3.Solver()
    solver.set(timeout=30000)
    solver.add(*conditions)
    verdict = solver.check()
    if verdict != z3.sat:
        raise ValueError(f"path guard has no second witness: {verdict}")
    return "sat"


def analyze(engine, binary, trace_path):
    report = json.loads(trace_path.read_text())
    if sha256(binary.read_bytes()).hexdigest() != report["binary_sha256"]:
        raise ValueError("binary hash differs from native trace")
    if engine == "python":
        paths = [p for p in report["paths"] if p["entry_values"]["left"] == 9 and
                 p["entry_values"]["right"] == 5]
        assert len(paths) == 1
        path = paths[0]
        assert path["exit_reason"] == "next bytecode handler" and path["result_compact_integer"] == 14
        x = z3.BitVec("PY_DIGIT_X", 32)
        cache = read_vaddr(binary, 0xA42A10, 0xA42A10 + 262 * 32)
        cache_hash = sha256(cache).hexdigest()
        if report["runtime_cache_sha256_at_sync"] != cache_hash:
            raise ValueError("Python runtime small-int cache differs from ELF at sync")
        for value in range(10, 257):
            offset = (value + 5) * 32
            tag = int.from_bytes(cache[offset + 16:offset + 24], "little")
            digit = int.from_bytes(cache[offset + 24:offset + 28], "little")
            if tag != 8 or digit != value:
                raise ValueError(f"invalid cached PyLong mapping for {value}")
        memory, initial_bytes = small_int_memory(path["rows"],
            int(path["entry_values"]["left_address"], 16), 9, x)
        symbols = {}
    else:
        paths = [p for p in report["paths"] if p["entry_values"].get("accumulator_smi") == 9 and
                 p["entry_values"].get("immediate") == 5]
        assert len(paths) == 1
        path = paths[0]
        assert path["exit_reason"] == "left handler range" and path["result_compact_integer"] == 14
        x = z3.BitVec("JS_SMI_X", 32)
        memory, initial_bytes = initial_memory(path["rows"])
        symbols = {0: z3.Concat(x, z3.BitVecVal(0, 32))}
    rows = path["rows"]
    if any(a["next_pc"] != b["pc"] for a, b in zip(rows, rows[1:])):
        raise ValueError("native trace has an instruction gap")
    before = rows[0]["registers"]
    model = PathReplay(rows[0], rows, lifted_instructions(binary, rows),
        register_symbols={offset: symbols.get(offset, z3.BitVecVal(before[name], 64))
                          for offset, name in REGISTER_OFFSETS.items()},
        flag_symbols={offset: z3.BitVecVal((before["eflags"] >> bit) & 1, 8)
                      for offset, bit in FLAG_OFFSETS.items()},
        memory_symbol=memory, address_guards=True)
    model.run()
    guard = z3.And(*(item["condition"] for item in model.guards))
    prove_unsat(z3.Not(guard), x == 9)
    second_witness = prove_sat(guard, x == 10)
    if engine == "javascript":
        actual = model.regs[0]
        expected = z3.Concat(x + z3.BitVecVal(5, 32), z3.BitVecVal(0, 32))
        proof = prove_unsat(guard, actual != expected)
        prove_unsat(guard, z3.Not(z3.BVAddNoOverflow(x, z3.BitVecVal(5, 32), True)))
        site = hex(rows[-1]["pc"])
        abstract_result = "signed32(RAX_out >> 32) = signed32(X + 5)"
        if model.regs_concrete[0] != path["exit_registers"]["rax"]:
            raise ValueError("JS exit accumulator mismatch")
    else:
        # The PyLong helper computes a signed coefficient sum in RCX and
        # indexes CPython's immortal [-5,256] integer cache from that sum.
        site = hex(0x5E9780)
        # The last step at this site precedes the cache-bound check.
        prefix = rows[:next(i for i, r in enumerate(rows) if r["pc"] == 0x5E9780)]
        prefix_model = PathReplay(prefix[0], prefix, lifted_instructions(binary, prefix),
            register_symbols={offset: z3.BitVecVal(before[name], 64)
                              for offset, name in REGISTER_OFFSETS.items()},
            flag_symbols={offset: z3.BitVecVal((before["eflags"] >> bit) & 1, 8)
                          for offset, bit in FLAG_OFFSETS.items()},
            memory_symbol=memory, address_guards=True)
        prefix_model.run()
        prefix_guard = z3.And(*(item["condition"] for item in prefix_model.guards))
        actual = prefix_model.regs[8]  # RCX before LEA/cache selection.
        expected = z3.ZeroExt(32, x) + z3.BitVecVal(5, 64)
        proof = prove_unsat(prefix_guard, actual != expected)
        abstract_result = "RCX_before_cache = zero_extend32(X) + 5"
        if prefix_model.regs_concrete[8] != 14:
            raise ValueError("Python concrete sum is not 14")
        output_store = next(item for item in model.effects if item["pc"] == hex(0x562316))
        output_slot = output_store["observed_address"]
        output_pointer = z3.Concat(*reversed([
            z3.Select(model.memory, z3.BitVecVal(output_slot + index, 64))
            for index in range(8)]))
        cache_pointer = z3.BitVecVal(0xA42A10, 64) + \
            ((z3.ZeroExt(32, x) + z3.BitVecVal(10, 64)) << 5)
        prove_unsat(guard, output_pointer != cache_pointer)
        bounded = z3.And(z3.UGE(x, z3.BitVecVal(5, 32)),
                         z3.ULE(x, z3.BitVecVal(251, 32)))
        prove_unsat(guard, z3.UGE(x, z3.BitVecVal(5, 32)),
                    z3.UGT(x, z3.BitVecVal(251, 32)))
        prove_sat(guard, x == 5)
        prove_sat(guard, bounded, x == 251)
        prove_unsat(guard, bounded, output_pointer != cache_pointer)
        for effect in model.effects:
            start = effect["observed_address"]
            if start < 0xA42A10 + 262 * 32 and start + effect["width"] > 0xA42A10:
                raise ValueError("recorded handler wrote the small-int cache")
    return {"engine": engine, "binary_sha256": report["binary_sha256"],
            "trace_sha256": sha256(trace_path.read_bytes()).hexdigest(),
            "entry_pc": report["entry_pc"], "exit_pc": path["exit_pc"],
            "exit_reason": path["exit_reason"], "witness_input": 9,
            "witness_output": path["result_compact_integer"],
            "native_steps": len(rows), "pcode_operations": model.operation_count,
            "initial_memory_bytes": initial_bytes,
            "guard_count": len(model.guards), "expression_site": site,
            "expression": abstract_result, "conditional_equality_check": proof,
            "second_guard_witness_x10": second_witness,
            "python_cache_pointer_check": "unsat" if engine == "python" else None,
            "python_cache_sha256": cache_hash if engine == "python" else None,
            "python_cache_verified_output_range": "10..256" if engine == "python" else None,
            "python_input_bound": "5 <= X <= 251" if engine == "python" else None,
            "proof_scope": "recorded native path, stable first-read memory, and SLEIGH x86-64 P-code"}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("python_trace", type=Path)
    parser.add_argument("javascript_trace", type=Path)
    args = parser.parse_args()
    result = {"schema_version": 1, "cases": [
        analyze("python", Path("/usr/bin/python3.13"), args.python_trace),
        analyze("javascript", Path(shutil.which("node")), args.javascript_trace)]}
    target = ROOT / "cross_value_path_result.json"
    target.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({case["engine"]: {"steps": case["native_steps"],
                                      "pcode": case["pcode_operations"],
                                      "proof": case["conditional_equality_check"]}
                      for case in result["cases"]}))


if __name__ == "__main__":
    main()
