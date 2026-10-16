"""Replay the observed input-carrying P-code slice, with explicit unknown scope."""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import tarfile

from z3 import BitVec, BitVecVal, Solver, ZeroExt, SignExt, LShR, simplify, substitute, unsat


REGISTERS = {0: "rax", 8: "rcx", 16: "rdx", 40: "rbp", 48: "rsi",
             128: "r8", 160: "r12", 168: "r13", 184: "r15"}
PATH = [
    (0x40149B, [0]), (0x4014B3, [0]),
    (0x402A04, [0, 1]),
    (0x411B50, [0, 1]), (0x411B54, [0, 1]),
    (0x416EA1, [0, 1]), (0x416EA7, [0, 1]),
    (0x4164D0, [0, 1, 2]), (0x4164D7, [2]),
    (0x417CE4, [0]), (0x417CE7, [4, 5]), (0x417CEA, [0, 1]),
]
MASK = (1 << 64) - 1
GUARD_PCS = {0x4164E5, 0x4164E9, 0x4164EC}


def load_bundle(path):
    wanted = {pc for pc, _ in PATH} | {0x4164EC}
    found = {}
    with tarfile.open(path, "r:gz") as archive:
        for member in archive:
            if "/function-" not in member.name or not member.name.endswith(".json"):
                continue
            data = json.load(archive.extractfile(member))
            for instruction in data["instructions"]:
                pc = instruction["address"]["byte_offset"]
                if pc in wanted:
                    found[pc] = instruction
    if set(found) != wanted:
        raise AssertionError("missing selected P-code instructions")
    return found


def load_trace(path):
    entries = [json.loads(line) for line in path.read_text().splitlines()]
    steps = {}
    for entry in entries:
        if entry["type"] != "step":
            continue
        pc = entry["pc"]
        if pc in {p for p, _ in PATH} | GUARD_PCS:
            if pc in steps:
                raise AssertionError(f"selected PC repeated: {pc:#x}")
            steps[pc] = entry
    wanted = {p for p, _ in PATH} | GUARD_PCS
    if set(steps) != wanted:
        raise AssertionError(f"selected PCs missing: {sorted(wanted - set(steps))}")
    return entries[0], steps, entries[-1]


def value(node, registers, unique, memory, access):
    kind, offset, size = node["kind_code"], node["byte_offset"], node["byte_size"]
    bits = size * 8
    if kind == 1:
        return BitVecVal(offset, bits)
    if kind == 3:
        return unique[(offset, size)]
    if kind == 2:
        name = REGISTERS[offset]
        concrete = BitVecVal(registers[name] & ((1 << bits) - 1), bits)
        return concrete
    raise AssertionError(f"unsupported varnode kind: {kind}")


def replay(bundle, meta, steps):
    x = BitVec("X", 64)
    input_word = meta["input_word"]
    symbolic_mem = {}
    symbolic_registers = {}
    edges = []
    add_expr = None
    constant_expr = None
    for pc, ordinals in PATH:
        step = steps[pc]
        ops = bundle[pc]["operations"]
        unique = {}
        regs = step["registers"]
        for ordinal in ordinals:
            op = ops[ordinal]
            assert op["ordinal"] == ordinal
            opcode = op["opcode"]
            nodes = op["inputs"]

            def get(node):
                if node["kind_code"] == 2:
                    key = (node["byte_offset"], node["byte_size"])
                    if key in symbolic_registers:
                        expr = symbolic_registers[key]
                        if simplify(substitute(expr, (x, BitVecVal(input_word, 64)))).as_long() != (
                            regs[REGISTERS[key[0]]] & ((1 << (key[1] * 8)) - 1)):
                            # Other intervening instructions may redefine registers.
                            # Preserve symbols only while their observed value agrees.
                            del symbolic_registers[key]
                        else:
                            return expr
                    if pc == 0x40149B and key == (48, 8):
                        return x
                return value(node, regs, unique, symbolic_mem, step["memory"])

            if opcode == "COPY":
                result = get(nodes[0])
            elif opcode == "LOAD":
                address = simplify(get(nodes[1])).as_long()
                matches = [m for m in step["memory"] if m["address"] == address]
                if len(matches) != 1 or matches[0]["before"] is None:
                    raise AssertionError(f"no actual memory read at {pc:#x}")
                actual = matches[0]["before"]
                if address not in symbolic_mem:
                    raise AssertionError(f"unresolved source memory at {pc:#x}")
                result = symbolic_mem[address]
                assert simplify(substitute(result, (x, BitVecVal(input_word, 64)))).as_long() == actual
                edges.append({"pc": hex(pc), "kind": "LOAD", "address": hex(address), "value": actual})
            elif opcode == "STORE":
                address = simplify(get(nodes[1])).as_long()
                result = get(nodes[2])
                matches = [m for m in step["memory"] if m["address"] == address]
                if len(matches) != 1 or matches[0]["after"] is None:
                    raise AssertionError(f"no actual memory write at {pc:#x}")
                actual = matches[0]["after"]
                assert simplify(substitute(result, (x, BitVecVal(input_word, 64)))).as_long() == actual
                symbolic_mem[address] = result
                edges.append({"pc": hex(pc), "kind": "STORE", "address": hex(address), "value": actual})
                continue
            elif opcode == "INT_AND":
                result = get(nodes[0]) & get(nodes[1])
            elif opcode == "INT_RIGHT":
                result = LShR(get(nodes[0]), get(nodes[1]))
            elif opcode == "INT_SUB":
                result = get(nodes[0]) - get(nodes[1])
            elif opcode == "INT_SEXT":
                source = get(nodes[0])
                result = SignExt(op["output"]["byte_size"] * 8 - source.size(), source)
            elif opcode == "INT_ADD":
                result = get(nodes[0]) + get(nodes[1])
            else:
                raise AssertionError(f"unsupported selected opcode {opcode} at {pc:#x}")
            output = op["output"]
            assert output is not None
            if output["kind_code"] == 3:
                unique[(output["byte_offset"], output["byte_size"])] = result
            elif output["kind_code"] == 2:
                key = (output["byte_offset"], output["byte_size"])
                symbolic_registers[key] = result
                observed = step["registers_after"][REGISTERS[key[0]]] & ((1 << (key[1] * 8)) - 1)
                assert simplify(substitute(result, (x, BitVecVal(input_word, 64)))).as_long() == observed
            else:
                raise AssertionError("unsupported selected output")
            if pc == 0x417CE4:
                constant_expr = result
            if pc == 0x417CE7 and ordinal == 5:
                add_expr = result
    assert add_expr is not None and constant_expr is not None
    solver = Solver()
    solver.add(add_expr != x + BitVecVal(7, 64))
    assert solver.check() == unsat
    assert simplify(constant_expr).as_long() == 7
    add = steps[0x417CE7]
    assert add["memory"][0]["before"] == input_word
    assert steps[0x417CEA]["memory"][0]["after"] == ((input_word + 7) & MASK)
    tag = steps[0x4164E5]["memory"]
    assert len(tag) == 1 and tag[0]["size"] == 1 and tag[0]["before"] == 3
    assert steps[0x4164E9]["registers"]["rcx"] & 255 == 3
    guard = steps[0x4164EC]
    assert guard["next_pc"] == 0x417CE4
    assert any(op["opcode"] == "CBRANCH" for op in bundle[0x4164EC]["operations"])
    return {
        "input": meta["input"],
        "formula": "(X + 7) mod 2^64",
        "pcode_path_operation_count": sum(len(ords) for _, ords in PATH),
        "pcode_slice_smt_inequivalence": "unsat",
        "source_to_vm_memory_edges": edges,
        "bytecode_immediate_derived_by_pcode": 7,
        "observed_result_word": steps[0x417CEA]["memory"][0]["after"],
        "observed_local_guard": {"tag_byte": 3, "compare_pc": "0x4164e9",
                                 "pcode_cbranch_pc": "0x4164ec", "taken_target": "0x417ce4"},
        "unresolved": "other paths, alias changes, non-selected operations, calls and error handling",
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("bundle", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("traces", nargs="+", type=Path)
    args = parser.parse_args()
    bundle = load_bundle(args.bundle)
    results = []
    for path in args.traces:
        meta, steps, summary = load_trace(path)
        result = replay(bundle, meta, steps)
        result["trace_sha256"] = sha256(path.read_bytes()).hexdigest()
        result["trace_steps_to_add_store"] = summary["steps"]
        results.append(result)
    report = {"bundle_sha256": sha256(args.bundle.read_bytes()).hexdigest(),
              "results": results,
              "scope": "selected observed input path; SMT proves only the replayed slice algebra"}
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
