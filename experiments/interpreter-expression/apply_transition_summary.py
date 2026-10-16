"""Apply a serialized P-code transition summary to a boundary snapshot.

This evaluator knows bitvectors, memory, guards and ordered effects. It has no
Lua opcode dispatch table or language-level arithmetic rules.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path

import z3


def declarations(summary):
    result = {}
    for item in summary["interface"]["inputs"]:
        sort = item["sort"]
        if sort.startswith("BV"):
            result[item["name"]] = z3.BitVec(item["name"], int(sort[2:]))
        elif sort == "Array(BV64,BV8)":
            result[item["name"]] = z3.Array(item["name"], z3.BitVecSort(64), z3.BitVecSort(8))
        else:
            raise ValueError(f"unsupported sort {sort}")
    return result


def expression(source, sort, decls):
    if sort == "Bool":
        ast = z3.parse_smt2_string(f"(assert {source})", decls=decls)
        assert len(ast) == 1
        return ast[0]
    assert sort.startswith("BV")
    result = z3.BitVec("__summary_result", int(sort[2:]))
    ast = z3.parse_smt2_string(f"(assert (= __summary_result {source}))",
                               decls={**decls, "__summary_result": result})
    assert len(ast) == 1 and z3.is_eq(ast[0])
    eq = ast[0]
    return eq.arg(1) if eq.arg(0).eq(result) else eq.arg(0)


def concrete(solver, expr):
    if solver.check() != z3.sat:
        raise AssertionError("inconsistent input snapshot")
    value = solver.model().eval(expr, model_completion=True)
    solver.push()
    solver.add(expr != value)
    unique = solver.check() == z3.unsat
    solver.pop()
    if not unique:
        raise ValueError("expression depends on uncaptured input state")
    return value.as_long() if z3.is_bv_value(value) else z3.is_true(value)


def load_trace(path, entry_pc, exit_pc, occurrence=0):
    records = [json.loads(line) for line in path.read_text().splitlines()]
    entries = [row for row in records if row.get("type") == "step" and row["pc"] == entry_pc]
    entry = entries[occurrence]
    handler_rows = []
    for row in records:
        if row.get("type") != "step" or row["step"] < entry["step"]:
            continue
        handler_rows.append(row)
        if row["next_pc"] == exit_pc:
            break
    return entry, handler_rows


def apply(summary, binary, trace, occurrence=0, entry_override=None):
    if sha256(binary.read_bytes()).hexdigest() != summary["identity"]["executable_code_sha256"]:
        raise ValueError("summary executable hash does not match")
    entry_pc = int(summary["identity"]["entry_cutpoint"], 16)
    exit_pc = int(summary["identity"]["exit_cutpoint"], 16)
    entry, rows = load_trace(trace, entry_pc, exit_pc, occurrence)
    if entry_override is not None:
        entry = entry_override
    decls = declarations(summary)
    solver = z3.Solver()
    for item in summary["interface"]["inputs"]:
        bind = item["binding"]
        kind = bind["kind"]
        if kind == "entry_memory":
            continue
        actual = entry["registers"][bind["name"]]
        if kind == "register_slice":
            actual = (actual >> bind["low_bit"]) & ((1 << bind["width"]) - 1)
        elif kind == "register_bit":
            actual = (actual >> bind["bit"]) & 1
        elif kind != "register":
            raise ValueError(f"unsupported binding {kind}")
        solver.add(decls[item["name"]] == z3.BitVecVal(actual, decls[item["name"]].size()))
    snapshot = entry.get("entry_memory")
    if summary["case"]["reads"] and snapshot is None:
        raise ValueError("trace has no entry memory snapshot")
    memory_base = snapshot["base"] if snapshot is not None else 0
    memory = bytes.fromhex(snapshot["bytes_hex"]) if snapshot is not None else b""
    memory_name = next((item["name"] for item in summary["interface"]["inputs"]
                        if item["binding"]["kind"] == "entry_memory"), None)
    reads = []
    for item in summary["case"]["reads"]:
        if item["memory_version"] != 0:
            raise ValueError("post-write memory reads require a versioned snapshot evaluator")
        address = concrete(solver, expression(item["address"], "BV64", decls))
        width = item["width"]
        if address < memory_base or address + width > memory_base + len(memory):
            raise ValueError(f"required memory outside snapshot at {address:#x}")
        for i in range(width):
            solver.add(z3.Select(decls[memory_name], z3.BitVecVal(address + i, 64)) ==
                       z3.BitVecVal(memory[address - memory_base + i], 8))
        value = int.from_bytes(memory[address - memory_base:address - memory_base + width], "little")
        reads.append({"pc": item["pc"], "address": address, "width": width, "value": value})
    for guard in summary["case"]["path_guard"]:
        if not concrete(solver, expression(guard, "Bool", decls)):
            return {"status": "unknown(outside conditional path)"}
    if rows[-1]["next_pc"] != int(summary["identity"]["exit_cutpoint"], 16):
        raise AssertionError("handler did not reach the summary exit cutpoint")
    effects = []
    for item in summary["case"]["ordered_effects"]:
        address = concrete(solver, expression(item["address"], "BV64", decls))
        value = concrete(solver, expression(item["value"], f"BV{item['width'] * 8}", decls))
        effects.append({"kind": item["kind"], "pc": item["pc"], "ordinal": item["ordinal"],
                        "address": address, "width": item["width"], "value": value})
    outputs = []
    for item in summary["case"].get("outputs", []):
        value = concrete(solver, expression(item["expression"], item["sort"], decls))
        outputs.append({"name": item["name"], "value": value})
        binding = item.get("observed_binding")
        if binding is not None:
            observed = rows[-1]["registers_after"][binding["name"]]
            if binding["kind"] == "register_bit":
                observed = (observed >> binding["bit"]) & 1
            elif binding["kind"] == "register_slice":
                observed = (observed >> binding["low_bit"]) & ((1 << binding["width"]) - 1)
            elif binding["kind"] != "register":
                raise ValueError(f"unsupported output binding {binding['kind']}")
            if value != observed:
                raise AssertionError(f"summary output {item['name']} disagrees with trace")
    observed_writes = []
    observed_reads = []
    for row in rows:
        for access in row["memory"]:
            if access["access"] & 1:
                observed_reads.append({"pc": hex(row["pc"]), "address": access["address"],
                                       "width": access["size"], "value": access["before"]})
            if access["access"] & 2:
                observed_writes.append({"pc": hex(row["pc"]), "address": access["address"],
                                        "width": access["size"], "value": access["after"]})
    projected = [{k: effect[k] for k in ("pc", "address", "width", "value")}
                 for effect in effects]
    if projected != observed_writes:
        raise AssertionError(f"summary writes disagree with trace: {projected} != {observed_writes}")
    unique_reads = list({(r["pc"], r["address"], r["width"], r["value"]): r
                         for r in reads}.values())
    if unique_reads != observed_reads:
        raise AssertionError(f"summary reads disagree with trace: {unique_reads} != {observed_reads}")
    return {"status": "differentially_validated",
            "reads": reads, "predicted_effects": effects, "outputs": outputs,
            "native_steps_within_summary": len(rows)}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("summary", type=Path)
    parser.add_argument("binary", type=Path)
    parser.add_argument("trace", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--occurrence", type=int, default=0)
    args = parser.parse_args()
    summary = json.loads(args.summary.read_text())
    result = apply(summary, args.binary, args.trace, args.occurrence)
    result["summary_sha256"] = sha256(args.summary.read_bytes()).hexdigest()
    result["trace_sha256"] = sha256(args.trace.read_bytes()).hexdigest()
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
