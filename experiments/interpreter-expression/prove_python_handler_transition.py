"""Serialize and reuse one observed CPython BINARY_OP native transition.

The contract includes all 16 GPRs, five modeled flags, 31 native reads,
12 ordered writes and the next handler. It is conditional on the cached-int
path and a fixed CPython binary/cache image; alternate paths remain unknown.
"""
from __future__ import annotations

from copy import deepcopy
import gzip
from hashlib import sha256
import json

import z3

from apply_transition_summary import expression
from cross_dispatch_pcode import read_vaddr
from pcode_transition_summary import FLAG_OFFSETS, REGISTER_OFFSETS
from prove_cross_full_flow import NativePathReplay, PYTHON, ROOT, load_trace, verify_cache
from prove_cross_value_path import lifted_instructions
from prove_js_handler_transition import observed_accesses, path_shape
from prove_js_summary_reuse import concrete_bindings, concrete_value
from prove_python_value_reuse import CACHE_BASE, add_segment, observed_operands


SOURCE = ROOT / "artifacts/cross_python_full_9.json.gz"
HOLDOUTS = [ROOT / f"artifacts/python_holdout_{value}.json.gz"
            for value in (37, 251)]
SUMMARY = ROOT / "python_binary_op_full_handler_summary.json"
RESULT = ROOT / "python_full_handler_reuse_result.json"
FIXTURE = ROOT / "python_holdout_fixture.py"


def holdout(path, binary_hash, cache_hash):
    with gzip.open(path, "rt") as stream:
        meta, section, result = [json.loads(line) for line in stream]
    if (meta["binary_sha256"] != binary_hash or
            meta["fixture_sha256"] != sha256(FIXTURE.read_bytes()).hexdigest() or
            meta["runtime_cache_sha256_at_entry"] != cache_hash or
            meta["runtime_cache_sha256_at_exit"] != cache_hash or
            result["output"] != meta["input"] + 5):
        raise ValueError("holdout identity or output differs")
    return meta, section["rows"], result


def declarations():
    regs = {offset: z3.BitVec(f"R_{name.upper()}", 64)
            for offset, name in REGISTER_OFFSETS.items()}
    flags = {offset: z3.BitVec(f"F_{bit}", 8)
             for offset, bit in FLAG_OFFSETS.items()}
    memory = z3.Array("M0", z3.BitVecSort(64), z3.BitVecSort(8))
    decls = {f"R_{name.upper()}": regs[offset]
             for offset, name in REGISTER_OFFSETS.items()}
    decls.update({f"F_{bit}": flags[offset]
                  for offset, bit in FLAG_OFFSETS.items()})
    decls["M0"] = memory
    return regs, flags, memory, decls


def make_case(rows):
    regs, flags, memory, decls = declarations()
    model = NativePathReplay(rows[0], rows, lifted_instructions(PYTHON, rows),
                             register_symbols=regs, flag_symbols=flags,
                             memory_symbol=memory, address_guards=False)
    model.run()
    native_writes = observed_accesses(rows, 2)
    if (len(rows) != 116 or len(model.effects) != 12 or len(model.reads) != 31 or
            model.successor is None or
            [(item["pc"], item["observed_address"], item["width"], item["observed"])
             for item in model.effects] !=
            [(item["pc"], item["address"], item["width"], item["value"])
             for item in native_writes]):
        raise ValueError("source path or native effect inventory changed")
    source_sub = concrete_bindings(decls, rows)
    if any(not z3.is_true(z3.simplify(z3.substitute(item["condition"],
                                                         *source_sub)))
           for item in model.guards):
        raise ValueError("source witness violates its symbolic path guard")
    return {
        "identity": {"entry_pc": hex(rows[0]["pc"]),
                     "next_handler_pc": hex(rows[-1]["next_pc"]),
                     "path_shape_sha256": path_shape(rows),
                     "native_steps": len(rows)},
        "guard": z3.simplify(z3.And(*(item["condition"] for item in
                                      model.guards))).sexpr(),
        "outputs": ([{"binding": name, "sort": "BV64",
                      "expression": z3.simplify(model.regs[offset]).sexpr()}
                     for offset, name in REGISTER_OFFSETS.items()] +
                    [{"binding": f"eflag{bit}", "sort": "BV8",
                      "expression": z3.simplify(model.flags[offset]).sexpr()}
                     for offset, bit in FLAG_OFFSETS.items()]),
        "reads": [{"pc": item["pc"], "width": item["width"],
                   "address": z3.simplify(item["address"]).sexpr()}
                  for item in model.reads],
        "ordered_effects": [{"pc": item["pc"], "width": item["width"],
                             "address": z3.simplify(item["address"]).sexpr(),
                             "value": z3.simplify(item["value"]).sexpr()}
                            for item in model.effects],
        "successor": z3.simplify(model.successor).sexpr(),
        "evidence": {"source_input": 9, "source_output": 14,
                     "pcode_operations": model.operation_count,
                     "path_guard_count": len(model.guards),
                     "read_count": len(model.reads),
                     "write_count": len(model.effects)}}


def apply_case(summary, meta, rows):
    if (summary.get("schema_version") != "native-handler-transition-v1" or
            summary.get("engine") != "python"):
        return {"status": "unknown(summary schema or engine)"}
    if (meta["binary_sha256"] != summary["binary_sha256"] or
            meta["runtime_cache_sha256_at_entry"] != summary["cache_sha256"] or
            meta["runtime_cache_sha256_at_exit"] != summary["cache_sha256"]):
        return {"status": "unknown(binary or cache identity)"}
    x = meta["input"]
    if (type(x) is not int or not 5 <= x <= 251 or
            meta["left_pointer"] != CACHE_BASE + (x + 5) * 32 or
            meta["right_pointer"] != CACHE_BASE + 10 * 32):
        return {"status": "unknown(cached integer domain)"}
    if (not rows or any(a["next_pc"] != b["pc"] for a, b in zip(rows, rows[1:])) or
            rows[0]["pc"] != int(summary["case"]["identity"]["entry_pc"], 16) or
            len(rows) != summary["case"]["identity"]["native_steps"] or
            path_shape(rows) != summary["case"]["identity"]["path_shape_sha256"] or
            rows[-1]["next_pc"] != int(summary["case"]["identity"]["next_handler_pc"], 16)):
        return {"status": "unknown(path identity)"}
    cache = read_vaddr(PYTHON, CACHE_BASE, CACHE_BASE + 262 * 32)
    if sha256(cache).hexdigest() != summary["cache_sha256"]:
        return {"status": "unknown(cache image)"}
    try:
        operands = observed_operands(rows, cache)
    except (ValueError, KeyError):
        return {"status": "unknown(operand evidence)"}
    if ([item["pointer"] for item in operands] !=
            [hex(meta["left_pointer"]), hex(meta["right_pointer"])] or
            [item["value"] for item in operands] != [x, 5] or
            meta["output_slot"] != rows[-1]["registers_after"]["r15"] - 8):
        return {"status": "unknown(operand or result slot mismatch)"}
    cache_end = CACHE_BASE + len(cache)
    if any(item["access"] & 2 and
           item["address"] < cache_end and
           item["address"] + item["size"] > CACHE_BASE
           for row in rows for item in row["memory"]):
        return {"status": "unknown(cache write)"}
    case = summary["case"]
    expected_outputs = {name: "BV64" for name in REGISTER_OFFSETS.values()}
    expected_outputs.update({f"eflag{bit}": "BV8" for bit in FLAG_OFFSETS.values()})
    if (len(case["outputs"]) != len(expected_outputs) or
            {item["binding"]: item["sort"] for item in case["outputs"]} !=
            expected_outputs):
        return {"status": "unknown(incomplete state contract)"}
    _, _, _, decls = declarations()
    sub = concrete_bindings(decls, rows)
    if not z3.is_true(z3.simplify(z3.substitute(
            expression(case["guard"], "Bool", decls), *sub))):
        return {"status": "unknown(outside path guard)"}
    predicted = {}
    for item in case["outputs"]:
        name = item["binding"]
        value = concrete_value(expression(item["expression"], item["sort"], decls),
                               sub)
        actual = (rows[-1]["registers_after"][name]
                  if name in REGISTER_OFFSETS.values() else
                  (rows[-1]["registers_after"]["eflags"] >> int(name[5:])) & 1)
        if value != actual:
            return {"status": "unknown(state mismatch)", "binding": name}
        predicted[name] = value
    predicted_reads = [{"pc": item["pc"], "width": item["width"],
                        "address": concrete_value(expression(item["address"],
                                                             "BV64", decls), sub)}
                       for item in case["reads"]]
    observed_reads = [{key: item[key] for key in ("pc", "width", "address")}
                      for item in observed_accesses(rows, 1)]
    if predicted_reads != observed_reads:
        return {"status": "unknown(read footprint mismatch)"}
    predicted_effects = [{"pc": item["pc"], "width": item["width"],
                          "address": concrete_value(expression(item["address"],
                                                               "BV64", decls), sub),
                          "value": concrete_value(expression(item["value"],
                                              f"BV{item['width'] * 8}", decls), sub)}
                         for item in case["ordered_effects"]]
    if predicted_effects != observed_accesses(rows, 2):
        return {"status": "unknown(ordered effects mismatch)"}
    successor = concrete_value(expression(case["successor"], "BV64", decls), sub)
    if successor != rows[-1]["next_pc"]:
        return {"status": "unknown(successor mismatch)"}
    result_slot = meta["output_slot"]
    result_effects = [item for item in predicted_effects
                      if item["address"] == result_slot and item["width"] == 8]
    expected_pointer = CACHE_BASE + (x + 10) * 32
    if len(result_effects) != 1 or result_effects[0]["value"] != expected_pointer:
        return {"status": "unknown(numeric result mismatch)"}
    return {"status": "differentially_validated_full_observed_path",
            "input": x, "result": x + 5, "result_pointer": hex(expected_pointer),
            "next_handler_pc": hex(successor), "native_steps": len(rows),
            "reads_checked": len(predicted_reads),
            "ordered_writes_checked": len(predicted_effects),
            "register_and_flag_outputs_checked": len(predicted),
            "target_pcode_steps_replayed": 0}


def main():
    source_meta, source_rows, _ = load_trace(SOURCE, "python", 9, PYTHON)
    source_segment, _ = add_segment(source_rows)
    binary_hash = sha256(PYTHON.read_bytes()).hexdigest()
    cache_hash = verify_cache(source_meta)
    summary = {"schema_version": "native-handler-transition-v1",
        "engine": "python", "binary_sha256": binary_hash,
        "cache_sha256": cache_hash,
        "scope": "observed cached PyLong BINARY_OP path, X in [5,251], Y=5",
        "entry_interface": "all GPRs, five modeled flags, first-read memory M0",
        "case": make_case(source_segment),
        "source_trace_sha256": sha256(SOURCE.read_bytes()).hexdigest(),
        "limits": ["fixed CPython 3.13 binary and verified small-int cache image",
                   "observed path through next handler entry only",
                   "source value proof specializes object/frame addresses",
                   "alternate Python types, allocations and errors are unknown"]}
    SUMMARY.write_text(json.dumps(summary, indent=2) + "\n")
    reloaded = json.loads(SUMMARY.read_text())
    applications = []
    for path in HOLDOUTS:
        meta, rows, oracle = holdout(path, binary_hash, cache_hash)
        applied = apply_case(reloaded, meta, rows)
        if (applied["status"] != "differentially_validated_full_observed_path" or
                applied["result"] != oracle["output"]):
            raise ValueError(f"target application failed: {path.name}: {applied}")
        applications.append({"input": meta["input"], "oracle": oracle["output"],
                             "trace_sha256": sha256(path.read_bytes()).hexdigest(),
                             "application": applied})
    meta, rows, _ = holdout(HOLDOUTS[0], binary_hash, cache_hash)
    wrong_write = deepcopy(rows)
    next(item for row in wrong_write for item in row["memory"]
         if item["access"] & 2)["after"] ^= 1
    missing_write = deepcopy(rows)
    row = next(row for row in missing_write if any(
        item["access"] & 2 for item in row["memory"]))
    row["memory"] = [item for item in row["memory"] if not item["access"] & 2]
    missing_output = deepcopy(reloaded)
    missing_output["case"]["outputs"] = missing_output["case"]["outputs"][:-1]
    bad_path = deepcopy(rows)
    bad_path[-1]["next_pc"] = 0
    negatives = {
        "wrong_binary": apply_case(reloaded, {**meta, "binary_sha256": "wrong"}, rows),
        "wrong_cache": apply_case(reloaded, {**meta,
                                  "runtime_cache_sha256_at_entry": "wrong"}, rows),
        "outside_domain": apply_case(reloaded, {**meta, "input": 252}, rows),
        "wrong_operand_metadata": apply_case(
            reloaded, {**meta, "left_pointer": CACHE_BASE + (38 + 5) * 32,
                       "input": 38}, rows),
        "wrong_output_slot": apply_case(
            reloaded, {**meta, "output_slot": meta["output_slot"] + 8}, rows),
        "missing_output": apply_case(missing_output, meta, rows),
        "changed_write": apply_case(reloaded, meta, wrong_write),
        "missing_write": apply_case(reloaded, meta, missing_write),
        "wrong_successor": apply_case(reloaded, meta, bad_path),
        "wrong_engine": apply_case({**reloaded, "engine": "javascript"}, meta, rows),
        "wrong_schema": apply_case({**reloaded,
                                     "schema_version": "unsupported"}, meta, rows)}
    if any(not item["status"].startswith("unknown(") for item in negatives.values()):
        raise ValueError("invalid application was accepted")
    result = {"status": "bounded complete observed Python BINARY_OP path reused",
        "summary_sha256": sha256(SUMMARY.read_bytes()).hexdigest(),
        "source_trace_sha256": summary["source_trace_sha256"],
        "source": summary["case"]["evidence"],
        "applications": applications, "negative_probes": negatives,
        "metrics": {"target_cases": len(applications),
                    "applied_correct": len(applications),
                    "target_pcode_steps_replayed": 0},
        "limits": summary["limits"]}
    RESULT.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result["metrics"]))


if __name__ == "__main__":
    main()
