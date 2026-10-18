"""Reuse a Python numeric transition without exporting PyObject addresses.

The source P-code proof is conditional on the recorded cached-PyLong path.
The second native path is checked using its recorded concrete input/output
objects, cache layout and instruction identity; its P-code is not replayed.
This is a value-level summary, not yet a complete handler-effect summary.
"""
from __future__ import annotations

from hashlib import sha256
import json

import z3

from cross_dispatch_pcode import read_vaddr
from prove_cross_full_flow import (CACHE_BASE, PYTHON, ROOT, bounded,
                                   checked_segment, load_trace, one, unsat,
                                   verify_cache, word)
from prove_cross_value_path import small_int_memory


SOURCE = ROOT / "artifacts/cross_python_full_9.json.gz"
TARGET = ROOT / "artifacts/cross_python_full_0.json.gz"
SUMMARY = ROOT / "python_numeric_value_summary.json"
RESULT = ROOT / "python_numeric_value_reuse_result.json"
CACHE_COUNT = 262
CACHE_STRIDE = 32


def add_segment(rows):
    child = one(rows, 0x565038)
    start = one(rows, 0x56227C, after=child)
    stop = one(rows, 0x56173B, after=start)
    return rows[start:stop], rows[stop]


def cache_value(cache, pointer):
    offset = pointer - CACHE_BASE
    if offset < 0 or offset >= CACHE_COUNT * CACHE_STRIDE or offset % CACHE_STRIDE:
        raise ValueError("object pointer is outside the verified small-int cache")
    tag = int.from_bytes(cache[offset + 16:offset + 24], "little")
    digit = int.from_bytes(cache[offset + 24:offset + 28], "little")
    if tag != (1 if digit == 0 else 8) or offset != (digit + 5) * CACHE_STRIDE:
        raise ValueError("cached PyLong object does not have the expected layout")
    return digit


def observed_operands(rows, cache):
    frame_top = rows[0]["registers"]["r15"]
    slots = (frame_top - 16, frame_top - 8)
    operands = []
    for slot in slots:
        reads = [(index, access) for index, row in enumerate(rows)
                 for access in row["memory"] if access["address"] == slot and
                 access["size"] == 8 and access["access"] & 1]
        if len(reads) != 1:
            raise ValueError("numeric operand read is missing or ambiguous")
        operands.append({"slot": hex(slot), "step": reads[0][0],
                         "pointer": hex(reads[0][1]["before"]),
                         "value": cache_value(cache, reads[0][1]["before"])})
    return operands


def output_write(rows, return_row):
    slot = return_row["registers"]["r15"] - 8
    hits = [(index, access) for index, row in enumerate(rows)
            for access in row["memory"] if access["address"] == slot and
            access["size"] == 8 and access["access"] & 2]
    if len(hits) != 1:
        raise ValueError("numeric result slot has an ambiguous native write")
    return {"slot": hex(slot), "step": hits[0][0],
            "pointer": hex(hits[0][1]["after"])}


def evaluate_expression(node, bindings):
    if set(node) == {"var"} and node["var"] in bindings:
        return bindings[node["var"]]
    if set(node) == {"const"} and type(node["const"]) is int:
        return node["const"]
    if set(node) == {"op", "left", "right"} and node["op"] == "add":
        return evaluate_expression(node["left"], bindings) + \
               evaluate_expression(node["right"], bindings)
    raise ValueError(f"unsupported serialized value expression: {node}")


def apply_value_summary(summary, left, right, cache_hash, mode="value"):
    if (summary.get("schema_version") != "vm-value-summary-v1" or
            type(left) is not int or type(right) is not int or
            summary["engine_type"] != "cached_nonnegative_PyLong" or
            summary["inputs"] != [
                {"name": "X", "type": "cached_nonnegative_PyLong"},
                {"name": "Y", "type": "cached_nonnegative_PyLong"}] or
            summary["output"]["type"] != "cached_nonnegative_PyLong"):
        return {"status": "unknown(type contract)"}
    if mode == "transition":
        return {"status": "unknown(unresolved native effects)"}
    if mode != "value":
        return {"status": "unknown(requested scope)"}
    guard = summary["guard"]
    if (guard["cache_sha256"] != cache_hash or
            summary["evidence"]["cache_sha256"] != cache_hash):
        return {"status": "unknown(cache identity)"}
    if not guard["minimum_x"] <= left <= guard["maximum_x"] or \
            right != guard["right_equals"]:
        return {"status": "unknown(outside proved domain)"}
    return {"status": "applied", "value": evaluate_expression(
        summary["output"]["value_expression"], {"X": left, "Y": right})}


def main():
    source_meta, source_rows, source_end = load_trace(SOURCE, "python", 9, PYTHON)
    target_meta, target_rows, target_end = load_trace(TARGET, "python", 0, PYTHON)
    source_cache_hash = verify_cache(source_meta)
    if verify_cache(target_meta) != source_cache_hash:
        raise ValueError("source and target cache images differ")
    cache = read_vaddr(PYTHON, CACHE_BASE, CACHE_BASE + CACHE_COUNT * CACHE_STRIDE)
    source_add, source_ret = add_segment(source_rows)
    target_add, target_ret = add_segment(target_rows)
    if [(r["pc"], r["bytes"], r["next_pc"]) for r in source_add] != [
            (r["pc"], r["bytes"], r["next_pc"]) for r in target_add]:
        raise ValueError("target uses a different native handler path")
    source_inputs = observed_operands(source_add, cache)
    target_inputs = observed_operands(target_add, cache)
    if ([item["value"] for item in source_inputs] != [9, 5] or
            [item["value"] for item in target_inputs] != [5, 5] or
            source_inputs[0]["pointer"] == target_inputs[0]["pointer"] or
            source_inputs[0]["slot"] == target_inputs[0]["slot"]):
        raise ValueError("source and target are not distinct cached objects and frames")
    x = z3.BitVec("PYTHON_ABSTRACT_INPUT", 32)
    memory, _ = small_int_memory(source_add,
        int(source_inputs[0]["pointer"], 16), 9, x)
    model, guard, stats = checked_segment(source_add, PYTHON, memory)
    source_output = output_write(source_add, source_ret)
    source_expected_ptr = z3.BitVecVal(CACHE_BASE, 64) + \
        ((z3.ZeroExt(32, x) + z3.BitVecVal(10, 64)) << 5)
    unsat(bounded(x), z3.Not(guard))
    unsat(bounded(x), guard,
          word(model.memory, int(source_output["slot"], 16)) != source_expected_ptr)
    if (cache_value(cache, int(source_output["pointer"], 16)) != 14 or
            source_end["output_raw"] != int(source_output["pointer"], 16)):
        raise ValueError("source result is inconsistent with the numeric abstraction")
    # The public contract carries values, types and a bounded path guard.
    # Native addresses and object pointers belong only to the evidence and
    # the target's cache resolver, not to the reusable value expression.
    summary = {"schema_version": "vm-value-summary-v1",
        "engine_type": "cached_nonnegative_PyLong",
        "inputs": [{"name": "X", "type": "cached_nonnegative_PyLong"},
                   {"name": "Y", "type": "cached_nonnegative_PyLong"}],
        "guard": {"minimum_x": 5, "maximum_x": 251, "right_equals": 5,
                  "cache_sha256": source_cache_hash},
        "output": {"type": "cached_nonnegative_PyLong",
                   "value_expression": {"op": "add", "left": {"var": "X"},
                                        "right": {"const": 5}}},
        "effect_scope": "numeric result only; other native writes remain unresolved",
        "proof_scope": "source P-code proof specializes object/frame addresses and other native state; target is a concrete differential check",
        "evidence": {"binary_sha256": source_meta["binary_sha256"],
                     "source_trace_sha256": sha256(SOURCE.read_bytes()).hexdigest(),
                     "cache_sha256": source_cache_hash,
                     "source_input_value": 9, "source_output_value": 14,
                     "source_native_steps": stats["native_steps"],
                     "source_pcode_operations": stats["pcode_operations"],
                     "source_guard_count": stats["guard_count"],
                     "conditional_equality": "unsat counterexample"}}
    SUMMARY.write_text(json.dumps(summary, indent=2) + "\n")
    reloaded = json.loads(SUMMARY.read_text())
    target_x, target_y = [item["value"] for item in target_inputs]
    if (reloaded["evidence"]["binary_sha256"] != target_meta["binary_sha256"] or
            reloaded["evidence"]["source_trace_sha256"] != sha256(SOURCE.read_bytes()).hexdigest()):
        raise ValueError("serialized source proof identity mismatch")
    application = apply_value_summary(reloaded, target_x, target_y, source_cache_hash)
    if application["status"] != "applied":
        raise ValueError(f"target summary application failed: {application}")
    predicted_value = application["value"]
    target_output = output_write(target_add, target_ret)
    target_pointer = int(target_output["pointer"], 16)
    if (cache_value(cache, target_pointer) != predicted_value or
            target_pointer != CACHE_BASE + (predicted_value + 5) * CACHE_STRIDE or
            target_end["output_raw"] != target_pointer):
        raise ValueError("reused numeric summary disagrees with target result")
    native_writes = [access for row in target_add for access in row["memory"]
                     if access["access"] & 2]
    negative_probes = {
        "below_domain": apply_value_summary(reloaded, 4, 5, source_cache_hash),
        "wrong_right_operand": apply_value_summary(reloaded, 9, 6, source_cache_hash),
        "wrong_cache": apply_value_summary(reloaded, 9, 5, "wrong-cache-digest"),
        "full_transition": apply_value_summary(reloaded, 9, 5, source_cache_hash,
                                                mode="transition"),
        "wrong_type": apply_value_summary(
            {**reloaded, "engine_type": "unknown-object"}, 9, 5, source_cache_hash)}
    if any(not item["status"].startswith("unknown(")
           for item in negative_probes.values()):
        raise ValueError("an invalid summary application was accepted")
    result = {"status": "conditional Python numeric-value summary reused",
        "summary_sha256": sha256(SUMMARY.read_bytes()).hexdigest(),
        "target_trace_sha256": sha256(TARGET.read_bytes()).hexdigest(),
        "source_input": source_inputs, "target_input": target_inputs,
        "source_result": source_output, "target_result": target_output,
        "predicted_numeric_result": predicted_value,
        "observed_numeric_result": cache_value(cache, target_pointer),
        "target_native_steps": len(target_add),
        "target_pcode_steps_replayed": 0,
        "negative_probes": negative_probes,
        "target_other_native_writes_outside_value_contract": len(native_writes) - 1,
        "limits": ["source P-code proof specializes native object/frame addresses and other state",
                   "target is concrete differential validation, not a theorem for arbitrary cached-object/frame states",
                   "cached PyLong path and verified fixed binary cache image only",
                   "non-result writes and errors require an effect-aware summary"]}
    RESULT.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"source_value": 9, "target_value": target_x,
                      "target_result": predicted_value,
                      "target_pcode_steps_replayed": 0,
                      "other_writes": len(native_writes) - 1}))


if __name__ == "__main__":
    main()
