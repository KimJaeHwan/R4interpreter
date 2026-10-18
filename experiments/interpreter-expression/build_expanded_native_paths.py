"""Build bounded native transition cases for Python allocation and JS strings.

These are complete observed native paths to the next handler. The BigInt
exception probe stops at an earlier runtime indirect branch and is excluded.
"""
from __future__ import annotations

import gzip
from hashlib import sha256
import json
from pathlib import Path
import shutil

import z3

from cross_dispatch_pcode import read_vaddr
from pcode_transition_summary import FLAG_OFFSETS, REGISTER_OFFSETS
from prove_cross_full_flow import NativePathReplay, PYTHON, ROOT
from prove_cross_value_path import lifted_instructions
from prove_js_handler_transition import observed_accesses, path_shape
from prove_js_summary_reuse import concrete_bindings
from prove_python_value_reuse import CACHE_BASE, observed_operands


ARTIFACTS = ROOT / "artifacts"
PYTHON_SOURCE = ARTIFACTS / "python_holdout_252.json.gz"
JS_SOURCE = ARTIFACTS / "js_string_full_probe_37.json.gz"
PYTHON_SUMMARY = ROOT / "python_allocated_result_summary.json"
JS_SUMMARY = ROOT / "js_string_add_full_handler_summary.json"


def records(path):
    with gzip.open(path, "rt") as stream:
        return [json.loads(line) for line in stream]


def bindings(decls, rows):
    result = concrete_bindings(decls, rows)
    for name in ("fs_base", "gs_base"):
        symbol = decls.get(name.upper())
        if symbol is not None:
            result.append((symbol, z3.BitVecVal(rows[0]["registers"][name], 64)))
    return result


def native_reads(rows):
    return [(hex(row["pc"]), access["address"], access["size"])
            for row in rows for access in row["memory"] if access["access"] & 1]


def make_case(rows, binary, label, preconditions, segment_bases=False):
    regs = {offset: z3.BitVec(f"R_{name.upper()}", 64)
            for offset, name in REGISTER_OFFSETS.items()}
    flags = {offset: z3.BitVec(f"F_{bit}", 8)
             for offset, bit in FLAG_OFFSETS.items()}
    memory = z3.Array("M0", z3.BitVecSort(64), z3.BitVecSort(8))
    model = NativePathReplay(rows[0], rows, lifted_instructions(binary, rows),
                             register_symbols=regs, flag_symbols=flags,
                             memory_symbol=memory, address_guards=False)
    extras = {}
    if segment_bases:
        extras = {name.upper(): z3.BitVec(name.upper(), 64)
                  for name in ("fs_base", "gs_base")}
        model.segment_base_symbols = {name: extras[name.upper()]
                                      for name in ("fs_base", "gs_base")}
    model.run()
    native_writes = observed_accesses(rows, 2)
    if (model.successor is None or
            [(item["pc"], item["observed_address"], item["width"], item["observed"])
             for item in model.effects] !=
            [(item["pc"], item["address"], item["width"], item["value"])
             for item in native_writes]):
        raise ValueError("P-code and native write inventories disagree")
    modeled_reads = list(dict.fromkeys((item["pc"], item["observed_address"],
                                        item["width"]) for item in model.reads))
    if modeled_reads != native_reads(rows):
        raise ValueError("P-code and native read inventories disagree")
    decls = {f"R_{name.upper()}": regs[offset]
             for offset, name in REGISTER_OFFSETS.items()}
    decls.update({f"F_{bit}": flags[offset]
                  for offset, bit in FLAG_OFFSETS.items()})
    decls.update(extras)
    decls["M0"] = memory
    source_sub = bindings(decls, rows)
    if any(not z3.is_true(z3.simplify(z3.substitute(item["condition"],
                                                         *source_sub)))
           for item in model.guards):
        raise ValueError("source witness violates the replayed P-code path")
    return {"label": label,
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
        **({"vm_cursor": z3.simplify(model.regs[160] + model.regs[136]).sexpr()}
           if preconditions["kind"] == "javascript_string" else {}),
        "preconditions": preconditions,
        "interface_extensions": ([{"name": name, "sort": "BV64",
                                  "binding": {"kind": "segment_base",
                                              "name": name.lower()}}
                                 for name in extras] if extras else []),
        "evidence": {"pcode_operations": model.operation_count,
                     "pcode_reads": len(model.reads),
                     "unique_native_reads": len(modeled_reads),
                     "ordered_native_writes": len(model.effects),
                     "path_guard_count": len(model.guards)}}


def main():
    py_meta, py_body, py_result = records(PYTHON_SOURCE)
    js_meta, js_body, js_result = records(JS_SOURCE)
    py_rows, js_rows = py_body["rows"], js_body["rows"]
    node = Path(shutil.which("node"))
    py_hash = sha256(PYTHON.read_bytes()).hexdigest()
    js_hash = sha256(node.read_bytes()).hexdigest()
    cache = read_vaddr(PYTHON, CACHE_BASE, CACHE_BASE + 262 * 32)
    cache_hash = sha256(cache).hexdigest()
    py_operands = observed_operands(py_rows, cache)
    if (py_meta["binary_sha256"] != py_hash or
            py_meta["runtime_cache_sha256_at_entry"] != cache_hash or
            py_meta["runtime_cache_sha256_at_exit"] != cache_hash or
            [item["value"] for item in py_operands] != [252, 5] or
            py_result["output"] != 257 or len(py_rows) != 146):
        raise ValueError("Python allocation source evidence changed")
    py_pre = {"kind": "python_allocated_result", "cache_sha256": cache_hash,
              "minimum_x": 252, "maximum_x": 256, "right": 5,
              "result_kind": "one_digit_positive_PyLong"}
    python_summary = {
        "schema_version": "native-handler-transition-v1",
        "engine": "python", "binary_sha256": py_hash,
        "cache_sha256": cache_hash,
        "scope": "observed cached-input, allocated one-digit PyLong result path",
        "case": make_case(py_rows, PYTHON, "allocated_result_257",
                          py_pre, segment_bases=True),
        "source_trace_sha256": sha256(PYTHON_SOURCE.read_bytes()).hexdigest(),
        "limits": ["input cached PyLong X in [252,256], right operand 5",
                   "allocator state is supplied by target first-read memory",
                   "one observed native path to next handler entry"]}
    if (js_meta["binary_sha256"] != js_hash or
            js_meta["fixture_sha256"] != sha256(
                (ROOT / "js_string_holdout_fixture.js").read_bytes()).hexdigest() or
            js_meta["input"] != 37 or js_meta["input_type"] != "string" or
            not js_meta["full_handler"] or js_result["output"] != "375" or
            len(js_rows) != 230 or js_rows[-1]["next_pc"] != 0x1BC6F40):
        raise ValueError("JavaScript string source evidence changed")
    js_pre = {"kind": "javascript_string",
              "fixture_sha256": js_meta["fixture_sha256"],
              "input_decimal_digits": 2,
              "result_kind": "string_concat_with_5"}
    js_summary = {"schema_version": "native-handler-transition-v1",
        "engine": "javascript", "binary_sha256": js_hash,
        "scope": "observed two-digit string + Smi 5 path to Return handler",
        "cases": [make_case(js_rows, node, "two_digit_string_concat",
                            js_pre)],
        "source_trace_sha256": sha256(JS_SOURCE.read_bytes()).hexdigest(),
        "limits": ["fixed Node --jitless binary and same native path",
                   "string object allocations and writes are modeled as native effects",
                   "different string lengths and exception paths remain unknown"]}
    PYTHON_SUMMARY.write_text(json.dumps(python_summary, indent=2) + "\n")
    JS_SUMMARY.write_text(json.dumps(js_summary, indent=2) + "\n")
    print(json.dumps({"python": python_summary["case"]["evidence"],
                      "javascript": js_summary["cases"][0]["evidence"]}))


if __name__ == "__main__":
    main()
