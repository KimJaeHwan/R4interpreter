"""Freeze five reusable P-code segments for a bounded V8 string-copy loop."""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import shutil

import z3

from build_expanded_native_paths import records
from compose_js_string_loop import (EVEN_SOURCE, LOOP_STEPS, ODD_SOURCE,
                                    PREFIX_END, symbolic_model)
from pcode_transition_summary import FLAG_OFFSETS, REGISTER_OFFSETS
from prove_cross_full_flow import ROOT
from prove_js_handler_transition import observed_accesses, path_shape
from prove_js_summary_reuse import concrete_bindings


OUTPUT = ROOT / "js_string_loop_transition_summary.json"


def make_segment(label, rows, node):
    decls = {f"R_{name.upper()}": z3.BitVec(f"R_{name.upper()}", 64)
             for name in REGISTER_OFFSETS.values()}
    decls.update({f"F_{bit}": z3.BitVec(f"F_{bit}", 8)
                  for bit in FLAG_OFFSETS.values()})
    decls["M0"] = z3.Array("M0", z3.BitVecSort(64), z3.BitVecSort(8))
    model = symbolic_model(rows, node,
        {name: decls[f"R_{name.upper()}"] for name in REGISTER_OFFSETS.values()},
        decls["M0"],
        {bit: decls[f"F_{bit}"] for bit in FLAG_OFFSETS.values()})
    expected_writes = observed_accesses(rows, 2)
    if [(item["pc"], item["observed_address"], item["width"], item["observed"])
        for item in model.effects] != [
            (item["pc"], item["address"], item["width"], item["value"])
            for item in expected_writes]:
        raise ValueError(f"{label}: native/P-code write inventory mismatch")
    modeled_reads = list(dict.fromkeys((item["pc"], item["observed_address"],
                                        item["width"]) for item in model.reads))
    native_reads = [(hex(row["pc"]), item["address"], item["size"])
                    for row in rows for item in row["memory"] if item["access"] & 1]
    if modeled_reads != native_reads:
        raise ValueError(f"{label}: native/P-code read inventory mismatch")
    source_bindings = concrete_bindings(decls, rows)
    if any(not z3.is_true(z3.simplify(z3.substitute(item["condition"],
                                                 *source_bindings)))
           for item in model.guards):
        raise ValueError(f"{label}: source guard failed")
    successor = getattr(model, "successor", None)
    if successor is None:
        successor = z3.BitVecVal(rows[-1]["next_pc"], 64)
    return {"label": label,
            "identity": {"entry_pc": hex(rows[0]["pc"]),
                         "next_pc": hex(rows[-1]["next_pc"]),
                         "native_steps": len(rows),
                         "path_shape_sha256": path_shape(rows)},
            "guard": z3.simplify(z3.And(*(item["condition"]
                                           for item in model.guards))).sexpr(),
            "outputs": ([{"name": f"R_{name.upper()}", "sort": "BV64",
                          "expression": z3.simplify(model.regs[offset]).sexpr()}
                         for offset, name in REGISTER_OFFSETS.items()] +
                        [{"name": f"F_{bit}", "sort": "BV8",
                          "expression": z3.simplify(model.flags[offset]).sexpr()}
                         for offset, bit in FLAG_OFFSETS.items()]),
            "reads": [{"pc": item["pc"], "width": item["width"],
                       "address": z3.simplify(item["address"]).sexpr(),
                       "value": z3.simplify(item["value_expression"]).sexpr()}
                      for item in model.reads],
            "effects": [{"kind": "Write", "pc": item["pc"],
                         "width": item["width"],
                         "address": z3.simplify(item["address"]).sexpr(),
                         "value": z3.simplify(item["value"]).sexpr()}
                        for item in model.effects],
            "successor": z3.simplify(successor).sexpr(),
            "evidence": {"source_pcode_operations": model.operation_count,
                         "source_guards": len(model.guards),
                         "source_unique_native_reads": len(modeled_reads),
                         "source_ordered_writes": len(model.effects)}}


def main():
    odd = records(ODD_SOURCE)[1]["rows"]
    even = records(EVEN_SOURCE)[1]["rows"]
    node = Path(shutil.which("node"))
    segments = [
        make_segment("prefix", odd[:PREFIX_END], node),
        make_segment("pair_continue", even[PREFIX_END:PREFIX_END + LOOP_STEPS], node),
        make_segment("pair_exit", odd[PREFIX_END:PREFIX_END + LOOP_STEPS], node),
        make_segment("odd_tail_and_return", odd[PREFIX_END + LOOP_STEPS:], node),
        make_segment("even_return", even[201:], node),
    ]
    fixture = ROOT / "js_string_holdout_fixture.js"
    summary = {"schema_version": "composed-native-loop-transition-v1",
        "engine": "javascript", "binary_sha256": sha256(node.read_bytes()).hexdigest(),
        "fixture_sha256": sha256(fixture.read_bytes()).hexdigest(),
        "scope": "observed Node --jitless two-to-eleven-digit string + Smi 5 path family",
        "interface": {"inputs": ([{"name": f"R_{name.upper()}", "sort": "BV64"}
                                  for name in REGISTER_OFFSETS.values()] +
                                 [{"name": f"F_{bit}", "sort": "BV8"}
                                  for bit in FLAG_OFFSETS.values()] +
                                 [{"name": "M0", "sort": "Array(BV64,BV8)"}])},
        "loop": {"minimum_digits": 2, "maximum_digits": 11,
                 "entry_cursor": 15, "pair_stride": 2,
                 "pair_count": "floor(decimal_digit_count / 2)",
                 "pair_intermediate": "pair_continue",
                 "pair_final": "pair_exit",
                 "odd_suffix": "odd_tail_and_return",
                 "even_suffix": "even_return",
                 "copy_nonalias": "source and destination character regions do not overlap"},
        "segments": segments,
        "source_traces": {"odd": {"name": ODD_SOURCE.name,
                                  "sha256": sha256(ODD_SOURCE.read_bytes()).hexdigest()},
                          "even": {"name": EVEN_SOURCE.name,
                                   "sha256": sha256(EVEN_SOURCE.read_bytes()).hexdigest()}},
        "limits": ["exact binary and fixture; same prefix and suffix path shapes",
                   "native first-read memory and path observations required for application",
                   "segment effects compose in order; exception and alternative allocation paths unknown"]}
    OUTPUT.write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps({"segments": len(segments),
                      "source_pcode_operations": sum(
                          item["evidence"]["source_pcode_operations"]
                          for item in segments),
                      "summary_sha256": sha256(OUTPUT.read_bytes()).hexdigest()}))


if __name__ == "__main__":
    main()
