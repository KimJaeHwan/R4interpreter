"""Freeze the existing CPython PyLong allocation path for the shared core."""
from __future__ import annotations

from hashlib import sha256
import json

import z3

from build_expanded_native_paths import PYTHON_SOURCE, records
from composed_native_transition import path_shape
from pcode_transition_summary import FLAG_OFFSETS, REGISTER_OFFSETS
from prove_cross_full_flow import NativePathReplay, PYTHON, ROOT
from prove_cross_value_path import lifted_instructions
from prove_js_handler_transition import observed_accesses
from prove_js_summary_reuse import concrete_bindings


SOURCE_SUMMARY = ROOT / "python_allocated_result_summary.json"
OUTPUT = ROOT / "python_allocated_composed_summary.json"


def main():
    source = json.loads(SOURCE_SUMMARY.read_text())
    meta, body, result = records(PYTHON_SOURCE)
    rows = body["rows"]
    case = source["case"]
    binary_hash = sha256(PYTHON.read_bytes()).hexdigest()
    if (source["schema_version"] != "native-handler-transition-v1" or
            source["engine"] != "python" or
            source["binary_sha256"] != binary_hash or
            meta["binary_sha256"] != binary_hash or
            result["output"] != 257 or
            case["identity"]["path_shape_sha256"] != path_shape(
                rows, "pc_bytes_next")):
        raise ValueError("Python allocation source identity changed")
    regs = {offset: z3.BitVec(f"R_{name.upper()}", 64)
            for offset, name in REGISTER_OFFSETS.items()}
    flags = {offset: z3.BitVec(f"F_{bit}", 8)
             for offset, bit in FLAG_OFFSETS.items()}
    memory = z3.Array("M0", z3.BitVecSort(64), z3.BitVecSort(8))
    bases = {name: z3.BitVec(name, 64) for name in ("FS_BASE", "GS_BASE")}
    model = NativePathReplay(rows[0], rows, lifted_instructions(PYTHON, rows),
        register_symbols=regs, flag_symbols=flags, memory_symbol=memory,
        address_guards=False)
    model.segment_base_symbols = {name.lower(): symbol
                                  for name, symbol in bases.items()}
    model.run()
    if (model.operation_count != case["evidence"]["pcode_operations"] or
            len(model.reads) != len(case["reads"]) or
            len(model.effects) != len(case["ordered_effects"]) or
            len(model.guards) != case["evidence"]["path_guard_count"]):
        raise ValueError("Python source P-code inventory changed")
    native_reads = [(hex(row["pc"]), access["address"], access["size"])
                    for row in rows for access in row["memory"]
                    if access["access"] & 1]
    model_reads = list(dict.fromkeys((item["pc"], item["observed_address"],
                                      item["width"]) for item in model.reads))
    if model_reads != native_reads:
        raise ValueError("Python native/P-code read inventory differs")
    model_writes = [(item["pc"], item["observed_address"], item["width"],
                     item["observed"]) for item in model.effects]
    actual_writes = [(item["pc"], item["address"], item["width"], item["value"])
                     for item in observed_accesses(rows, 2)]
    if model_writes != actual_writes:
        raise ValueError("Python native/P-code write inventory differs")
    inputs = ([{"name": f"R_{name.upper()}", "sort": "BV64"}
               for name in REGISTER_OFFSETS.values()] +
              [{"name": f"F_{bit}", "sort": "BV8"}
               for bit in FLAG_OFFSETS.values()] +
              [{"name": "M0", "sort": "Array(BV64,BV8)"}] +
              case["interface_extensions"])
    bindings = concrete_bindings({**{f"R_{name.upper()}": regs[offset]
                                   for offset, name in REGISTER_OFFSETS.items()},
                                  **{f"F_{bit}": flags[offset]
                                     for offset, bit in FLAG_OFFSETS.items()},
                                  "M0": memory}, rows)
    bindings += [(symbol, z3.BitVecVal(
        rows[0]["registers"][name.lower()], 64))
        for name, symbol in bases.items()]
    if any(not z3.is_true(z3.simplify(z3.substitute(
            item["condition"], *bindings))) for item in model.guards):
        raise ValueError("Python source guard failed")
    segment = {"label": "allocated_pylong_path",
        "preserved_state": {name.lower(): "x86_scalar_no_base_write_v1"
                            for name in bases},
        "identity": {"entry_pc": case["identity"]["entry_pc"],
                     "next_pc": case["identity"]["next_handler_pc"],
                     "native_steps": len(rows),
                     "path_shape_mode": "pc_bytes_next",
                     "path_shape_sha256": path_shape(rows, "pc_bytes_next")},
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
        "successor": z3.simplify(model.successor).sexpr(),
        "evidence": {"source_pcode_operations": model.operation_count,
                     "source_guards": len(model.guards),
                     "source_pcode_reads": len(model.reads),
                     "source_unique_native_reads": len(model_reads),
                     "source_ordered_writes": len(model.effects)}}
    if (segment["guard"] != case["guard"] or
            segment["successor"] != case["successor"] or
            [item["expression"] for item in segment["outputs"]] !=
            [item["expression"] for item in case["outputs"]] or
            [tuple(item[key] for key in ("pc", "address", "width", "value"))
             for item in segment["effects"]] !=
            [tuple(item[key] for key in ("pc", "address", "width", "value"))
             for item in case["ordered_effects"]] or
            [tuple(item[key] for key in ("pc", "address", "width"))
             for item in segment["reads"]] !=
            [tuple(item[key] for key in ("pc", "address", "width"))
             for item in case["reads"]]):
        raise ValueError("frozen segment differs from the prior Python transition")
    summary = {"schema_version": "composed-native-segment-transition-v1",
        "engine": "python", "binary_sha256": binary_hash,
        "fixture_sha256": meta["fixture_sha256"],
        "interface": {"inputs": inputs},
        "preconditions": case["preconditions"],
        "segments": [segment],
        "source_trace_sha256": sha256(PYTHON_SOURCE.read_bytes()).hexdigest(),
        "source_summary_sha256": sha256(SOURCE_SUMMARY.read_bytes()).hexdigest(),
        "limits": ["exact CPython binary and bounded cached-input domain",
                   "native first-read memory and path observation required",
                   "Write effects do not prove object allocation or freshness"]}
    OUTPUT.write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps({"native_steps": len(rows),
                      "source_pcode_operations": model.operation_count,
                      "summary_sha256": sha256(OUTPUT.read_bytes()).hexdigest()}))


if __name__ == "__main__":
    main()
