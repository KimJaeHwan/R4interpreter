"""Discover observed JS handler and arithmetic-prefix cutpoints from P-code.

The caller slice supplies the arithmetic operation, not a hand-selected PC.
This only identifies boundaries on these recorded paths. It does not infer a
static CFG or promise that alternate exits share the same successor.
"""
from __future__ import annotations

import gzip
from hashlib import sha256
import json
from pathlib import Path

import pypcode


ROOT = Path(__file__).resolve().parent
CALLER_TRACE = ROOT / "artifacts/cross_js_full_9.json.gz"
REUSE_TRACE = ROOT / "artifacts/js_summary_reuse_9.json.gz"
CALLER_SLICE = ROOT / "js_caller_backward_slice_result.json"
RESULT = ROOT / "js_boundary_discovery_result.json"


def read_trace(path):
    with gzip.open(path, "rt") as stream:
        return [json.loads(line) for line in stream]


def pcode_names(row, context, cache):
    key = (row["pc"], row["bytes"])
    if key not in cache:
        cache[key] = [item.opcode.name for item in context.translate(
            bytes.fromhex(row["bytes"]), base_address=row["pc"],
            max_instructions=1).ops]
    return cache[key]


def find_boundary(rows, arithmetic, context, cache, full_handler=True):
    additions = [index for index, row in enumerate(rows)
                 if hex(row["pc"]) == arithmetic["pc"] and
                 pcode_names(row, context, cache)[arithmetic["ordinal"] + 1] == "INT_ADD"]
    if len(additions) != 1:
        raise ValueError(f"value-producing arithmetic is not unique: {additions}")
    add_index = additions[0]
    exit_indices = [index for index in range(add_index + 1, len(rows))
                    if "BRANCHIND" in pcode_names(rows[index], context, cache)]
    if full_handler and not exit_indices:
        raise ValueError("observed handler did not reach an indirect dispatch")
    end_index = exit_indices[0] if exit_indices else len(rows) - 1
    post_add_branches = [index for index in range(add_index + 1, end_index)
                         if "CBRANCH" in pcode_names(rows[index], context, cache)]
    if not post_add_branches:
        raise ValueError("no arithmetic-path conditional cutpoint")
    prefix_end = post_add_branches[0]
    if (any(access["access"] & 2 for row in rows[:prefix_end + 1]
             for access in row["memory"]) or
            any(set(pcode_names(row, context, cache)) & {"CALL", "CALLIND", "RETURN",
                                                         "CALLOTHER", "BRANCHIND"}
                for row in rows[:prefix_end + 1])):
        raise ValueError("candidate arithmetic prefix contains side effects or opaque control")
    return {"arithmetic_index": add_index, "prefix_end_index": prefix_end,
            "prefix_exit_pc": hex(rows[prefix_end]["next_pc"]),
            "prefix_exit_branch_pc": hex(rows[prefix_end]["pc"]),
            "handler_dispatch_index": end_index if exit_indices else None,
            "handler_dispatch_pc": hex(rows[end_index]["pc"]) if exit_indices else None,
            "next_handler_pc": hex(rows[end_index]["next_pc"]) if exit_indices else None}


def main():
    caller = json.loads(CALLER_SLICE.read_text())
    full = read_trace(CALLER_TRACE)
    reuse = read_trace(REUSE_TRACE)
    full_meta, full_summary = full[0], full[-1]
    reuse_meta, paths, reuse_summary = reuse[0], reuse[1:-1], reuse[-1]
    if (caller["trace_sha256"] != sha256(CALLER_TRACE.read_bytes()).hexdigest() or
            caller["binary_sha256"] != full_meta["binary_sha256"] or
            full_meta["binary_sha256"] != reuse_meta["binary_sha256"] or
            len(paths) != 2 or reuse_summary["paths"] != 2 or
            not full_summary["through_return"]):
        raise ValueError("boundary discovery input traces are stale")
    arithmetic = caller["discovered_value_chain"]["value_arithmetic"]
    context = pypcode.Context("x86:LE:64:default")
    cache = {}
    full_rows = full[1:-1]
    full_add_step = arithmetic["step"]
    if full_rows[full_add_step]["pc"] != int(arithmetic["pc"], 16):
        raise ValueError("caller arithmetic step mismatch")
    entry_branches = [index for index in range(full_add_step - 1, -1, -1)
                      if "BRANCHIND" in pcode_names(full_rows[index], context, cache)]
    if not entry_branches:
        raise ValueError("handler entry dispatch not found")
    entry_dispatch = entry_branches[0]
    entry_step = entry_dispatch + 1
    entry_pc = full_rows[entry_step]["pc"]
    if full_rows[entry_dispatch]["next_pc"] != entry_pc:
        raise ValueError("entry dispatch does not lead to handler")
    full_boundary = find_boundary(full_rows[entry_step:], arithmetic, context, cache)
    path_boundaries = []
    for path in paths:
        rows = path["rows"]
        if rows[0]["pc"] != entry_pc or any(a["next_pc"] != b["pc"]
                                         for a, b in zip(rows, rows[1:])):
            raise ValueError("reuse path has a different entry or is discontinuous")
        boundary = find_boundary(rows, arithmetic, context, cache)
        if rows[boundary["handler_dispatch_index"]] is not rows[-1]:
            raise ValueError("recorded local path extends beyond handler dispatch")
        path_boundaries.append(boundary)
    first, second = (path["rows"] for path in paths)
    end_indices = [item["prefix_end_index"] for item in path_boundaries]
    if (end_indices[0] != end_indices[1] or
            [(row["pc"], row["bytes"], row["next_pc"]) for row in first[:end_indices[0]+1]] !=
            [(row["pc"], row["bytes"], row["next_pc"]) for row in second[:end_indices[1]+1]] or
            path_boundaries[0]["prefix_exit_pc"] != full_boundary["prefix_exit_pc"] or
            path_boundaries[0]["prefix_exit_branch_pc"] != full_boundary["prefix_exit_branch_pc"]):
        raise ValueError("arithmetic-prefix cutpoint does not transfer between traces")
    report = {"status": "observed P-code control boundary discovery",
        "full_trace_sha256": caller["trace_sha256"],
        "reuse_trace_sha256": sha256(REUSE_TRACE.read_bytes()).hexdigest(),
        "entry_dispatch": {"step": entry_dispatch, "pc": hex(full_rows[entry_dispatch]["pc"]),
                           "opcode": "BRANCHIND", "target_pc": hex(entry_pc)},
        "arithmetic": arithmetic,
        "full_path": {**full_boundary, "entry_step": entry_step,
                      "entry_pc": hex(entry_pc)},
        "reuse_paths": [{**boundary, "bytecode_offset": path["bytecode_offset"]}
                        for boundary, path in zip(path_boundaries, paths)],
        "prefix": {"entry_pc": hex(entry_pc),
                   "end_index_in_local_paths": end_indices[0],
                   "end_branch_pc": full_boundary["prefix_exit_branch_pc"],
                   "exit_pc": full_boundary["prefix_exit_pc"],
                   "native_steps": end_indices[0] + 1},
        "limits": ["boundaries are for observed paths in a pinned Node binary",
                   "other handler exits and bytecode configurations require independent analysis"]}
    RESULT.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"entry": report["prefix"]["entry_pc"],
                      "prefix_exit": report["prefix"]["exit_pc"],
                      "prefix_steps": report["prefix"]["native_steps"],
                      "handler_exits": [item["next_handler_pc"]
                                        for item in path_boundaries]}))


if __name__ == "__main__":
    main()
