"""Use daasdmlkas SSA/backward slices to select real AddSmi path dependencies.

The observed straight-line native prefix is wrapped as a path-local P-code
function. Native branch directions remain external evidence, not a claim that
the static CFG or all runtime paths have been reconstructed.
"""
from __future__ import annotations

import gzip
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


ROOT = Path(__file__).resolve().parent
TDO_REPO = Path(os.environ.get("DAASDMLKAS_REPO", ROOT.parents[2] / "daasdmlkas"))
sys.path[:0] = [str(TDO_REPO / "src"), str(TDO_REPO / "tests/intra")]

from synthetic import (RAM, FunctionBuilder, const, normalize_with_observation,
                       op, operation_node_at, ram, reg, tmp)
from tdo_v2.graph_contracts import NodeKind
from tdo_v2.query import BackwardSliceQuery

from prove_cross_value_path import lifted_instructions
from prove_js_summary_reuse import prefix


TRACE = ROOT / "artifacts/js_summary_reuse_9.json.gz"
CALLER_TRACE = ROOT / "artifacts/cross_js_full_9.json.gz"
CALLER_RESULT = ROOT / "js_caller_backward_slice_result.json"
BOUNDARY = ROOT / "js_boundary_discovery_result.json"
RESULT = ROOT / "js_slice_selection_result.json"
CONTROL_OPS = {"CBRANCH", "BRANCH", "BRANCHIND", "CALL", "CALLIND", "RETURN"}


def converted_node(node, instruction_index):
    kind, offset, size = node["kind_code"], node["byte_offset"], node["byte_size"]
    if kind == 1:
        return const(offset, size)
    if kind == 2:
        return reg(offset, size)
    if kind == 3:
        # SLEIGH unique-space slots may be reused by different instructions.
        return tmp(offset + instruction_index * 0x1000000, size)
    if kind == 4:
        return ram(offset, size)
    raise ValueError(f"unsupported P-code storage kind {kind}")


def build_observation(rows, lifted):
    builder = FunctionBuilder()
    by_position = {}
    total_operations = 0
    for index, row in enumerate(rows):
        converted = []
        native_operations = lifted[row["pc"]]["operations"]
        for ordinal, item in enumerate(native_operations):
            total_operations += 1
            if item["opcode"] in CONTROL_OPS:
                if item["opcode"] != "CBRANCH" or ordinal != len(native_operations) - 1:
                    raise ValueError("unsafe control operation in path-local SSA adapter")
                continue
            inputs = [converted_node(node, index) for node in item["inputs"]]
            if item["opcode"] in ("LOAD", "STORE"):
                # pypcode's constant space identifier is not the synthetic
                # observation's RAM id; the second operand is still original.
                inputs[0] = const(RAM)
            output = converted_node(item["output"], index) if item["output_present"] else None
            by_position[(index, len(converted))] = (row["pc"], ordinal, item["opcode"])
            converted.append(op(item["opcode"], inputs, output))
        builder.ins(*converted)
    builder.ret(realistic=False)
    function, observation = normalize_with_observation(builder)
    return function, observation, by_position, total_operations


def operation_map(nodes, function, by_position):
    selected = []
    for node in nodes:
        record = function.dependencies.node(node)
        if record.kind is not NodeKind.OPERATION:
            continue
        parts = record.key.split(":")
        if len(parts) < 5 or parts[0] != "op":
            raise ValueError(f"unexpected SSA operation key {record.key}")
        index = (int(parts[2], 16) - 0x1000) // 4
        ordinal = int(parts[3])
        if (index, ordinal) not in by_position:
            raise ValueError("slice reached an unmapped or synthetic operation")
        pc, native_ordinal, opcode = by_position[(index, ordinal)]
        selected.append({"native_pc": hex(pc), "pcode_ordinal": native_ordinal,
                         "opcode": opcode})
    return sorted(selected, key=lambda item: (int(item["native_pc"], 16),
                                               item["pcode_ordinal"]))


def previous_definition(lifted, rows, position, node, native_to_synthetic):
    identity = (node["kind_code"], node["byte_offset"], node["byte_size"])
    for index in range(position[0], -1, -1):
        operations = lifted[rows[index]["pc"]]["operations"]
        end = position[1] if index == position[0] else len(operations)
        for ordinal in range(end - 1, -1, -1):
            item = operations[ordinal]
            output = item["output"]
            if output and (output["kind_code"], output["byte_offset"],
                           output["byte_size"]) == identity:
                if (index, ordinal) not in native_to_synthetic:
                    raise ValueError("predicate producer was excluded from SSA observation")
                return native_to_synthetic[(index, ordinal)]
    raise ValueError("branch predicate producer is outside selected native prefix")


def main():
    with gzip.open(TRACE, "rt") as stream:
        records = [json.loads(line) for line in stream]
    meta, path = records[:2]
    binary = Path(shutil.which("node"))
    if meta["binary_sha256"] != sha256(binary.read_bytes()).hexdigest():
        raise ValueError("Node code hash changed")
    rows = prefix(path["rows"])
    lifted = lifted_instructions(binary, rows)
    function, observation, by_position, total_ops = build_observation(rows, lifted)
    caller = json.loads(CALLER_RESULT.read_text())
    if (caller["trace_sha256"] != sha256(CALLER_TRACE.read_bytes()).hexdigest() or
            caller["binary_sha256"] != meta["binary_sha256"] or caller["debts"] or
            not any(group["role"] == "parent_parameter"
                    for group in caller["entry_source_groups"])):
        raise ValueError("caller-result backward slice evidence is stale or unresolved")
    discovered_add = caller["discovered_value_chain"]["value_arithmetic"]
    native_to_synthetic = {(index, native_ordinal): (index, synthetic_ordinal)
                           for (index, synthetic_ordinal), (_, native_ordinal, _)
                           in by_position.items()}
    sink_candidates = [(index, ordinal) for (index, ordinal), (pc, native_ordinal, opcode)
                       in by_position.items()
                       if opcode == "INT_ADD" and hex(pc) == discovered_add["pc"] and
                       native_ordinal == discovered_add["ordinal"] and
                       observation.instructions[index].operations[ordinal].output is not None and
                       observation.instructions[index].operations[ordinal].output.coordinate.byte_offset == 24]
    if len(sink_candidates) != 1:
        raise ValueError(f"result sink is ambiguous: {sink_candidates}")
    query = BackwardSliceQuery()

    def run_slice(index, ordinal):
        seed = operation_node_at(function, index, ordinal)
        result = query.run(function, seed)
        return {"selected": operation_map(result.reachable_nodes, function, by_position),
                "nodes": len(result.reachable_nodes),
                "observed_inputs": len(result.observed_input_nodes),
                "unresolved_reads": len(result.reachable_unresolved_read_nodes)}

    value = run_slice(*sink_candidates[0])
    guards = []
    for index, row in enumerate(rows):
        for ordinal, item in enumerate(lifted[row["pc"]]["operations"]):
            if item["opcode"] != "CBRANCH":
                continue
            producer = previous_definition(lifted, rows, (index, ordinal),
                                           item["inputs"][1], native_to_synthetic)
            guard_slice = run_slice(*producer)
            guards.append({"branch_pc": hex(row["pc"]),
                           "taken": row["next_pc"] == item["inputs"][0]["byte_offset"],
                           "producer_pc": hex(rows[producer[0]]["pc"]),
                           **guard_slice})
    if [item["branch_pc"] for item in guards] != ["0x1bb779d", "0x1bb77a9"]:
        raise ValueError("native branch sites changed")
    value_pcs = {item["native_pc"] for item in value["selected"]}
    if (not {"0x1bb7780", "0x1bb778f", "0x1bb77a3", "0x1bb77a6"} <= value_pcs or
            {"0x1bb7793", "0x1bb7797"} & value_pcs or
            value["unresolved_reads"]):
        raise ValueError("value slice did not isolate the AddSmi arithmetic dependencies")
    selected = {(item["native_pc"], item["pcode_ordinal"])
                for part in [value, *guards] for item in part["selected"]}
    report = {"status": "path-local SSA data and predicate producer slices",
        "trace_sha256": sha256(TRACE.read_bytes()).hexdigest(),
        "binary_sha256": meta["binary_sha256"],
        "daasdmlkas_commit": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=TDO_REPO, text=True).strip(),
        "source": "real SLEIGH P-code, wrapped as an observed straight-line native path",
        "caller_trace_sha256": caller["trace_sha256"],
        "boundary_discovery_sha256": sha256(BOUNDARY.read_bytes()).hexdigest(),
        "caller_value_chain": caller["discovered_value_chain"],
        "caller_entry_source_groups": caller["entry_source_groups"],
        "caller_excluded_region_audit": caller["excluded_region_audit"],
        "sink": {"pc": discovered_add["pc"], "register": "rbx", "width": 8},
        "native_instructions": len(rows), "pcode_operations": total_ops,
        "value_slice": value, "predicate_producers": guards,
        "union_selected_pcode_operations": len(selected),
        "excluded_frame_load_pcs": ["0x1bb7793", "0x1bb7797"],
        "unresolved": ["caller-level control and excluded-region opaque effects need separate checks",
                       "branch direction and path feasibility are checked by native replay/Z3",
                       "path-local SSA does not prove interprocedural or alternate paths",
                       "unmodeled memory aliases outside the observed prefix remain unknown"]}
    RESULT.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"value_slice_operations": len(value["selected"]),
                      "predicate_slices": [len(g["selected"]) for g in guards],
                      "union_operations": len(selected),
                      "total_pcode_operations": total_ops}))


if __name__ == "__main__":
    main()
