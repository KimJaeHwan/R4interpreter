"""Backward native P-code provenance from caller RAX across the full JS trace.

This is a concrete path-local byte-lane slice. It discovers value producers and
memory bridges before the daasdmlkas SSA query narrows each local expression.
It records missing/ambiguous effects instead of treating them as proofs.
"""
from __future__ import annotations

from collections import Counter
import gzip
from hashlib import sha256
import json
from pathlib import Path

import pypcode


ROOT = Path(__file__).resolve().parent
TRACE = ROOT / "artifacts/cross_js_full_9.json.gz"
RESULT = ROOT / "js_caller_backward_slice_result.json"


def lanes(space, offset, size, step):
    return {(space, step if space == "unique" else 0, offset + index)
            for index in range(size)}


def node_lanes(node, step):
    kind = node.space.name
    if kind == "register":
        return lanes("register", node.offset, node.size, step)
    if kind == "unique":
        return lanes("unique", node.offset, node.size, step)
    if kind == "ram":
        return lanes("memory", node.offset, node.size, step)
    if kind == "const":
        return set()
    raise ValueError(f"unsupported P-code varnode space {kind}")


def memory_candidates(row, width, mode):
    return [entry for entry in row["memory"]
            if entry["size"] == width and entry["access"] & mode]


def selected_sources(operation, row, step, live, debts):
    name = operation.opcode.name
    if name == "STORE":
        width = operation.inputs[2].size
        candidates = memory_candidates(row, width, 2)
        touched = [(entry, lanes("memory", entry["address"], width, step) & live)
                   for entry in candidates]
        touched = [(entry, active) for entry, active in touched if active]
        if not touched:
            return False, set(), set(), []
        if len(candidates) != 1:
            debts.append({"step": step, "pc": hex(row["pc"]),
                          "reason": "ambiguous native memory write address",
                          "candidate_addresses": [hex(x["address"]) for x in candidates]})
        killed = set().union(*(active for _, active in touched))
        source = node_lanes(operation.inputs[2], step)
        return True, killed, source, [entry["address"] for entry, _ in touched]
    if operation.output is None:
        return False, set(), set(), []
    produced = node_lanes(operation.output, step)
    active = produced & live
    if not active:
        return False, set(), set(), []
    if name == "LOAD":
        candidates = memory_candidates(row, operation.output.size, 1)
        if not candidates:
            debts.append({"step": step, "pc": hex(row["pc"]),
                          "reason": "selected P-code LOAD lacks captured native read"})
            return True, active, set(), []
        if len(candidates) != 1:
            debts.append({"step": step, "pc": hex(row["pc"]),
                          "reason": "ambiguous native memory read address",
                          "candidate_addresses": [hex(x["address"]) for x in candidates]})
        source = set().union(*(lanes("memory", item["address"], item["size"], step)
                               for item in candidates))
        return True, active, source, [item["address"] for item in candidates]
    if name in {"CALLOTHER", "INDIRECT"}:
        debts.append({"step": step, "pc": hex(row["pc"]),
                      "reason": f"selected opaque P-code operation {name}"})
    source = set().union(*(node_lanes(item, step) for item in operation.inputs))
    return True, active, source, []


def caller_slice(rows):
    ctx = pypcode.Context("x86:LE:64:default")
    lifted = {}
    live = lanes("register", 0, 8, 0)  # Caller-visible RAX at the dispatch cutpoint.
    selected = []
    debts = []
    return_edges = []
    step_counts = Counter()
    excluded = Counter()
    excluded_examples = {}
    selected_internal_controls = []
    for step in range(len(rows) - 1, -1, -1):
        row = rows[step]
        signature = (row["pc"], row["bytes"])
        if signature not in lifted:
            lifted[signature] = [op for op in ctx.translate(
                bytes.fromhex(row["bytes"]), base_address=row["pc"],
                max_instructions=1).ops if op.opcode.name != "IMARK"]
        operations = lifted[signature]
        live_after = set(live)
        matched_native_writes = set()
        selected_ordinals = set()
        for ordinal in range(len(operations) - 1, -1, -1):
            operation = operations[ordinal]
            included, killed, source, addresses = selected_sources(
                operation, row, step, live, debts)
            if not included:
                continue
            live.difference_update(killed)
            live.update(source)
            if operation.opcode.name == "STORE":
                matched_native_writes.update(addresses)
            selected.append({"step": step, "pc": hex(row["pc"]),
                             "ordinal": ordinal, "opcode": operation.opcode.name,
                             "memory_addresses": [hex(x) for x in addresses]})
            selected_ordinals.add(ordinal)
            step_counts[step] += 1
        if selected_ordinals and any(op.opcode.name == "CBRANCH" for op in operations):
            selected_internal_controls.append({"step": step, "pc": hex(row["pc"]),
                                               "instruction": row["instruction"]})
        for access in row["memory"]:
            if (access["access"] & 2 and access["address"] not in matched_native_writes and
                    lanes("memory", access["address"], access["size"], step) & live_after):
                debts.append({"step": step, "pc": hex(row["pc"]),
                              "reason": "selected native write has no modeled P-code STORE",
                              "address": hex(access["address"])})
            elif access["access"] & 2 and access["address"] not in matched_native_writes:
                excluded["native_memory_writes_outside_value_slice"] += 1
                excluded_examples.setdefault("native_memory_writes_outside_value_slice", {
                    "step": step, "pc": hex(row["pc"]), "address": hex(access["address"])})
        for operation in operations:
            if operation.opcode.name in {"CALL", "CALLIND", "RETURN", "CBRANCH",
                                         "BRANCH", "BRANCHIND", "CALLOTHER"}:
                category = "control_or_opaque_" + operation.opcode.name.lower()
                excluded[category] += 1
                excluded_examples.setdefault(category, {"step": step,
                    "pc": hex(row["pc"]), "instruction": row["instruction"]})
        dangling = {item for item in live if item[0] == "unique" and item[1] == step}
        if dangling:
            debts.append({"step": step, "pc": hex(row["pc"]),
                          "reason": "unresolved instruction-local unique value",
                          "byte_count": len(dangling)})
            live.difference_update(dangling)
        if row["instruction"].startswith("ret") and any(
                item[0] == "register" and item[2] < 8 for item in live_after):
            return_edges.append({"step": step, "pc": hex(row["pc"]),
                                 "next_pc": hex(row["next_pc"]),
                                 "rax": hex(row["registers"]["rax"])})
    selected.sort(key=lambda item: (item["step"], item["ordinal"]))
    if selected_internal_controls:
        debts.append({"reason": "selected native instruction contains internal P-code control",
                      "examples": selected_internal_controls[:8],
                      "count": len(selected_internal_controls)})
    audit = {"excluded_counts": dict(sorted(excluded.items())),
             "excluded_examples": excluded_examples,
             "selected_internal_control_instructions": len(selected_internal_controls),
             "interpretation": "excluded effects do not touch the demanded concrete value bytes on this recorded path; control edges and unknown-address effects are not generally proved safe"}
    return selected, debts, live, return_edges, len(lifted), len(step_counts), audit


def group_entry_sources(inputs, parent_address, rows, selected, add_step):
    addresses = sorted(item[2] for item in inputs if item[0] == "memory")
    groups = []
    for address in addresses:
        if not groups or address != groups[-1]["address"] + groups[-1]["size"]:
            groups.append({"address": address, "size": 0})
        groups[-1]["size"] += 1
    for group in groups:
        start, end = group["address"], group["address"] + group["size"]
        readers = [(item, access) for item in selected if item["opcode"] == "LOAD"
                   for access in rows[item["step"]]["memory"]
                   if access["access"] & 1 and access["address"] < end and
                   access["address"] + access["size"] > start]
        group["first_selected_read"] = ({"step": readers[0][0]["step"],
            "pc": readers[0][0]["pc"], "value_raw": readers[0][1]["before"]}
            if readers else None)
        if start == parent_address and group["size"] == 8:
            group["role"] = "parent_parameter"
        elif (group["size"] == 1 and readers and readers[0][0]["step"] < add_step and
              add_step - readers[0][0]["step"] < 32):
            group["role"] = "observed_bytecode_immediate"
        else:
            group["role"] = "other_runtime_input_or_generated_code"
        group["address"] = hex(start)
    return groups


def discover_value_chain(rows, selected, meta, summary, returns):
    parent_address = meta["entry_value_address"]
    watches = {item["label"]: item for item in summary["hardware_watch_intervals"]}
    child_address = watches["child_parameter"]["address"]
    def events(opcode, address):
        return [item for item in selected if item["opcode"] == opcode and
                address in (int(value, 16) for value in item["memory_addresses"])]
    parent_reads = events("LOAD", parent_address)
    child_writes = events("STORE", child_address)
    child_reads = events("LOAD", child_address)
    if len(parent_reads) != 1 or len(child_writes) != 1 or len(child_reads) != 1:
        raise ValueError("caller/child parameter bridge is ambiguous")
    candidates = [item for item in selected if item["opcode"] == "INT_ADD" and
        item["step"] > child_reads[0]["step"] and
        item["step"] < len(rows) and
        any(rows[item["step"]]["registers_after"][reg] == summary["output_raw"] and
            rows[item["step"]]["registers"][reg] != summary["output_raw"]
            for reg in ("rax", "rbx", "rcx", "rdx", "rsi", "rdi"))]
    if len(candidates) != 1:
        raise ValueError(f"value-producing arithmetic is ambiguous: {candidates}")
    add = candidates[0]
    bridge = [parent_reads[0], child_writes[0], child_reads[0], add]
    if [item["step"] for item in bridge] != sorted(item["step"] for item in bridge):
        raise ValueError("discovered bridge is out of execution order")
    child_writes_after_source = [access for access in rows[child_writes[0]["step"]]["memory"]
                                 if access["address"] == child_address]
    if (len(child_writes_after_source) != 1 or
            child_writes_after_source[0]["after"] != meta["entry_value_raw"] or
            rows[child_reads[0]["step"]]["memory"][0]["before"] != meta["entry_value_raw"]):
        raise ValueError("concrete parent/child value bridge mismatch")
    return {"parent_parameter_read": parent_reads[0],
            "child_parameter_write": child_writes[0],
            "child_parameter_read": child_reads[0],
            "value_arithmetic": add,
            "returned_result_edges": [edge for edge in sorted(returns, key=lambda x:x["step"])
                                      if edge["step"] > add["step"] and
                                      int(edge["rax"], 16) == summary["output_raw"]],
            "observed_parameter_raw": meta["entry_value_raw"],
            "observed_result_raw": summary["output_raw"],
            "watch_noninterference": {
                "parent": {"address": hex(parent_address),
                           "start_step": watches["parent_parameter"]["start_step"],
                           "end_step": watches["parent_parameter"]["end_step"]},
                "child": {"address": hex(child_address),
                          "start_step": watches["child_parameter"]["start_step"],
                          "end_step": watches["child_parameter"]["end_step"]},
                "write_hits": summary["hardware_watch_events"],
                "read_hits": summary["hardware_read_events"]}}


def main():
    with gzip.open(TRACE, "rt") as stream:
        records = [json.loads(line) for line in stream]
    meta, summary = records[0], records[-1]
    rows = records[1:-1]
    if (meta["engine"] != "javascript" or not summary["through_return"] or
            summary["steps"] != len(rows) or
            summary["output_raw"] != 14 << 32 or
            any(a["next_pc"] != b["pc"] for a, b in zip(rows, rows[1:]))):
        raise ValueError("full caller trace is incomplete or changed")
    selected, debts, inputs, returns, lifted, selected_steps, audit = caller_slice(rows)
    selected_pcs = {item["pc"] for item in selected}
    chain = discover_value_chain(rows, selected, meta, summary, returns)
    groups = group_entry_sources(inputs, meta["entry_value_address"], rows,
                                 selected, chain["value_arithmetic"]["step"])
    report = {"status": "concrete path-local caller-result backward slice",
        "trace_sha256": sha256(TRACE.read_bytes()).hexdigest(),
        "binary_sha256": meta["binary_sha256"],
        "caller_result": {"location": "RAX", "value_raw": summary["output_raw"]},
        "native_steps": len(rows), "distinct_native_instructions_lifted": lifted,
        "selected_steps": selected_steps, "selected_pcode_operations": len(selected),
        "selected": selected, "return_edges_with_live_result": sorted(returns,
            key=lambda item: item["step"]),
        "discovered_value_chain": chain,
        "entry_source_groups": groups,
        "excluded_region_audit": audit,
        "entry_sources": [{"kind": kind, "step": step, "address": hex(offset)}
                          for kind, step, offset in sorted(inputs)],
        "debts": debts,
        "limits": ["concrete recorded path and observed memory addresses only",
                   "branch feasibility and unobserved memory effects require separate checks",
                   "call/return control edges are reported, not proved by data-only slicing"]}
    RESULT.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"selected_steps": selected_steps,
                      "selected_operations": len(selected),
                      "entry_source_bytes": len(inputs),
                      "return_edges": len(returns),
                      "debts": len(debts),
                      "key_pcs": sorted(selected_pcs & {
                          "0x1bb77a6", "0x1ba8d09", "0x1bbdb33"})}))


if __name__ == "__main__":
    main()
