"""Backward native P-code provenance from caller RAX across the full JS trace.

This is a concrete path-local byte-lane slice. It discovers value producers and
memory bridges before the daasdmlkas SSA query narrows each local expression.
It records missing/ambiguous effects instead of treating them as proofs.
"""
from __future__ import annotations

import gzip
from hashlib import sha256
import json
from pathlib import Path

from common_native_slice import caller_slice, lanes

ROOT = Path(__file__).resolve().parent
TRACE = ROOT / "artifacts/cross_js_full_9.json.gz"
RESULT = ROOT / "js_caller_backward_slice_result.json"


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
