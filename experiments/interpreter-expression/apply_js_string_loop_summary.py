"""Apply a frozen composed V8 loop summary without replaying P-code."""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import shutil

import z3

from build_expanded_native_paths import records
from common_observed_transition import javascript_string_preconditions
from composed_native_transition import apply_segment, evaluate, parse_segments
from compose_js_string_loop import TARGET_VALUES
from freeze_js_string_loop import OUTPUT as SUMMARY
from pcode_transition_summary import FLAG_OFFSETS, REGISTER_OFFSETS
from prove_cross_full_flow import ROOT
from prove_js_string_copy_family import trace_for
from prove_lua_full_flow import initial_memory


RESULT = ROOT / "js_string_frozen_loop_application_result.json"


def apply(summary, decls, parsed, value, meta, rows, observed_result, binary_hash):
    digits = len(str(value))
    loop = summary["loop"]
    if (summary["schema_version"] != "composed-native-loop-transition-v1" or
            summary["engine"] != "javascript" or
            summary["binary_sha256"] != binary_hash or
            meta["binary_sha256"] != binary_hash or
            meta.get("input") != value or
            not loop["minimum_digits"] <= digits <= loop["maximum_digits"]):
        return {"input": value, "status": "unknown(binary/schema/length domain)"}
    pre = {"preconditions": {"fixture_sha256": summary["fixture_sha256"],
                             "input_decimal_digits": digits}}
    reason = javascript_string_preconditions(pre, meta, rows)
    if reason:
        return {"input": value, "status": reason}
    first = rows[0]["registers"]
    state = {name: first[name] for name in REGISTER_OFFSETS.values()}
    flags = {bit: (first["eflags"] >> bit) & 1 for bit in FLAG_OFFSETS.values()}
    memory, _ = initial_memory(rows)
    stages = []
    cursor = 0
    roles = ["prefix"] + ["pair_continue"] * (digits // 2 - 1) + [
        "pair_exit", "odd_tail_and_return" if digits & 1 else "even_return"]
    for label in roles:
        segment = parsed[label]
        width = segment["identity"]["native_steps"]
        applied, reason = apply_segment(label, segment, rows[cursor:cursor + width],
                                        summary, decls, state, flags, memory)
        if reason:
            return {"input": value, "status": reason,
                    "completed_stages": stages}
        state, flags, memory, evidence = applied
        cursor += width
        stages.append({key: value for key, value in evidence.items()
                       if key != "predicted_effects"})
        if label == "prefix":
            source = first["rax"] - 1 + 16
            destination = state["r14"] + 15
            if not (source + digits <= destination or
                    destination + digits <= source):
                return {"input": value, "status": "unknown(copy region alias)"}
    if cursor != len(rows):
        return {"input": value, "status": "unknown(unconsumed target path)"}
    char_base = state["rax"] - 1 + 16
    projected = bytes(evaluate(z3.Select(memory,
        z3.BitVecVal(char_base + index, 64)), [])
        for index in range(digits + 1)).decode("ascii")
    if projected != observed_result["output"]:
        return {"input": value, "status": "unknown(output)"}
    return {"input": value, "status": "differentially_validated",
            "digits": digits, "pair_iterations": digits // 2,
            "output": projected, "native_steps": len(rows),
            "target_pcode_operations_replayed": 0,
            "source_pcode_operations_replayed_at_application": 0,
            "target_intermediate_state_used_as_input": False,
            "stages": stages}


def main():
    summary = json.loads(SUMMARY.read_text())
    decls, parsed = parse_segments(summary, {"prefix", "pair_continue",
        "pair_exit", "odd_tail_and_return", "even_return"})
    node = Path(shutil.which("node"))
    binary_hash = sha256(node.read_bytes()).hexdigest()
    targets = []
    for value in TARGET_VALUES:
        path = trace_for(value)
        meta, body, observed_result = records(path)
        outcome = apply(summary, decls, parsed, value, meta, body["rows"],
                        observed_result, binary_hash)
        outcome["trace"] = path.name
        outcome["trace_sha256"] = sha256(path.read_bytes()).hexdigest()
        targets.append(outcome)
    bad_meta, bad_body, bad_output = records(trace_for(10000))
    bad_immediate = deepcopy(bad_body["rows"])
    immediate_address = (bad_immediate[0]["registers"]["r12"] +
                         bad_immediate[0]["registers"]["r9"] + 1) & ((1 << 64) - 1)
    next(item for item in bad_immediate[0]["memory"] if item["access"] & 1 and
         item["size"] == 1 and item["address"] == immediate_address)["before"] = 6
    bad_alias = deepcopy(bad_body["rows"])
    bad_alias[0]["registers"]["rax"] = bad_alias[-1]["registers_after"]["rax"]
    bad_write = deepcopy(bad_body["rows"])
    first_write = next(access for row in bad_write for access in row["memory"]
                       if access["access"] & 2)
    first_write["after"] ^= 1
    bad_path = deepcopy(bad_body["rows"])
    bad_path[187]["bytes"] = "90"
    probes = {"wrong_immediate": apply(summary, decls, parsed, 10000,
                                        bad_meta, bad_immediate, bad_output,
                                        binary_hash)["status"],
              "wrong_entry_object": apply(summary, decls, parsed, 10000,
                                            bad_meta, bad_alias, bad_output,
                                            binary_hash)["status"],
              "wrong_ordered_write": apply(summary, decls, parsed, 10000,
                                           bad_meta, bad_write, bad_output,
                                           binary_hash)["status"],
              "wrong_native_path": apply(summary, decls, parsed, 10000,
                                         bad_meta, bad_path, bad_output,
                                         binary_hash)["status"]}
    if (sum(item["status"] == "differentially_validated" for item in targets) != 10 or
            any(not item["status"].startswith("unknown(") for item in targets[10:]) or
            any(not item.startswith("unknown(") for item in probes.values())):
        raise ValueError("unexpected frozen-loop applicability")
    report = {"schema_version": 1,
              "summary_sha256": sha256(SUMMARY.read_bytes()).hexdigest(),
              "targets": targets, "negative_probes": probes,
              "metrics": {"targets": len(targets),
                          "full_native_transitions_matched": sum(
                              item["status"] == "differentially_validated"
                              for item in targets),
                          "unknown": sum(item["status"].startswith("unknown(")
                                         for item in targets),
                          "target_pcode_operations_replayed": 0,
                          "source_pcode_operations_replayed_at_application": 0},
              "limits": ["native trace supplies the target path and first-read memory",
                         "only observed x86-64 scalar state and native reads/writes are checked",
                         "exact pinned Node binary, fixture and length 2..11 domain",
                         "allocation alias and arbitrary-path completeness are not proved"]}
    RESULT.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report["metrics"]))


if __name__ == "__main__":
    main()
