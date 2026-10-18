"""Apply a frozen composed V8 loop summary without replaying P-code."""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import shutil

import z3

from apply_transition_summary import declarations, expression
from build_expanded_native_paths import records
from common_observed_transition import javascript_string_preconditions
from compose_js_string_loop import TARGET_VALUES
from freeze_js_string_loop import OUTPUT as SUMMARY
from pcode_transition_summary import FLAG_OFFSETS, REGISTER_OFFSETS
from prove_cross_full_flow import ROOT
from prove_js_string_copy_family import trace_for
from prove_lua_full_flow import initial_memory


RESULT = ROOT / "js_string_frozen_loop_application_result.json"


def number(term):
    value = z3.simplify(term)
    if not z3.is_bv_value(value):
        raise ValueError("frozen expression depends on an unbound input")
    return value.as_long()


def path_shape(rows):
    data = [[hex(row["pc"]), row["bytes"], hex(row["next_pc"])] for row in rows]
    return sha256(json.dumps(data, separators=(",", ":")).encode()).hexdigest()


def parse_segments(summary):
    decls = declarations(summary)
    parsed = {}
    for segment in summary["segments"]:
        parsed[segment["label"]] = {
            "guard": expression(segment["guard"], "Bool", decls),
            "outputs": [(item["name"], expression(item["expression"],
                                                    item["sort"], decls))
                        for item in segment["outputs"]],
            "reads": [(item, expression(item["address"], "BV64", decls),
                       expression(item["value"], f"BV{item['width'] * 8}", decls))
                      for item in segment["reads"]],
            "effects": [(item, expression(item["address"], "BV64", decls),
                         expression(item["value"], f"BV{item['width'] * 8}", decls))
                        for item in segment["effects"]],
            "successor": expression(segment["successor"], "BV64", decls),
            "identity": segment["identity"],
            "evidence": segment["evidence"]}
    if set(parsed) != {"prefix", "pair_continue", "pair_exit",
                       "odd_tail_and_return", "even_return"}:
        raise ValueError("frozen loop segment roles changed")
    return decls, parsed


def evaluate(ast, bindings):
    return number(z3.substitute(ast, *bindings))


def apply_segment(label, segment, rows, decls, state, flags, memory):
    identity = segment["identity"]
    if (not rows or len(rows) != identity["native_steps"] or
            hex(rows[0]["pc"]) != identity["entry_pc"] or
            hex(rows[-1]["next_pc"]) != identity["next_pc"] or
            path_shape(rows) != identity["path_shape_sha256"]):
        return None, f"unknown({label} path shape)"
    bindings = [(decls[f"R_{name.upper()}"], z3.BitVecVal(state[name], 64))
                for name in REGISTER_OFFSETS.values()]
    bindings += [(decls[f"F_{bit}"], z3.BitVecVal(flags[bit], 8))
                 for bit in FLAG_OFFSETS.values()]
    bindings.append((decls["M0"], memory))
    if not z3.is_true(z3.simplify(z3.substitute(segment["guard"], *bindings))):
        return None, f"unknown({label} guard)"
    reads = []
    for item, address_ast, value_ast in segment["reads"]:
        address, value = evaluate(address_ast, bindings), evaluate(value_ast, bindings)
        key = (item["pc"], address, item["width"])
        if key not in [(r["pc"], r["address"], r["width"]) for r in reads]:
            reads.append({"pc": item["pc"], "address": address,
                          "width": item["width"], "value": value})
    actual_reads = [{"pc": hex(row["pc"]), "address": access["address"],
                     "width": access["size"], "value": access["before"]}
                    for row in rows for access in row["memory"] if access["access"] & 1]
    if reads != actual_reads:
        return None, f"unknown({label} read footprint/value)"
    effects = []
    for item, address_ast, value_ast in segment["effects"]:
        if item["kind"] != "Write":
            return None, f"unknown({label} effect kind)"
        effects.append({"pc": item["pc"], "address": evaluate(address_ast, bindings),
                        "width": item["width"], "value": evaluate(value_ast, bindings)})
    actual_effects = [{"pc": hex(row["pc"]), "address": access["address"],
                       "width": access["size"], "value": access["after"]}
                      for row in rows for access in row["memory"] if access["access"] & 2]
    if effects != actual_effects:
        return None, f"unknown({label} ordered effects)"
    outputs = {name: evaluate(ast, bindings) for name, ast in segment["outputs"]}
    expected_names = ({f"R_{name.upper()}" for name in REGISTER_OFFSETS.values()} |
                      {f"F_{bit}" for bit in FLAG_OFFSETS.values()})
    if set(outputs) != expected_names:
        return None, f"unknown({label} incomplete state)"
    next_state = {name: outputs[f"R_{name.upper()}"]
                  for name in REGISTER_OFFSETS.values()}
    next_flags = {bit: outputs[f"F_{bit}"] for bit in FLAG_OFFSETS.values()}
    observed = rows[-1]["registers_after"]
    if (any(next_state[name] != observed[name] for name in next_state) or
            any(next_flags[bit] != ((observed["eflags"] >> bit) & 1)
                for bit in next_flags)):
        return None, f"unknown({label} state)"
    if evaluate(segment["successor"], bindings) != rows[-1]["next_pc"]:
        return None, f"unknown({label} successor)"
    next_memory = memory
    for item in effects:
        for index in range(item["width"]):
            next_memory = z3.Store(next_memory,
                z3.BitVecVal((item["address"] + index) & ((1 << 64) - 1), 64),
                z3.BitVecVal((item["value"] >> (8 * index)) & 255, 8))
    return (next_state, next_flags, next_memory,
            {"label": label, "native_steps": len(rows),
             "reads_checked": len(reads), "ordered_writes_checked": len(effects),
             "outputs_checked": len(outputs)}), None


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
                                        decls, state, flags, memory)
        if reason:
            return {"input": value, "status": reason,
                    "completed_stages": stages}
        state, flags, memory, evidence = applied
        cursor += width
        stages.append(evidence)
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
    decls, parsed = parse_segments(summary)
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
