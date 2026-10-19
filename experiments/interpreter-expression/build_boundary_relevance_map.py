"""Connect bounded VM boundaries to a lossless control-obligation inventory.

This is an evidence map, not a handler decompiler. A dispatch-to-dispatch
interval is a candidate until its stored native transition is admitted.
Observed value slices cannot prove that an alternate branch is irrelevant.
"""
from __future__ import annotations

from collections import Counter
from copy import deepcopy
import gzip
import json

from capstone import Cs, CS_ARCH_X86, CS_MODE_64

from audit_observed_dependencies import one_cmov_negative
from audit_python_branch_candidates import conditional_successors
from build_common_control_worklist import build as rebuild_worklist
from build_common_program_representation import (JS_TRACE, LUA_BINARY, LUA_TRACE,
    OUTPUT as PROGRAM_IL, ROOT, digest,
    lua_flow_trace, lua_vm_rows)
from common_native_slice import caller_slice, lanes
from common_program_path_il import require
from cross_dispatch_pcode import read_vaddr
from discover_dispatch_intervals import (SUMMARY as DISPATCH_SUMMARY,
    candidates, run_case as rerun_dispatch_case)
from map_lua_branch_dispatch import (OUTPUT as LUA_DISPATCH_MAP,
    build as rebuild_lua_map)
from probe_python_remaining_scope import TRACES
from probe_unseen_python_path import PYTHON
from prove_cross_full_flow import load_trace
from prove_lua_full_flow import trace_records
from apply_bounded_python_program import HOLDOUT
from apply_transition_summary import load_trace as load_lua_segment


WORKLIST = ROOT / "common_control_worklist_v1.json"
DISCOVERY = ROOT / "dispatch_interval_discovery_result.json"
PRIOR_PY_DISPATCH = ROOT / "artifacts/cross_python_9_native.json.gz"
OUTPUT = ROOT / "boundary_relevance_map_v1.json"
RESULT = ROOT / "boundary_relevance_map_result.json"
PY_TRACES = {**TRACES, 255: HOLDOUT}


def span_items(worklist, unit_id, begin, end):
    return [item for item in worklist["occurrences"]
            if item["unit_id"] == unit_id and
            begin <= item["step_in_unit"] < end]


def python_boundaries(program, worklist):
    result = []
    with gzip.open(PRIOR_PY_DISPATCH, "rt") as stream:
        prior = json.load(stream)
    require(prior["marker"]["bytecode_sha256"] ==
            next(unit for unit in worklist["units"]
                 if unit["id"] == "python_252")["fixture"]["sha256"] and
            any(item["code_name"] == "branchCall" for item in prior["events"]),
            "prior Python fetch fixture differs")
    for route in program["routes"]:
        if route["engine"] != "python":
            continue
        witness = route["input_domain"]["value"]
        trace = PY_TRACES[witness]
        _, rows, _ = load_trace(trace, "python", witness, PYTHON)
        require(digest(trace) == route["trace_sha256"] and
                len(rows) == route["native_steps"],
                "Python route trace changed")
        found = candidates(rows)
        for node in route["nodes"]:
            if node["id"] not in ("numeric_transition", "next_transition"):
                continue
            begin, end = node["native_span"]
            matches = [item for item in found if
                       (item["begin"], item["end_exclusive"]) == (begin, end)]
            require(len(matches) == 1 and
                    node["entry_pc"] == matches[0]["entry_pc"] and
                    node["exit_successor"] == matches[0]["exit_pc"] and
                    node["certificate"]["grade"] ==
                    "computed_frozen_native_transition",
                    "Python computed node is not the observed dispatch interval")
            boundary = matches[0]
            occurrences = span_items(worklist, route["id"], begin, end)
            result.append({"id": f"{route['id']}:{node['id']}",
                "unit_id": route["id"], "engine": "python",
                "binary_sha256": route["binary_sha256"],
                "trace_sha256": route["trace_sha256"],
                "fixture": next(unit["fixture"] for unit in worklist["units"]
                                if unit["id"] == route["id"]),
                "span_in_unit": [begin, end],
                "entry_predecessor_step": boundary["entry_predecessor"],
                "entry_pc": boundary["entry_pc"],
                "exit_successor": boundary["exit_pc"],
                "boundary_kind": "observed_indirect_dispatch_pair",
                "admission_grade": "computed_exact_native_transition_for_witness",
                "bytecode_binding": {"grade": "same_fixture_dispatch_pattern_only",
                    "bytecode_offset": None,
                    "prior_dispatch_trace_sha256": digest(PRIOR_PY_DISPATCH)},
                "occurrence_ids": [item["id"] for item in occurrences],
                "alternate_exits_complete": False,
                "handler_semantics_complete": False})
    return result


def local_boundaries(program, worklist, discovery, lua_map):
    result = []
    for route in program["routes"]:
        if route["id"] not in ("lua_segment", "javascript_segment"):
            continue
        node = route["nodes"][0]
        begin, end = node["native_span"]
        if route["engine"] == "lua":
            _, rows = load_lua_segment(LUA_TRACE, int(node["entry_pc"], 16),
                                       int(node["exit_successor"], 16))
            require(route["binary_sha256"] == lua_map["binary_sha256"] and
                    next(unit["fixture"]["sha256"] for unit in worklist["units"]
                         if unit["id"] == route["id"]) !=
                    lua_map["bytecode_sha256"] and
                    any(event["handler_entry_pc"] == node["entry_pc"]
                        for case in lua_map["traces"] for event in case["events"]),
                    "Lua local cutpoint was conflated with branch-call bytecode")
            binding = {"grade": "local_cutpoint_no_same_fixture_fetch_map",
                       "bytecode_offset": None,
                       "different_fixture_same_handler_pc": node["entry_pc"]}
        else:
            with gzip.open(JS_TRACE, "rt") as stream:
                records = [json.loads(line) for line in stream]
            rows = records[1]["rows"]
            other = next(item for item in discovery["cases"]
                         if item["engine"] == "javascript" and item["input"] == 43)
            require(other["status"] == "differentially_validated" and
                    other["boundary"]["native_steps"] == len(rows) and
                    other["boundary"]["entry_pc"] == node["entry_pc"],
                    "JavaScript other-trace interval changed")
            binding = {"grade": "local_cutpoint_other_trace_dispatch_pair",
                       "bytecode_offset": None,
                       "other_trace_sha256": other["trace_sha256"],
                       "same_fixture_proved": False}
        require(digest(LUA_TRACE if route["engine"] == "lua" else JS_TRACE) ==
                route["trace_sha256"] and len(rows) == end - begin and
                rows[0]["pc"] == int(node["entry_pc"], 16) and
                rows[-1]["next_pc"] == int(node["exit_successor"], 16) and
                node["certificate"]["status"] == "differentially_validated",
                "local transition or source trace changed")
        result.append({"id": f"{route['id']}:{node['id']}",
            "unit_id": route["id"], "engine": route["engine"],
            "binary_sha256": route["binary_sha256"],
            "trace_sha256": route["trace_sha256"],
            "fixture": next(unit["fixture"] for unit in worklist["units"]
                            if unit["id"] == route["id"]),
            "span_in_unit": [begin, end],
            "entry_predecessor_step": None,
            "entry_pc": node["entry_pc"],
            "exit_successor": node["exit_successor"],
            "boundary_kind": "local_value_analysis_cutpoint",
            "admission_grade": "frozen_local_transition_reused",
            "bytecode_binding": binding,
            "occurrence_ids": [item["id"] for item in
                               span_items(worklist, route["id"], begin, end)],
            "alternate_exits_complete": False,
            "handler_semantics_complete": False})
    return result


def lua_vm_boundaries(program, worklist, lua_map):
    result = []
    dispatch_by_label = {item["input_label"]: item for item in lua_map["traces"]}
    for chain in program["proof_chains"]:
        unit = next(item for item in worklist["units"]
                    if item["id"] == chain["id"])
        label = chain["id"].removeprefix("lua_branch_")
        rows = lua_vm_rows(trace_records(lua_flow_trace(label)))
        window = unit["trace_window"]
        ledger = chain["links"][5]["native_ledger"]
        require(digest(lua_flow_trace(label)) == chain["trace_sha256"] and
                rows[0]["step"] == window["start_native_step"] and
                rows[-1]["step"] == window["end_native_step_inclusive"] and
                rows[0]["pc"] == int(ledger["entry_pc"], 16) and
                rows[-1]["next_pc"] == int(ledger["exit_successor"], 16),
                "Lua VM window differs from its source trace")
        matches = []
        if label in dispatch_by_label:
            matches = [item for item in dispatch_by_label[label]["events"]
                       if window["start_native_step"] <=
                       item["dispatch_trace_step"] <= window["end_native_step_inclusive"] and
                       item["handler_entry_pc"] == chain["proof_evidence"]["vm_path"]["callee_native_pc"]]
            require(len(matches) == 1 and
                    dispatch_by_label[label]["trace_sha256"] == chain["trace_sha256"] and
                    dispatch_by_label[label]["bytecode_sha256"] ==
                    chain["bytecode_sha256"],
                    "Lua same-trace bytecode-to-handler link changed")
        binding = ({"grade": "same_trace_bytecode_fetch_and_dispatch",
                    "bytecode_offset": matches[0]["file_byte_offset"],
                    "numeric_opcode": matches[0]["numeric_opcode"],
                    "dispatch_trace_step": matches[0]["dispatch_trace_step"],
                    "handler_entry_pc": matches[0]["handler_entry_pc"]}
                   if matches else {"grade": "same_fixture_fetch_not_mapped_on_this_trace",
                                    "bytecode_offset": None})
        result.append({"id": f"{chain['id']}:vm_window",
            "unit_id": chain["id"], "engine": "lua",
            "binary_sha256": chain["binary_sha256"],
            "trace_sha256": chain["trace_sha256"],
            "fixture": unit["fixture"],
            "span_in_unit": [0, len(rows)],
            "trace_window": window,
            "entry_predecessor_step": None,
            "entry_pc": ledger["entry_pc"],
            "exit_successor": ledger["exit_successor"],
            "boundary_kind": "contiguous_vm_value_window",
            "admission_grade": "guard_and_value_pcode_proved_for_witness",
            "bytecode_binding": binding,
            "occurrence_ids": [item["id"] for item in
                               span_items(worklist, chain["id"], 0, len(rows))],
            "alternate_exits_complete": False,
            "handler_semantics_complete": False})
    return result


def selected_slices(program, worklist):
    route = next(item for item in program["routes"] if item["id"] == "python_252")
    node = next(item for item in route["nodes"] if item["id"] == "numeric_transition")
    _, py_full, _ = load_trace(PY_TRACES[252], "python", 252, PYTHON)
    begin, end = node["native_span"]
    py_rows = py_full[begin:end]
    lua_rows = lua_vm_rows(trace_records(lua_flow_trace("x0")))
    with gzip.open(JS_TRACE, "rt") as stream:
        js_rows = [json.loads(line) for line in stream][1]["rows"]
    scopes = (("python_252:numeric_transition", "python_252", begin, py_rows,
               lanes("memory", py_rows[-1]["registers_after"]["r15"] - 8, 8, 0)),
              ("lua_branch_x0:vm_window", "lua_branch_x0", 0, lua_rows,
               lanes("register", 160, 8, 0)),
              ("javascript_segment:handler_segment", "javascript_segment", 0,
               js_rows, lanes("register", 0, 8, 0)))
    reports = []
    touched = {}
    for boundary_id, unit_id, offset, rows, value_sink in scopes:
        effects = [access for row in rows for access in row["memory"]
                   if access["access"] & 2]
        effect_sink = set().union(*(lanes("memory", access["address"],
                                         access["size"], 0)
                                    for access in effects)) if effects else set()
        variants = (("value", value_sink, False),
                    ("value_and_observed_writes", value_sink | effect_sink, False),
                    ("plus_addresses_and_all_observed_control",
                     value_sink | effect_sink, True))
        selected_by_variant = {}
        counts = {}
        for name, sinks, broad in variants:
            selected, debts, _, _, _, step_count, audit = caller_slice(
                rows, sinks, include_address_control=broad,
                strict_schedule=True)
            selected_by_variant[name] = {item["step"] for item in selected}
            counts[name] = {"selected_pcode_operations": len(selected),
                "selected_native_steps": step_count,
                "retained_control_pcode_operations":
                    audit["retained_control_operations"],
                "unsupported_local_control_steps":
                    audit["unsupported_local_control_steps"],
                "syntactic_debts": len(debts)}
        require(selected_by_variant["value"] <=
                selected_by_variant["value_and_observed_writes"] <=
                selected_by_variant["plus_addresses_and_all_observed_control"],
                "wider sink lost selected native steps")
        cases = span_items(worklist, unit_id, offset, offset + len(rows))
        for item in cases:
            local_step = item["step_in_unit"] - offset
            touched[item["id"]] = {"analysis_boundary_id": boundary_id,
                "in_value_slice_step": local_step in selected_by_variant["value"],
                "in_value_or_write_slice_step": local_step in
                    selected_by_variant["value_and_observed_writes"],
                "in_address_control_audit_step": local_step in
                    selected_by_variant["plus_addresses_and_all_observed_control"]}
        reports.append({"boundary_id": boundary_id, "unit_id": unit_id,
            "native_steps": len(rows), "observed_write_records": len(effects),
            "effect_sink_byte_lanes": len(effect_sink),
            "variants": counts,
            "native_control_occurrences_in_scope": len(cases),
            "classification_rule": "slice membership is a same-step signal; all branch and call obligations remain"})
    return reports, touched, py_full


def classify_all(worklist, touched):
    result = []
    for item in worklist["occurrences"]:
        signal = touched.get(item["id"])
        if signal is None:
            status = "relevance_unresolved_outside_selected_slice"
        elif item["kind"] == "NativeCallOccurrence":
            status = "call_return_exception_obligation"
        else:
            status = "branch_reachability_obligation_preserved"
        result.append({"occurrence_id": item["id"],
            "kind": item["kind"], "status": status,
            "slice_signal": signal,
            "opposite_edge_closed": False,
            "exception_edge_closed": False,
            "safe_to_delete": False})
    return result


def lua_first_branch_frontier(program, worklist, lua_map):
    """Locate one observed alternate edge inside a shared bytecode handler."""
    traces = {item["input_label"]: item for item in lua_map["traces"]}
    segments = {}
    event_pairs = {}
    for label, following_offset in (("x0", 59), ("x9", 75)):
        mapped = traces[label]["events"]
        before = next(item for item in mapped if item["file_byte_offset"] == 51)
        after = next(item for item in mapped
                     if item["file_byte_offset"] == following_offset)
        require(before["handler_entry_pc"] == "0x415ee0" and
                before["numeric_opcode"] == 61 and
                after["fetch_trace_step"] > before["dispatch_trace_step"],
                "Lua branch-bytecode handler changed")
        rows = {row["step"]: row for row in
                trace_records(lua_flow_trace(label))
                if row.get("type") == "replay_step"}
        begin, end = before["dispatch_trace_step"] + 1, after["fetch_trace_step"]
        require(all(step in rows for step in range(begin, end + 1)),
                "Lua branch handler path is not continuously captured")
        segment = [rows[step] for step in range(begin, end + 1)]
        require(all(left["next_pc"] == right["pc"] for left, right in
                    zip(segment, segment[1:])),
                "Lua branch handler native path is discontinuous")
        segments[label] = segment
        event_pairs[label] = (before, after)
    first = next(index for index, (zero, nonzero) in
                 enumerate(zip(segments["x0"], segments["x9"]))
                 if zero["pc"] != nonzero["pc"] or
                    zero["next_pc"] != nonzero["next_pc"])
    zero, nonzero = segments["x0"][first], segments["x9"][first]
    decoded = next(Cs(CS_ARCH_X86, CS_MODE_64).disasm(
        read_vaddr(LUA_BINARY, zero["pc"], zero["pc"] + 15), zero["pc"]))
    require(zero["instruction"] == nonzero["instruction"] ==
            f"{decoded.mnemonic} {decoded.op_str}",
            "Lua branch trace instruction differs from pinned binary")
    successors = conditional_successors({**zero, "bytes": bytes(decoded.bytes).hex()})
    require(first == 20 and zero["pc"] == nonzero["pc"] == 0x415F30 and
            successors is not None and
            {zero["next_pc"], nonzero["next_pc"]} == successors and
            zero["instruction"] == nonzero["instruction"],
            "Lua first alternate edge is not the same native conditional")
    occurrences = {}
    for label, row in (("x0", zero), ("x9", nonzero)):
        unit_id = f"lua_branch_{label}"
        match = [item for item in worklist["occurrences"]
                 if item["unit_id"] == unit_id and
                 item["kind"] == "NativeConditionalOccurrence" and
                 item["trace_native_step"] == row["step"] and
                 item["pc"] == hex(row["pc"])]
        require(len(match) == 1 and
                match[0]["observed_successor"] == hex(row["next_pc"]),
                "Lua alternate edge lost native occurrence identity")
        occurrences[label] = match[0]["id"]
    guards = {}
    for label in ("x0", "x9"):
        chain = next(item for item in program["proof_chains"]
                     if item["id"] == f"lua_branch_{label}")
        proof = chain["proof_evidence"]["vm_path"]
        require(proof["guard_equivalence"] == "unsat" and
                proof["guard"] == ("X == 0" if label == "x0" else "X != 0"),
                "Lua whole-window path guard changed")
        guards[label] = proof["guard"]
    return {"bytecode_file_offset_before": 51,
        "bytecode_numeric_opcode_before": 61,
        "shared_handler_entry_pc": "0x415ee0",
        "first_differing_native_instruction_index_from_handler_entry": first,
        "native_branch_pc": hex(zero["pc"]),
        "cases": [{"input_label": label,
            "source_dispatch_trace_step": event_pairs[label][0]["dispatch_trace_step"],
            "first_divergence_trace_step": segments[label][first]["step"],
            "occurrence_id": occurrences[label],
            "observed_successor": hex(segments[label][first]["next_pc"]),
            "next_captured_bytecode_file_offset":
                event_pairs[label][1]["file_byte_offset"],
            "whole_vm_window_path_guard": guards[label]}
            for label in ("x0", "x9")],
        "branch_predicate_proved_individually": False,
        "next_captured_fetch_is_immediate_bytecode_successor": False,
        "scope": "one observed bytecode handler in two source traces"}


def build():
    program = json.loads(PROGRAM_IL.read_text())
    worklist = json.loads(WORKLIST.read_text())
    lua_map = json.loads(LUA_DISPATCH_MAP.read_text())
    discovery = json.loads(DISCOVERY.read_text())
    require(program["schema_version"] == "common-program-representation-v1" and
            worklist["schema_version"] == "common-control-worklist-v1" and
            worklist["program_il_sha256"] == digest(PROGRAM_IL) and
            lua_map["schema_version"] == "lua-branch-dispatch-map-v1" and
            worklist == rebuild_worklist() and
            lua_map == rebuild_lua_map(),
            "upstream boundary or local-control evidence changed")
    js_other = next(item for item in discovery["cases"]
                    if item["engine"] == "javascript" and item["input"] == 43)
    require(js_other == rerun_dispatch_case(
                json.loads(DISPATCH_SUMMARY.read_text()), "javascript", 43,
                "next_boundary_js_43.json.gz"),
            "other-trace JavaScript dispatch certificate changed")
    boundaries = (python_boundaries(program, worklist) +
                  local_boundaries(program, worklist, discovery, lua_map) +
                  lua_vm_boundaries(program, worklist, lua_map))
    slices, touched, py_rows = selected_slices(program, worklist)
    frontier = lua_first_branch_frontier(program, worklist, lua_map)
    cmov = one_cmov_negative(py_rows)
    require(all(x["status"] == "unknown" for x in cmov.values()),
            "unexecuted CMOV definition was accepted")
    doc = {"schema_version": "boundary-relevance-map-v1",
        "source_sha256": {"program_il": digest(PROGRAM_IL),
            "control_worklist": digest(WORKLIST),
            "lua_dispatch_map": digest(LUA_DISPATCH_MAP),
            "dispatch_discovery": digest(DISCOVERY)},
        "whole_program_complete": False,
        "all_vm_bytecodes_mapped": False,
        "boundaries": boundaries,
        "first_lua_branch_frontier": frontier,
        "relevance_slices": slices,
        "occurrence_classifications": classify_all(worklist, touched),
        "negative_cmov_evidence": cmov,
        "limits": ["dispatch pairs are observed candidates, not general handler boundaries",
                   "Lua local cutpoint and branch-call VM window have different bytecode fixtures",
                   "a missing value-slice step cannot prove a branch irrelevant",
                   "all alternate exits, normal/exception calls and memory lifetime effects remain obligations",
                   "observed writes seeded as sinks do not prove earlier writes removable"]}
    validate_structure(doc, worklist)
    return doc


def validate_structure(doc, worklist):
    require(doc["schema_version"] == "boundary-relevance-map-v1" and
            doc["whole_program_complete"] is False and
            doc["all_vm_bytecodes_mapped"] is False and
            len(doc["boundaries"]) == 17 and
            len(doc["relevance_slices"]) == 3,
            "boundary map scope promoted")
    frontier = doc["first_lua_branch_frontier"]
    require(frontier["branch_predicate_proved_individually"] is False and
            frontier["next_captured_fetch_is_immediate_bytecode_successor"] is False and
            frontier["native_branch_pc"] == "0x415f30" and
            [item["occurrence_id"] for item in frontier["cases"]] ==
            ["lua_branch_x0:branch:32", "lua_branch_x9:branch:32"] and
            {item["observed_successor"] for item in frontier["cases"]} ==
            {"0x415d51", "0x415f36"},
            "Lua first alternate edge or scope changed")
    all_ids = [item["id"] for item in worklist["occurrences"]]
    labels = doc["occurrence_classifications"]
    require([item["occurrence_id"] for item in labels] == all_ids and
            len({item["id"] for item in doc["boundaries"]}) == 17,
            "a control occurrence or boundary disappeared")
    by_id = {item["id"]: item for item in worklist["occurrences"]}
    for boundary in doc["boundaries"]:
        require(boundary["alternate_exits_complete"] is False and
                boundary["handler_semantics_complete"] is False and
                boundary["span_in_unit"][1] > boundary["span_in_unit"][0] and
                all(by_id[name]["unit_id"] == boundary["unit_id"] for name in
                    boundary["occurrence_ids"]),
                "boundary promoted or occurrence mixed")
        if boundary["boundary_kind"] == "local_value_analysis_cutpoint":
            require(boundary["entry_predecessor_step"] is None,
                    "local cutpoint promoted to dispatch pair")
    for label in labels:
        source = by_id[label["occurrence_id"]]
        require(label["kind"] == source["kind"] and
                label["safe_to_delete"] is False and
                label["opposite_edge_closed"] is False and
                label["exception_edge_closed"] is False and
                label["status"] in {
                    "relevance_unresolved_outside_selected_slice",
                    "branch_reachability_obligation_preserved",
                    "call_return_exception_obligation"},
                "control obligation incorrectly removed")
        if source["kind"] == "NativeCallOccurrence":
            require(label["status"] != "branch_reachability_obligation_preserved",
                    "call exception path lost")


def validate(doc, canonical, worklist):
    validate_structure(doc, worklist)
    require(doc == canonical, "boundary or relevance evidence differs from sources")


def negative_controls(doc, worklist):
    mutations = {
        "shift_python_boundary": lambda d: d["boundaries"][0]["span_in_unit"].__setitem__(0, 684),
        "promote_lua_cutpoint": lambda d: next(x for x in d["boundaries"]
            if x["unit_id"] == "lua_segment").update(
                boundary_kind="observed_indirect_dispatch_pair"),
        "repeat_lua_pc_occurrence_swap": lambda d: next(x for x in d["occurrence_classifications"]
            if x["occurrence_id"] == "lua_branch_x0:branch:159").update(
                occurrence_id="lua_branch_x0:branch:166"),
        "drop_address_control_obligation": lambda d: next(x for x in d["occurrence_classifications"]
            if x["kind"] == "NativeConditionalOccurrence").update(safe_to_delete=True),
        "close_call_exception": lambda d: next(x for x in d["occurrence_classifications"]
            if x["kind"] == "NativeCallOccurrence").update(exception_edge_closed=True),
        "foreign_bytecode_offset": lambda d: next(x for x in d["boundaries"]
            if x["bytecode_binding"]["grade"] == "same_trace_bytecode_fetch_and_dispatch")
            ["bytecode_binding"].update(bytecode_offset=0),
        "branch_frontier_wrong_edge": lambda d:
            d["first_lua_branch_frontier"]["cases"][0].update(
                observed_successor="0xdeadbeef"),
    }
    result = {}
    for name, mutation in mutations.items():
        altered = deepcopy(doc)
        mutation(altered)
        try:
            validate(altered, doc, worklist)
        except (ValueError, KeyError):
            result[name] = "rejected"
        else:
            result[name] = "unexpectedly_accepted"
    require(all(value == "rejected" for value in result.values()),
            "invalid boundary or control evidence accepted")
    return result


def upstream_negative_controls():
    """Exercise the equality gate after source-derived upstream admission."""
    trusted = {"program": json.loads(PROGRAM_IL.read_text()),
               "worklist": json.loads(WORKLIST.read_text()),
               "lua_dispatch": json.loads(LUA_DISPATCH_MAP.read_text())}
    mutations = {
        "python_transition_certificate": lambda d: next(node for node in
            d["program"]["routes"][0]["nodes"]
            if node["id"] == "numeric_transition")["certificate"].update(
                grade="observed_only"),
        "missing_worklist_occurrence": lambda d:
            d["worklist"]["occurrences"].pop(),
        "foreign_lua_bytecode_offset": lambda d:
            d["lua_dispatch"]["traces"][0]["events"][-1].update(
                file_byte_offset=0),
    }
    result = {}
    for name, mutation in mutations.items():
        changed = deepcopy(trusted)
        mutation(changed)
        try:
            require(changed == trusted,
                    "upstream artifact differs from source-admitted canonical")
        except ValueError:
            result[name] = "rejected"
        else:
            result[name] = "unexpectedly_accepted"
    require(all(value == "rejected" for value in result.values()),
            "altered upstream artifact passed the canonical gate")
    return result


def main():
    worklist = json.loads(WORKLIST.read_text())
    doc = build()
    negatives = negative_controls(doc, worklist)
    upstream_negatives = upstream_negative_controls()
    OUTPUT.write_text(json.dumps(doc, indent=2) + "\n")
    validate(json.loads(OUTPUT.read_text()), doc, worklist)
    report = {"schema_version": doc["schema_version"],
        "artifact_sha256": digest(OUTPUT),
        "boundaries_by_kind": dict(Counter(item["boundary_kind"]
            for item in doc["boundaries"])),
        "control_classifications": dict(Counter(item["status"]
            for item in doc["occurrence_classifications"])),
        "slice_operation_counts": {item["boundary_id"]: {
            name: value["selected_pcode_operations"]
            for name, value in item["variants"].items()}
            for item in doc["relevance_slices"]},
        "first_lua_branch_frontier": {
            "native_branch_pc": doc["first_lua_branch_frontier"]["native_branch_pc"],
            "next_captured_bytecode_offsets": [item[
                "next_captured_bytecode_file_offset"] for item in
                doc["first_lua_branch_frontier"]["cases"]]},
        "negative_controls": negatives,
        "upstream_negative_controls": upstream_negatives,
        "whole_program_complete": False}
    RESULT.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key: report[key] for key in
        ("boundaries_by_kind", "control_classifications",
         "slice_operation_counts", "whole_program_complete")}, indent=2))


if __name__ == "__main__":
    main()
