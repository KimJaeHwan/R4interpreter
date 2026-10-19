"""Build a provenance-aware control obligation worklist across VM engines.

An item denotes one *occurrence* of an observed native branch or call. A
different trace at the same PC is evidence of an alternate edge, not proof of
reachability from the source's other fixed entry state. SMT SAT is a proposal;
only a checked native trace can classify its execution.
"""
from __future__ import annotations

from copy import deepcopy
import gzip
from hashlib import sha256
import json

import z3

from audit_python_branch_candidates import (RESULT as PRIOR_AUDIT,
    checked_case, classify, conditional_successors)
from build_common_program_representation import (JS_TRACE, OUTPUT as IL_PATH,
    ROOT, build as rebuild_il, digest, lua_flow_trace, lua_vm_rows)
from common_program_path_il import require
from prove_lua_full_flow import trace_records
from probe_connected_python_prefix import OPAQUE_START, first_read_memory, replay
from probe_python_prefix_branches import (RESULT as PREFIX_RESULT,
    ZERO, query as prefix_query)
from probe_python_remaining_scope import RESULT as NUMERIC_RESULT, TRACES
from probe_unseen_python_path import PYTHON
from prove_cross_full_flow import load_trace


OUTPUT = ROOT / "common_control_worklist_v1.json"
RESULT = ROOT / "common_control_worklist_result.json"
NEW_TRACE = ROOT / "artifacts/python_control_probe_x1.json.gz"
NEW_MARKER = ROOT / "artifacts/python_control_probe_x1.marker.json"
LUA_PLUS11_BYTECODE = ROOT / "lua_chunk_plus11.luac"


def branch_id(unit_id, step):
    return f"{unit_id}:branch:{step}"


def call_id(unit_id, step):
    return f"{unit_id}:call:{step}"


def fixture_for(unit, il):
    if unit["engine"] == "python":
        return {"kind": "python_fixture_bytecode",
            "sha256": il["python_fixture_bytecode_sha256"]}
    if unit["id"] == "lua_segment":
        return {"kind": "lua_chunk_plus11_bytecode",
                "sha256": digest(LUA_PLUS11_BYTECODE)}
    if unit["engine"] == "lua":
        return {"kind": "lua_branch_call_bytecode",
                "sha256": unit["bytecode_sha256"]}
    with gzip.open(JS_TRACE, "rt") as stream:
        meta = json.loads(stream.readline())
    require(meta["binary_sha256"] == unit["binary_sha256"],
            "JavaScript fixture binary changed")
    return {"kind": "javascript_fixture",
            "sha256": meta["fixture_sha256"]}


def units_from_il(il):
    units = []
    for route in il["routes"]:
        units.append({"id": route["id"], "engine": route["engine"],
            "binary_sha256": route["binary_sha256"],
            "source_trace_sha256": route["trace_sha256"],
            "application_unit": route["application_unit"],
            "source_input_binding": route["input_domain"],
            "control_scope": "selected_native_path_or_segment",
            "trace_window": None,
            "control": route["control"],
            "conditional_proofs": route.get("source_fixed_conditional_proofs", []),
            "fixture": fixture_for(route, il)})
    for chain in il["proof_chains"]:
        label = chain["id"].removeprefix("lua_branch_")
        rows = lua_vm_rows(trace_records(lua_flow_trace(label)))
        require(len(rows) == chain["links"][5]["native_ledger"]["native_steps"],
                "Lua trace window differs from saved VM ledger")
        units.append({"id": chain["id"], "engine": chain["engine"],
            "binary_sha256": chain["binary_sha256"],
            "source_trace_sha256": chain["trace_sha256"],
            "application_unit": chain["application_unit"],
            "source_input_binding": {"kind": "observed_input_word",
                                     "value": chain["input_word"],
                                     "guard": chain["guard"]},
            "control_scope": "contiguous_vm_window_only",
            "trace_window": {"start_native_step": rows[0]["step"],
                             "end_native_step_inclusive": rows[-1]["step"]},
            "control": chain["vm_control"], "conditional_proofs": [],
            "fixture": fixture_for(chain, il)})
    return units


def occurrence_inventory(units):
    items = []
    for unit in units:
        require(unit["control"]["complete"] is False,
                "unproved control inventory marked complete")
        seen = set()
        proofs = {item["absolute_step"]: item for item in
                  unit["conditional_proofs"]}
        require(len(proofs) == len(unit["conditional_proofs"]),
                "conditional certificate applied to duplicate occurrence")
        for branch in unit["control"]["conditional_branches"]:
            step = branch["step_in_slice"]
            require(step not in seen, "duplicate native branch occurrence")
            seen.add(step)
            proof = proofs.get(step)
            require(proof is None or
                    (proof["pc"] == branch["pc"] and
                     proof["opposite_successor"] == branch["opposite_successor"] and
                     proof["prefix_opposite"] == "unsat"),
                    "source-fixed proof assigned to wrong occurrence")
            items.append({"id": branch_id(unit["id"], step),
                "kind": "NativeConditionalOccurrence",
                "unit_id": unit["id"], "engine": unit["engine"],
                "binary_sha256": unit["binary_sha256"],
                "fixture": unit["fixture"],
                "source_trace_sha256": unit["source_trace_sha256"],
                "source_input_binding": unit["source_input_binding"],
                "control_scope": unit["control_scope"],
                "trace_native_step": (unit["trace_window"]["start_native_step"] + step
                                      if unit["trace_window"] else None),
                "step_in_unit": step, "pc": branch["pc"],
                "pcode_guard_index": (proof.get("pcode_guard_index")
                                      if proof is not None else None),
                "mnemonic": branch["mnemonic"],
                "observed_successor": branch["observed_successor"],
                "target_successor": branch["opposite_successor"],
                "other_trace_status": branch["opposite_status"],
                "source_fixed_unsat_certificate": proof,
                "global_infeasible_proved": False,
                "obligation": "prove or observe this opposite edge in its stated context"})
        require(set(proofs) <= seen,
                "conditional proof has no native branch occurrence")
        for call in unit["control"]["calls"]:
            step = call["step_in_slice"]
            require(step not in seen, "call and branch share native occurrence")
            seen.add(step)
            require(call["exception_edge"].startswith("unknown"),
                    "normal call return incorrectly closed exception path")
            items.append({"id": call_id(unit["id"], step),
                "kind": "NativeCallOccurrence", "unit_id": unit["id"],
                "engine": unit["engine"],
                "binary_sha256": unit["binary_sha256"],
                "fixture": unit["fixture"],
                "source_trace_sha256": unit["source_trace_sha256"],
                "source_input_binding": unit["source_input_binding"],
                "control_scope": unit["control_scope"],
                "trace_native_step": (unit["trace_window"]["start_native_step"] + step
                                      if unit["trace_window"] else None),
                "step_in_unit": step, "pc": call["pc"],
                "observed_target": call["target"],
                "target_kind": call["target_kind"],
                "observed_return_edge": call["return_edge"],
                "exception_edge": call["exception_edge"],
                "exception_infeasible_proved": False,
                "obligation": "enumerate exceptional and alternate return paths"})
    require(len({item["id"] for item in items}) == len(items),
            "control worklist occurrence ID collision")
    return items


def candidate_evidence(occurrences, il):
    prefix = json.loads(PREFIX_RESULT.read_text())
    numeric = json.loads(NUMERIC_RESULT.read_text())["branch"]
    prior = json.loads(PRIOR_AUDIT.read_text())
    source_meta, source_rows, _ = load_trace(TRACES[252], "python", 252, PYTHON)
    x = z3.BitVec("CONTROL_WORKLIST_X", 32)
    memory, _ = first_read_memory(source_rows[:683],
                                  source_meta["entry_value_address"], 252, x)
    model, _ = replay(source_rows[:OPAQUE_START], memory)
    restricted = prefix_query(model, x, 251, 256)
    widened = prefix_query(model, x, 0, 256)
    require(restricted == [{"guard_index": item["guard_index"],
                            "pc": item["pc"], "opposite": "unsat", "witness": None}
                           for item in restricted] and
            len(restricted) == len(widened) == 62 and
            [item for item in widened if item["opposite"] == "sat"] ==
            [{key: prefix["candidate"][key] for key in
              ("guard_index", "pc", "opposite", "witness")}],
            "prefix SMT worklist changed")
    require(prefix["source_trace_sha256"] == digest(TRACES[252]) and
            prefix["candidate_trace_sha256"] == digest(ZERO) and
            prior["binary_sha256"] == digest(PYTHON) and
            prior["schema_version"] == "python-branch-candidate-audit-v1" and
            prior["complete_route_set"] is False,
            "prior Python candidate source changed")
    p, n = prefix["candidate"], numeric["first_feasible_alternate"]
    require(p["witness"] == 0 and n["witness"] == 251 and
            p["opposite"] == n["opposite"] == "sat",
            "stored candidate witness changed")
    by_id = {item["id"]: item for item in occurrences}
    target_specs = (("prefix", p, [0, 256]),
                    ("numeric", n, [251, 256]))
    old_targets = (("prefix", ZERO, 0, "earlier_divergence"),
                   ("numeric", TRACES[251], 251, "target_opposite_observed"))
    probes = []
    for name, path, value, expected_status in old_targets + (
            ("prefix", NEW_TRACE, 1, "target_same_edge"),
            ("numeric", NEW_TRACE, 1, "earlier_divergence")):
        _, target, _ = load_trace(path, "python", value, PYTHON)
        spec, domain = next((spec, domain) for kind, spec, domain in target_specs
                            if kind == name)
        target_pc = int(spec["pc"], 16)
        matches = [item for item in occurrences
                   if item["unit_id"] == "python_252" and
                   item["kind"] == "NativeConditionalOccurrence" and
                   item["pc"] == spec["pc"]]
        require(len(matches) == 1, "candidate target has ambiguous native occurrence")
        target_item = matches[0]
        result = checked_case(TRACES[252], 252, path, value, value,
                              target_pc, spec["guard_index"],
                              domain if value != 1 else None)
        if value == 1:
            result["query"] = "not_queried; concrete native probe against stored target"
        require(result["status"] == expected_status and
                result["target_native_pc"] == target_item["pc"] and
                result["source_trace_sha256"] == target_item["source_trace_sha256"],
                "native candidate outcome changed")
        if value != 1:
            expected = next(item for item in prior["cases"]
                            if item["candidate_input"] == value)
            require(result == expected,
                    "prior candidate execution certificate changed")
        followup = None
        followup_edge = None
        if result["status"] == "earlier_divergence":
            followup = branch_id("python_252", result["first_relevant_step"])
            require(followup in by_id and
                    by_id[followup]["pc"] == result["first_relevant_pc"],
                    "earlier divergence is not a decoded source branch")
            step = result["first_relevant_step"]
            src, dst = source_rows[step], target[step]
            successors = conditional_successors(src)
            require(src["pc"] == dst["pc"] and successors is not None and
                    src["next_pc"] in successors and
                    dst["next_pc"] in successors and
                    src["next_pc"] != dst["next_pc"],
                    "earlier divergence is not an audited alternate branch edge")
            followup_edge = {"target_trace_step": step,
                             "source_successor": hex(src["next_pc"]),
                             "actual_successor": hex(dst["next_pc"])}
        probes.append({"id": f"python_{name}_x{value}",
            "target_obligation_id": target_item["id"],
            "followup_obligation_id": followup,
            "followup_actual_edge": followup_edge,
            "input_generation": ("source_fixed_SMT_model" if value != 1 else
                                 "concrete_new_probe"),
            "solver_result": "sat" if value != 1 else "not_queried",
            "source_fixed_query_domain": domain if value != 1 else None,
            "query_prefix_excludes_current_guard": True if value != 1 else None,
            "query_guard_index": spec["guard_index"] if value != 1 else None,
            "target_source_guard_index": spec["guard_index"],
            "source_fixed_entry_environment_reproduced": False,
            "native_observation_closes_target_candidate":
                result["status"] == "target_opposite_observed",
            "classification": result["status"],
            "audit": result,
            "target_trace_sha256": digest(path)})
        if value == 1 and name == "prefix":
            require(result["first_relevant_step"] == 158 and
                    not result["native_observation_closes_candidate"],
                    "new Python prefix probe was promoted")
        if value == 1 and name == "numeric":
            require(result["first_relevant_step"] == 331 and
                    followup == branch_id("python_252", 331),
                    "new Python numeric probe lost earlier divergence")
    _, holdout, holdout_summary = load_trace(NEW_TRACE, "python", 1, PYTHON)
    require(len(holdout) == 1002 and holdout_summary["through_return"] is True and
            holdout_summary["hardware_watch_enabled"] is True and
            holdout_summary["output_raw"] == holdout_summary["function_return_raw"] and
            source_meta["marker"]["bytecode_sha256"] ==
            load_trace(NEW_TRACE, "python", 1, PYTHON)[0]["marker"]["bytecode_sha256"] and
            json.loads(NEW_MARKER.read_text())["bytecode_sha256"] ==
            source_meta["marker"]["bytecode_sha256"],
            "new Python full native trace or fixture differs")
    # Recheck the classifier's failure modes on the new raw trace.
    require(classify(source_rows, holdout[:100], int(p["pc"], 16))[0] ==
            "target_not_reached", "truncated target was accepted")
    changed = [dict(row) for row in holdout]
    changed[158] = {**changed[158], "next_pc": 0xDEADBEEF}
    require(classify(source_rows, changed, int(p["pc"], 16))[0] ==
            "trace_invalid", "illegal successor was accepted")
    return probes


def build():
    il = rebuild_il()
    require(json.loads(IL_PATH.read_text()) == il,
            "saved common IL differs from source-derived canonical IL")
    path_il = json.loads((ROOT / "evidence_program_path_il.json").read_text())
    require(il["schema_version"] == "common-program-representation-v1" and
            path_il["schema_version"] == "evidence-program-path-il-v1",
            "upstream common IL changed")
    units = units_from_il({**il,
        "python_fixture_bytecode_sha256": path_il["contract"]["fixture_bytecode_sha256"]})
    items = occurrence_inventory(units)
    probes = candidate_evidence(items, il)
    doc = {"schema_version": "common-control-worklist-v1",
        "kind": "observed_native_control_occurrences_and_candidate_audit",
        "program_il_sha256": digest(IL_PATH),
        "source_sha256": {"prior_python_candidates": digest(PRIOR_AUDIT),
            "prefix_smt_worklist": digest(PREFIX_RESULT),
            "numeric_scope": digest(NUMERIC_RESULT),
            "new_python_trace": digest(NEW_TRACE),
            "new_python_marker": digest(NEW_MARKER)},
        "whole_program_complete": False,
        "entry_environment_complete": False,
        "units": [{key: unit[key] for key in
                   ("id", "engine", "binary_sha256", "source_trace_sha256",
                    "application_unit", "source_input_binding",
                    "control_scope", "trace_window", "fixture")}
                  for unit in units],
        "occurrences": items, "candidate_probes": probes,
        "limits": ["only observed native path and contiguous Lua VM occurrences",
                   "same PC in another occurrence or environment is not a proof",
                   "SMT SAT is a candidate; target trace can diverge earlier",
                   "normal return does not close exception paths",
                   "JS caller and Lua watched-slot gaps remain outside this inventory"]}
    validate_structure(doc)
    return doc


def validate_structure(doc):
    require(doc["schema_version"] == "common-control-worklist-v1" and
            doc["whole_program_complete"] is False and
            doc["entry_environment_complete"] is False and
            len(doc["units"]) == 13 and len(doc["candidate_probes"]) == 4,
            "control worklist schema or scope promoted")
    unit_ids = {unit["id"] for unit in doc["units"]}
    require(len(unit_ids) == len(doc["units"]) and
            len({item["id"] for item in doc["occurrences"]}) ==
            len(doc["occurrences"]), "unit or occurrence identity collision")
    by_id = {item["id"]: item for item in doc["occurrences"]}
    by_unit = {unit["id"]: unit for unit in doc["units"]}
    for item in doc["occurrences"]:
        unit = by_unit[item["unit_id"]]
        require(item["unit_id"] in unit_ids and
                item["id"] == (branch_id(item["unit_id"], item["step_in_unit"])
                               if item["kind"] == "NativeConditionalOccurrence" else
                               call_id(item["unit_id"], item["step_in_unit"])) and
                item["source_trace_sha256"] == unit["source_trace_sha256"] and
                item["binary_sha256"] == unit["binary_sha256"] and
                item["fixture"] == unit["fixture"] and
                item["source_input_binding"] == unit["source_input_binding"] and
                item["trace_native_step"] ==
                (unit["trace_window"]["start_native_step"] + item["step_in_unit"]
                 if unit["trace_window"] else None),
                "control occurrence lost exact source context")
        if item["kind"] == "NativeConditionalOccurrence":
            require(item["other_trace_status"] in
                    ("unknown(unexplored edge)", "observed_in_other_trace") and
                    item["global_infeasible_proved"] is False and
                    item["target_successor"] != item["observed_successor"] and
                    item["pcode_guard_index"] ==
                    (item["source_fixed_unsat_certificate"].get("pcode_guard_index")
                     if item["source_fixed_unsat_certificate"] else None),
                    "native branch promoted beyond evidence")
        else:
            require(item["kind"] == "NativeCallOccurrence" and
                    item["exception_edge"].startswith("unknown") and
                    item["exception_infeasible_proved"] is False,
                    "observed return closed exception obligation")
    allowed_status = {"earlier_divergence", "target_same_edge",
                      "target_opposite_observed", "target_not_reached",
                      "trace_invalid", "solver_timeout", "unsupported_binding"}
    for probe in doc["candidate_probes"]:
        target = by_id[probe["target_obligation_id"]]
        require(target["kind"] == "NativeConditionalOccurrence" and
                target["pc"] == probe["audit"]["target_native_pc"] and
                probe["classification"] == probe["audit"]["status"] and
                probe["classification"] in allowed_status and
                probe["target_source_guard_index"] ==
                probe["audit"]["source_pcode_guard_index"] and
                probe["source_fixed_entry_environment_reproduced"] is False and
                probe["native_observation_closes_target_candidate"] ==
                (probe["classification"] == "target_opposite_observed") and
                probe["target_trace_sha256"] ==
                probe["audit"]["target_trace_sha256"],
                "candidate execution status or domain promoted")
        if probe["classification"] == "earlier_divergence":
            require(probe["followup_obligation_id"] in by_id and
                    by_id[probe["followup_obligation_id"]]["pc"] ==
                    probe["audit"]["first_relevant_pc"] and
                    probe["followup_actual_edge"]["target_trace_step"] ==
                    probe["audit"]["first_relevant_step"] and
                    probe["followup_actual_edge"]["source_successor"] ==
                    by_id[probe["followup_obligation_id"]]["observed_successor"] and
                    probe["followup_actual_edge"]["actual_successor"] ==
                    by_id[probe["followup_obligation_id"]]["target_successor"],
                    "earlier divergence not linked to actual branch")
        else:
            require(probe["followup_obligation_id"] is None and
                    probe["followup_actual_edge"] is None,
                    "non-divergent candidate has false followup edge")
        if probe["input_generation"] == "concrete_new_probe":
            require(probe["solver_result"] == "not_queried" and
                    probe["source_fixed_query_domain"] is None and
                    probe["query_guard_index"] is None and
                    probe["query_prefix_excludes_current_guard"] is None and
                    probe["audit"]["query"].startswith("not_queried"),
                    "concrete probe promoted to SMT witness")
        else:
            require(probe["input_generation"] == "source_fixed_SMT_model" and
                    probe["solver_result"] == "sat" and
                    probe["query_guard_index"] ==
                    probe["target_source_guard_index"] and
                    probe["query_prefix_excludes_current_guard"] is True,
                    "SMT candidate identity changed")


def validate(doc, canonical):
    validate_structure(doc)
    require(doc == canonical, "saved control worklist differs from rechecked sources")


def negative_controls(doc):
    mutations = {
        "occurrence_step_swap": lambda d: d["occurrences"][0].update(step_in_unit=1),
        "wrong_target_successor": lambda d: d["occurrences"][0].update(
            target_successor="0xdeadbeef"),
        "fixture_swap": lambda d: d["units"][0].update(
            fixture=d["units"][-1]["fixture"]),
        "source_environment_promotion": lambda d: d["candidate_probes"][1].update(
            source_fixed_entry_environment_reproduced=True),
        "earlier_divergence_as_hit": lambda d: d["candidate_probes"][0].update(
            classification="target_opposite_observed"),
        "same_edge_as_hit": lambda d: d["candidate_probes"][2].update(
            native_observation_closes_target_candidate=True),
        "timeout_as_infeasible": lambda d: d["candidate_probes"][2].update(
            classification="infeasible_proved"),
        "current_guard_in_prefix": lambda d: d["candidate_probes"][0].update(
            query_prefix_excludes_current_guard=False),
        "call_exception_deleted": lambda d: next(item for item in d["occurrences"]
            if item["kind"] == "NativeCallOccurrence").update(
                exception_edge="proved_absent"),
        "lua_repeated_pc_wrong_occurrence": lambda d: next(item for item in d["occurrences"]
            if item["unit_id"] == "lua_branch_x0" and item["pc"] == "0x406879"
            and item["step_in_unit"] == 159).update(step_in_unit=166),
        "holdout_trace_swap": lambda d: d["candidate_probes"][2].update(
            target_trace_sha256=d["candidate_probes"][0]["target_trace_sha256"]),
    }
    result = {}
    for name, mutation in mutations.items():
        changed = deepcopy(doc)
        mutation(changed)
        try:
            validate(changed, doc)
        except (ValueError, KeyError):
            result[name] = "rejected"
        else:
            result[name] = "unexpectedly_accepted"
    require(all(status == "rejected" for status in result.values()),
            "invalid control evidence accepted")
    return result


def main():
    doc = build()
    negatives = negative_controls(doc)
    OUTPUT.write_text(json.dumps(doc, indent=2) + "\n")
    validate(json.loads(OUTPUT.read_text()), doc)
    occurrences = doc["occurrences"]
    engines = {}
    for engine in ("python", "lua", "javascript"):
        selected = [item for item in occurrences if item["engine"] == engine]
        branches = [item for item in selected if item["kind"] ==
                    "NativeConditionalOccurrence"]
        engines[engine] = {"branch_occurrences": len(branches),
            "call_occurrences": len(selected) - len(branches),
            "opposites_seen_in_another_trace": sum(item["other_trace_status"] ==
                "observed_in_other_trace" for item in branches),
            "source_fixed_unsat_occurrences": sum(
                item["source_fixed_unsat_certificate"] is not None
                for item in branches)}
    report = {"schema_version": doc["schema_version"],
        "artifact_sha256": digest(OUTPUT), "units": len(doc["units"]),
        "engines": engines,
        "candidate_probes": [{"id": item["id"],
            "input": item["audit"]["candidate_input"],
            "classification": item["classification"],
            "first_relevant_step": item["audit"]["first_relevant_step"],
            "followup_obligation_id": item["followup_obligation_id"]}
            for item in doc["candidate_probes"]],
        "negative_controls": negatives,
        "whole_program_complete": False,
        "limits": doc["limits"]}
    RESULT.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"units": len(doc["units"]), "engines": engines,
        "candidate_probes": report["candidate_probes"],
        "negative_controls_rejected": len(negatives)}, indent=2))


if __name__ == "__main__":
    main()
