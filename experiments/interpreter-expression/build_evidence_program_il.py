"""Build and independently recheck a bounded whole-trace program-IL candidate.

The IL covers every observed native step and effect. Opaque nodes preserve
observations but do not supply executable semantics or path completeness.
"""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json

import pypcode

from common_program_path_il import (PathILError, native_path_ledger, require,
                                    validate_partition, value_dag)
from probe_connected_python_prefix import (OPAQUE_END, OPAQUE_START,
                                           NUMERIC_START, RESULT as PREFIX_RESULT,
                                           one as replay_prefix)
from probe_python_prefix_branches import (RESULT as PREFIX_BRANCH_RESULT,
                                          main as regenerate_prefix_branches)
from probe_connected_python_program import (matching_boundary, observed_edges,
                                            path_inventory, value_proof_sources)
from probe_python_remaining_scope import (TRACES, bridge_and_suffix, branch_audit)
from probe_unseen_python_path import (CACHE_BASE, COMMON, GENERATED,
                                      NEIGHBOR_SUMMARY, PYTHON, ROOT)
from prove_cross_full_flow import load_trace


OUTPUT = ROOT / "evidence_program_path_il.json"
RESULT = ROOT / "evidence_program_path_result.json"
VALUE = ROOT / "common_numeric_refinement_result.json"
PRIOR = ROOT / "python_remaining_scope_result.json"
EXCEPTION = ROOT / "python_exception_boundary_result.json"


def digest(path):
    return sha256(path.read_bytes()).hexdigest()


def projected_dag():
    source = json.loads(VALUE.read_text())["value_il"]
    dag = deepcopy(source)
    dag["domain"] = "route-specific; consult value_refinement on each route"
    dag["interpretation"] = "BV32 arithmetic only; object decoding is route-specific"
    return dag


def proof_for_route(value, route_kind, proofs):
    expected = "cached" if value == 251 else "allocated"
    require(route_kind == expected and
            ((5 <= value <= 251) if route_kind == "cached" else
             (252 <= value <= 256)), "value outside route's proven source domain")
    return proofs[route_kind]


def contract(traces):
    bytecode = traces[252][0]["marker"]["bytecode_sha256"]
    require(all(item[0]["marker"]["bytecode_sha256"] == bytecode
                for item in traces.values()), "fixture bytecode differs across traces")
    return {"engine": "python", "binary_sha256": digest(PYTHON),
            "fixture_bytecode_sha256": bytecode,
            "observed_inputs": [251, 252, 254],
            "other_entry_state": "trace-specific; source252 fixed for SMT domain",
            "observable": "returned PyLong numeric value and preserved native byte effects"}


HANDOFFS = {"prefix_to_numeric": "observed_state_and_memory_ledger_only",
            "numeric_to_next": "computed_state_and_memory",
            "next_to_suffix": "computed_state_and_memory"}


def bundles():
    allocated = json.loads(GENERATED.read_text())
    neighbor = json.loads(NEIGHBOR_SUMMARY.read_text())
    cached = json.loads(COMMON.read_text())
    case = next(item for item in cached["cases"]
                if item["engine"] == "python" and
                item["preconditions"]["kind"] == "python_cached_int")
    return allocated, neighbor, {**cached, "cases": [case]}


def windows(rows, first_bundle, second_bundle):
    first = matching_boundary(rows, first_bundle["cases"][0])
    second = matching_boundary(rows, second_bundle["cases"][0])
    require(first["end_exclusive"] == second["begin"],
            "frozen transitions are not adjacent")
    require(first["begin"] == NUMERIC_START and
            rows[OPAQUE_START]["pc"] > 0x7F0000000000 and
            rows[OPAQUE_END]["pc"] == 0x56004D,
            "connected prefix or numeric cutpoint moved")
    spans = [
        ("caller_before_external", 0, OPAQUE_START, "PcodeReplayedWindow"),
        ("opaque_libc_vector_call", OPAQUE_START, OPAQUE_END, "OpaqueExternalCall"),
        ("caller_after_external", OPAQUE_END, first["begin"], "PcodeReplayedWindow"),
        ("numeric_transition", first["begin"], first["end_exclusive"],
         "FrozenNativeTransition"),
        ("next_transition", second["begin"], second["end_exclusive"],
         "FrozenNativeTransition"),
        ("caller_return", second["end_exclusive"], len(rows),
         "PcodeReplayedWindow")]
    return [{"id": name, "begin": start, "end_exclusive": end,
             "op": kind} for name, start, end, kind in spans]


def unsupported_pcode(rows):
    ctx = pypcode.Context("x86:LE:64:default")
    result = []
    for row in rows:
        operations = ctx.translate(bytes.fromhex(row["bytes"]) + b"\x00" * 15,
                                   base_address=row["pc"], max_instructions=1).ops
        if any(item.opcode.name == "CALLOTHER" for item in operations):
            result.append({"step": row["step"], "pc": hex(row["pc"]),
                           "instruction": row["instruction"],
                           "kind": "unsupported_pcode_CALLOTHER"})
    return result


def output_binding(value, rows, first_bundle, summary):
    b = matching_boundary(rows, first_bundle["cases"][0])
    first = rows[b["begin"]:b["end_exclusive"]]
    ptr = summary["output_raw"]
    if value == 251:
        require(ptr == CACHE_BASE + (value + 10) * 32,
                "cached result pointer differs from value decode")
        return {"kind": "pinned_cached_PyLong", "pointer": ptr,
                "numeric_value": value + 5,
                "evidence": "fixed executable cache layout and prior conditional proof"}
    field = [a for row in first for a in row["memory"]
             if a["access"] & 2 and a["address"] == ptr + 24 and a["size"] == 4]
    require(len(field) == 1 and field[0]["after"] == value + 5,
            "allocated object digit does not implement value projection")
    return {"kind": "observed_PyLong_fields", "pointer": ptr,
            "numeric_value": field[0]["after"],
            "evidence": "object digit native write; Allocate and freshness unknown"}


def build():
    regenerate_prefix_branches()
    traces = {value: load_trace(path, "python", value, PYTHON)
              for value, path in TRACES.items()}
    allocated, neighbor, cached = bundles()
    prior = json.loads(PRIOR.read_text())
    prefix = json.loads(PREFIX_RESULT.read_text())
    prefix_branches = json.loads(PREFIX_BRANCH_RESULT.read_text())
    require(prior["binary_sha256"] == digest(PYTHON) and
            prior["frozen_summaries_sha256"] ==
            {"first": digest(GENERATED), "second": digest(NEIGHBOR_SUMMARY),
             "cached": digest(COMMON)} and
            {item["input"]: item["trace_sha256"] for item in prior["paths"]} ==
            {value: digest(path) for value, path in TRACES.items()},
            "prior scope evidence or source hashes changed")
    require(prefix["binary_sha256"] == digest(PYTHON) and
            {item["input"]: item["trace_sha256"] for item in prefix["cases"]} ==
            {value: digest(path) for value, path in TRACES.items()},
            "connected prefix proof provenance changed")
    require(prefix_branches["binary_sha256"] == digest(PYTHON) and
            prefix_branches["source_trace_sha256"] == digest(TRACES[252]) and
            prefix_branches["source_fixed_environment_domain"] == [251, 256] and
            prefix_branches["does_not_close_zero_candidate"] is True,
            "prefix branch worklist provenance changed")
    # Re-execute the prior bridge and branch proof instead of trusting labels.
    source_meta, source_rows, _ = traces[252]
    branch = branch_audit(source_rows, source_meta, traces[251][1], traces[254][1])
    require(branch == prior["branch"], "prior branch proof result changed")
    value_source = json.loads(VALUE.read_text())
    dag = projected_dag()
    proofs = value_proof_sources()
    require([node["op"] for node in dag["nodes"]] == ["input", "bv", "bvadd"] and
            dag["nodes"][1]["value"] == 5, "unexpected shared value projection")
    edges = observed_edges([item[1] for item in traces.values()])
    routes = []
    for value in (251, 252, 254):
        meta, rows, trace_summary = traces[value]
        route_kind = "cached" if value == 251 else "allocated"
        first_bundle = cached if value == 251 else allocated
        local = bridge_and_suffix(value, meta, rows, trace_summary,
                                  first_bundle, neighbor, route_kind)
        require(local == next(item for item in prior["paths"]
                              if item["input"] == value),
                "prior path bridge proof result changed")
        prefix_case = replay_prefix(value, meta, rows)
        require(prefix_case == next(item for item in prefix["cases"]
                                    if item["input"] == value),
                "connected prefix proof result changed")
        require(value_dag(dag, value) == value + 5,
                "value DAG differs from observed number")
        spans = windows(rows, first_bundle, neighbor)
        spans[3]["summary_sha256"] = digest(COMMON if value == 251 else GENERATED)
        spans[4]["summary_sha256"] = digest(NEIGHBOR_SUMMARY)
        nodes = native_path_ledger(rows, spans)
        conditional_proofs = []
        if value == 252:
            conditional_proofs.extend({**item,
                "scope": "source252 fixed other entry state and X=251..256"}
                for item in prefix_branches["native_conditional_proofs"])
            for item in branch["native_conditional_edges_proved_in_source_domain"]:
                proof = {**item,
                         "absolute_step": spans[3]["begin"] + item["step_in_selected"],
                         "scope": "source252 fixed other entry state and X=252..256"}
                conditional_proofs.append(proof)
        route = {"input": value, "route": route_kind,
                 "trace_sha256": digest(TRACES[value]),
                 "native_steps": len(rows), "output_pointer": trace_summary["output_raw"],
                 "value_projection": output_binding(value, rows, first_bundle,
                                                     trace_summary),
                 "value_refinement": proof_for_route(value, route_kind, proofs),
                 "handoff_certificates": HANDOFFS,
                 "prefix_replay": prefix_case,
                 "nodes": nodes,
                 "control": path_inventory(rows, edges),
                 "conditional_proofs": conditional_proofs,
                 "unsupported_native_lift": unsupported_pcode(rows),
                 "lifetime_effect": "unknown(no CPython allocator authority)"}
        routes.append(route)
    doc = {"schema_version": "evidence-program-path-il-v1",
           "purpose": "bounded, evidence-bearing reporting IR; no whole-program semantics",
           "execution_semantics": "reporting_only_no_native_executor",
           "contract": contract(traces),
           "evidence_sha256": {"prior_scope": digest(PRIOR),
                               "connected_prefix": digest(PREFIX_RESULT),
                               "prefix_branch_worklist": digest(PREFIX_BRANCH_RESULT),
                               "numeric_value": digest(VALUE),
                               "cached_transition": digest(COMMON),
                               "allocated_transition": digest(GENERATED),
                               "next_transition": digest(NEIGHBOR_SUMMARY)},
           "value_projection": dag,
           "route_value_proofs": proofs,
           "shared_value_proof_engines":
               [item["engine"] for item in value_source["adapters"]],
           "branch_source_scope": branch,
           "prefix_branch_source_scope": prefix_branches,
           "routes": routes}
    require(doc["shared_value_proof_engines"] ==
            ["lua", "python", "javascript"],
            "three-engine value proof inventory changed")
    return doc, traces


def readiness(doc):
    routes = doc["routes"]
    opaque = sum(node["native_steps"] for route in routes
                 for node in route["nodes"] if node["op"] == "OpaqueExternalCall")
    opaque_regions = sum(node["op"] == "OpaqueExternalCall" for route in routes
                         for node in route["nodes"])
    unexplored_branches = sum(branch["opposite_status"].startswith("unknown")
                              for route in routes
                              for branch in route["control"]["conditional_branches"])
    unknown_exception_edges = sum(call["exception_edge"].startswith("unknown")
                                  for route in routes for call in route["control"]["calls"])
    unsupported = sum(len(route["unsupported_native_lift"]) for route in routes)
    proved_source_edges = sum(len(route["conditional_proofs"]) for route in routes)
    proved_unobserved = sum(
        branch["opposite_status"].startswith("unknown")
        for route in routes for branch in route["control"]["conditional_branches"]
        if any(proof["absolute_step"] == branch["step_in_slice"]
               for proof in route["conditional_proofs"]))
    unique_unexplored = {(branch["pc"], branch["opposite_successor"])
                         for route in routes
                         for branch in route["control"]["conditional_branches"]
                         if branch["opposite_status"].startswith("unknown")}
    unique_unknown_calls = {(call["pc"], call["target"])
                            for route in routes for call in route["control"]["calls"]
                            if call["exception_edge"].startswith("unknown")}
    unproven_lifetime = sum(route["route"] == "allocated" and
                            route["lifetime_effect"].startswith("unknown")
                            for route in routes)
    return {"observed_path_partition_complete": True,
            "observed_native_access_ledger_complete_for_traces": True,
            "value_projection_executable": True,
            "native_program_il_executable": False,
            "declared_route_set_complete": False,
            "lifetime_effects_authorized": unproven_lifetime == 0,
            "whole_logic_reconstruction_ready": False,
            "common_program_il_final": False,
            "counts": {"opaque_native_steps_across_routes": opaque,
                       "opaque_regions": opaque_regions,
                       "unexplored_branch_occurrences": unexplored_branches,
                       "conditional_native_edges_proved_in_source_domain": proved_source_edges,
                       "previously_unobserved_edges_closed_by_source_proof": proved_unobserved,
                       "unclosed_branch_occurrences_after_source_proof":
                           unexplored_branches - proved_unobserved,
                       "unique_unexplored_native_edges": len(unique_unexplored),
                       "unknown_call_exception_edges": unknown_exception_edges,
                       "unique_unknown_call_targets": len(unique_unknown_calls),
                       "unsupported_pcode_occurrences": unsupported,
                       "allocated_routes_without_lifetime_authority": unproven_lifetime},
            "scope": "three exact observed inputs, not arbitrary input/environment completeness"}


def validate(doc, traces, result=None):
    require(doc.get("schema_version") == "evidence-program-path-il-v1" and
            doc.get("purpose") ==
                "bounded, evidence-bearing reporting IR; no whole-program semantics" and
            doc.get("execution_semantics") == "reporting_only_no_native_executor" and
            doc["contract"] == contract(traces),
            "program contract changed")
    require(doc["evidence_sha256"] ==
            {"prior_scope": digest(PRIOR),
             "connected_prefix": digest(PREFIX_RESULT),
             "prefix_branch_worklist": digest(PREFIX_BRANCH_RESULT),
             "numeric_value": digest(VALUE),
             "cached_transition": digest(COMMON),
             "allocated_transition": digest(GENERATED),
             "next_transition": digest(NEIGHBOR_SUMMARY)},
            "program evidence hash changed")
    require(doc["value_projection"] == projected_dag(),
            "value projection source changed")
    proofs = value_proof_sources()
    require(doc["route_value_proofs"] == proofs,
            "route-specific refinement sources changed")
    require(doc["shared_value_proof_engines"] ==
            [item["engine"] for item in json.loads(VALUE.read_text())["adapters"]],
            "shared value proof provenance changed")
    allocated, neighbor, cached = bundles()
    prefix = json.loads(PREFIX_RESULT.read_text())
    prefix_branches = json.loads(PREFIX_BRANCH_RESULT.read_text())
    require(doc["prefix_branch_source_scope"] == prefix_branches and
            prefix_branches["source_trace_sha256"] == digest(TRACES[252]) and
            prefix_branches["does_not_close_zero_candidate"] is True,
            "prefix branch candidate or certificate changed")
    edges = observed_edges([item[1] for item in traces.values()])
    require([r["input"] for r in doc["routes"]] == [251, 252, 254],
            "route missing or duplicated")
    for route in doc["routes"]:
        value = route["input"]
        meta, rows, summary = traces[value]
        first = cached if value == 251 else allocated
        require(route["route"] == ("cached" if value == 251 else "allocated") and
                route["trace_sha256"] == digest(TRACES[value]) and
                route["native_steps"] == len(rows) and
                route["output_pointer"] == summary["output_raw"],
                "route identity or output changed")
        require(route["value_refinement"] ==
                proof_for_route(value, route["route"], proofs) and
                route["handoff_certificates"] == HANDOFFS,
                "route proof domain or state/memory handoff grade changed")
        spans = windows(rows, first, neighbor)
        spans[3]["summary_sha256"] = digest(COMMON if value == 251 else GENERATED)
        spans[4]["summary_sha256"] = digest(NEIGHBOR_SUMMARY)
        validate_partition(route, rows, spans)
        require(route["prefix_replay"] == next(item for item in prefix["cases"]
                                                if item["input"] == value),
                "connected prefix certificate omitted or changed")
        require(route["control"] == path_inventory(rows, edges),
                "branch/call/return inventory omitted or changed")
        expected_proofs = []
        if value == 252:
            expected_proofs.extend({**item,
                "scope": "source252 fixed other entry state and X=251..256"}
                for item in prefix_branches["native_conditional_proofs"])
            for item in doc["branch_source_scope"]["native_conditional_edges_proved_in_source_domain"]:
                expected_proofs.append({**item,
                    "absolute_step": spans[3]["begin"] + item["step_in_selected"],
                    "scope": "source252 fixed other entry state and X=252..256"})
        require(route["conditional_proofs"] == expected_proofs and
                all(any(edge["step_in_slice"] == item["absolute_step"] and
                            edge["pc"] == item["pc"] and
                            edge["opposite_successor"] == item["opposite_successor"]
                            for edge in route["control"]["conditional_branches"])
                    for item in route["conditional_proofs"]),
                "conditional proof assigned to wrong native branch")
        require(route["unsupported_native_lift"] == unsupported_pcode(rows),
                "unsupported P-code occurrence omitted")
        require(route["value_projection"] == output_binding(value, rows, first, summary) and
                value_dag(doc["value_projection"], value) ==
                route["value_projection"]["numeric_value"],
                "value projection does not match native output")
        require(route["lifetime_effect"] ==
                "unknown(no CPython allocator authority)",
                "lifetime promoted without ownership proof")
    source = traces[252]
    require(doc["branch_source_scope"] == branch_audit(source[1], source[0],
                                                        traces[251][1], traces[254][1]),
            "bounded branch certificate changed")
    if result is not None:
        exception = json.loads(EXCEPTION.read_text())
        require(result["related_exception_observation"] == {
                    "artifact_sha256": digest(EXCEPTION),
                    "binary_sha256": exception["cases"][0]["binary_sha256"],
                    "observed_cases": len(exception["cases"]),
                    "status": "separate controlled-pool fixture; observed cutpoints only",
                    "closes_selected_routes": False},
                "separate exception evidence was promoted or changed")
        require(result["related_zero_branch_candidate"] == {
                    "artifact_sha256": digest(PREFIX_BRANCH_RESULT),
                    "source_fixed_environment_sat_witness": 0,
                    "candidate_execution_status": "earlier divergence; proposed PC not reached",
                    "closes_proposed_edge": False},
                "unrealized SAT candidate was promoted to observed edge")
        require(result["readiness"] == readiness(doc) and
                result["program_il_sha256"] ==
                sha256(OUTPUT.read_bytes()).hexdigest(),
                "readiness or program IL artifact changed")


def negative_controls(doc, traces):
    controls = {}
    def reject(name, mutate):
        changed = deepcopy(doc)
        mutate(changed)
        try:
            validate(changed, traces)
        except (PathILError, KeyError, ValueError):
            controls[name] = "rejected"
        else:
            raise PathILError(f"negative control accepted: {name}")
    reject("missing_native_effect", lambda x:
           x["routes"][1]["nodes"][1]["effects"].pop())
    reject("wrong_state_handoff", lambda x:
           x["routes"][1]["nodes"][2]["entry_state"].__setitem__(
               "rax", x["routes"][1]["nodes"][2]["entry_state"]["rax"] ^ 1))
    reject("omitted_branch", lambda x:
           x["routes"][1]["control"]["conditional_branches"].pop())
    reject("omitted_conditional_certificate", lambda x:
           x["routes"][1]["conditional_proofs"].pop())
    reject("exception_called_normal", lambda x:
           x["routes"][1]["control"]["calls"][0].__setitem__(
               "exception_edge", "normal_return"))
    reject("false_allocate", lambda x:
           x["routes"][1].__setitem__("lifetime_effect", "Allocate"))
    reject("wrong_value_operand", lambda x:
           x["value_projection"]["nodes"][1].__setitem__("value", 6))
    reject("false_value_refinement_domain", lambda x:
           x["routes"][1]["value_refinement"].__setitem__(
               "domain", "all BV32 inputs"))
    reject("wrong_fixture_bytecode", lambda x:
           x["contract"]["fixture_bytecode_sha256"].__setitem__(
               "branchCall", "0" * 64))
    reject("fake_native_executor", lambda x:
           x.__setitem__("execution_semantics", "fully_executable"))
    reject("wrong_route_summary", lambda x:
           x["routes"][0]["nodes"][3].__setitem__(
               "summary_sha256", digest(GENERATED)))
    reject("hidden_opaque_region", lambda x:
           x["routes"][1]["nodes"][1].__setitem__("op", "FrozenNativeTransition"))
    reject("hidden_masked_write", lambda x:
           next(e for e in x["routes"][1]["nodes"][1]["effects"]
                if e["kind"] == "ObservedDeltaPossibleMaskedWrite").__setitem__(
                    "kind", "NativeWrite"))
    malformed_dag = deepcopy(doc["value_projection"])
    malformed_dag["nodes"][1]["sort"] = "BV64"
    try:
        value_dag(malformed_dag, 252)
    except PathILError:
        controls["mixed_width_value_dag"] = "rejected"
    else:
        raise PathILError("mixed-width typed value DAG was accepted")
    return controls


def main():
    doc, traces = build()
    validate(doc, traces)
    OUTPUT.write_text(json.dumps(doc, indent=2) + "\n")
    result = {"schema_version": "evidence-program-path-result-v1",
              "program_il_sha256": digest(OUTPUT),
              "readiness": readiness(doc),
              "related_exception_observation": {
                  "artifact_sha256": digest(EXCEPTION),
                  "binary_sha256": json.loads(EXCEPTION.read_text())["cases"][0]["binary_sha256"],
                  "observed_cases": len(json.loads(EXCEPTION.read_text())["cases"]),
                  "status": "separate controlled-pool fixture; observed cutpoints only",
                  "closes_selected_routes": False},
              "related_zero_branch_candidate": {
                  "artifact_sha256": digest(PREFIX_BRANCH_RESULT),
                  "source_fixed_environment_sat_witness": 0,
                  "candidate_execution_status": "earlier divergence; proposed PC not reached",
                  "closes_proposed_edge": False},
              "negative_controls": negative_controls(doc, traces),
              "next_obligations": [
                  "replace prefix opaque regions with computed state/memory transitions",
                  "model vector memset or bind a checked external-call effect contract",
                  "rebind zero-object tag and environment before accepting widened-prefix SAT candidate",
                  "enumerate branch alternatives and actual exception exits under a declared environment",
                  "obtain allocator extent/generation/ownership authority for CPython",
                  "lower semantic call/control/effect operations to an executable cross-engine IL"]}
    altered = deepcopy(result)
    altered["readiness"]["whole_logic_reconstruction_ready"] = True
    try:
        validate(doc, traces, altered)
    except PathILError:
        result["negative_controls"]["false_whole_logic_ready"] = "rejected"
    else:
        raise PathILError("false whole-logic readiness was accepted")
    altered = deepcopy(result)
    altered["related_exception_observation"]["closes_selected_routes"] = True
    try:
        validate(doc, traces, altered)
    except PathILError:
        result["negative_controls"]["foreign_exception_evidence_promoted"] = "rejected"
    else:
        raise PathILError("foreign exception evidence closed a route")
    altered = deepcopy(result)
    altered["related_zero_branch_candidate"]["closes_proposed_edge"] = True
    try:
        validate(doc, traces, altered)
    except PathILError:
        result["negative_controls"]["unrealized_sat_candidate_promoted"] = "rejected"
    else:
        raise PathILError("unrealized SAT candidate closed an edge")
    validate(doc, traces, result)
    RESULT.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"routes": len(doc["routes"]),
                      "opaque_steps": result["readiness"]["counts"]["opaque_native_steps_across_routes"],
                      "unexplored_branches": result["readiness"]["counts"]["unexplored_branch_occurrences"],
                      "negative_controls": len(result["negative_controls"])}))


if __name__ == "__main__":
    main()
