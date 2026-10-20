"""Compose source-rebuilt control observations with individual predicates."""
from __future__ import annotations

from copy import deepcopy
import json

from build_common_program_representation import ROOT, digest
from build_control_frontier_matrix import (OUTPUT as MATRIX,
    build as rebuild_matrix)
from common_program_path_il import require
from prove_lua_native_branch_predicate import (OUTPUT as LUA_PROOF,
    build as rebuild_lua_proof)
from prove_python_cache_branch_predicate import (OUTPUT as PY_PROOF,
    build as rebuild_python_proof)


OUTPUT = ROOT / "control_frontier_progress_v1.json"


def source_canonical():
    stored = {"matrix": json.loads(MATRIX.read_text()),
              "lua": json.loads(LUA_PROOF.read_text()),
              "python": json.loads(PY_PROOF.read_text())}
    canonical = {"matrix": rebuild_matrix(),
                 "lua": rebuild_lua_proof(),
                 "python": rebuild_python_proof()}
    require(stored == canonical,
            "saved control frontier or predicate differs from source replay")
    mutations = {
        "same_pc_wrong_occurrence": lambda d:
            next(item for item in d["matrix"]["occurrences"]
                 if item["occurrence_id"] == "lua_branch_x0:branch:159")
            ["opposite_evidence"].append({"occurrence_id": "lua_branch_x0:branch:166"}),
        "foreign_fixture_context": lambda d:
            next(item for item in d["matrix"]["occurrences"]
                 if item["occurrence_id"] == "python_251:branch:764")
            ["fixture"]["sha256"].update(addFive="0" * 64),
        "wrong_python_predicate_verdict": lambda d:
            d["python"]["cases"][0].update(
                prior_and_predicate_xor_candidate="sat"),
        "wrong_lua_predicate_verdict": lambda d:
            d["lua"]["cases"][0].update(
                prior_and_predicate_xor_candidate="sat"),
        "drop_call_exception_obligation": lambda d:
            next(item for item in d["matrix"]["occurrences"]
                 if item["kind"] == "NativeCallOccurrence").update(
                     exception_edge_complete=True),
    }
    negatives = {}
    for name, mutate in mutations.items():
        changed = deepcopy(stored)
        mutate(changed)
        negatives[name] = "rejected" if changed != canonical else "unexpectedly_accepted"
    require(all(value == "rejected" for value in negatives.values()),
            "frontier negative control survived source comparison")
    return canonical, negatives


def build():
    canonical, negatives = source_canonical()
    matrix, lua, python = (canonical[name] for name in
                           ("matrix", "lua", "python"))
    by_id = {item["occurrence_id"]: item for item in matrix["occurrences"]}
    predicate_links = []
    for engine, proof in (("lua", lua), ("python", python)):
        for case in proof["cases"]:
            item = by_id[case["target_occurrence_id"]]
            require(item["engine"] == engine and
                    item["trace_sha256"] == case["trace_sha256"] and
                    item["observed_successor"] == case["observed_successor"] and
                    item["opposite_evidence"] and
                    item["bytecode_context"] is not None and
                    case["prior_and_predicate_xor_candidate"] == "unsat",
                    "individual branch proof lacks matching frontier evidence")
            predicate_links.append({"occurrence_id": item["occurrence_id"],
                "engine": engine, "trace_sha256": item["trace_sha256"],
                "predicate": ("X == 0" if engine == "lua" else
                              "X >= 252 within 251..256"),
                "proof_grade": "native_pcode_under_prior_guards_and_fixed_snapshot",
                "bytecode_context": item["bytecode_context"],
                "alternate_paths_complete": False})
    counts = matrix["classification_counts"]
    observed = sum(counts.get(key, 0) for key in (
        "opposite_observed_same_prefix_and_bytecode_context",
        "opposite_observed_same_prefix_bytecode_unknown"))
    require(len(predicate_links) == 6 and observed == 11 and
            counts["normal_return_observed_exception_unknown"] == 61 and
            counts["opposite_observed_same_prefix_and_bytecode_context"] == 6 and
            len(matrix["excluded_earlier_divergence_probes"]) == 2 and
            matrix["occurrence_count"] == 720,
            "control frontier progress counts changed")
    return {"schema_version": "control-frontier-progress-v1",
        "matrix_sha256": digest(MATRIX),
        "lua_predicate_sha256": digest(LUA_PROOF),
        "python_predicate_sha256": digest(PY_PROOF),
        "occurrence_count": 720,
        "classification_counts": counts,
        "observed_opposite_occurrences": observed,
        "same_trace_bytecode_context_occurrences": 6,
        "individually_proved_predicate_occurrences": len(predicate_links),
        "predicate_links": predicate_links,
        "normal_return_observed_exception_unknown": 61,
        "excluded_earlier_divergence_probes":
            matrix["excluded_earlier_divergence_probes"],
        "negative_controls": negatives,
        "complete_handler_alternate_exit_sets": 0,
        "whole_program_complete": False,
        "remaining": ["collect and prove VM-semantic branch alternatives",
                      "model calls, exceptional exits and object lifetimes",
                      "compose certified VM-state transitions into whole logic"]}


def main():
    doc = build()
    OUTPUT.write_text(json.dumps(doc, indent=2) + "\n")
    require(json.loads(OUTPUT.read_text()) == doc,
            "frontier progress artifact changed after writing")
    print(json.dumps({"occurrences": doc["occurrence_count"],
                      "observed_opposite": doc["observed_opposite_occurrences"],
                      "proved_predicates": doc["individually_proved_predicate_occurrences"],
                      "complete_handler_alternate_exit_sets": 0}))


if __name__ == "__main__":
    main()
