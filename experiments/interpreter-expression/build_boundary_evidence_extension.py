"""Attach newly proved branch/cursor evidence to selected boundary IDs."""
from __future__ import annotations

import json
from copy import deepcopy

from build_common_program_representation import ROOT, digest
from common_program_path_il import require
from prove_lua_native_branch_predicate import (OUTPUT as LUA_PROOF,
    build as rebuild_lua_proof)
from map_cross_same_trace_cursor import (OUTPUT as CURSOR_PROOF,
    build as rebuild_cursor_proof)
from build_boundary_relevance_map import (OUTPUT as BASE_MAP,
    build as rebuild_base_map)
from discover_dispatch_intervals import OUTPUT as DISCOVERY


OUTPUT = ROOT / "boundary_evidence_extension_v1.json"


def canonical_sources():
    stored = {"base": json.loads(BASE_MAP.read_text()),
              "lua": json.loads(LUA_PROOF.read_text()),
              "cursors": json.loads(CURSOR_PROOF.read_text())}
    canonical = {"base": rebuild_base_map(),
                 "lua": rebuild_lua_proof(),
                 "cursors": rebuild_cursor_proof()}
    require(stored == canonical,
            "stored boundary, branch, or cursor evidence differs from source replay")
    changes = {
        "base_wrong_branch_edge": lambda d:
            d["base"]["first_lua_branch_frontier"]["cases"][0].update(
                observed_successor="0xdeadbeef"),
        "lua_false_unsat_label": lambda d:
            d["lua"]["cases"][0].update(
                prior_and_predicate_xor_candidate="sat"),
        "python_wrong_cursor_offset": lambda d:
            d["cursors"]["cases"][0].update(
                fixture_manifest_opcode_offset=8),
        "js_wrong_trace_hash": lambda d:
            d["cursors"]["cases"][1].update(trace_sha256="0" * 64),
    }
    rejected = {}
    for name, change in changes.items():
        altered = deepcopy(stored)
        change(altered)
        rejected[name] = "rejected" if altered != canonical else "unexpectedly_accepted"
    require(all(value == "rejected" for value in rejected.values()),
            "altered upstream evidence survived canonical comparison")
    return canonical, rejected


def build():
    canonical, negatives = canonical_sources()
    base, lua, cursors = (canonical[name] for name in
                          ("base", "lua", "cursors"))
    discovery = json.loads(DISCOVERY.read_text())
    frontier = base["first_lua_branch_frontier"]
    require(lua["schema_version"] == "lua-native-branch-predicate-v1" and
            cursors["schema_version"] == "cross-same-trace-cursor-v1" and
            frontier["native_branch_pc"] == "0x415f30" and
            frontier["branch_predicate_proved_individually"] is False and
            len(lua["cases"]) == 2 and len(cursors["cases"]) == 2,
            "boundary extension inputs changed")
    lua_links = []
    for proof in lua["cases"]:
        earlier = next(item for item in frontier["cases"]
                       if item["input_label"] == proof["input_label"])
        boundary = next(item for item in base["boundaries"]
                        if item["unit_id"] ==
                        f"lua_branch_{proof['input_label']}")
        require(earlier["occurrence_id"] == proof["target_occurrence_id"] and
                earlier["observed_successor"] == proof["observed_successor"] and
                boundary["trace_sha256"] == proof["trace_sha256"] and
                proof["prior_and_predicate_xor_candidate"] == "unsat" and
                proof["prior_with_x_zero"] == proof["prior_with_x_nonzero"] == "sat",
                "Lua proof does not extend the recorded branch occurrence")
        lua_links.append({"boundary_id": boundary["id"],
                          "occurrence_id": proof["target_occurrence_id"],
                          "raw_taken_predicate": "X == 0",
                          "proof_grade": "native_pcode_predicate_under_prior_guards_two_sided_sat",
                          "alternate_paths_complete": False})
    py, js = cursors["cases"]
    py_boundary = next(item for item in base["boundaries"]
                       if item["id"] == py["boundary_id"])
    js_boundary = next(item["boundary"] for item in discovery["cases"]
                       if item["engine"] == "javascript" and item["input"] == 43)
    require(py_boundary["trace_sha256"] == py["trace_sha256"] and
            py_boundary["entry_pc"] == py["handler_entry_pc"] and
            py["fixture_manifest_opcode_offset"] == 6 and
            js_boundary["entry_pc"] == js["handler_entry_pc"] and
            js["cursor_delta_from_first_child_fetch"] == 2 and
            js["absolute_bytecode_offset"] is None,
            "cursor proof does not extend the selected dispatch boundaries")
    return {"schema_version": "boundary-evidence-extension-v1",
        "base_map_sha256": digest(BASE_MAP),
        "lua_predicate_proof_sha256": digest(LUA_PROOF),
        "cross_cursor_proof_sha256": digest(CURSOR_PROOF),
        "upstream_negative_controls": negatives,
        "lua_branch_links": lua_links,
        "cursor_links": [
            {"boundary_id": py_boundary["id"], "engine": "python",
             "trace_sha256": py["trace_sha256"],
             "opcode_byte": py["selected_opcode_byte"],
             "bytecode_offset": py["fixture_manifest_opcode_offset"],
             "grade": py["binding_grade"]},
            {"boundary_id": js["boundary_id"], "engine": "javascript",
             "trace_sha256": js["trace_sha256"],
             "opcode_byte": js["selected_opcode_byte"],
             "relative_cursor_offset": js["cursor_delta_from_first_child_fetch"],
             "absolute_bytecode_offset": None,
             "grade": js["binding_grade"],
             "same_as_local_js_holdout_fixture": False}],
        "whole_program_complete": False,
        "remaining_obligations": [
            "other branch opposites and call/exception exits",
            "safe object, memory and lifetime effects across handlers",
            "compose bounded VM transitions into a readable full-program IL"]}


def main():
    doc = build()
    OUTPUT.write_text(json.dumps(doc, indent=2) + "\n")
    require(json.loads(OUTPUT.read_text()) == doc,
            "boundary evidence extension changed after writing")
    print(json.dumps({"lua_branch_links": len(doc["lua_branch_links"]),
                      "cursor_links": len(doc["cursor_links"]),
                      "whole_program_complete": False}))


if __name__ == "__main__":
    main()
