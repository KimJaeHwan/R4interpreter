"""Classify every saved native control occurrence by same-context evidence."""
from __future__ import annotations

from collections import Counter, defaultdict
from copy import deepcopy
import gzip
from hashlib import sha256
import json
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_64

from apply_bounded_python_program import HOLDOUT
from apply_transition_summary import load_trace as load_lua_local
from audit_python_branch_candidates import conditional_successors
from build_boundary_relevance_map import OUTPUT as BOUNDARIES
from build_common_control_worklist import OUTPUT as WORKLIST
from build_boundary_evidence_extension import build as rebuild_prior_extension
from build_common_program_representation import (JS_TRACE, LUA_BINARY,
    LUA_BYTECODE,
    LUA_TRACE, ROOT, digest, lua_flow_trace, lua_vm_rows)
from common_program_path_il import require
from cross_dispatch_pcode import read_vaddr
from map_cross_same_trace_cursor import (PRIOR_PY, python_binding,
    python_fixture_manifest)
from map_lua_branch_dispatch import build as rebuild_lua_map
from probe_python_remaining_scope import TRACES
from probe_unseen_python_path import PYTHON
from prove_cross_full_flow import JAVASCRIPT, load_trace
from prove_lua_full_flow import trace_records


OUTPUT = ROOT / "control_frontier_matrix_v1.json"
PY_TRACES = {**TRACES, 255: HOLDOUT}
LUA_MAP = ROOT / "lua_branch_dispatch_map_v1.json"
PREVIOUS_EXTENSION = ROOT / "boundary_evidence_extension_v1.json"


def source_rows(unit, boundaries):
    uid = unit["id"]
    if unit["engine"] == "python":
        value = int(uid.removeprefix("python_"))
        path = PY_TRACES[value]
        meta, rows, _ = load_trace(path, "python", value, PYTHON)
        require(unit["fixture"]["sha256"] ==
                meta["marker"]["bytecode_sha256"],
                "Python frontier fixture differs from trace")
    elif uid == "lua_segment":
        path = LUA_TRACE
        boundary = next(item for item in boundaries if item["unit_id"] == uid)
        _, rows = load_lua_local(path, int(boundary["entry_pc"], 16),
                                 int(boundary["exit_successor"], 16))
        meta = None
    elif uid == "javascript_segment":
        path = JS_TRACE
        with gzip.open(path, "rt") as stream:
            records = [json.loads(line) for line in stream]
        meta, rows = records[0], records[1]["rows"]
        require(meta["binary_sha256"] == unit["binary_sha256"] and
                meta["fixture_sha256"] == unit["fixture"]["sha256"],
                "JavaScript local frontier fixture differs")
    else:
        path = lua_flow_trace(uid.removeprefix("lua_branch_"))
        records = trace_records(path)
        rows = lua_vm_rows(records)
        meta = records[0]
        require(Path(records[0]["bytecode"]).name == LUA_BYTECODE.name and
                unit["fixture"]["sha256"] == digest(LUA_BYTECODE),
                "Lua frontier bytecode differs")
    require(digest(path) == unit["source_trace_sha256"] and rows,
            "frontier source trace changed")
    return path, rows, meta


def native_bytes(row, engine):
    if "bytes" in row:
        blob = row["bytes"]
        if row["pc"] < 0x70000000:
            binary = {"python": PYTHON, "javascript": JAVASCRIPT,
                      "lua": LUA_BINARY}[engine]
            require(bytes.fromhex(blob) == read_vaddr(
                binary, row["pc"], row["pc"] + len(blob) // 2),
                "frontier trace bytes differ from pinned executable")
        return blob
    require(engine == "lua", "native instruction bytes missing")
    decoded = next(Cs(CS_ARCH_X86, CS_MODE_64).disasm(
        read_vaddr(LUA_BINARY, row["pc"], row["pc"] + 15), row["pc"]))
    require(f"{decoded.mnemonic} {decoded.op_str}".strip() ==
            row["instruction"], "Lua frontier native instruction changed")
    return decoded.bytes.hex()


def boundary_for(item, boundaries):
    found = [b for b in boundaries if b["unit_id"] == item["unit_id"] and
             b["span_in_unit"][0] <= item["step_in_unit"] <
             b["span_in_unit"][1]]
    require(len(found) <= 1, "control occurrence belongs to overlapping boundaries")
    return found[0] if found else None


def anchor(item, boundary, rows):
    if boundary is None:
        return None
    begin, _ = boundary["span_in_unit"]
    step = item["step_in_unit"]
    prefix = [(hex(row["pc"]), native_bytes(row, item["engine"]),
               hex(row["next_pc"])) for row in rows[begin:step]]
    require(rows[begin]["pc"] == int(boundary["entry_pc"], 16),
            "control boundary entry changed")
    return {"boundary_id": boundary["id"],
            "boundary_kind": boundary["boundary_kind"],
            "handler_entry_pc": boundary["entry_pc"],
            "step_from_boundary_entry": step - begin,
            "prefix_sha256": sha256(json.dumps(prefix).encode()).hexdigest()}


def counterpart_key(item):
    anchor = item["anchor"]
    if anchor is None or item["kind"] != "NativeConditionalOccurrence":
        return None
    return (item["engine"], item["binary_sha256"],
            json.dumps(item["fixture"], sort_keys=True),
            anchor["boundary_kind"], anchor["handler_entry_pc"],
            anchor["step_from_boundary_entry"], anchor["prefix_sha256"],
            item["pc"], item["native_bytes"])


def build():
    saved = json.loads(WORKLIST.read_text())
    boundaries = json.loads(BOUNDARIES.read_text())["boundaries"]
    previous = json.loads(PREVIOUS_EXTENSION.read_text())
    lua_map = json.loads(LUA_MAP.read_text())
    # The prior extension rebuilds the base boundary map, which rebuilds and
    # compares the entire worklist. Check the other two stored inputs directly.
    require(previous == rebuild_prior_extension() and
            lua_map == rebuild_lua_map(),
            "frontier upstream maps differ from original native evidence")
    upstream = {"boundaries": json.loads(BOUNDARIES.read_text()),
                "extension": previous, "lua_map": lua_map}
    changed_boundary = deepcopy(upstream)
    changed_boundary["boundaries"]["boundaries"][0]["span_in_unit"][0] += 1
    changed_boundary["extension"]["base_map_sha256"] = sha256(
        (json.dumps(changed_boundary["boundaries"], indent=2) + "\n").encode()
    ).hexdigest()
    changed_lua = deepcopy(upstream)
    changed_lua["lua_map"]["traces"][0]["events"][0]["file_byte_offset"] = 0
    changed_lua["boundaries"]["source_sha256"]["lua_dispatch_map"] = sha256(
        (json.dumps(changed_lua["lua_map"], indent=2) + "\n").encode()
    ).hexdigest()
    changed_lua["extension"]["base_map_sha256"] = sha256(
        (json.dumps(changed_lua["boundaries"], indent=2) + "\n").encode()
    ).hexdigest()
    upstream_negatives = {
        "boundary_start_and_matching_extension_hash":
            "rejected" if changed_boundary != upstream else "unexpectedly_accepted",
        "lua_fetch_offset_and_matching_upper_hashes":
            "rejected" if changed_lua != upstream else "unexpectedly_accepted"}
    require(all(value == "rejected" for value in upstream_negatives.values()),
            "co-mutated upstream evidence survived canonical comparison")
    require(len(saved["occurrences"]) == 720 and
            previous["base_map_sha256"] == digest(BOUNDARIES) and
            len(previous["lua_branch_links"]) == 2,
            "frontier upstream evidence changed")
    units = {unit["id"]: unit for unit in saved["units"]}
    source = {uid: source_rows(unit, boundaries)
              for uid, unit in units.items()}
    candidates = []
    for occurrence in saved["occurrences"]:
        item = deepcopy(occurrence)
        uid = item["unit_id"]
        _, rows, _ = source[uid]
        step = item["step_in_unit"]
        require(0 <= step < len(rows), "control occurrence outside source trace")
        row = rows[step]
        require(hex(row["pc"]) == item["pc"] and
                item["source_trace_sha256"] == units[uid]["source_trace_sha256"] and
                (item["trace_native_step"] is None or
                 item["trace_native_step"] == row["step"]),
                "control occurrence maps to a different native step")
        blob = native_bytes(row, item["engine"])
        if item["kind"] == "NativeConditionalOccurrence":
            legal = conditional_successors({**row, "bytes": blob})
            require(legal == {int(item["observed_successor"], 16),
                              int(item["target_successor"], 16)} and
                    row["next_pc"] == int(item["observed_successor"], 16),
                    "frontier branch successor or instruction differs")
        else:
            require(row["next_pc"] == int(item["observed_target"], 16) and
                    item["observed_return_edge"] ==
                    "observed_at_matching_stack_depth" and
                    item["exception_edge"].startswith("unknown") and
                    item["exception_infeasible_proved"] is False,
                    "frontier call return/exception obligation changed")
        boundary = boundary_for(item, boundaries)
        candidates.append({"occurrence_id": item["id"],
            "kind": item["kind"], "unit_id": uid, "engine": item["engine"],
            "binary_sha256": item["binary_sha256"],
            "fixture": item["fixture"],
            "trace_sha256": item["source_trace_sha256"],
            "step_in_unit": step, "trace_native_step": row["step"],
            "pc": item["pc"], "native_bytes": blob,
            "native_byte_provenance": ("pinned_executable"
                if row["pc"] < 0x70000000 else "captured_external_mapping"),
            "observed_successor": hex(row["next_pc"]),
            "target_successor": item.get("target_successor"),
            "anchor": anchor(item, boundary, rows),
            "source_fixed_unsat": item.get("source_fixed_unsat_certificate")
                is not None,
            "normal_return_observed": item.get("observed_return_edge") ==
                "observed_at_matching_stack_depth",
            "exception_edge": item.get("exception_edge"),
            "opposite_evidence": [],
            "bytecode_context": None,
            "alternate_edge_complete": False,
            "exception_edge_complete": False})
    # The independently checked numeric dispatch mapping can be applied to
    # each exact same-trace Python input, but only at the selected child handler.
    with gzip.open(PRIOR_PY, "rt") as stream:
        prior = json.load(stream)
    manifest = python_fixture_manifest()
    for uid in PY_TRACES:
        key = f"python_{uid}"
        _, rows, meta = source[key]
        pointer = {"address": meta["marker"]["code_pointers"]["addFive"],
                   "bytecode_sha256": meta["marker"]["bytecode_sha256"]}
        require(manifest["hashes"] == pointer["bytecode_sha256"],
                "regenerated Python bytecode differs from native trace marker")
        offset = python_binding(rows[617], rows[675], rows[682], rows[683],
                                pointer, prior["marker"], manifest)
        target = next(x for x in candidates if
                      x["occurrence_id"] == f"{key}:branch:764")
        require(target["pc"] == "0x5e978a" and
                target["anchor"]["handler_entry_pc"] == "0x56227c",
                "Python cache branch left the selected handler")
        target["bytecode_context"] = {"grade": "same_trace_fetch_to_handler",
            "fixture_offset": offset, "numeric_opcode": 0x2D,
            "handler_entry_pc": "0x56227c"}
    for label in ("x0", "x9"):
        case = next(x for x in lua_map["traces"] if x["input_label"] == label)
        event = next(x for x in case["events"] if x["file_byte_offset"] == 51)
        target = next(x for x in candidates if
                      x["occurrence_id"] == f"lua_branch_{label}:branch:32")
        require(event["handler_entry_pc"] == "0x415ee0" and
                event["numeric_opcode"] == 61 and
                case["trace_sha256"] == target["trace_sha256"] and
                target["pc"] == "0x415f30",
                "Lua branch no longer follows same-trace bytecode dispatch")
        target["bytecode_context"] = {"grade": "same_trace_fetch_to_handler",
            "fixture_offset": 51, "numeric_opcode": 61,
            "handler_entry_pc": "0x415ee0"}
    groups = defaultdict(list)
    for item in candidates:
        key = counterpart_key(item)
        if key is not None:
            groups[key].append(item)
    for group in groups.values():
        for item in group:
            item["opposite_evidence"] = [{"occurrence_id": other["occurrence_id"],
                 "trace_sha256": other["trace_sha256"],
                 "trace_native_step": other["trace_native_step"],
                 "successor": other["observed_successor"],
                 "bytecode_context": other["bytecode_context"]}
                for other in group if other["unit_id"] != item["unit_id"] and
                other["observed_successor"] == item["target_successor"]]
    by_id = {item["occurrence_id"]: item for item in candidates}
    require(all(by_id[key]["opposite_evidence"] for key in
                ("python_251:branch:764", "python_252:branch:764",
                 "lua_branch_x0:branch:32", "lua_branch_x9:branch:32")) and
            not by_id["lua_branch_x0:branch:159"]["opposite_evidence"] and
            not by_id["lua_branch_x0:branch:166"]["opposite_evidence"] and
            not by_id["lua_branch_x9:branch:203"]["opposite_evidence"] and
            not by_id["lua_branch_x9:branch:210"]["opposite_evidence"],
            "repeated Lua loop branch was conflated with a same occurrence")
    changed_fixture = deepcopy(by_id["python_251:branch:764"])
    changed_fixture["fixture"]["sha256"]["addFive"] = "0" * 64
    require(counterpart_key(changed_fixture) !=
            counterpart_key(by_id["python_252:branch:764"]),
            "different Python bytecode fixture was conflated")
    for item in candidates:
        if item["kind"] == "NativeCallOccurrence":
            item["classification"] = "normal_return_observed_exception_unknown"
        elif (item["opposite_evidence"] and item["bytecode_context"] and
              any(other["bytecode_context"] == item["bytecode_context"]
                  for other in item["opposite_evidence"])):
            item["classification"] = "opposite_observed_same_prefix_and_bytecode_context"
        elif item["opposite_evidence"]:
            item["classification"] = "opposite_observed_same_prefix_bytecode_unknown"
        elif item["source_fixed_unsat"]:
            item["classification"] = "opposite_unsat_in_source_fixed_domain"
        else:
            item["classification"] = "opposite_unresolved"
    counts = Counter(item["classification"] for item in candidates)
    excluded_probes = [{"id": probe["id"],
        "target_obligation_id": probe["target_obligation_id"],
        "classification": probe["classification"],
        "target_trace_sha256": probe["target_trace_sha256"],
        "promoted_to_same_occurrence_evidence": False}
        for probe in saved["candidate_probes"]
        if probe["classification"] == "earlier_divergence"]
    require(len(excluded_probes) == 2 and
            {item["id"] for item in excluded_probes} ==
            {"python_prefix_x0", "python_numeric_x1"},
            "earlier-divergence probes were promoted")
    require(sum(counts.values()) == 720 and
            len({item["occurrence_id"] for item in candidates}) == 720 and
            sum(item["kind"] == "NativeCallOccurrence" for item in candidates) == 61 and
            all(not item["alternate_edge_complete"] and
                    not item["exception_edge_complete"] for item in candidates),
            "frontier inventory removed or closed an obligation")
    return {"schema_version": "control-frontier-matrix-v1",
        "worklist_sha256": digest(WORKLIST),
        "boundary_map_sha256": digest(BOUNDARIES),
        "prior_extension_sha256": digest(PREVIOUS_EXTENSION),
        "occurrence_count": len(candidates),
        "classification_counts": dict(counts),
        "upstream_negative_controls": upstream_negatives,
        "excluded_earlier_divergence_probes": excluded_probes,
        "occurrences": candidates,
        "limits": ["opposite trace uses a different fixed entry snapshot",
                   "external libc instruction bytes are captured in the trace, not checked against the main executable",
                   "matching native control prefixes do not prove all VM paths",
                   "only explicitly bound bytecode sites carry a bytecode context",
                   "normal returns do not close exception exits"]}


def main():
    doc = build()
    OUTPUT.write_text(json.dumps(doc, indent=2) + "\n")
    require(json.loads(OUTPUT.read_text()) == doc,
            "frontier matrix changed after writing")
    print(json.dumps(doc["classification_counts"], sort_keys=True))


if __name__ == "__main__":
    main()
