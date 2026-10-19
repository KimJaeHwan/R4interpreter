"""Build a bounded, engine-neutral *representational* program IL.

The saved graph is an evidence-bearing view of selected native paths. P-code
windows point to a pinned replay implementation; it is not a standalone native
executor. A local handler segment is never promoted to an enclosing program.
"""
from __future__ import annotations

from copy import deepcopy
import gzip
from hashlib import sha256
import json
from pathlib import Path
import shutil

from capstone import Cs, CS_ARCH_X86, CS_MODE_64

from apply_bounded_python_program import HOLDOUT, run_route
from build_evidence_program_il import bundles, validate as validate_path_il, windows
from common_observed_transition import apply_case
from common_program_path_il import fingerprint, native_path_ledger, require, value_dag
from cross_dispatch_pcode import read_vaddr
from probe_connected_python_program import observed_edges, path_inventory
from probe_python_remaining_scope import TRACES
from probe_unseen_python_path import (COMMON as CACHED_SUMMARY,
    GENERATED as ALLOCATED_SUMMARY, NEIGHBOR_SUMMARY, PYTHON, ROOT)
from prove_cross_full_flow import load_trace as load_python_trace
from apply_transition_summary import load_trace as load_lua_trace
from bounded_memset_contract import LIBC_SHA256, EXPECTED_OFFSETS, EXPECTED_BYTES


OUTPUT = ROOT / "common_program_representation_v1.json"
RESULT = ROOT / "common_program_representation_result.json"
PATH_IL = ROOT / "evidence_program_path_il.json"
APPLICATION = ROOT / "bounded_python_program_application_result.json"
COMMON = ROOT / "common_three_engine_transitions.json"
VALUE = ROOT / "common_numeric_refinement_result.json"
LUA_BINARY = ROOT / "lua_interpreter_fixture"
LUA_TRACE = ROOT / "artifacts/lua_handler_plus11_x9.jsonl"
JS_TRACE = ROOT / "artifacts/js_handler_holdout_37.json.gz"


def digest(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def external_contract(certificate):
    require(certificate["status"] == "checked_exact_witness_conditional_contract" and
            certificate["libc_sha256"] == LIBC_SHA256 and
            certificate["definite_write_extent"] == 8 and
            certificate["defined_flag_bits"] == [0, 6, 7, 11] and
            certificate["undefined_flag_bits"] == [2],
            "bounded libc certificate changed")
    return {"contract_id": "pinned_libc_avx512_zero8_v1",
            "code_identity": {"libc_sha256": LIBC_SHA256,
                "instruction_offsets": [hex(offset) for offset in EXPECTED_OFFSETS],
                "instruction_bytes": EXPECTED_BYTES},
            "preconditions": ["exact selected twelve-instruction path",
                "RDX = 8", "RSI = 0", "RDI page offset <= 0xfc0",
                "RDI + 64 and RSP + 8 do not wrap BV64",
                "[RDI,RDI+8) and [RSP,RSP+8) do not alias",
                "stack return address = 0x56004d",
                "incoming scalar state and first-read bytes match witness"],
            "effect": {"kind": "DefiniteByteWrite", "base": "old RDI",
                "extent_bytes": 8, "value": "0x00 per byte",
                "same_value_writes_preserved": True,
                "observed_address": certificate["definite_write_address"]},
            "scalar_outputs": {"RAX": "old RDI", "RDI": "old RDI & 0xfff",
                "RCX": "0xff", "RSP": "old RSP + 8",
                "other_modeled_GPR": "unchanged", "FS_BASE": "unchanged",
                "GS_BASE": "unchanged"},
            "flag_outputs": {"defined_zero_bits": [0, 6, 7, 11],
                "undefined_bits": [2]},
            "excluded_live_out": ["vector registers", "mask registers"],
            "certificate": deepcopy(certificate),
            "implementation": "bounded_memset_contract.py:apply"}


def obligations(control, *, enclosing, lifetime=False, vector=False):
    result = []
    for branch in control["conditional_branches"]:
        result.append({"op": "UnknownEdge", "pc": branch["pc"],
            "observed_successor": branch["observed_successor"],
            "other_successor": branch["opposite_successor"],
            "status": branch["opposite_status"],
            "semantics": "unresolved_outside_selected_path"})
    for call in control["calls"]:
        result.append({"op": "UnknownExceptionEdge", "pc": call["pc"],
            "status": call["exception_edge"],
            "semantics": "unresolved_outside_selected_path"})
        if call["return_edge"].startswith("unknown"):
            result.append({"op": "UnknownReturnEdge", "pc": call["pc"],
                "status": call["return_edge"],
                "semantics": "unresolved_outside_selected_path"})
    if lifetime:
        result.append({"op": "UnknownLifetime", "status":
            "native writes do not establish allocator authority/freshness",
            "semantics": "unresolved_object_effect"})
    if vector:
        result.append({"op": "UnknownVectorMaskLiveOut", "status":
            "libc contract excludes vector and mask register live-out",
            "semantics": "unresolved_state_component"})
    result.append({"op": "UnknownEnclosingProgram" if enclosing else
                   "UnknownOutsideSelectedPath", "status":
                   "other inputs, paths, and environment states unproved",
                   "semantics": "unresolved_program_coverage"})
    return result


def python_routes(published, application):
    by_input = {case["input"]: case for case in application["cases"]}
    published_routes = {route["input"]: route for route in published["routes"]}
    allocated, neighbor, cached = bundles()
    loaded = {value: load_python_trace(TRACES.get(value, HOLDOUT), "python",
                                      value, PYTHON) for value in (251, 252, 254, 255)}
    validate_path_il(published, {value: loaded[value] for value in (251, 252, 254)})
    source_edges = observed_edges([loaded[value][1] for value in (251, 252, 254)])
    routes = []
    for value in (251, 252, 254, 255):
        trace = TRACES.get(value, HOLDOUT)
        meta, rows, summary = loaded[value]
        first = cached if value == 251 else allocated
        spans = windows(rows, first, neighbor)
        spans[3]["summary_sha256"] = digest(CACHED_SUMMARY if value == 251
                                              else ALLOCATED_SUMMARY)
        spans[4]["summary_sha256"] = digest(NEIGHBOR_SUMMARY)
        ledger = native_path_ledger(rows, spans)
        if value in published_routes:
            require(ledger == published_routes[value]["nodes"],
                    "published Python native access ledger changed")
        checked = run_route(value, trace, published_routes.get(value))
        require(checked == by_input[value] and checked["status"] == "bounded_path_applied" and
                checked["nodes_applied"] == 6 and
                checked["trace_sha256"] == digest(trace),
                "Python computed path application changed")
        certificates = checked["certificates"]
        require([c["node"] for c in certificates] == [n["id"] for n in ledger],
                "Python node certificate order changed")
        nodes = []
        for node, certificate in zip(ledger, certificates):
            operation = {"PcodeReplayedWindow": "PcodeWindow",
                         "OpaqueExternalCall": "CheckedExternalEffect",
                         "FrozenNativeTransition": "GuardedNativeTransition"}[node["op"]]
            body = {"id": node["id"], "op": operation,
                "native_span": [node["begin"], node["end_exclusive"]],
                "entry_pc": node["entry_pc"], "exit_successor": node["exit_successor"],
                "observed_ledger": node,
                "handoff": "computed_scalar_and_byte_memory_exact_witness",
                "certificate": certificate}
            if operation == "PcodeWindow":
                body["semantic_source"] = {"op": "PcodeReplay",
                    "implementation": "probe_connected_python_prefix.py:replay",
                    "implementation_sha256": {
                        filename: digest(ROOT / filename) for filename in (
                            "probe_connected_python_prefix.py",
                            "prove_cross_full_flow.py",
                            "pcode_transition_summary.py")},
                    "trace_sha256": digest(trace),
                    "instruction_bytes_sha256": fingerprint(
                        [row["bytes"] for row in rows[node["begin"]:node["end_exclusive"]]])}
            elif operation == "CheckedExternalEffect":
                body["contract"] = external_contract(certificate)
            else:
                body["transition_case"] = deepcopy(
                    (first if node["id"] == "numeric_transition" else neighbor)["cases"][0])
                body["transition_case_sha256"] = fingerprint(body["transition_case"])
                body["source_summary_sha256"] = node["summary_sha256"]
            nodes.append(body)
        control = path_inventory(rows, source_edges if value in published_routes else {})
        if value in published_routes:
            require(control == published_routes[value]["control"],
                    "published Python control inventory changed")
        require(not control["complete"], "Python control coverage promoted")
        routes.append({"id": f"python_{value}", "engine": "python",
            "application_unit": "selected_full_native_path",
            "validation_grade": "computed_scalar_and_byte_memory_exact_witness",
            "binary_sha256": digest(PYTHON), "trace_sha256": digest(trace),
            "input_domain": {"kind": "single_exact_witness", "value": value,
                "other_entry_state": "trace-specific first-read environment"},
            "native_steps": len(rows), "nodes": nodes,
            "control": control,
            "obligations": obligations(control, enclosing=False,
                lifetime=value != 251, vector=True),
            "value_binding": {"input": value, "output": checked["numeric_value"],
                "projection": "BV32 X + 5", "output_pointer": checked["output_pointer"],
                "grade": checked["output_grade"]},
            "source_fixed_conditional_proofs":
                published_routes[value]["conditional_proofs"] if value in published_routes else []})
    return routes


def local_segment(common, case_index, binary, trace, rows, meta):
    case = common["cases"][case_index]
    result = apply_case(common, case, binary, rows, meta)
    require(result["status"] == "differentially_validated",
            f"{case['engine']} segment application changed: {result['status']}")
    if case["engine"] == "lua":
        decoder = Cs(CS_ARCH_X86, CS_MODE_64)
        augmented = []
        for row in rows:
            decoded = next(decoder.disasm(read_vaddr(binary, row["pc"], row["pc"] + 15),
                                          row["pc"]))
            require(f"{decoded.mnemonic} {decoded.op_str}".strip() ==
                    row["instruction"], "Lua instruction bytes changed")
            augmented.append({**row, "bytes": decoded.bytes.hex()})
        control = path_inventory(augmented, {})
    else:
        control = path_inventory(rows, {})
    ledger = native_path_ledger(rows, [{"id": "handler_segment", "begin": 0,
        "end_exclusive": len(rows), "op": "GuardedNativeTransition"}])[0]
    require(case["identity"]["binary_sha256"] == digest(binary) and
            case["identity"]["native_steps"] == len(rows) and
            case["identity"]["entry_pc"] == ledger["entry_pc"] and
            case["identity"]["next_pc"] == ledger["exit_successor"],
            "local segment identity changed")
    return {"id": f"{case['engine']}_segment", "engine": case["engine"],
        "application_unit": "single_handler_segment",
        "validation_grade": "frozen_summary_reused_at_target",
        "binary_sha256": digest(binary), "trace_sha256": digest(trace),
        "input_domain": {"kind": "exact_target_snapshot_and_guard",
            "preconditions": case["preconditions"]},
        "native_steps": len(rows),
        "nodes": [{"id": "handler_segment", "op": "GuardedNativeTransition",
            "native_span": [0, len(rows)], "entry_pc": ledger["entry_pc"],
            "exit_successor": ledger["exit_successor"],
            "observed_ledger": ledger, "handoff": "local_segment_only",
            "transition_case": deepcopy(case), "certificate": result}],
        "control": control,
        "obligations": obligations(control, enclosing=True),
        "value_binding": None}


def build():
    published = json.loads(PATH_IL.read_text())
    application = json.loads(APPLICATION.read_text())
    common = json.loads(COMMON.read_text())
    value = json.loads(VALUE.read_text())
    require(published["schema_version"] == "evidence-program-path-il-v1" and
            application["program_il_sha256"] == digest(PATH_IL) and
            common["schema_version"] == "common-observed-transition-v1" and
            value["schema_version"] == "common-numeric-refinement-v1",
            "upstream artifact identity changed")
    require([item["engine"] for item in value["adapters"]] ==
            ["lua", "python", "javascript"] and
            all(value_dag(value["value_il"], x) == x + 5 for x in (5, 251)),
            "common value DAG changed")
    _, lua_rows = load_lua_trace(LUA_TRACE, 0x4164B8, 0x415B24)
    with gzip.open(JS_TRACE, "rt") as stream:
        js_records = [json.loads(line) for line in stream]
    require(len(js_records) == 3 and js_records[1]["type"] == "path",
            "JS handler trace changed")
    js_binary = Path(shutil.which("node") or "")
    require(js_binary.is_file(), "pinned Node binary unavailable")
    routes = python_routes(published, application)
    routes.append(local_segment(common, 0, LUA_BINARY, LUA_TRACE, lua_rows, None))
    routes.append(local_segment(common, 3, js_binary, JS_TRACE,
                                js_records[1]["rows"], js_records[0]))
    doc = {"schema_version": "common-program-representation-v1",
        "kind": "bounded_representational_il",
        "state_model": {"architecture": "x86-64", "endian": "little",
            "scalar": "16 GPRs; modeled CF/PF/ZF/SF/OF; FS/GS bases",
            "memory": "byte-addressed, ordered writes and first-read environment",
            "excluded": ["vector register live-out", "mask register live-out",
                         "heap ownership/freshness without authority"]},
        "execution_semantics": "value_DAG_only; native nodes require cited replay/evaluator",
        "whole_program_complete": False,
        "source_sha256": {"path_il": digest(PATH_IL),
            "python_application": digest(APPLICATION),
            "common_transitions": digest(COMMON), "value_refinement": digest(VALUE),
            "lua_target_trace": digest(LUA_TRACE), "js_target_trace": digest(JS_TRACE)},
        "value_library": {"value_il": value["value_il"],
            "adapters": value["adapters"],
            "application_note": "BV32 X+5 is independent of selected Lua plus11 segment"},
        "routes": routes}
    validate_structure(doc)
    return doc


def validate_structure(doc):
    require(doc["schema_version"] == "common-program-representation-v1" and
            doc["whole_program_complete"] is False and len(doc["routes"]) == 6,
            "common program schema or completeness changed")
    require([r["engine"] for r in doc["routes"]] ==
            ["python"] * 4 + ["lua", "javascript"], "engine mapping changed")
    require(doc["value_library"]["application_note"].endswith("plus11 segment") and
            value_dag(doc["value_library"]["value_il"], 5) == 10 and
            value_dag(doc["value_library"]["value_il"], 251) == 256,
            "value projection changed")
    for route in doc["routes"]:
        python = route["engine"] == "python"
        require(route["application_unit"] == ("selected_full_native_path" if python else
                "single_handler_segment") and route["validation_grade"] ==
                ("computed_scalar_and_byte_memory_exact_witness" if python else
                 "frozen_summary_reused_at_target") and
                len(route["nodes"]) == (6 if python else 1),
                "route scope or grade changed")
        require(route["input_domain"]["kind"] ==
                ("single_exact_witness" if python else
                 "exact_target_snapshot_and_guard") and
                route["control"]["complete"] is False and
                any(o["op"] == ("UnknownOutsideSelectedPath" if python else
                                 "UnknownEnclosingProgram") for o in route["obligations"]),
                "unknown path obligation omitted")
        require(sum(n["native_span"][1] - n["native_span"][0]
                    for n in route["nodes"]) == route["native_steps"] and
                all(a["native_span"][1] == b["native_span"][0] and
                    a["exit_successor"] == b["entry_pc"] for a, b in
                    zip(route["nodes"], route["nodes"][1:])),
                "native node partition or handoff changed")
        for node in route["nodes"]:
            require(node["observed_ledger"]["entry_pc"] == node["entry_pc"] and
                    node["observed_ledger"]["exit_successor"] ==
                    node["exit_successor"], "ledger identity changed")
            if node["op"] == "CheckedExternalEffect":
                require(node["contract"]["effect"]["extent_bytes"] == 8 and
                        node["contract"]["effect"]["value"] == "0x00 per byte" and
                        node["contract"]["code_identity"]["libc_sha256"] ==
                        LIBC_SHA256 and node["contract"]["flag_outputs"] ==
                        {"defined_zero_bits": [0, 6, 7, 11], "undefined_bits": [2]},
                        "external contract weakened")
            if node["op"] == "GuardedNativeTransition":
                require(node["transition_case"]["engine"] == route["engine"] and
                        node["transition_case"]["identity"]["binary_sha256"] ==
                        route["binary_sha256"] and
                        node.get("transition_case_sha256",
                                 fingerprint(node["transition_case"])) ==
                        fingerprint(node["transition_case"]),
                        "transition authority changed")
            if node["op"] == "PcodeWindow":
                require(node["semantic_source"]["implementation"] ==
                        "probe_connected_python_prefix.py:replay" and
                        node["semantic_source"]["implementation_sha256"] ==
                        {filename: digest(ROOT / filename) for filename in (
                            "probe_connected_python_prefix.py",
                            "prove_cross_full_flow.py",
                            "pcode_transition_summary.py")},
                        "P-code semantic implementation changed")
        expected = obligations(route["control"], enclosing=not python,
            lifetime=python and route["id"] != "python_251", vector=python)
        require(route["obligations"] == expected and
                all(o["semantics"].startswith("unresolved") for o in expected),
                "unknown edge/lifetime obligation changed")


def validate(doc, canonical):
    """Compare a saved IL to fresh, source-derived and reapplied evidence.

    The canonical argument must come from build() in this invocation; a hash
    alone is never treated as evidence that a semantic claim is true.
    """
    validate_structure(doc)
    require(doc == canonical, "saved IL differs from source-derived canonical IL")


def negative_controls(doc):
    mutations = {
        "engine_swap": lambda d: d["routes"][4].update(engine="python"),
        "domain_promotion": lambda d: d["routes"][0]["input_domain"].update(
            kind="all_inputs"),
        "handoff_promotion": lambda d: d["routes"][4]["nodes"][0].update(
            handoff="computed_scalar_and_byte_memory_exact_witness"),
        "libc_extent": lambda d: d["routes"][0]["nodes"][1]["contract"]["effect"].update(
            extent_bytes=64),
        "libc_output": lambda d: d["routes"][0]["nodes"][1]["contract"]["scalar_outputs"].update(
            RAX="old RSI"),
        "native_effect": lambda d: d["routes"][4]["nodes"][0]["transition_case"]["effects"].clear(),
        "guard": lambda d: d["routes"][5]["nodes"][0]["transition_case"]["condition"].clear(),
        "source_trace": lambda d: d["routes"][4].update(trace_sha256="0" * 64),
        "false_branch_certificate": lambda d: d["routes"][1]["source_fixed_conditional_proofs"][0].update(
            opposite_successor="0x0"),
        "unknown_deletion": lambda d: d["routes"][0]["obligations"].pop(),
        "unknown_as_noop": lambda d: d["routes"][0]["obligations"][0].update(
            semantics="no_op"),
        "value_operand": lambda d: d["value_library"]["value_il"]["nodes"][2].update(
            args=[0, 0]),
    }
    result = {}
    for name, mutate in mutations.items():
        changed = deepcopy(doc)
        mutate(changed)
        try:
            validate(changed, doc)
        except (ValueError, KeyError):
            result[name] = "rejected"
        else:
            result[name] = "unexpectedly_accepted"
    require(all(x == "rejected" for x in result.values()),
            "common IL negative control accepted")
    return result


def main():
    doc = build()
    negatives = negative_controls(doc)
    OUTPUT.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n")
    validate(json.loads(OUTPUT.read_text()), doc)
    counts = {route["id"]: {"native_steps": route["native_steps"],
        "nodes": len(route["nodes"]), "unknown_obligations": len(route["obligations"]),
        "conditional_branches": len(route["control"]["conditional_branches"]),
        "calls": len(route["control"]["calls"])} for route in doc["routes"]}
    report = {"schema_version": doc["schema_version"], "artifact_sha256": digest(OUTPUT),
        "routes": counts, "negative_controls": negatives,
        "scope": "4 exact Python full native paths; 1 Lua and 1 JS local segment",
        "whole_program_complete": False, "native_standalone_executable": False,
        "remaining": ["enumerate and prove other control/exception paths",
            "authorize object lifetime and heap effects",
            "compose enclosing Lua/JS paths and broader input/environment domains",
            "render readable whole-program logic from verified CFG"]}
    RESULT.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
