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
import z3

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
import apply_common_pool_effects as python_pool
import apply_lua_pool_effects as lua_pool
from composed_native_transition import parse_segments
from prove_lua_full_flow import (MAIN_BUNDLE, contiguous, first_memory, prove_input,
    prove_return, prove_vm_path, trace_records, first_step)
from project_lua_call_bridge import BUNDLE as LUA_BUNDLE, BYTECODE as LUA_BYTECODE


OUTPUT = ROOT / "common_program_representation_v1.json"
RESULT = ROOT / "common_program_representation_result.json"
PATH_IL = ROOT / "evidence_program_path_il.json"
APPLICATION = ROOT / "bounded_python_program_application_result.json"
COMMON = ROOT / "common_three_engine_transitions.json"
VALUE = ROOT / "common_numeric_refinement_result.json"
LUA_BINARY = ROOT / "lua_interpreter_fixture"
LUA_TRACE = ROOT / "artifacts/lua_handler_plus11_x9.jsonl"
JS_TRACE = ROOT / "artifacts/js_handler_holdout_37.json.gz"
LUA_FLOW = ROOT / "lua_branch_full_flow.json"
LUA_FLOW_LABELS = ("x0", "x9", "one", "minus1", "max", "min", "x42")
LUA_HOLDOUT_TRACE = ROOT / "artifacts/integrated_lua_branch_42.jsonl"


def lua_flow_trace(label):
    return (LUA_HOLDOUT_TRACE if label == "x42" else
            ROOT / f"artifacts/lua_branch_full_flow_{label}.jsonl")


def digest(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def conditional_bv64_dag():
    """Typed, language-independent value view of the pinned Lua branch case."""
    return {"schema_version": "bounded-conditional-value-il-v1",
        "input": {"name": "X", "sort": "BV64"},
        "nodes": [
            {"id": 0, "op": "input", "sort": "BV64", "name": "X"},
            {"id": 1, "op": "bv", "sort": "BV64", "value": 0},
            {"id": 2, "op": "eq", "sort": "Bool", "args": [0, 1]},
            {"id": 3, "op": "bv", "sort": "BV64", "value": 10},
            {"id": 4, "op": "bv", "sort": "BV64", "value": 5},
            {"id": 5, "op": "bvadd", "sort": "BV64", "args": [0, 4]},
            {"id": 6, "op": "ite", "sort": "BV64", "args": [2, 3, 5]}],
        "result": {"node": 6, "name": "P", "sort": "BV64"},
        "interpretation": "X==0 ? 10 : (X+5) modulo 2^64",
        "scope": "pinned Lua branch-call bytecode; source-fixed non-input state and path"}


def evaluate_conditional_value(dag, witness):
    require(dag["schema_version"] == "bounded-conditional-value-il-v1" and
            dag["input"] == {"name": "X", "sort": "BV64"} and
            type(witness) is int and 0 <= witness < 1 << 64,
            "conditional value interface changed")
    values = []
    sorts = []
    for index, node in enumerate(dag["nodes"]):
        require(node["id"] == index, "conditional value DAG order changed")
        operation = node["op"]
        if operation == "input":
            require(node["name"] == "X" and node["sort"] == "BV64",
                    "conditional value input changed")
            value, sort = witness, "BV64"
        elif operation == "bv":
            require(node["sort"] == "BV64" and type(node["value"]) is int and
                    0 <= node["value"] < 1 << 64, "conditional constant changed")
            value, sort = node["value"], "BV64"
        else:
            args = node["args"]
            require(all(type(arg) is int and 0 <= arg < index for arg in args),
                    "conditional value operand changed")
            if operation == "eq":
                require(len(args) == 2 and sorts[args[0]] == sorts[args[1]] == "BV64"
                        and node["sort"] == "Bool", "conditional comparison ill-typed")
                value, sort = values[args[0]] == values[args[1]], "Bool"
            elif operation == "bvadd":
                require(len(args) == 2 and sorts[args[0]] == sorts[args[1]] ==
                        node["sort"] == "BV64", "conditional addition ill-typed")
                value, sort = (values[args[0]] + values[args[1]]) & ((1 << 64) - 1), "BV64"
            elif operation == "ite":
                require(len(args) == 3 and sorts[args[0]] == "Bool" and
                        sorts[args[1]] == sorts[args[2]] == node["sort"] == "BV64",
                        "conditional select ill-typed")
                value, sort = values[args[1]] if values[args[0]] else values[args[2]], "BV64"
            else:
                raise ValueError("unsupported conditional value opcode")
        values.append(value)
        sorts.append(sort)
    require(dag["result"] == {"node": len(values) - 1, "name": "P", "sort": "BV64"}
            and sorts[-1] == "BV64", "conditional value result changed")
    return values[-1]


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


def lua_vm_rows(records):
    branch = next(row for row in records if row.get("type") == "replay_step" and
                  row["pc"] == 0x417E50)
    source = max((row for row in records if row.get("type") == "replay_step" and
                  row["pc"] == 0x416EA1 and row["step"] < branch["step"]),
                 key=lambda row: row["step"])
    add = first_step(records, 0x417CEA)
    rows = [row for row in records if row.get("type") == "replay_step" and
            source["step"] <= row["step"] < add["step"]] + [add]
    require(all(a["step"] + 1 == b["step"] and a["next_pc"] == b["pc"]
                for a, b in zip(rows, rows[1:])),
            "Lua VM source-to-payload path is not contiguous")
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    augmented = []
    for row in rows:
        decoded = next(decoder.disasm(read_vaddr(LUA_BINARY, row["pc"],
                                                row["pc"] + 15), row["pc"]))
        require(f"{decoded.mnemonic} {decoded.op_str}".strip() ==
                row["instruction"], "Lua VM path instruction bytes changed")
        augmented.append({**row, "bytes": decoded.bytes.hex()})
    return augmented


def lua_value_chains():
    """Reprove value handoffs, retaining gaps in native state as obligations."""
    published = json.loads(LUA_FLOW.read_text())
    require(published["kind"] == "bounded_native_input_and_return_flow" and
            published["binary_sha256"] == digest(LUA_BINARY) and
            published["bytecode_sha256"] == digest(LUA_BYTECODE) and
            published["bundle_sha256"] == digest(LUA_BUNDLE) and
            published["main_bundle_sha256"] == digest(MAIN_BUNDLE) and
            [item["path"] for item in published["paths"]] == list(LUA_FLOW_LABELS[:-1]) and
            published["unconditional_full_script_proof"] is False,
            "Lua full-flow proof source identity changed")
    records_by_label = {label: trace_records(lua_flow_trace(label))
                        for label in LUA_FLOW_LABELS}
    vm_rows_by_label = {label: lua_vm_rows(records) for label, records in
                        records_by_label.items()}
    edges = observed_edges(vm_rows_by_label.values())
    x, p = z3.BitVec("COMMON_LUA_FLOW_X", 64), z3.BitVec("COMMON_LUA_FLOW_P", 64)
    value_il = conditional_bv64_dag()
    chains = []
    published_by_label = {item["path"]: item for item in published["paths"]}
    for label in LUA_FLOW_LABELS:
        expected = published_by_label.get(label)
        records = records_by_label[label]
        rows = vm_rows_by_label[label]
        trace = lua_flow_trace(label)
        if expected is None:
            require(label == "x42" and records[0]["input"] ==
                    records[0]["input_word"] == 42,
                    "Lua holdout input/provenance changed")
            witness = 47
        else:
            require(expected["trace_sha256"] == digest(trace) and
                    records[0]["input_word"] ==
                    (int(expected["witness_input"]) & ((1 << 64) - 1)),
                    "Lua trace input/provenance changed")
            witness = int(expected["witness_payload"])
        proofs = {"input_prefix": prove_input(records, x),
                  "vm_path": prove_vm_path(records, x, witness),
                  "return_suffix": prove_return(records, p, witness)}
        require((expected is None or all(proofs[key] == expected[key]
                                         for key in proofs)) and
                evaluate_conditional_value(value_il, records[0]["input_word"]) == witness and
                proofs["vm_path"]["native_instructions"] == len(rows),
                "Lua value chain proof or BV64 value changed")
        control = path_inventory(rows, edges)
        vm_ledger = native_path_ledger(rows, [{"id": "guarded_vm_path", "begin": 0,
            "end_exclusive": len(rows), "op": "GuardedPcodeValuePath"}])[0]
        initial_slot = first_memory(first_step(records, 0x402A04), 2)["address"]
        copied_slot = first_memory(first_step(records, 0x411B54), 2)["address"]
        return_slot = first_memory(contiguous(records, 0x417CEA, 0x401542)[-1], 2)["address"]
        links = [
            {"op": "ObservedInputBinding", "from": "X", "to": "RSI@0x401490",
             "grade": "observed_exact_witness_and_pinned_ABI"},
            {"op": "PcodeValueTransfer", "from": "RSI", "to": "LuaSlotA",
             "slot_address": hex(initial_slot), "proof_ref": "input_prefix",
             "intervening_ABI_assumption":
                 "x86-64 SysV preserves RBP across luaL_newstate; witness checked",
             "full_native_state": "unknown"},
            {"op": "AuditedNoWriteBridge", "from": "LuaSlotA", "to": "LuaSlotA",
             "slot_address": hex(initial_slot), "write_records_inspected":
                proofs["input_prefix"]["a_to_b_intervening_writes_inspected"],
             "hardware_watch": True, "watch_scope": "this_observed_execution_only",
             "full_native_state": "unknown"},
            {"op": "PcodeValueTransfer", "from": "LuaSlotA", "to": "LuaSlotB",
             "slot_address": hex(copied_slot), "proof_ref": "input_prefix"},
            {"op": "AuditedNoWriteBridge", "from": "LuaSlotB", "to": "LuaSlotB",
             "slot_address": hex(copied_slot), "write_records_inspected":
                proofs["input_prefix"]["b_to_source_intervening_writes_inspected"],
             "hardware_watch": True, "watch_scope": "this_observed_execution_only",
             "full_native_state": "unknown"},
            {"op": "GuardedPcodeValuePath", "from": "LuaSlotB", "to": "P",
             "guard": proofs["vm_path"]["guard"],
             "value_expression": proofs["vm_path"]["payload_expression"],
             "native_ledger": vm_ledger, "proof_ref": "vm_path",
             "semantic_source": {"implementation": "prove_lua_full_flow.py:prove_vm_path",
                 "implementation_sha256": digest(ROOT / "prove_lua_full_flow.py"),
                 "bundle_sha256": digest(LUA_BUNDLE)}},
            {"op": "PcodeValueTransfer", "from": "P", "to": "NativeReturnSlot",
             "slot_address": hex(return_slot), "proof_ref": "return_suffix"},
            {"op": "AuditedNoWriteBridge", "from": "NativeReturnSlot",
             "to": "NativeReturnSlot", "slot_address": hex(return_slot),
             "write_records_inspected":
                proofs["return_suffix"]["lua_close_intervening_writes_inspected"],
             "hardware_watch": True, "watch_scope": "this_observed_execution_only",
             "full_native_state": "unknown"},
            {"op": "PcodeValueTransfer", "from": "NativeReturnSlot",
             "to": "RSI@printf", "proof_ref": "return_suffix"}]
        unresolved = obligations(control, enclosing=False)
        unresolved += [{"op": "UnknownNativeStateAcrossGap",
                        "status": "three monitored value slots; other state not continuously replayed",
                        "semantics": "unresolved_native_state"},
                       {"op": "UnknownHeapLifetime",
                        "status": "default Lua allocator ownership/GC effects not authorized here",
                        "semantics": "unresolved_object_effect"}]
        chains.append({"id": f"lua_branch_{label}", "engine": "lua",
            "application_unit": "sparse_input_to_printf_value_chain",
            "validation_grade": "SMT_value_flow_and_witness_write_watch",
            "native_full_state_handoff": False,
            "binary_sha256": digest(LUA_BINARY),
            "bytecode_sha256": digest(LUA_BYTECODE),
            "trace_sha256": digest(trace), "input_word": records[0]["input_word"],
            "output_word": witness, "value_il_ref": "lua_branch_BV64",
            "evidence_role": "new_value_chain_holdout" if label == "x42" else
                             "published_full_flow_rechecked",
            "guard": proofs["vm_path"]["guard"],
            "links": links, "vm_control": control, "proof_evidence": proofs,
            "assumptions": published["assumptions"], "obligations": unresolved,
            "relationship_to_lua_plus11_segment":
                "different bytecode and path; no composed native transition"})
    return chains, value_il


def controlled_lifetime_domains():
    """Reapply owned fixture effects; never authorize default VM allocators."""
    domains = []
    for engine, module, code_binary, expected_schema, expected_domain in (
            ("python", python_pool, python_pool.BINARY,
             "common-lifetime-effect-application-v1", "controlled_obj_pool"),
            ("lua", lua_pool, lua_pool.BINARY,
             "lua-common-lifetime-effect-v1", "controlled_lua_string_pool")):
        published = json.loads(module.RESULT.read_text())
        summary = json.loads(module.SUMMARY.read_text())
        proof = json.loads(module.PROOF.read_text())
        summary_hash, proof_hash = digest(module.SUMMARY), digest(module.PROOF)
        require(published["schema_version"] == expected_schema and
                published["native_summary_sha256"] == summary_hash and
                published["native_refinement_sha256"] == proof_hash and
                summary["binary_sha256"] == digest(code_binary) and
                proof["summary_sha256"] == summary_hash and
                all(len(proof["proofs"][name]) == 4 for name in
                    ("allocate", "release")) and
                all(result == "unsat" for group in proof["proofs"].values()
                    for item in group for key, result in item.items()
                    if key != "slot"),
                "controlled lifetime source or native refinement changed")
        declarations, segments = parse_segments(summary, {"allocate", "release"})
        if engine == "python":
            require(summary["source_trace_sha256"] == digest(
                ROOT / "artifacts/python_pool_source.json.gz") and
                summary["logical_effect_schema_version"] ==
                "common-lifetime-effect-v1", "Python pool source changed")
            cases = [module.apply_case(value, origin, summary, declarations,
                     segments, summary_hash, proof_hash)
                     for value, origin in module.CASES]
            controls = module.rejection_controls(summary, declarations,
                                                  segments, summary_hash, proof_hash)
        else:
            require(summary["source_trace_sha256"] == digest(module.SOURCE),
                    "Lua pool source changed")
            cases = [module.run_case(value, origin, summary, segments,
                     declarations, summary_hash, proof_hash)
                     for value, origin in module.CASES]
            controls = module.rejection_controls(summary, segments,
                                                  declarations, summary_hash, proof_hash)
        require(cases == published["cases"] and
                controls == published["rejection_controls"] and
                len(cases) == 3 and all(case["effects"] for case in cases),
                "controlled lifetime application changed")
        require(all(effect["domain_id"] == expected_domain and
                    effect["evidence"]["native_summary_sha256"] == summary_hash
                    for case in cases for effect in case["effects"]
                    if effect["kind"] != "AllocationFailed"),
                "controlled lifetime effect escaped its domain")
        domains.append({"engine": engine, "domain_id": expected_domain,
            "application_unit": "controlled_pool_fixture_only",
            "authority": "fixture_declared_static_reservations",
            "binary_sha256": digest(code_binary),
            "native_summary_sha256": summary_hash,
            "native_refinement_sha256": proof_hash,
            "source_application_sha256": digest(module.RESULT),
            "effect_schema": "common-lifetime-effect-v1",
            "cases": cases, "rejection_controls": controls,
            "evidence_boundary": published["evidence_boundary"],
            "limits": published["limits"],
            "attached_to_program_routes": [],
            "does_not_authorize": ["default CPython allocator ownership",
                "default Lua allocator ownership", "JavaScript heap lifetime"]})
    return domains


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
    lua_chains, lua_branch_dag = lua_value_chains()
    lifetime_domains = controlled_lifetime_domains()
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
            "lua_target_trace": digest(LUA_TRACE), "js_target_trace": digest(JS_TRACE),
            "lua_full_flow": digest(LUA_FLOW),
            "lua_x42_holdout_trace": digest(LUA_HOLDOUT_TRACE)},
        "value_library": {"value_il": value["value_il"],
            "adapters": value["adapters"],
            "application_note": "BV32 X+5 is independent of selected Lua plus11 segment",
            "lua_branch_BV64": lua_branch_dag},
        "routes": routes, "proof_chains": lua_chains,
        "lifetime_domains": lifetime_domains}
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
    lua_value_il = doc["value_library"]["lua_branch_BV64"]
    require(lua_value_il == conditional_bv64_dag() and
            [chain["id"] for chain in doc["proof_chains"]] ==
            [f"lua_branch_{label}" for label in LUA_FLOW_LABELS],
            "Lua branch value IL or chain inventory changed")
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
    link_ops = ["ObservedInputBinding", "PcodeValueTransfer",
                "AuditedNoWriteBridge", "PcodeValueTransfer",
                "AuditedNoWriteBridge", "GuardedPcodeValuePath",
                "PcodeValueTransfer", "AuditedNoWriteBridge",
                "PcodeValueTransfer"]
    for label, chain in zip(LUA_FLOW_LABELS, doc["proof_chains"]):
        proof = chain["proof_evidence"]
        links = chain["links"]
        expected_guard = "X == 0" if chain["input_word"] == 0 else "X != 0"
        require(chain["engine"] == "lua" and
                chain["application_unit"] == "sparse_input_to_printf_value_chain" and
                chain["validation_grade"] == "SMT_value_flow_and_witness_write_watch" and
                chain["native_full_state_handoff"] is False and
                chain["binary_sha256"] == digest(LUA_BINARY) and
                chain["bytecode_sha256"] == digest(LUA_BYTECODE) and
                chain["trace_sha256"] == digest(lua_flow_trace(label)) and
                chain["evidence_role"] == ("new_value_chain_holdout" if label == "x42"
                                           else "published_full_flow_rechecked") and
                chain["value_il_ref"] == "lua_branch_BV64" and
                evaluate_conditional_value(lua_value_il, chain["input_word"]) ==
                chain["output_word"] and
                chain["guard"] == proof["vm_path"]["guard"] == expected_guard and
                proof["vm_path"]["payload_equivalence"] == "unsat" and
                proof["vm_path"]["guard_equivalence"] == "unsat" and
                proof["return_suffix"]["native_stack_to_printf_argument_pcode_proved"]
                is True and
                [link["op"] for link in links] == link_ops and
                links[5]["native_ledger"]["native_steps"] ==
                proof["vm_path"]["native_instructions"] and
                links[5]["guard"] == chain["guard"] and
                links[5]["semantic_source"]["implementation_sha256"] ==
                digest(ROOT / "prove_lua_full_flow.py"),
                "Lua guarded value chain or semantic source changed")
        require(all(link["hardware_watch"] is True and
                    link["watch_scope"] == "this_observed_execution_only" and
                    link["full_native_state"] == "unknown"
                    for link in links if link["op"] == "AuditedNoWriteBridge"),
                "audited gap promoted to computed native transition")
        require(links[1]["intervening_ABI_assumption"] ==
                "x86-64 SysV preserves RBP across luaL_newstate; witness checked" and
                links[1]["full_native_state"] == "unknown",
                "Lua ABI assumption was dropped or promoted")
        require(chain["vm_control"]["complete"] is False and
                chain["obligations"] == obligations(chain["vm_control"],
                    enclosing=False) + [
                    {"op": "UnknownNativeStateAcrossGap",
                     "status": "three monitored value slots; other state not continuously replayed",
                     "semantics": "unresolved_native_state"},
                    {"op": "UnknownHeapLifetime",
                     "status": "default Lua allocator ownership/GC effects not authorized here",
                     "semantics": "unresolved_object_effect"}],
                "Lua branch/control/gap obligations changed")
    require([domain["domain_id"] for domain in doc["lifetime_domains"]] ==
            ["controlled_obj_pool", "controlled_lua_string_pool"],
            "controlled ownership domain mapping changed")
    for domain in doc["lifetime_domains"]:
        require(domain["application_unit"] == "controlled_pool_fixture_only" and
                domain["authority"] == "fixture_declared_static_reservations" and
                domain["effect_schema"] == "common-lifetime-effect-v1" and
                domain["attached_to_program_routes"] == [] and
                len(domain["cases"]) == 3 and
                all(effect["domain_id"] == domain["domain_id"]
                    for case in domain["cases"] for effect in case["effects"]
                    if effect["kind"] != "AllocationFailed") and
                "default CPython allocator ownership" in domain["does_not_authorize"] and
                "default Lua allocator ownership" in domain["does_not_authorize"],
                "controlled pool effect promoted to default allocator")


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
        "lua_branch_value": lambda d: d["value_library"]["lua_branch_BV64"]["nodes"][4].update(
            value=6),
        "lua_gap_promotion": lambda d: d["proof_chains"][0]["links"][2].update(
            full_native_state="computed"),
        "lua_guard_swap": lambda d: d["proof_chains"][0].update(guard="X != 0"),
        "lua_watch_omission": lambda d: d["proof_chains"][1]["links"][7].update(
            hardware_watch=False),
        "lua_watch_domain_promotion": lambda d: d["proof_chains"][0]["links"][2].update(
            watch_scope="all_inputs"),
        "lua_abi_omission": lambda d: d["proof_chains"][0]["links"][1].pop(
            "intervening_ABI_assumption"),
        "lua_lifetime_promotion": lambda d: d["proof_chains"][0]["obligations"].pop(),
        "lua_holdout_trace_swap": lambda d: d["proof_chains"][-1].update(
            trace_sha256=d["proof_chains"][1]["trace_sha256"]),
        "pool_domain_swap": lambda d: d["lifetime_domains"][1].update(
            domain_id="controlled_obj_pool"),
        "pool_default_authority": lambda d: d["lifetime_domains"][0].update(
            authority="default_cpython_allocator"),
        "pool_route_attachment": lambda d: d["lifetime_domains"][0][
            "attached_to_program_routes"].append("python_252"),
        "pool_effect_extent": lambda d: d["lifetime_domains"][1]["cases"][0][
            "effects"][0].update(requested_extent=106),
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
        "lua_value_chains": [{"id": chain["id"], "vm_native_steps":
            chain["links"][5]["native_ledger"]["native_steps"],
            "vm_conditional_branches":
                len(chain["vm_control"]["conditional_branches"]),
            "opposite_edges_observed_elsewhere": sum(
                branch["opposite_status"] == "observed_in_other_trace"
                for branch in chain["vm_control"]["conditional_branches"]),
            "vm_calls": len(chain["vm_control"]["calls"]),
            "open_obligations": len(chain["obligations"])}
            for chain in doc["proof_chains"]],
        "controlled_lifetime_domains": [{"engine": domain["engine"],
            "domain_id": domain["domain_id"], "runs": len(domain["cases"]),
            "effects": sum(len(case["effects"]) for case in domain["cases"]),
            "attached_to_program_routes": domain["attached_to_program_routes"]}
            for domain in doc["lifetime_domains"]],
        "scope": "4 exact Python full native paths; 1 Lua and 1 JS local segment; "
                 "7 sparse Lua input-to-printf value chains including x42 holdout",
        "whole_program_complete": False, "native_standalone_executable": False,
        "remaining": ["enumerate and prove other control/exception paths",
            "authorize default allocator lifetime and heap effects",
            "connect full native state across Lua gaps and JS enclosing paths",
            "prove broader input/environment domains",
            "render readable whole-program logic from verified CFG"]}
    RESULT.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
