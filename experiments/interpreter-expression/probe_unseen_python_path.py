"""Discover, freeze, and reuse an observed Python path absent from the seed.

Freeze reads the full 252 trace, the pinned executable, and no pre-existing
allocated-path summary. It selects a candidate by an output-object goal,
replays P-code, proves a bounded decoded value, and emits a full transition.
Apply reads only that emitted transition for the fresh 255 native segment.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path

import z3

from build_expanded_native_paths import make_case, records
from common_observed_transition import (apply_case, normalize_native,
                                         python_preconditions, shape)
from cross_dispatch_pcode import read_vaddr
from discover_dispatch_intervals import candidates
from pcode_transition_summary import FLAG_OFFSETS, REGISTER_OFFSETS
from prove_cross_full_flow import CACHE_BASE, PYTHON, load_trace, replay
from prove_cross_value_path import small_int_memory


ROOT = Path(__file__).resolve().parent
ARTIFACTS = ROOT / "artifacts"
SOURCE = ARTIFACTS / "next_boundary_py_252.json.gz"
FRESH = ARTIFACTS / "next_unseen_python_255.json.gz"
NEIGHBOR_TARGET = ARTIFACTS / "next_boundary_py_43.json.gz"
GENERATED = ROOT / "unseen_python_generated_transition.json"
SOURCE_PROOF = ROOT / "unseen_python_generated_proof.json"
RESULT = ROOT / "unseen_python_family_result.json"
NEIGHBOR_SUMMARY = ROOT / "unseen_python_neighbor_transition.json"
NEIGHBOR_RESULT = ROOT / "unseen_python_neighbor_result.json"
COMMON = ROOT / "common_three_engine_transitions.json"
VALUE_IL = ROOT / "common_numeric_refinement_result.json"
MASK64 = (1 << 64) - 1


def digest(path):
    return sha256(path.read_bytes()).hexdigest()


def solve(want, *clauses):
    solver = z3.Solver()
    solver.set(timeout=30000)
    solver.add(*clauses)
    got = solver.check()
    if got != want:
        raise ValueError(f"expected {want}, got {got}")
    return str(got)


def domain(x):
    return z3.And(z3.UGE(x, z3.BitVecVal(252, 32)),
                  z3.ULE(x, z3.BitVecVal(256, 32)))


def symbolic_word(memory, address, width):
    return z3.Concat(*reversed([z3.Select(memory, address +
        z3.BitVecVal(index, 64)) for index in range(width)]))


def selected_result_object(segment):
    """Locate an output-slot pointer with type/tag/digit writes in this window."""
    slot = segment[-1]["registers_after"]["r15"] - 8
    writes = [(row, access) for row in segment for access in row["memory"]
              if access["access"] & 2]
    possible = []
    for _, item in writes:
        if item["address"] != slot or item["size"] != 8:
            continue
        pointer = item["after"]
        if all(any(access["address"] == pointer + offset and
                   access["size"] == width
                   for _, access in writes)
               for offset, width in ((8, 8), (16, 8), (24, 4))):
            possible.append((slot, pointer))
    return possible


def choose_candidate(rows):
    inventory = []
    matches = []
    for item in candidates(rows):
        segment = rows[item["begin"]:item["end_exclusive"]]
        results = selected_result_object(segment)
        record = {**item, "result_object_matches": len(results),
                  "selection_reason": ("output slot pointer and object type/tag/digit writes"
                                       if len(results) == 1 else
                                       "no unique output-object write contract")}
        inventory.append(record)
        if len(results) == 1:
            matches.append((item, segment, results[0]))
    if len(matches) != 1:
        raise ValueError(f"output-object boundary ambiguous: {len(matches)}")
    return matches[0], inventory


def prove_value(segment, input_pointer, slot, observed_pointer, source_input):
    x = z3.BitVec("X", 32)
    memory, first_read_bytes = small_int_memory(segment, input_pointer,
                                                 source_input, x)
    model, guard = replay(segment, PYTHON, memory)
    slot_address = z3.BitVecVal(slot, 64)
    pointer = symbolic_word(model.memory, slot_address, 8)
    digit = symbolic_word(model.memory,
                          pointer + z3.BitVecVal(24, 64), 4)
    tag = symbolic_word(model.memory,
                        pointer + z3.BitVecVal(16, 64), 8)
    type_pointer = symbolic_word(model.memory,
                                 pointer + z3.BitVecVal(8, 64), 8)
    source_type = int.from_bytes(read_vaddr(PYTHON, CACHE_BASE + 8,
                                             CACHE_BASE + 16), "little")
    witness_solver = z3.Solver()
    witness_solver.add(domain(x), guard,
                       x == z3.BitVecVal(source_input, 32))
    if witness_solver.check() != z3.sat:
        raise ValueError("selected source path has no symbolic witness")
    observed_digit = witness_solver.model().eval(digit, model_completion=True)
    if not z3.is_bv_value(observed_digit):
        raise ValueError("source result digit is not a BV32 value")
    constant = (observed_digit.as_long() - source_input) & 0xFFFFFFFF
    if constant != 5:
        raise ValueError("unexpected inferred native arithmetic constant")
    y = x + z3.BitVecVal(constant, 32)
    proofs = {"fixed_environment_path_guard_covers_domain":
              solve(z3.unsat, domain(x), z3.Not(guard)),
              "decoded_final_digit_equals_candidate":
              solve(z3.unsat, domain(x), guard, digit != y),
              "final_pointer_matches_observation":
              solve(z3.unsat, domain(x), guard,
                    pointer != z3.BitVecVal(observed_pointer, 64)),
              "result_tag_equals_one_digit_positive":
              solve(z3.unsat, domain(x), guard,
                    tag != z3.BitVecVal(8, 64)),
              "result_type_matches_pinned_PyLong":
              solve(z3.unsat, domain(x), guard,
                    type_pointer != z3.BitVecVal(source_type, 64)),
              "wrong_plus_six_has_counterexample":
              solve(z3.sat, domain(x), guard,
                    digit != x + z3.BitVecVal(6, 32)),
              "output_does_not_alias_input_object":
              solve(z3.unsat, domain(x), guard,
                    pointer == z3.BitVecVal(input_pointer, 64)),
              "output_does_not_alias_result_slot":
              solve(z3.unsat, domain(x), guard,
                    pointer == slot_address),
              "output_does_not_alias_static_cache":
              solve(z3.unsat, domain(x), guard,
                    z3.UGE(pointer, z3.BitVecVal(CACHE_BASE, 64)),
                    z3.ULT(pointer, z3.BitVecVal(CACHE_BASE + 262 * 32, 64)))}
    if len(model.effects) != len([access for row in segment
            for access in row["memory"] if access["access"] & 2]):
        raise ValueError("value replay omitted a native write")
    return {"input_sort": "BV32", "decoded_output_sort": "BV32",
        "input_binding": "digit at fixed source PyLong object +24",
        "output_binding": "final memory at output slot -> pointer +8/+16/+24",
        "inferred_additive_constant": constant,
        "conditional_domain": "252 <= X <= 256, fixed other registers, flags, first-read memory, FS/GS and allocator state",
        "proofs": proofs, "value_replay_pcode_operations": model.operation_count,
        "value_replay_guard_count": len(model.guards),
        "value_replay_reads": len(model.reads),
        "value_replay_writes": len(model.effects),
        "fixed_first_read_bytes": first_read_bytes,
        "logical_allocate_or_freshness_proved": False}


def freeze():
    meta, rows, summary = load_trace(SOURCE, "python", 252, PYTHON)
    (boundary, segment, (slot, pointer)), inventory = choose_candidate(rows)
    if summary["output_raw"] != pointer:
        raise ValueError("selected result object differs from caller observation")
    value = prove_value(segment, meta["entry_value_address"],
                        slot, pointer, meta["entry_value_raw"])
    cache = read_vaddr(PYTHON, CACHE_BASE, CACHE_BASE + 262 * 32)
    cache_hash = sha256(cache).hexdigest()
    if cache_hash != meta["runtime_cache_sha256_at_sync"]:
        raise ValueError("source small-integer cache identity changed")
    preconditions = {"kind": "python_allocated_result",
        "cache_sha256": cache_hash, "minimum_x": 252,
        "maximum_x": 256, "right": value["inferred_additive_constant"]}
    case = make_case(segment, PYTHON, "discovered_output_object_path",
                     preconditions, segment_bases=True)
    if (len(case["reads"]) != value["value_replay_reads"] or
            len(case["ordered_effects"]) != value["value_replay_writes"]):
        raise ValueError("symbolic full transition differs from value replay inventory")
    binary_hash = digest(PYTHON)
    source = {"schema_version": "native-handler-transition-v1",
        "engine": "python", "binary_sha256": binary_hash,
        "case": case, "limits": [
            "selected by observed output object goal; not an arbitrary handler classifier",
            "one observed path with fixed allocator environment for value proof",
            "Write effects do not prove Allocate or freshness"]}
    normalized = normalize_native(source, "python", case, digest(SOURCE))
    bundle = {"schema_version": "common-observed-transition-v1",
        "semantic_model": {"architecture": "x86-64", "endian": "little",
            "memory": "byte-addressed", "integers": "typed bitvectors",
            "expression": "SMT-LIB 2 term"},
        "cases": [normalized],
        "source_trace_sha256": digest(SOURCE),
        "generation_rule": "BRANCHIND delimiter + observed output-slot pointer and object field writes; no prior allocated summary"}
    source_adapter = {"input": meta["entry_value_raw"],
        "runtime_cache_sha256_at_entry": cache_hash,
        "runtime_cache_sha256_at_exit": cache_hash,
        "left_pointer": meta["entry_value_address"],
        "right_pointer": CACHE_BASE + (value["inferred_additive_constant"] + 5) * 32,
        "output_slot": slot}
    source_verdict = apply_case(bundle, normalized, PYTHON, segment, source_adapter)
    if source_verdict["status"] != "differentially_validated":
        raise ValueError(f"generated summary fails source application: {source_verdict}")
    GENERATED.write_text(json.dumps(bundle, indent=2) + "\n")
    proof = {"schema_version": 1, "generated_summary_sha256": digest(GENERATED),
        "source_trace_sha256": digest(SOURCE), "binary_sha256": binary_hash,
        "source_input": meta["entry_value_raw"],
        "candidate_inventory": inventory, "selected_boundary": boundary,
        "selection_object_pointer": hex(pointer), "selection_output_slot": hex(slot),
        "generated_case_metrics": case["evidence"],
        "source_application": source_verdict,
        "value_refinement": value,
        "generation_did_not_read_prior_allocated_summary": True}
    SOURCE_PROOF.write_text(json.dumps(proof, indent=2) + "\n")
    print(json.dumps({"candidates": len(inventory),
                      "selected_steps": len(segment),
                      "native_reads": len(case["reads"]),
                      "ordered_writes": len(case["ordered_effects"]),
                      "value_constant": value["inferred_additive_constant"]}))


def require_unknown(name, verdict):
    status = verdict["status"]
    if not status.startswith("unknown("):
        raise ValueError(f"negative {name} was admitted: {verdict}")
    return status


def change_read_after_write(rows):
    """Change a later read's recorded value while keeping earlier writes intact."""
    changed = deepcopy(rows)
    written = set()
    for row in changed:
        for access in row["memory"]:
            if access["access"] & 1:
                for index in range(access["size"]):
                    if (access["address"] + index) & MASK64 in written:
                        access["before"] ^= 1 << (index * 8)
                        return changed
            if access["access"] & 2:
                written.update((access["address"] + index) & MASK64
                               for index in range(access["size"]))
    raise ValueError("no read-after-write to test")


def final_writes(rows):
    written = {}
    for row in rows:
        for access in row["memory"]:
            if access["access"] & 2:
                for index in range(access["size"]):
                    written[access["address"] + index] = \
                        (access["after"] >> (8 * index)) & 255
    return written


def final_number(written, address, width):
    try:
        return int.from_bytes(bytes(written[address + index]
                                    for index in range(width)), "little")
    except KeyError as error:
        raise ValueError("object field absent from observed native writes") from error


def apply():
    bundle = json.loads(GENERATED.read_text())
    source_proof = json.loads(SOURCE_PROOF.read_text())
    if (source_proof["generated_summary_sha256"] != digest(GENERATED) or
            source_proof["source_trace_sha256"] != bundle["source_trace_sha256"] or
            len(bundle["cases"]) != 1):
        raise ValueError("generated transition or source proof changed")
    case = bundle["cases"][0]
    meta, body, observed = records(FRESH)
    rows = body["rows"]
    if meta["input"] != 255:
        raise ValueError("fresh holdout input changed")
    verdict = apply_case(bundle, case, PYTHON, rows, meta)
    if verdict["status"] != "differentially_validated":
        raise ValueError(f"fresh 255 transition failed: {verdict}")
    written = final_writes(rows)
    pointer = final_number(written, meta["output_slot"], 8)
    cache = read_vaddr(PYTHON, CACHE_BASE, CACHE_BASE + 262 * 32)
    layout = {"refcount": final_number(written, pointer, 8),
              "type_pointer": final_number(written, pointer + 8, 8),
              "size_tag": final_number(written, pointer + 16, 8),
              "digit": final_number(written, pointer + 24, 4)}
    expected = meta["input"] + source_proof["value_refinement"]["inferred_additive_constant"]
    if (layout != {"refcount": 1,
                   "type_pointer": int.from_bytes(cache[8:16], "little"),
                   "size_tag": 8, "digit": expected} or
            observed["output"] != expected):
        raise ValueError("fresh object decode differs from value IL or program output")
    negatives = {}
    changed = deepcopy(rows)
    changed[-1]["next_pc"] ^= 1
    negatives["wrong_successor"] = require_unknown("wrong successor",
        apply_case(bundle, case, PYTHON, changed, meta))
    changed = deepcopy(rows)
    first_read = next(access for row in changed for access in row["memory"]
                      if access["access"] & 1)
    first_read["address"] ^= 1
    negatives["wrong_read_address"] = require_unknown("read address",
        apply_case(bundle, case, PYTHON, changed, meta))
    changed = deepcopy(rows)
    first_read = next(access for row in changed for access in row["memory"]
                      if access["access"] & 1)
    first_read["before"] ^= 1
    negatives["wrong_read_value"] = require_unknown("read value",
        apply_case(bundle, case, PYTHON, changed, meta))
    changed = deepcopy(rows)
    changed[0]["registers"]["fs_base"] ^= 0x1000
    negatives["wrong_fs_base"] = require_unknown("FS base",
        apply_case(bundle, case, PYTHON, changed, meta))
    changed = deepcopy(rows)
    changed[-1]["registers_after"]["gs_base"] ^= 0x1000
    negatives["changed_final_gs_base"] = require_unknown("final GS base",
        apply_case(bundle, case, PYTHON, changed, meta))
    negatives["wrong_read_after_write_value"] = require_unknown(
        "read-after-write value", apply_case(bundle, case, PYTHON,
                                             change_read_after_write(rows), meta))
    changed = deepcopy(rows)
    for row in changed:
        for access in row["memory"]:
            if access["access"] & 2:
                row["memory"].remove(access)
                break
        else:
            continue
        break
    negatives["missing_write"] = require_unknown("missing write",
        apply_case(bundle, case, PYTHON, changed, meta))
    for name, offset, width in (("wrong_pointer", None, 8),
                                ("wrong_type", 8, 8),
                                ("wrong_tag", 16, 8),
                                ("wrong_digit", 24, 4)):
        changed = deepcopy(rows)
        address = meta["output_slot"] if offset is None else pointer + offset
        field = next(access for row in changed for access in row["memory"]
                     if access["access"] & 2 and access["address"] == address
                     and access["size"] == width)
        field["after"] ^= 1
        negatives[name] = require_unknown(name,
            apply_case(bundle, case, PYTHON, changed, meta))
    changed_bundle = deepcopy(bundle)
    changed_bundle["cases"][0]["effects"].pop()
    negatives["core_missing_effect"] = require_unknown("core missing effect",
        apply_case(changed_bundle, changed_bundle["cases"][0], PYTHON, rows, meta))
    changed_bundle = deepcopy(bundle)
    effects = changed_bundle["cases"][0]["effects"]
    effects[0], effects[1] = effects[1], effects[0]
    negatives["core_reordered_effects"] = require_unknown("core effect order",
        apply_case(changed_bundle, changed_bundle["cases"][0], PYTHON, rows, meta))
    changed_bundle = deepcopy(bundle)
    changed_bundle["cases"][0]["successor"] = "#x0000000000000000"
    negatives["core_wrong_successor"] = require_unknown("core successor",
        apply_case(changed_bundle, changed_bundle["cases"][0], PYTHON, rows, meta))
    changed = deepcopy(meta)
    changed["input"] = 257
    negatives["outside_domain_257_metadata"] = require_unknown("outside domain",
        apply_case(bundle, case, PYTHON, rows, changed))
    common = json.loads(COMMON.read_text())
    cached = next(item for item in common["cases"] if item["engine"] == "python"
                  and item["preconditions"]["kind"] == "python_cached_int")
    cached_meta, cached_body, cached_observed = records(
        ARTIFACTS / "python_holdout_251.json.gz")
    cached_adapter = {"input": 251,
        "runtime_cache_sha256_at_entry": cached_meta["runtime_cache_sha256_at_entry"],
        "runtime_cache_sha256_at_exit": cached_meta["runtime_cache_sha256_at_exit"],
        "left_pointer": cached_meta["left_pointer"],
        "right_pointer": cached_meta["right_pointer"],
        "output_slot": cached_meta["output_slot"]}
    cached_verdict = apply_case(common, cached, PYTHON,
                                cached_body["rows"], cached_adapter)
    if cached_verdict["status"] != "differentially_validated":
        raise ValueError("cached 251 path no longer admits its own summary")
    negatives["allocated_on_cached_251"] = require_unknown("allocated on 251",
        apply_case(bundle, case, PYTHON, cached_body["rows"], cached_meta))
    negatives["allocated_domain_251"] = python_preconditions(case,
        cached_meta, cached_body["rows"])
    if not negatives["allocated_domain_251"].startswith("unknown("):
        raise ValueError("allocated precondition admitted cached 251")
    old_meta, old_body, _ = records(ARTIFACTS / "python_holdout_252.json.gz")
    old_adapter = {"input": 252,
        "runtime_cache_sha256_at_entry": old_meta["runtime_cache_sha256_at_entry"],
        "runtime_cache_sha256_at_exit": old_meta["runtime_cache_sha256_at_exit"],
        "left_pointer": old_meta["left_pointer"],
        "right_pointer": old_meta["right_pointer"],
        "output_slot": old_meta["output_slot"]}
    negatives["cached_on_allocated_252"] = require_unknown("cached on 252",
        apply_case(common, cached, PYTHON, old_body["rows"], old_adapter))
    negatives["cached_domain_252"] = python_preconditions(cached,
        old_adapter, old_body["rows"])
    if not negatives["cached_domain_252"].startswith("unknown("):
        raise ValueError("cached precondition admitted allocated 252")
    _, source_rows, _ = load_trace(SOURCE, "python", 252, PYTHON)
    edge = source_proof["selected_boundary"]["entry_predecessor"]
    changed_full = deepcopy(source_rows)
    changed_full[edge]["bytes"] = "90"
    changed_candidates = candidates(changed_full)
    if any(item["native_steps"] == case["identity"]["native_steps"] and
           shape(changed_full[item["begin"]:item["end_exclusive"]],
                 case["identity"]["path_shape_mode"]) ==
           case["identity"]["path_shape_sha256"]
           for item in changed_candidates):
        raise ValueError("removed dispatch edge retained frozen boundary")
    negatives["removed_dispatch_edge"] = "unknown(no exact frozen delimiter pair)"
    changed_full = deepcopy(source_rows)
    changed_full.pop(source_proof["selected_boundary"]["begin"] + 1)
    try:
        candidates(changed_full)
    except ValueError:
        negatives["missing_middle_row"] = "rejected(discontinuous trace)"
    else:
        raise ValueError("missing native row was admitted as continuous")
    changed_full = deepcopy(source_rows)
    index = source_proof["selected_boundary"]["begin"] + 1
    changed_full[index], changed_full[index + 1] = changed_full[index + 1], changed_full[index]
    try:
        candidates(changed_full)
    except ValueError:
        negatives["reordered_middle_rows"] = "rejected(discontinuous trace)"
    else:
        raise ValueError("reordered native rows were admitted as continuous")
    value_il = json.loads(VALUE_IL.read_text())
    prior_python = next(item for item in value_il["adapters"] if
                        item["engine"] == "python")
    if (prior_python["inferred_additive_constant"] !=
            source_proof["value_refinement"]["inferred_additive_constant"] or
            prior_python["proof"]["decoded_native_equals_value_il"] != "unsat" or
            cached_observed["output"] != 256):
        raise ValueError("cached and allocated numeric IL cannot be merged")
    # This older artifact is read only after independent generation and the
    # fresh application. It is a regression comparison, never a source input.
    old_summary_path = ROOT / "python_allocated_result_summary.json"
    old = json.loads(old_summary_path.read_text())["case"]
    old_identity = old["identity"]
    identity = case["identity"]
    old_matches = (
        identity["entry_pc"] == old_identity["entry_pc"] and
        identity["next_pc"] == old_identity["next_handler_pc"] and
        identity["path_shape_sha256"] == old_identity["path_shape_sha256"] and
        identity["native_steps"] == old_identity["native_steps"] and
        case["condition"] == [old["guard"]] and
        case["successor"] == old["successor"] and
        [item["expression"] for item in case["outputs"]] ==
        [item["expression"] for item in old["outputs"]] and
        [(item["pc"], item["width"], item["address"]) for item in case["reads"]] ==
        [(item["pc"], item["width"], item["address"]) for item in old["reads"]] and
        [(item["pc"], item["width"], item["address"], item["value"])
         for item in case["effects"]] ==
        [(item["pc"], item["width"], item["address"], item["value"])
         for item in old["ordered_effects"]])
    if not old_matches:
        raise ValueError("independent generated transition differs from old reference")
    family_il = deepcopy(value_il["value_il"])
    family_il["domain"] = "unsigned X in [5,256], with a separately admitted native path contract for each subrange"
    result = {"schema_version": 1,
        "generated_summary_sha256": digest(GENERATED),
        "source_proof_sha256": digest(SOURCE_PROOF),
        "fresh_trace_sha256": digest(FRESH),
        "generated_path": {"status": verdict["status"],
            "source_input": 252, "fresh_input": meta["input"],
            "source_steps": case["identity"]["native_steps"],
            "fresh_steps": len(rows),
            "reads_checked": verdict["reads_checked"],
            "ordered_writes_checked": verdict["ordered_writes_checked"],
            "target_pcode_steps_replayed": verdict["target_pcode_steps_replayed"],
            "fresh_object_layout": layout, "fresh_decoded_value": layout["digit"]},
        "negative_controls": negatives,
        "post_generation_reference_comparison": {
            "old_summary_sha256": digest(old_summary_path),
            "full_guard_state_read_write_successor_match": old_matches,
            "old_summary_used_to_generate": False},
        "numeric_path_family": {"value_il": family_il,
            "input_domain_union": "5..256 only under the corresponding admitted path contract",
            "cached_path": {"domain": "5..251", "fresh_251_status":
                             cached_verdict["status"],
                             "ordered_writes": cached_verdict["ordered_writes_checked"]},
            "allocated_path": {"domain": "252..256 under fixed source allocator state for value proof",
                               "fresh_255_status": verdict["status"],
                               "ordered_writes": verdict["ordered_writes_checked"]},
            "routing_completeness_proved": False,
            "logical_allocate_or_freshness_proved": False,
            "meaning": "two alternative path contracts share one numeric value IL; native effects remain distinct"},
        "limits": ["candidate selection uses a Python object-field analysis goal",
                   "fresh full transition is differentially validated on one 255 trace",
                   "value coverage holds with the fixed source allocator/TLS/free-list memory and other entry state",
                   "no new unknown engine opcode classification or all-path routing proof"]}
    RESULT.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"fresh_status": verdict["status"],
                      "fresh_value": layout["digit"],
                      "negative_controls": len(negatives),
                      "cached_writes": cached_verdict["ordered_writes_checked"],
                      "allocated_writes": verdict["ordered_writes_checked"]}))


def neighbor_boundary(rows, preceding):
    next_windows = [item for item in candidates(rows)
                    if item["begin"] == preceding["end_exclusive"] and
                    item["entry_pc"] != preceding["entry_pc"]]
    if len(next_windows) != 1:
        raise ValueError("adjacent distinct dispatch interval is ambiguous")
    return next_windows[0]


def freeze_neighbor():
    _, rows, _ = load_trace(SOURCE, "python", 252, PYTHON)
    (preceding, _, _), _ = choose_candidate(rows)
    boundary = neighbor_boundary(rows, preceding)
    segment = rows[boundary["begin"]:boundary["end_exclusive"]]
    case = make_case(segment, PYTHON, "unclassified_adjacent_dispatch_interval",
                     {"kind": "observed_native_path"}, segment_bases=True)
    source = {"schema_version": "native-handler-transition-v1",
        "engine": "python", "binary_sha256": digest(PYTHON),
        "case": case, "limits": ["native interval only; bytecode and high-level meaning unclassified"]}
    native = normalize_native(source, "python", case, digest(SOURCE))
    bundle = {"schema_version": "common-observed-transition-v1",
        "semantic_model": {"architecture": "x86-64", "endian": "little",
            "memory": "byte-addressed", "integers": "typed bitvectors",
            "expression": "SMT-LIB 2 term"},
        "cases": [native], "source_trace_sha256": digest(SOURCE),
        "selection": {"kind": "unique adjacent distinct BRANCHIND interval",
                      "preceding_boundary": preceding,
                      "selected_boundary": boundary},
        "claim": "full observed native transition; no bytecode or value semantics assigned"}
    if apply_case(bundle, native, PYTHON, segment)["status"] != "differentially_validated":
        raise ValueError("new adjacent native summary fails its source observation")
    NEIGHBOR_SUMMARY.write_text(json.dumps(bundle, indent=2) + "\n")
    print(json.dumps({"native_steps": len(segment),
                      "reads": len(native["reads"]),
                      "writes": len(native["effects"]),
                      "meaning_classified": False}))


def apply_neighbor():
    bundle = json.loads(NEIGHBOR_SUMMARY.read_text())
    case = bundle["cases"][0]
    _, rows, _ = load_trace(NEIGHBOR_TARGET, "python", 43, PYTHON)
    identity = case["identity"]
    matching = [item for item in candidates(rows)
                if item["native_steps"] == identity["native_steps"] and
                shape(rows[item["begin"]:item["end_exclusive"]],
                      identity["path_shape_mode"]) == identity["path_shape_sha256"]]
    if len(matching) != 1:
        raise ValueError("new adjacent interval absent or ambiguous on 43")
    boundary = matching[0]
    segment = rows[boundary["begin"]:boundary["end_exclusive"]]
    verdict = apply_case(bundle, case, PYTHON, segment)
    if verdict["status"] != "differentially_validated":
        raise ValueError("new interval native effects do not apply on 43")
    changed = deepcopy(segment)
    changed[-1]["next_pc"] ^= 1
    wrong_successor = require_unknown("neighbor wrong successor",
        apply_case(bundle, case, PYTHON, changed))
    changed_bundle = deepcopy(bundle)
    changed_bundle["cases"][0]["effects"].pop()
    missing_effect = require_unknown("neighbor missing effect",
        apply_case(changed_bundle, changed_bundle["cases"][0], PYTHON, segment))
    changed = deepcopy(segment)
    changed[-1]["registers_after"]["fs_base"] ^= 0x1000
    wrong_final_fs = require_unknown("neighbor final FS base",
        apply_case(bundle, case, PYTHON, changed))
    wrong_read_after_write = require_unknown("neighbor read-after-write",
        apply_case(bundle, case, PYTHON, change_read_after_write(segment)))
    report = {"schema_version": 1,
        "generated_summary_sha256": digest(NEIGHBOR_SUMMARY),
        "source_trace_sha256": digest(SOURCE),
        "fresh_trace_sha256": digest(NEIGHBOR_TARGET),
        "source_preceding_path": "allocated result interval for input 252",
        "target_preceding_path": "cached result interval for input 43",
        "matched_boundary": boundary, "native_transition": verdict,
        "wrong_successor": wrong_successor,
        "core_missing_effect": missing_effect,
        "wrong_final_fs_base": wrong_final_fs,
        "wrong_read_after_write_value": wrong_read_after_write,
        "bytecode_or_high_level_handler_meaning_identified": False,
        "value_projection_derived_from_this_interval": False,
        "scope": "adjacent native dispatch interval can be generated and reused across two observed predecessor paths; semantic classification remains open"}
    NEIGHBOR_RESULT.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"status": verdict["status"],
                      "reads": verdict["reads_checked"],
                      "writes": verdict["ordered_writes_checked"],
                      "target_pcode_steps_replayed": verdict["target_pcode_steps_replayed"]}))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("phase", choices=("freeze", "apply",
                                          "freeze_neighbor", "apply_neighbor"))
    args = parser.parse_args()
    if args.phase == "freeze":
        freeze()
    elif args.phase == "apply":
        apply()
    elif args.phase == "freeze_neighbor":
        freeze_neighbor()
    else:
        apply_neighbor()


if __name__ == "__main__":
    main()
