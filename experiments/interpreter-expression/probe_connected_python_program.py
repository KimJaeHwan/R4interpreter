"""Connect two frozen CPython native intervals and expose the remaining holes.

The first interval's predicted state and byte memory feed the second. The
report is a bounded, evidence-linked program view, not a complete decompile.
"""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86_const import X86_OP_IMM

from common_observed_transition import apply_case, shape
from discover_dispatch_intervals import candidates
from probe_unseen_python_path import (ARTIFACTS, CACHE_BASE, COMMON, GENERATED,
    NEIGHBOR_SUMMARY, PYTHON, ROOT, SOURCE, final_number, final_writes)
from prove_cross_full_flow import load_trace
from prove_lua_full_flow import initial_memory


FRESH = ARTIFACTS / "next_connected_py_255.json.gz"
CACHED = ARTIFACTS / "next_boundary_py_43.json.gz"
RESULT = ROOT / "connected_python_program_result.json"
VIEW = ROOT / "connected_python_program.txt"
CACHED_VALUE_PROOF = ROOT / "common_numeric_refinement_result.json"
ALLOCATED_VALUE_PROOF = ROOT / "unseen_python_generated_proof.json"
CACHED_VALUE_SOURCE = ARTIFACTS / "cross_python_value_9_native.json"


def digest(path):
    return sha256(path.read_bytes()).hexdigest()


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def matching_boundary(rows, case):
    identity = case["identity"]
    found = [item for item in candidates(rows)
             if shape(rows[item["begin"]:item["end_exclusive"]],
                      identity["path_shape_mode"]) == identity["path_shape_sha256"]]
    require(len(found) == 1, "frozen native interval absent or ambiguous")
    return found[0]


def raw_effects(rows):
    return [{"pc": hex(row["pc"]), "address": access["address"],
             "width": access["size"], "value": access["after"]}
            for row in rows for access in row["memory"] if access["access"] & 2]


def effect_projection(first_rows, second_rows, slot, pointer, expected_digit,
                      allocated):
    """Group display operations, retaining every native write and its order."""
    first = raw_effects(first_rows)
    second = raw_effects(second_rows)
    fields = ((0, 8, "refcount"), (8, 8, "type_pointer"),
              (16, 8, "size_tag"), (24, 4, "digit"))
    object_ordinals = []
    layout = {}
    if allocated:
        for offset, width, name in fields:
            matched = [index for index, effect in enumerate(first)
                       if effect["address"] == pointer + offset and
                       effect["width"] == width]
            require(len(matched) == 1, f"object field {name} absent or ambiguous")
            object_ordinals.append(matched[0])
            layout[name] = first[matched[0]]["value"]
    slot_ordinals = [index for index, effect in enumerate(first)
                     if effect["address"] == slot and effect["width"] == 8 and
                     effect["value"] == pointer]
    require(len(slot_ordinals) == 1, "result slot pointer write absent")
    slot_ordinal = slot_ordinals[0]
    if allocated:
        require(layout["refcount"] == 1 and layout["size_tag"] == 8 and
                layout["digit"] == expected_digit,
                "projected PyLong layout differs from proven numeric value")
    object_ordinals.sort()
    selected = set(object_ordinals + [slot_ordinal])
    require(len(selected) == (5 if allocated else 1),
            "object and result-slot writes alias")
    groups = [{"op": "OpaqueNativeWrites", "raw_write_ordinals":
              [index for index in range(len(first)) if index not in selected]}]
    if allocated:
        groups.append({"op": "PyLongFieldWrites",
                       "raw_write_ordinals": object_ordinals,
                       "object_pointer": pointer, "fields": layout,
                       "lifetime_kind": "unknown"})
    groups.extend([
        {"op": "ResultSlotPointerWrite", "raw_write_ordinals": [slot_ordinal],
         "slot": slot, "pointer": pointer},
        {"op": "NextIntervalNativeWrites", "raw_write_ordinals":
         list(range(len(second))) }])
    validate_projection(first, second, groups)
    return {"first_native_writes": first, "second_native_writes": second,
            "display_groups": groups, "native_writes_deleted": 0,
            "allocator_lifetime_effect": "unknown(no Allocate/Free contract for CPython allocator)"}


def validate_projection(first, second, groups):
    roles = [group["op"] for group in groups]
    require(roles in (["OpaqueNativeWrites", "PyLongFieldWrites",
                       "ResultSlotPointerWrite", "NextIntervalNativeWrites"],
                      ["OpaqueNativeWrites", "ResultSlotPointerWrite",
                       "NextIntervalNativeWrites"]), "effect group roles changed")
    for effects, selected in ((first, groups[:-1]), (second, groups[-1:])):
        ordinals = [number for group in selected
                    for number in group["raw_write_ordinals"]]
        require(len(ordinals) == len(effects) and
                ordinals == list(range(len(effects))) and
                all(group["raw_write_ordinals"] ==
                    sorted(group["raw_write_ordinals"]) for group in selected),
                "native effect lost, duplicated, or reordered inside a group")
    if "PyLongFieldWrites" in roles:
        fields = groups[1]
        pointer = fields["object_pointer"]
        require(sorted(first[index]["address"] - pointer
                       for index in fields["raw_write_ordinals"]) ==
                [0, 8, 16, 24],
                "object field binding no longer matches native writes")
    slot = groups[-2]
    require(first[slot["raw_write_ordinals"][0]]["address"] == slot["slot"] and
            first[slot["raw_write_ordinals"][0]]["value"] == slot["pointer"],
            "result slot binding no longer matches native write")


def decoder():
    result = Cs(CS_ARCH_X86, CS_MODE_64)
    result.detail = True
    return result


def path_inventory(rows, all_observed_edges):
    """Classify direct control edges in this slice; never infer completeness."""
    disassembler = decoder()
    branches, calls, returns = [], [], []
    for index, row in enumerate(rows):
        decoded = list(disassembler.disasm(bytes.fromhex(row["bytes"]),
                                            row["pc"]))
        require(len(decoded) == 1 and decoded[0].size * 2 == len(row["bytes"]),
                "native control instruction decode changed")
        insn = decoded[0]
        if insn.mnemonic.startswith("j") and insn.mnemonic != "jmp":
            require(insn.operands and insn.operands[0].type == X86_OP_IMM,
                    "unsupported conditional branch target")
            taken, fallthrough = insn.operands[0].imm, row["pc"] + insn.size
            require(row["next_pc"] in (taken, fallthrough),
                    "observed branch edge disagrees with native instruction")
            opposite = fallthrough if row["next_pc"] == taken else taken
            branches.append({"step_in_slice": index, "pc": hex(row["pc"]),
                "mnemonic": insn.mnemonic, "observed_successor": hex(row["next_pc"]),
                "opposite_successor": hex(opposite),
                "opposite_status": ("observed_in_other_trace" if opposite in
                    all_observed_edges.get(row["pc"], set()) else "unknown(unexplored edge)"),
                "infeasible_proved": False})
        if insn.mnemonic.startswith("call"):
            direct = bool(insn.operands and insn.operands[0].type == X86_OP_IMM)
            if direct:
                require(insn.operands[0].imm == row["next_pc"],
                        "direct call target disagrees with instruction")
            return_address = row["pc"] + insn.size
            call_rsp = row["registers"]["rsp"]
            returned = any(later["instruction"].startswith("ret") and
                           later["next_pc"] == return_address and
                           later["registers"]["rsp"] == call_rsp - 8 and
                           later["registers_after"]["rsp"] == call_rsp
                           for later in rows[index + 1:])
            calls.append({"step_in_slice": index, "pc": hex(row["pc"]),
                "target": hex(row["next_pc"]), "target_kind":
                "decoded_direct" if direct else "observed_indirect",
                "return_address": hex(return_address),
                "return_edge": ("observed_at_matching_stack_depth" if returned else
                                "unknown(outside slice or unmatched stack)"),
                "exception_edge": "unknown(not enumerated)"})
        if insn.mnemonic.startswith("ret"):
            returns.append({"step_in_slice": index, "pc": hex(row["pc"]),
                            "observed_successor": hex(row["next_pc"])})
    return {"conditional_branches": branches, "calls": calls,
            "returns": returns,
            "complete": False,
            "reason": "alternate edges, calls, exceptions and enclosing caller paths are not exhaustively proved"}


def validate_inventory(actual, expected):
    require(actual == expected, "control edge or unresolved obligation omitted")
    require(not actual["complete"], "unproved path coverage marked complete")


def observed_edges(trace_rows):
    result = {}
    for rows in trace_rows:
        for row in rows:
            result.setdefault(row["pc"], set()).add(row["next_pc"])
    return result


def adapter(meta, input_value, slot):
    cache = meta["runtime_cache_sha256_at_sync"]
    return {"input": input_value,
        "runtime_cache_sha256_at_entry": cache,
        "runtime_cache_sha256_at_exit": cache,
        "left_pointer": meta["entry_value_address"],
        "right_pointer": CACHE_BASE + 10 * 32,
        "output_slot": slot}


def value_proof_sources():
    cached = json.loads(CACHED_VALUE_PROOF.read_text())
    py = next(item for item in cached["adapters"] if item["engine"] == "python")
    allocated = json.loads(ALLOCATED_VALUE_PROOF.read_text())
    cache_checks = py["proof"]
    allocated_checks = allocated["value_refinement"]["proofs"]
    require(cached["source_summary_sha256"] == digest(COMMON) and
            py["binary_sha256"] == digest(PYTHON) and
            py["source_trace_sha256"] == digest(CACHED_VALUE_SOURCE) and
            py["inferred_additive_constant"] == 5 and
            cache_checks["path_guard_covers_core_domain"] == "unsat" and
            cache_checks["decoded_native_equals_value_il"] == "unsat",
            "cached value proof provenance or result changed")
    require(allocated["generated_summary_sha256"] == digest(GENERATED) and
            allocated["source_trace_sha256"] == digest(SOURCE) and
            allocated["binary_sha256"] == digest(PYTHON) and
            allocated["value_refinement"]["inferred_additive_constant"] == 5 and
            allocated_checks["fixed_environment_path_guard_covers_domain"] ==
            "unsat" and
            allocated_checks["decoded_final_digit_equals_candidate"] == "unsat",
            "allocated value proof provenance or result changed")
    return {"cached": {"proof_artifact": CACHED_VALUE_PROOF.name,
            "proof_sha256": digest(CACHED_VALUE_PROOF),
            "source_trace_sha256": digest(CACHED_VALUE_SOURCE),
            "domain": "5..251", "grade": "source fixed-environment SMT proof"},
        "allocated": {"proof_artifact": ALLOCATED_VALUE_PROOF.name,
            "proof_sha256": digest(ALLOCATED_VALUE_PROOF),
            "source_trace_sha256": digest(SOURCE),
            "domain": "252..256", "grade": "source fixed-environment SMT proof"}}


def cross_boundary_reads(first_rows, second_rows):
    written = {access["address"] + index
               for row in first_rows for access in row["memory"]
               if access["access"] & 2 for index in range(access["size"])}
    return [(row, access) for row in second_rows for access in row["memory"]
            if access["access"] & 1 and
            any(access["address"] + index in written
                for index in range(access["size"]))]


def one_path(input_value, path, first_bundle, second_bundle, all_edges,
             allocated):
    meta, rows, summary = load_trace(path, "python", input_value, PYTHON)
    first_case, second_case = first_bundle["cases"][0], second_bundle["cases"][0]
    first_boundary = matching_boundary(rows, first_case)
    second_boundary = matching_boundary(rows, second_case)
    require(first_boundary["end_exclusive"] == second_boundary["begin"],
            "frozen intervals are not adjacent in the full trace")
    first_rows = rows[first_boundary["begin"]:first_boundary["end_exclusive"]]
    second_rows = rows[second_boundary["begin"]:second_boundary["end_exclusive"]]
    slot = first_rows[-1]["registers_after"]["r15"] - 8
    initial, _ = initial_memory(rows[first_boundary["begin"]:
                                    second_boundary["end_exclusive"]])
    first = apply_case(first_bundle, first_case, PYTHON, first_rows,
                       adapter(meta, input_value, slot), seeded_memory=initial,
                       return_execution=True)
    require(first["status"] == "differentially_validated",
            f"first interval rejected: {first['status']}")
    second = apply_case(second_bundle, second_case, PYTHON, second_rows,
                        seeded_state=first["_next_state"],
                        seeded_memory=first["_next_memory"],
                        return_execution=True)
    require(second["status"] == "differentially_validated",
            f"composed interval rejected: {second['status']}")
    crossing = cross_boundary_reads(first_rows, second_rows)
    require(crossing, "no cross-boundary memory read was exercised")
    pointer = final_number(final_writes(first_rows), slot, 8)
    require(pointer == summary["output_raw"] == summary["function_return_raw"],
            "object result is not observed at caller return")
    if not allocated:
        require(pointer == CACHE_BASE + (input_value + 10) * 32,
                "cached result pointer differs from frozen numeric decode")
    effects = effect_projection(first_rows, second_rows, slot, pointer,
                                input_value + 5, allocated)
    inventory = path_inventory(first_rows + second_rows, all_edges)
    return {"input": input_value, "route": "allocated" if allocated else "cached",
        "trace_sha256": digest(path),
        "first_boundary": first_boundary, "second_boundary": second_boundary,
        "prefix_native_steps_opaque": first_boundary["begin"],
        "composed_native_steps": len(first_rows) + len(second_rows),
        "suffix_native_steps_opaque": len(rows) - second_boundary["end_exclusive"],
        "first_transition": {key: val for key, val in first.items()
                             if not key.startswith("_")},
        "second_transition": {key: val for key, val in second.items()
                              if not key.startswith("_")},
        "cross_boundary_reads_checked": len(crossing),
        "value_il": {"sort": "BV32", "expression": "X + 5",
                     "conditional_domain": ("252 <= X <= 256" if allocated else
                        "5 <= X <= 251") + " with frozen other entry state"},
        "effects": effects, "control": inventory,
        "caller_return_pointer_observed": pointer,
        "_rows": (first_rows, second_rows),
        "_first_execution": first, "_second_execution": second,
        "_bundles": (first_bundle, second_bundle), "_adapter": adapter(meta, input_value, slot)}


def negative_controls(path):
    first_rows, second_rows = path["_rows"]
    first, second = path["_first_execution"], path["_second_execution"]
    first_bundle, second_bundle = path["_bundles"]
    second_case = second_bundle["cases"][0]
    controls = {}
    changed = deepcopy(second_rows)
    crossing = cross_boundary_reads(first_rows, changed)
    crossing[0][1]["before"] ^= 1
    verdict = apply_case(second_bundle, second_case, PYTHON, changed,
        seeded_state=first["_next_state"], seeded_memory=first["_next_memory"])
    require(verdict["status"] == "unknown(composed read memory mismatch)",
            f"cross-boundary read mutation was admitted: {verdict}")
    controls["wrong_cross_boundary_read"] = verdict["status"]
    changed_state = deepcopy(first["_next_state"])
    changed_state["registers"]["rax"] ^= 1
    verdict = apply_case(second_bundle, second_case, PYTHON, second_rows,
        seeded_state=changed_state, seeded_memory=first["_next_memory"])
    require(verdict["status"] == "unknown(composed entry state mismatch)",
            "wrong composed register was admitted")
    controls["wrong_prior_exit_register"] = verdict["status"]
    changed_state = deepcopy(first["_next_state"])
    changed_state["bases"]["fs_base"] ^= 1
    verdict = apply_case(second_bundle, second_case, PYTHON, second_rows,
        seeded_state=changed_state, seeded_memory=first["_next_memory"])
    require(verdict["status"] == "unknown(composed entry state mismatch)",
            "wrong composed FS base was admitted")
    controls["wrong_prior_exit_fs_base"] = verdict["status"]
    effects = path["effects"]
    changed_groups = deepcopy(effects["display_groups"])
    changed_groups[0]["raw_write_ordinals"].pop()
    try:
        validate_projection(effects["first_native_writes"],
                            effects["second_native_writes"], changed_groups)
    except ValueError:
        controls["deleted_opaque_write"] = "rejected(effect partition incomplete)"
    else:
        raise ValueError("deleted native write was accepted")
    changed_groups = deepcopy(effects["display_groups"])
    changed_groups[1]["object_pointer"] ^= 8
    try:
        validate_projection(effects["first_native_writes"],
                            effects["second_native_writes"], changed_groups)
    except ValueError:
        controls["wrong_object_field_binding"] = "rejected(field address mismatch)"
    else:
        raise ValueError("wrong object field binding was accepted")
    inventory = path["control"]
    for name, field in (("omitted_branch_edge", "conditional_branches"),
                        ("omitted_call_edge", "calls")):
        changed_inventory = deepcopy(inventory)
        require(changed_inventory[field], f"no {field} for negative control")
        changed_inventory[field].pop()
        try:
            validate_inventory(changed_inventory, inventory)
        except ValueError:
            controls[name] = "rejected(control inventory incomplete)"
        else:
            raise ValueError(f"{name} was accepted")
    changed_inventory = deepcopy(inventory)
    changed_inventory["calls"][0].pop("exception_edge")
    try:
        validate_inventory(changed_inventory, inventory)
    except ValueError:
        controls["omitted_exception_obligation"] = "rejected(exception obligation incomplete)"
    else:
        raise ValueError("omitted exception obligation was accepted")
    changed_inventory = deepcopy(inventory)
    changed_inventory["calls"][0]["target"] = "0x0"
    try:
        validate_inventory(changed_inventory, inventory)
    except ValueError:
        controls["wrong_observed_call_target"] = "rejected(call target evidence mismatch)"
    else:
        raise ValueError("wrong observed call target was accepted")
    changed_inventory = deepcopy(inventory)
    changed_inventory["calls"][0]["return_address"] = "0x0"
    try:
        validate_inventory(changed_inventory, inventory)
    except ValueError:
        controls["wrong_return_address"] = "rejected(return address evidence mismatch)"
    else:
        raise ValueError("wrong return address was accepted")
    changed_inventory = deepcopy(inventory)
    changed_inventory["complete"] = True
    try:
        validate_inventory(changed_inventory, inventory)
    except ValueError:
        controls["false_full_coverage"] = "rejected(unproved coverage)"
    else:
        raise ValueError("false path completeness was accepted")
    return controls


def cached_frame_controls(path):
    first_rows, _ = path["_rows"]
    bundle, _ = path["_bundles"]
    case = bundle["cases"][0]
    controls = {}
    for name, index, side, base in (
            ("cached_middle_gs_base", len(first_rows) // 2, "registers_after", "gs_base"),
            ("cached_final_fs_base", -1, "registers_after", "fs_base")):
        changed = deepcopy(first_rows)
        changed[index][side][base] ^= 1
        verdict = apply_case(bundle, case, PYTHON, changed, path["_adapter"],
                             return_execution=True)
        require(verdict["status"] == "unknown(segment base changed)",
                f"{name} was admitted: {verdict['status']}")
        controls[name] = verdict["status"]
    return controls


def readable(case):
    effects = case["effects"]["display_groups"]
    allocated = case["route"] == "allocated"
    text = [
        f"# Observed Python input {case['input']}; bounded path view",
        f"opaque caller prefix: {case['prefix_native_steps_opaque']} native steps",
        "branch/call: observed in trace; other edges remain unknown",
        "X: BV32 = input PyLong digit",
        f"Y: BV32 = X + 5  [source proof: {case['value_il']['proof_source']['domain']} in fixed source environment; this input: differential validation]",
        f"OpaqueNativeWrites({len(effects[0]['raw_write_ordinals'])})  [retained]",
    ]
    if allocated:
        text.append(f"PyLongFieldWrites(result_ptr, refcount=1, type=PyLong, tag=8, digit=Y)  [raw writes {effects[1]['raw_write_ordinals']}]")
    else:
        text.append("result_ptr = cached PyLong(Y)  [cache image contract]")
    text.extend([
        f"ResultSlotPointerWrite(result_slot, result_ptr)  [raw write {effects[-2]['raw_write_ordinals']}]",
        f"dispatch -> unclassified next interval ({case['second_boundary']['native_steps']} native steps)",
        f"NextIntervalNativeWrites({len(effects[-1]['raw_write_ordinals'])})  [retained]",
        f"opaque caller suffix: {case['suffix_native_steps_opaque']} native steps",
        f"observed caller return pointer: {case['caller_return_pointer_observed']:#x}",
        "lifetime: unknown; alternate branches and exception exits: unknown",
    ])
    return "\n".join(text)


def program_il(cases, proofs, first_summaries):
    """A typed value DAG with explicit native/opaque stateful operations."""
    value = json.loads(CACHED_VALUE_PROOF.read_text())["value_il"]
    require(value["schema_version"] == "bounded-value-il-v1" and
            [node["id"] for node in value["nodes"]] == [0, 1, 2] and
            [(node["op"], node.get("sort")) for node in value["nodes"]] ==
            [("input", "BV32"), ("bv", "BV32"), ("bvadd", "BV32")] and
            value["nodes"][0]["name"] == "X" and
            value["nodes"][1]["value"] == 5 and
            value["nodes"][2]["args"] == [0, 1] and
            value["result"] == {"node": 2, "name": "Y", "sort": "BV32"},
            "shared typed value IL changed")
    value = deepcopy(value)
    value["domain"] = ("route conditioned: cached 5..251, allocated 252..256; "
                       "each bound belongs to its pinned source proof")
    routes = []
    for case in cases:
        kind = case["route"]
        routes.append({"route": kind, "observed_input": case["input"],
            "admission": "observed path and frozen guard only",
            "source_proved_domain": proofs[kind]["domain"],
            "source_value_proof": proofs[kind],
            "operations": [
                {"op": "OpaqueNativePrefix",
                 "native_steps": case["prefix_native_steps_opaque"]},
                {"op": "DecodeInput", "output": "X", "sort": "BV32",
                 "contract": "PyLong digit in pinned entry environment"},
                {"op": "ValueIL", "output": "Y", "sort": "BV32",
                 "node": value["result"]["node"]},
                {"op": "NativeTransition", "role": "numeric",
                 "summary_sha256": first_summaries[kind],
                 "output_state": "state1", "output_memory": "memory1",
                 "effect_groups": case["effects"]["display_groups"][:-1]},
                {"op": "NativeTransition", "role": "unclassified_next",
                 "summary_sha256": digest(NEIGHBOR_SUMMARY),
                 "input_state": "state1", "input_memory": "memory1",
                 "output_state": "state2", "output_memory": "memory2",
                 "effect_groups": case["effects"]["display_groups"][-1:]},
                {"op": "OpaqueNativeSuffix",
                 "native_steps": case["suffix_native_steps_opaque"]},
                {"op": "ObservedCallerReturnPointer",
                 "value": case["caller_return_pointer_observed"]}],
            "unresolved": ["branch alternatives", "exception exits",
                           "allocator lifetime", "opaque prefix/suffix"]})
    return {"schema_version": "bounded-program-il-v1",
        "value_il": value,
        "routes": routes,
        "status": "reporting_ir_not_independently_executed",
        "scope": "observed two-interval composition; only those intervals' native writes remain ordered and complete; ValueIL is a projection"}


def main():
    first_bundle = json.loads(GENERATED.read_text())
    second_bundle = json.loads(NEIGHBOR_SUMMARY.read_text())
    cached_bundle = json.loads(COMMON.read_text())
    cached_case = next(case for case in cached_bundle["cases"]
                       if case["engine"] == "python" and
                       case["preconditions"]["kind"] == "python_cached_int")
    cached_bundle = {**cached_bundle, "cases": [cached_case]}
    require(first_bundle["source_trace_sha256"] == digest(SOURCE) and
            second_bundle["source_trace_sha256"] == digest(SOURCE),
            "frozen summary source provenance changed")
    _, cached_rows, _ = load_trace(CACHED, "python", 43, PYTHON)
    _, source_rows, _ = load_trace(SOURCE, "python", 252, PYTHON)
    _, fresh_rows, _ = load_trace(FRESH, "python", 255, PYTHON)
    edges = observed_edges((cached_rows, source_rows, fresh_rows))
    cached = one_path(43, CACHED, cached_bundle, second_bundle, edges, False)
    source = one_path(252, SOURCE, first_bundle, second_bundle, edges, True)
    fresh = one_path(255, FRESH, first_bundle, second_bundle, edges, True)
    controls = negative_controls(fresh)
    controls.update(cached_frame_controls(cached))
    proofs = value_proof_sources()
    for case in (cached, source, fresh):
        case["value_il"]["proof_source"] = proofs[case["route"]]
        case["value_il"]["whole_domain_proved_in_this_trace"] = (
            proofs[case["route"]]["source_trace_sha256"] == case["trace_sha256"])
    VIEW.write_text("\n\n".join(readable(case)
                                  for case in (cached, source, fresh)) + "\n")
    structured_il = program_il((cached, source, fresh), proofs,
        {"cached": digest(COMMON), "allocated": digest(GENERATED)})
    def public(case):
        return {key: value for key, value in case.items() if not key.startswith("_")}
    result = {"schema_version": 1,
        "frozen_summaries_sha256": {GENERATED.name: digest(GENERATED),
                                     NEIGHBOR_SUMMARY.name: digest(NEIGHBOR_SUMMARY),
                                     COMMON.name: digest(COMMON)},
        "cached": public(cached), "source": public(source), "fresh": public(fresh),
        "value_proof_sources": proofs,
        "program_il": structured_il,
        "cached_path_trace_sha256": digest(CACHED),
        "negative_controls": controls,
        "readable_view_sha256": digest(VIEW),
        "claims": {"two_interval_sequential_state_and_memory_composition": True,
                   "display_only_effect_grouping": True,
                   "native_write_elimination_proved": False,
                   "cpython_allocator_lifetime_proved": False,
                   "all_branch_call_exception_paths_complete": False,
                   "entire_program_decompiled": False},
        "limits": ["prefix and suffix of the caller trace remain opaque",
                   "all opposite branch edges and call exceptions need coverage evidence",
                   "full-trace first-read memory is supplied from each observed target trace",
                   "summary reuse is shown on one independent full input 255"]}
    RESULT.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"cached": cached["composed_native_steps"],
                      "source": source["composed_native_steps"],
                      "fresh": fresh["composed_native_steps"],
                      "cross_boundary_reads": fresh["cross_boundary_reads_checked"],
                      "negative_controls": len(controls),
                      "unresolved_branch_edges": sum(item["opposite_status"].startswith("unknown")
                        for item in fresh["control"]["conditional_branches"])}))


if __name__ == "__main__":
    main()
