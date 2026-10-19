"""Apply six connected path nodes using computed state and byte memory.

This is an exact-witness, selected-path executor. Trace first reads supply an
explicit entry environment; the trace is used to check results, never to
reinitialize state or memory at a node boundary.
"""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json

import z3

from bounded_memset_contract import (apply as apply_memset, checked_image,
                                     number)
from build_evidence_program_il import (OUTPUT as PATH_IL, RESULT as PATH_RESULT,
                                       bundles, windows)
from common_path_executor import execute
from common_observed_transition import apply_case
from common_program_path_il import PathILError, native_path_ledger, require
from pcode_transition_summary import FLAG_OFFSETS, REGISTER_OFFSETS
from probe_connected_python_prefix import first_read_memory, prove_witness, replay
from probe_connected_python_program import adapter
from probe_python_remaining_scope import TRACES
from probe_unseen_python_path import PYTHON, ROOT
from prove_cross_full_flow import CACHE_BASE, load_trace, word


RESULT = ROOT / "bounded_python_program_application_result.json"
HOLDOUT = ROOT / "artifacts/next_connected_py_255.json.gz"


def concrete_state(state, x, witness):
    return {"registers": {name: number(state["regs"][offset], x, witness)
                          for offset, name in REGISTER_OFFSETS.items()},
            "flags": {bit: number(state["flags"][bit], x, witness)
                      for bit in FLAG_OFFSETS.values()},
            "bases": state["bases"]}


def check_state(state, observed, x, witness):
    require(all(number(state["regs"][offset], x, witness) == observed[name]
                for offset, name in REGISTER_OFFSETS.items()),
            "node scalar state differs from computed predecessor")
    require(all(number(state["flags"][bit], x, witness) ==
                (observed["eflags"] >> bit) & 1
                for bit in state["known_flags"]),
            "node defined flags differ from computed predecessor")
    require(all(state["bases"][name] == observed[name]
                for name in ("fs_base", "gs_base")),
            "node segment-base frame differs")


def run_route(value, path, published=None):
    meta, rows, summary = load_trace(path, "python", value, PYTHON)
    allocated, neighbor, cached = bundles()
    first = cached if value == 251 else allocated
    spans = windows(rows, first, neighbor)
    if published is None:
        nodes = native_path_ledger(rows, spans)
    else:
        require(published["trace_sha256"] == sha256(path.read_bytes()).hexdigest() and
                [(n["id"], n["begin"], n["end_exclusive"], n["op"])
                 for n in published["nodes"]] ==
                [(n["id"], n["begin"], n["end_exclusive"], n["op"])
                 for n in native_path_ledger(rows, spans)],
                "published path node partition differs")
        nodes = published["nodes"]
    x = z3.BitVec(f"CONNECTED_PROGRAM_X_{value}", 32)
    memory, first_bytes = first_read_memory(rows, meta["entry_value_address"],
                                            value, x,
                                            symbolic_unobserved=True)
    entry = rows[0]["registers"]
    initial = {"regs": {offset: z3.BitVecVal(entry[name], 64)
                        for offset, name in REGISTER_OFFSETS.items()},
               "flags": {bit: z3.BitVecVal((entry["eflags"] >> bit) & 1, 8)
                         for bit in FLAG_OFFSETS.values()},
               "known_flags": set(FLAG_OFFSETS.values()),
               "bases": {name: entry[name] for name in ("fs_base", "gs_base")},
               "memory": memory}

    def pcode(node, incoming):
        selected = rows[node["begin"]:node["end_exclusive"]]
        try:
            check_state(incoming, selected[0]["registers"], x, value)
            model, guard = replay(selected, incoming["memory"],
                {name: incoming["regs"][offset]
                 for offset, name in REGISTER_OFFSETS.items()},
                incoming["flags"])
            proof = prove_witness(model, guard, selected, x, value)
            outgoing = {"regs": model.regs,
                        "flags": {bit: model.flags[offset]
                                  for offset, bit in FLAG_OFFSETS.items()},
                        "known_flags": set(FLAG_OFFSETS.values()),
                        "bases": incoming["bases"], "memory": model.memory}
            check_state(outgoing, selected[-1]["registers_after"], x, value)
        except (ValueError, AssertionError, KeyError) as error:
            return None, None, f"P-code {error}"
        return outgoing, {"grade": "computed_Pcode_exact_witness",
                          "native_steps": len(selected),
                          "guard_terms": proof["guard_terms"],
                          "ordered_writes": proof["ordered_writes"]}, None

    def external(node, incoming):
        selected = rows[node["begin"]:node["end_exclusive"]]
        try:
            check_state(incoming, selected[0]["registers"], x, value)
            from types import SimpleNamespace
            result = apply_memset(selected, SimpleNamespace(
                regs=incoming["regs"], memory=incoming["memory"]), x, value)
            outgoing = {"regs": {offset: result["registers"][name]
                                  for offset, name in REGISTER_OFFSETS.items()},
                        "flags": result["flags"],
                        "known_flags": set(result["evidence"]["defined_flag_bits"]),
                        "bases": incoming["bases"],
                        "memory": result["memory"]}
            check_state(outgoing, selected[-1]["registers_after"], x, value)
        except (ValueError, AssertionError, KeyError) as error:
            return None, None, f"checked external call {error}"
        return outgoing, {"grade": "conditional_checked_external_call",
                          **result["evidence"]}, None

    def frozen(node, incoming):
        selected = rows[node["begin"]:node["end_exclusive"]]
        bundle = first if node["id"] == "numeric_transition" else neighbor
        case = bundle["cases"][0]
        try:
            check_state(incoming, selected[0]["registers"], x, value)
            state = concrete_state(incoming, x, value)
            concrete_memory = z3.substitute(incoming["memory"],
                (x, z3.BitVecVal(value, 32)))
            extra = (adapter(meta, value,
                      selected[-1]["registers_after"]["r15"] - 8)
                     if node["id"] == "numeric_transition" else None)
            result = apply_case(bundle, case, PYTHON, selected, extra,
                                seeded_state=state,
                                seeded_memory=concrete_memory,
                                return_execution=True)
            require(result["status"] == "differentially_validated",
                    result["status"])
            target = result["_next_state"]
            outgoing = {"regs": {offset: z3.BitVecVal(
                                      target["registers"][name], 64)
                                  for offset, name in REGISTER_OFFSETS.items()},
                        "flags": {bit: z3.BitVecVal(target["flags"][bit], 8)
                                  for bit in FLAG_OFFSETS.values()},
                        "known_flags": set(FLAG_OFFSETS.values()),
                        "bases": target["bases"],
                        "memory": result["_next_memory"]}
            check_state(outgoing, selected[-1]["registers_after"], x, value)
        except (ValueError, AssertionError, KeyError) as error:
            return None, None, f"frozen transition {error}"
        return outgoing, {"grade": "computed_frozen_native_transition",
                          "native_steps": len(selected),
                          "reads_checked": result["reads_checked"],
                          "ordered_writes": result["ordered_writes_checked"]}, None

    applied = execute(nodes, initial, {
        "PcodeReplayedWindow": pcode,
        "OpaqueExternalCall": external,
        "FrozenNativeTransition": frozen}, expected_end=len(rows))
    if applied["status"] != "bounded_path_applied":
        return applied
    exit_state = applied.pop("_state")
    slot = summary["exit_registers"]["r15"] - 8
    predicted_output = number(word(exit_state["memory"], slot), x, value)
    require(predicted_output == summary["output_raw"] ==
            summary["function_return_raw"],
            "computed path does not contain returned object pointer")
    if value == 251:
        require(predicted_output == CACHE_BASE + (value + 10) * 32,
                "returned cached pointer does not encode X+5")
        numeric_grade = "pinned_cached_PyLong_layout"
    else:
        digit = z3.Concat(*reversed([
            z3.Select(exit_state["memory"],
                      z3.BitVecVal(predicted_output + 24 + index, 64))
            for index in range(4)]))
        require(number(digit, x, value) == value + 5,
                "computed result object digit differs from X+5")
        numeric_grade = "computed_allocated_object_digit"
    return {**applied, "input": value,
            "trace_sha256": sha256(path.read_bytes()).hexdigest(),
            "initial_environment_first_read_bytes": first_bytes,
            "output_pointer": hex(predicted_output),
            "numeric_value": value + 5,
            "output_grade": numeric_grade,
            "all_inputs_or_other_environments": False}


def negative_controls():
    meta, rows, _ = load_trace(TRACES[252], "python", 252, PYTHON)
    x = z3.BitVec("CONNECTED_NEGATIVE_X", 32)
    memory, _ = first_read_memory(rows, meta["entry_value_address"], 252, x,
                                  symbolic_unobserved=True)
    before, _ = replay(rows[:513], memory)
    original = rows[513:525]
    from types import SimpleNamespace
    incoming = SimpleNamespace(regs=before.regs, memory=before.memory)
    contract = apply_memset(original, incoming, x, 252)
    require(contract["evidence"]["same_value_write_lanes"] > 0 and
            contract["evidence"]["definite_write_extent"] == 8,
            "same-value masked stores were dropped")
    controls = {}

    def reject(name, change, action):
        altered = deepcopy(original)
        change(altered)
        try:
            action(altered)
        except (ValueError, AssertionError, KeyError):
            controls[name] = "rejected"
        else:
            raise PathILError(f"negative control accepted: {name}")

    reject("wrong_libc_code_byte",
           lambda r: r[0].__setitem__("bytes", "90" + r[0]["bytes"][2:]),
           checked_image)
    reject("truncated_libc_instruction",
           lambda r: r[0].__setitem__("bytes", r[0]["bytes"][:2]),
           checked_image)
    reject("extra_libc_memory_access",
           lambda r: r[0]["memory"].append({
               "address": 0x1000, "size": 1, "access": 1,
               "before": 0, "after": 0}),
           lambda r: apply_memset(r, incoming, x, 252))
    reject("extra_libc_memory_write",
           lambda r: r[1]["memory"].append({
               "address": 0x1000, "size": 1, "access": 2,
               "before": 1, "after": 0}),
           lambda r: apply_memset(r, incoming, x, 252))
    reject("wrong_libc_return_read_address",
           lambda r: r[11]["memory"][0].__setitem__(
               "address", r[11]["memory"][0]["address"] + 8),
           lambda r: apply_memset(r, incoming, x, 252))
    reject("wrong_libc_return_read_width",
           lambda r: r[11]["memory"][0].__setitem__("size", 4),
           lambda r: apply_memset(r, incoming, x, 252))
    reject("wrong_libc_return_read_mode",
           lambda r: r[11]["memory"][0].__setitem__("access", 2),
           lambda r: apply_memset(r, incoming, x, 252))
    reject("wrong_vector_mask_or_value",
           lambda r: r[10]["memory"][0].__setitem__(
               "after", r[10]["memory"][0]["after"] ^ (1 << 72)),
           lambda r: apply_memset(r, incoming, x, 252))
    reject("wrong_requested_extent",
           lambda r: r[0]["registers"].__setitem__("rdx", 9),
           lambda r: apply_memset(r, incoming, x, 252))
    changed = deepcopy(contract)
    changed["registers"]["rax"] = changed["registers"]["rax"] + 1
    try:
        check_state({"regs": {offset: changed["registers"][name]
                              for offset, name in REGISTER_OFFSETS.items()},
                     "flags": changed["flags"],
                     "known_flags": set(changed["evidence"]["defined_flag_bits"]),
                     "bases": {name: rows[0]["registers"][name]
                               for name in ("fs_base", "gs_base")}},
                    rows[524]["registers_after"], x, 252)
    except ValueError:
        controls["wrong_external_output_register"] = "rejected"
    else:
        raise PathILError("wrong libc return register accepted")
    after, _ = replay(rows[525:683], contract["memory"],
                      contract["registers"], contract["flags"])
    state = {"regs": after.regs,
             "flags": {bit: after.flags[offset]
                       for offset, bit in FLAG_OFFSETS.items()},
             "bases": {name: rows[0]["registers"][name]
                       for name in ("fs_base", "gs_base")}}
    computed = concrete_state(state, x, 252)
    bundle = bundles()[0]
    span = windows(rows, bundle, bundles()[1])[3]
    selected = rows[span["begin"]:span["end_exclusive"]]
    binding = adapter(meta, 252, selected[-1]["registers_after"]["r15"] - 8)
    injected = z3.substitute(after.memory, (x, z3.BitVecVal(252, 32)))
    first_access = next(a for row in selected for a in row["memory"]
                        if a["access"] & 1)
    bad_memory = z3.Store(injected,
                          z3.BitVecVal(first_access["address"], 64),
                          z3.BitVecVal((first_access["before"] ^ 1) & 255, 8))
    wrong_memory = apply_case(bundle, bundle["cases"][0], PYTHON, selected,
                              binding, seeded_state=computed,
                              seeded_memory=bad_memory)
    require(wrong_memory["status"].startswith("unknown"),
            "corrupt prefix-to-numeric memory accepted")
    controls["wrong_prefix_to_numeric_memory"] = "rejected"
    wrong_state = deepcopy(computed)
    wrong_state["registers"]["rax"] ^= 1
    verdict = apply_case(bundle, bundle["cases"][0], PYTHON, selected,
                         binding, seeded_state=wrong_state,
                         seeded_memory=injected)
    require(verdict["status"].startswith("unknown"),
            "corrupt prefix-to-numeric register accepted")
    controls["wrong_prefix_to_numeric_register"] = "rejected"
    unsupported = execute([{"begin": 0, "end_exclusive": 1,
                            "op": "UnverifiedNode", "id": "gap"}],
                          {}, {}, expected_end=1)
    require(unsupported["status"] == "unknown(unsupported node operation)",
            "unsupported IL node was skipped")
    controls["opaque_node_without_contract"] = "rejected"
    omitted = execute(native_path_ledger(rows,
                      windows(rows, bundle, bundles()[1]))[:-1], {}, {},
                      expected_end=len(rows))
    require(omitted["status"] == "unknown(incomplete node partition)",
            "omitted final node was accepted")
    controls["omitted_final_node"] = "rejected"
    unknown_byte = z3.simplify(z3.Select(memory,
        z3.BitVecVal(0x1000000000000000, 64)))
    require(not z3.is_bv_value(unknown_byte),
            "unobserved entry memory was fixed to a concrete value")
    controls["unobserved_memory_not_zero_filled"] = "symbolic"
    return controls


def main():
    doc = json.loads(PATH_IL.read_text())
    require(json.loads(PATH_RESULT.read_text())["program_il_sha256"] ==
            sha256(PATH_IL.read_bytes()).hexdigest(),
            "path IL result digest changed")
    require([route["input"] for route in doc["routes"]] == [251, 252, 254],
            "source route inventory changed")
    expected_fixture = doc["contract"]["fixture_bytecode_sha256"]
    cases = []
    for route in doc["routes"]:
        cases.append(run_route(route["input"], TRACES[route["input"]], route))
    hold_meta, _, _ = load_trace(HOLDOUT, "python", 255, PYTHON)
    require(hold_meta["marker"]["bytecode_sha256"] == expected_fixture,
            "holdout fixture bytecode differs")
    cases.append(run_route(255, HOLDOUT))
    require(all(item["status"] == "bounded_path_applied" and
                item["nodes_applied"] == 6 for item in cases),
            "connected program application failed")
    report = {"schema_version": "bounded-python-program-application-v1",
              "program_il_sha256": sha256(PATH_IL.read_bytes()).hexdigest(),
              "binary_sha256": sha256(PYTHON.read_bytes()).hexdigest(),
              "fixture_bytecode_sha256": expected_fixture,
              "cases": cases,
              "negative_controls": negative_controls(),
              "scope": "four exact observed native paths with first-read environment supplied at entry",
              "limits": ["the pinned libc path contract covers zero fill of eight bytes only",
                         "native P-code and frozen summaries follow observed path shapes",
                         "freshness, exception exits and other entry environments remain unknown",
                         "this is not a complete executable common program IL"]}
    RESULT.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"applied_inputs": [c["input"] for c in cases],
                      "nodes_each": 6,
                      "external_contracts": sum(c["certificates"][1]["grade"] ==
                         "conditional_checked_external_call" for c in cases)}))


if __name__ == "__main__":
    main()
