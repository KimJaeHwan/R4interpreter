"""Bounded branch, caller-bridge, and allocator-evidence audit for CPython.

All SMT claims hold with the source trace's fixed other entry state and
first-read memory. A target trace is checked independently; no bytecode
decompiler or Python opcode table is used.
"""
from __future__ import annotations

from hashlib import sha256
import json

import z3

from common_observed_transition import apply_case
from pcode_transition_summary import FLAG_OFFSETS, REGISTER_OFFSETS
from probe_connected_python_program import adapter, matching_boundary, require
from probe_unseen_python_path import ARTIFACTS, COMMON, GENERATED, NEIGHBOR_SUMMARY, PYTHON, ROOT, SOURCE
from prove_cross_full_flow import (CACHE_BASE, check_watches, find_write,
    initial_memory, load_trace, one, replay, unsat, word)
from prove_cross_value_path import small_int_memory


RESULT = ROOT / "python_remaining_scope_result.json"
TRACES = {252: SOURCE, 251: ARTIFACTS / "next_scope_py_251.json.gz",
          254: ARTIFACTS / "next_scope_py_254.json.gz"}


def digest(path):
    return sha256(path.read_bytes()).hexdigest()


def check_unsat(*clauses):
    solver = z3.Solver()
    solver.set(timeout=30000)
    solver.add(*clauses)
    require(solver.check() == z3.unsat, "symbolic bridge equality failed")


def bounded(x, lo, hi):
    return z3.And(z3.UGE(x, z3.BitVecVal(lo, 32)),
                  z3.ULE(x, z3.BitVecVal(hi, 32)))


def verify_suffix_entry(state, suffix):
    before = suffix[0]["registers"]
    require(all(before[name] == value for name, value in state["registers"].items()),
            "suffix entry GPR differs from preceding transition")
    require(all((before["eflags"] >> bit) & 1 == value
                for bit, value in state["flags"].items()),
            "suffix entry flags differ from preceding transition")
    require(all(before[name] == value for name, value in state["bases"].items()),
            "suffix entry FS/GS differ from preceding transition")
    for row in suffix:
        require(all(row["registers"][name] == state["bases"][name] and
                    row["registers_after"][name] == state["bases"][name]
                    for name in ("fs_base", "gs_base")),
                "suffix FS/GS changed or disagreed with entry frame")


def verify_suffix_model(model, guard, suffix):
    native_writes = [(hex(row["pc"]), access["address"], access["size"],
                      access["after"])
                     for row in suffix for access in row["memory"]
                     if access["access"] & 2]
    modeled_writes = [(item["pc"], item["observed_address"],
                       item["width"], item["observed"])
                      for item in model.effects]
    require(modeled_writes == native_writes,
            "suffix P-code writes differ in order, address, width or value")
    last = suffix[-1]["registers_after"]
    disagreements = [item["value_expression"] !=
                     z3.BitVecVal(item["observed"], item["width"] * 8)
                     for item in model.reads]
    disagreements += [item["value"] !=
                      z3.BitVecVal(item["observed"], item["width"] * 8)
                      for item in model.effects]
    disagreements += [model.regs[offset] != z3.BitVecVal(last[name], 64)
                      for offset, name in REGISTER_OFFSETS.items()]
    disagreements += [model.flags[offset] !=
                      z3.BitVecVal((last["eflags"] >> bit) & 1, 8)
                      for offset, bit in FLAG_OFFSETS.items()]
    check_unsat(guard, z3.Or(*disagreements))
    return {"modeled_reads": len(model.reads),
            "native_read_operands": sum(bool(a["access"] & 1)
                                        for row in suffix for a in row["memory"]),
            "ordered_native_writes": len(native_writes),
            "modeled_final_gprs": len(REGISTER_OFFSETS),
            "modeled_final_flags": len(FLAG_OFFSETS)}


def branch_audit(source_rows, source_meta, alternate_rows, heldout_rows):
    first = json.loads(GENERATED.read_text())["cases"][0]
    next_case = json.loads(NEIGHBOR_SUMMARY.read_text())["cases"][0]
    b = matching_boundary(source_rows, first)
    n = matching_boundary(source_rows, next_case)
    require(b["end_exclusive"] == n["begin"], "source intervals not adjacent")
    selected = source_rows[b["begin"]:n["end_exclusive"]]
    x = z3.BitVec("branch_X", 32)
    memory, _ = small_int_memory(selected, source_meta["entry_value_address"], 252, x)
    model, path_guard = replay(selected, PYTHON, memory)
    check_unsat(bounded(x, 252, 256), z3.Not(path_guard))
    guards = [item for item in model.guards if item["kind"] == "CBRANCH"]
    require(len(guards) == 33, "source P-code conditional inventory changed")
    results = []
    for lo, hi in ((252, 256), (251, 256)):
        solver = z3.Solver()
        solver.set(timeout=10000)
        solver.add(bounded(x, lo, hi))
        answers = []
        for index, item in enumerate(model.guards):
            if item["kind"] == "CBRANCH":
                solver.push()
                solver.add(z3.Not(item["condition"]))
                verdict = solver.check()
                witness = solver.model().eval(x).as_long() if verdict == z3.sat else None
                solver.pop()
                require(verdict != z3.unknown, "branch feasibility timed out")
                answers.append({"guard_index": index, "pc": item["pc"],
                                "opposite": str(verdict), "witness": witness})
            # Include only guards strictly earlier than the queried edge.
            solver.add(item["condition"])
        results.append({"domain": [lo, hi], "answers": answers})
    restricted, widened = results
    require(all(item["opposite"] == "unsat" for item in restricted["answers"]),
            "fixed source path has feasible alternate in its stated domain")
    sat_edges = [item for item in widened["answers"] if item["opposite"] == "sat"]
    require(len(sat_edges) == 1 and sat_edges[0]["witness"] == 251 and
            sat_edges[0]["pc"] == "0x5e978a", "alternate model changed")
    pc = int(sat_edges[0]["pc"], 16)
    observed = {value: next(row["next_pc"] for row in rows if row["pc"] == pc)
                for value, rows in ((252, source_rows), (251, alternate_rows),
                                    (254, heldout_rows))}
    require(observed[251] != observed[252] == observed[254],
            "SAT alternate did not reproduce on independent native trace")
    # Including the queried edge's own condition would hide this witness.
    edge_index = sat_edges[0]["guard_index"]
    guard_at_edge = model.guards[edge_index]["condition"]
    prefix_conditions = [item["condition"] for item in model.guards[:edge_index]]
    candidate = z3.Solver()
    candidate.add(bounded(x, 251, 256), *prefix_conditions,
                  z3.Not(guard_at_edge))
    require(candidate.check() == z3.sat and
            candidate.model().eval(x).as_long() == 251,
            "prefix-only query lost the genuine alternative")
    check_unsat(bounded(x, 251, 256), *prefix_conditions,
                guard_at_edge, z3.Not(guard_at_edge))
    require(sat_edges[0]["witness"] not in range(252, 257),
            "out-of-domain model accepted in restricted proof")
    return {"selected_native_steps": len(selected),
            "pcode_operations": model.operation_count,
            "pcode_cbranch_guards": len(guards),
            "source_domain": [252, 256],
            "opposite_edges_unsat_in_source_domain": len(restricted["answers"]),
            "widened_domain": [251, 256], "first_feasible_alternate": sat_edges[0],
            "observed_successors": {str(k): hex(v) for k, v in observed.items()},
            "scope": "source252 fixed other entry registers, allocator/TLS memory and earlier path guards",
            "remaining_after_first_divergence": "unknown; saved allocated suffix is inapplicable",
            "controls": ["current guard excluded from prefix query",
                         "out-of-domain witness excluded",
                         "SAT candidate executed independently"]}


def bridge_and_suffix(value, meta, rows, trace_summary, first_bundle, second_bundle,
                      route):
    first_case = first_bundle["cases"][0]
    second_case = second_bundle["cases"][0]
    b = matching_boundary(rows, first_case)
    n = matching_boundary(rows, second_case)
    require(b["end_exclusive"] == n["begin"], "summary intervals not adjacent")
    call = one(rows, 0x5636F9)
    child = one(rows, 0x565038, after=call)
    add = one(rows, 0x56227C, after=child)
    require(add == b["begin"] and call < child < add,
            "caller-to-child cutpoints changed")
    parent_frame, child_frame = rows[0]["registers"]["rbx"], rows[add]["registers"]["rbx"]
    parent_local, call_arg, child_local = parent_frame + 0x48, parent_frame + 0x60, child_frame + 0x48
    pointer = meta["entry_value_address"]
    require(pointer == CACHE_BASE + (value + 5) * 32,
            "input object is not the pinned cached PyLong")
    branch_end = one(rows, 0x564F61)
    require(branch_end < call, "entry branch is outside the caller prefix")
    x = z3.BitVec(f"entry_X_{value}", 32)
    memory, _ = small_int_memory(rows[:branch_end], pointer, value, x)
    entry, entry_guard = replay(rows[:branch_end], PYTHON, memory)
    domain = (5, 251) if route == "cached" else (252, 256)
    check_unsat(bounded(x, *domain), z3.Not(entry_guard))
    check_unsat(bounded(x, *domain), entry_guard,
                entry.regs[48] != z3.ZeroExt(32, x))
    watches = check_watches(trace_summary, {"parent_local", "parent_call_argument",
                                           "child_parameter"})
    require(watches["parent_call_argument"]["address"] == hex(call_arg) and
            watches["child_parameter"]["address"] == hex(child_local),
            "call slot watch mismatch")

    producer = max(i for i in range(call) if rows[i]["pc"] == 0x5612B0)
    ptr = z3.BitVec(f"parent_pointer_{value}", 64)
    segment = rows[producer:call]
    memory, _ = initial_memory(segment, [(parent_local, ptr, pointer)])
    parent, guard = replay(segment, PYTHON, memory)
    check_unsat(ptr == pointer, z3.Not(guard))
    check_unsat(guard, word(parent.memory, call_arg) != ptr)
    written_at, _, _ = find_write(rows, call_arg, pointer, before=call)
    arg_read = one(rows, 0x56036C, after=call)
    child_store = one(rows, 0x56036F, after=arg_read)
    def valid_call_binding(read_address, read_value, destination):
        return (read_address == call_arg and read_value == pointer and
                destination == child_local)

    observed_read = rows[arg_read]["memory"][0]
    observed_destination = rows[child_store]["memory"][0]["address"]
    require(valid_call_binding(observed_read["address"], observed_read["before"],
                               observed_destination),
            "call argument/parameter address or value mismatch")
    require(not valid_call_binding(observed_read["address"],
                                   observed_read["before"] ^ 1,
                                   observed_destination) and
            not valid_call_binding(observed_read["address"],
                                   observed_read["before"],
                                   observed_destination ^ 8),
            "corrupt call value or destination was accepted")
    require(not any(a["access"] & 2 and a["address"] < call_arg + 8 and
                    a["address"] + a["size"] > call_arg
                    for r in rows[written_at + 1:arg_read] for a in r["memory"]),
            "argument slot overwritten between production and consumption")
    bridge_ptr = z3.BitVec(f"bridge_pointer_{value}", 64)
    segment = rows[arg_read:child_store + 1]
    memory, _ = initial_memory(segment, [(call_arg, bridge_ptr, pointer)])
    bridge, guard = replay(segment, PYTHON, memory)
    check_unsat(bridge_ptr == pointer, z3.Not(guard))
    check_unsat(guard, word(bridge.memory, child_local) != bridge_ptr)

    child_load = one(rows, 0x5612B0, after=child)
    segment = rows[child_load:add]
    child_ptr = z3.BitVec(f"child_pointer_{value}", 64)
    memory, _ = initial_memory(segment, [(child_local, child_ptr, pointer)])
    load, guard = replay(segment, PYTHON, memory)
    check_unsat(child_ptr == pointer, z3.Not(guard))
    left, right = rows[add]["registers"]["r15"] - 16, rows[add]["registers"]["r15"] - 8
    check_unsat(guard, word(load.memory, left) != child_ptr)
    check_unsat(guard, word(load.memory, right) != CACHE_BASE + 10 * 32)

    first_rows, second_rows = rows[b["begin"]:b["end_exclusive"]], rows[n["begin"]:n["end_exclusive"]]
    suffix = rows[n["end_exclusive"]:]
    memory, _ = initial_memory(rows[b["begin"]:])
    first = apply_case(first_bundle, first_case, PYTHON, first_rows,
                       adapter(meta, value, first_rows[-1]["registers_after"]["r15"] - 8),
                       seeded_memory=memory, return_execution=True)
    require(first["status"] == "differentially_validated", "frozen first transition failed")
    second = apply_case(second_bundle, second_case, PYTHON, second_rows,
                        seeded_state=first["_next_state"],
                        seeded_memory=first["_next_memory"], return_execution=True)
    require(second["status"] == "differentially_validated", "frozen second transition failed")
    output = trace_summary["output_raw"]
    slot = second_rows[-1]["registers_after"]["r15"] - 8
    require(z3.simplify(word(second["_next_memory"], slot)).as_long() == output,
            "returned object not in parent output slot")
    verify_suffix_entry(second["_next_state"], suffix)
    corrupted_state = {**second["_next_state"],
                       "registers": {**second["_next_state"]["registers"],
                                     "rax": second["_next_state"]["registers"]["rax"] ^ 1}}
    try:
        verify_suffix_entry(corrupted_state, suffix)
    except ValueError:
        pass
    else:
        raise ValueError("corrupt suffix entry GPR was accepted")
    corrupted_state = {**second["_next_state"],
                       "flags": {**second["_next_state"]["flags"],
                                 6: second["_next_state"]["flags"][6] ^ 1}}
    try:
        verify_suffix_entry(corrupted_state, suffix)
    except ValueError:
        pass
    else:
        raise ValueError("corrupt suffix entry flag was accepted")
    corrupted_state = {**second["_next_state"],
                       "bases": {**second["_next_state"]["bases"],
                                 "fs_base": second["_next_state"]["bases"]["fs_base"] ^ 1}}
    try:
        verify_suffix_entry(corrupted_state, suffix)
    except ValueError:
        pass
    else:
        raise ValueError("corrupt suffix FS base was accepted")
    symbols = {name: z3.BitVecVal(number, 64)
               for name, number in second["_next_state"]["registers"].items()}
    outer, outer_guard = replay(suffix, PYTHON, second["_next_memory"], symbols)
    check_unsat(z3.Not(outer_guard))
    suffix_audit = verify_suffix_model(outer, outer_guard, suffix)
    exit_slot = trace_summary["exit_registers"]["r15"] - 8
    check_unsat(outer_guard, word(outer.memory, exit_slot) != output)
    require(trace_summary["function_return_raw"] == output,
            "function return and caller result disagree")
    corrupted_memory = z3.Store(second["_next_memory"],
                                z3.BitVecVal(slot, 64),
                                z3.BitVecVal((output ^ 1) & 255, 8))
    try:
        corrupted, corrupted_guard = replay(suffix, PYTHON, corrupted_memory, symbols)
    except ValueError:
        corrupted_rejected = True
    else:
        solver = z3.Solver()
        solver.add(corrupted_guard,
                   word(corrupted.memory, exit_slot) == output)
        corrupted_rejected = solver.check() == z3.unsat
    require(corrupted_rejected, "corrupt child return slot was accepted")
    return {"input": value, "route": route,
            "trace_sha256": digest(TRACES[value]),
            "prefix_total_native_steps": b["begin"],
            "entry_branch_replayed_native_steps": branch_end,
            "entry_branch_pcode_operations": entry.operation_count,
            "entry_branch_value_at_rsi":
                f"ZeroExt(32, X) under {domain[0]}..{domain[1]}, fixed entry environment",
            "proved_local_prefix_windows": {
                "parent_producer": call - producer,
                "argument_to_child_local": child_store + 1 - arg_read,
                "child_load": add - child_load},
            "prefix_unmodeled_gaps_remain": True,
            "frozen_first_native_steps": len(first_rows),
            "frozen_second_native_steps": len(second_rows),
            "suffix_replayed_native_steps": len(suffix),
            "suffix_pcode_operations": outer.operation_count,
            "suffix_full_state_and_memory_audit": suffix_audit,
            "output_pointer": hex(output),
            "numeric_value": value + 5,
            "status": "input/call local bridge, two frozen transitions, caller suffix replay validated",
            "negative_controls": ["wrong call argument value rejected",
                                  "wrong child parameter slot rejected",
                                  "wrong suffix entry GPR, flag and FS base rejected",
                                  "corrupted caller return slot rejected"]}


def allocator_audit(rows, bundle, value):
    b = matching_boundary(rows, bundle["cases"][0])
    seg = rows[b["begin"]:b["end_exclusive"]]
    slot = seg[-1]["registers_after"]["r15"] - 8
    writes = [(i, a) for i, row in enumerate(seg) for a in row["memory"] if a["access"] & 2]
    pointers = [a["after"] for _, a in writes if a["address"] == slot and a["size"] == 8]
    require(len(pointers) == 1, "ambiguous allocated result pointer")
    ptr = pointers[0]
    fields = [(offset, size) for offset, size in ((0, 8), (8, 8), (16, 8), (24, 4))
              if any(a["address"] == ptr + offset and a["size"] == size for _, a in writes)]
    require(len(fields) == 4, "allocated result field audit changed")
    prior_reads = [(i, row["pc"], a["address"])
                   for i, row in enumerate(seg) for a in row["memory"]
                   if a["access"] & 1 and ptr <= a["address"] < ptr + 28 and
                   not any(j < i and w["address"] <= a["address"] < w["address"] + w["size"]
                               for j, w in writes)]
    require(prior_reads, "allocator first-read evidence absent")
    require(any(row["pc"] == 0x5932F3 and row["next_pc"] == 0x5E9710 for row in seg),
            "internal helper call differs")
    return {"input": value, "object_pointer": hex(ptr),
            "object_field_writes": [list(item) for item in fields],
            "first_read_before_field_write": [{"step_in_first": i, "pc": hex(pc),
                                                "address": hex(addr)}
                                               for i, pc, addr in prior_reads],
            "helper_call_observed": "0x5932f3 -> 0x5e9710",
            "logical_allocate": "unknown", "logical_free": "unknown",
            "freshness_and_nonaliasing": "unknown",
            "missing_authority": ["allocator extent/generation and prior free/reuse history",
                                  "success and failure contract", "ownership transfer"],
            "negative_control": "field writes and returned pointer alone do not authorize Allocate"}


def main():
    loaded = {value: load_trace(path, "python", value, PYTHON)
              for value, path in TRACES.items()}
    first_bundle = json.loads(GENERATED.read_text())
    second_bundle = json.loads(NEIGHBOR_SUMMARY.read_text())
    cached_bundle = json.loads(COMMON.read_text())
    cached_case = next(item for item in cached_bundle["cases"]
                       if item["engine"] == "python" and
                       item["preconditions"]["kind"] == "python_cached_int")
    cached_bundle = {**cached_bundle, "cases": [cached_case]}
    branch = branch_audit(loaded[252][1], loaded[252][0],
                          loaded[251][1], loaded[254][1])
    paths = [bridge_and_suffix(value, *loaded[value],
                               cached_bundle if value == 251 else first_bundle,
                               second_bundle,
                               "cached" if value == 251 else "allocated")
             for value in (251, 252, 254)]
    lifetime = [allocator_audit(loaded[value][1], first_bundle, value)
                for value in (252, 254)]
    result = {"experiment": "CPython bounded missing-scope audit",
              "binary_sha256": digest(PYTHON),
              "frozen_summaries_sha256": {"first": digest(GENERATED),
                                           "second": digest(NEIGHBOR_SUMMARY),
                                           "cached": digest(COMMON)},
              "branch": branch, "paths": paths, "allocator": lifetime,
              "complete_python_program": False,
              "open_obligations": ["caller prefix gaps and alternate paths",
                                   "native calls and exceptions outside selected route",
                                   "CPython allocator lifetime contract",
                                   "independent model of all external memory effects"]}
    RESULT.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"branch_unsat": branch["opposite_edges_unsat_in_source_domain"],
                      "alternate_witness": branch["first_feasible_alternate"]["witness"],
                      "bridged_inputs": [p["input"] for p in paths],
                      "lifetime": [a["logical_allocate"] for a in lifetime]}))


if __name__ == "__main__":
    main()
