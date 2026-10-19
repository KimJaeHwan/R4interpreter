"""Prove the first observed Lua handler branch without assuming its own edge."""
from __future__ import annotations

from copy import deepcopy
import json

import z3

from audit_python_branch_candidates import conditional_successors
from build_common_program_representation import (LUA_BINARY, LUA_BYTECODE,
    ROOT, digest, lua_flow_trace, lua_vm_rows)
from common_program_path_il import require
from pcode_transition_summary import FLAG_OFFSETS, REGISTER_OFFSETS, PathReplay
from project_lua_call_bridge import BUNDLE, load_instructions
from prove_lua_full_flow import first_memory, initial_memory, prove_input, trace_records


OUTPUT = ROOT / "lua_native_branch_predicate_v1.json"
BRANCH_PC = 0x415F30


def verdict(*constraints):
    solver = z3.Solver()
    solver.set(timeout=30000)
    solver.add(*constraints)
    result = solver.check()
    require(result != z3.unknown, "Lua branch SMT timed out")
    return str(result)


def case(label):
    path = lua_flow_trace(label)
    records = trace_records(path)
    rows = lua_vm_rows(records)
    targets = [i for i, row in enumerate(rows) if row["pc"] == BRANCH_PC]
    require(targets == [32], "Lua native branch occurrence changed")
    prefix = rows[:targets[0] + 1]
    target = prefix[-1]
    successors = conditional_successors(target)
    require(successors == {0x415D51, 0x415F36} and
            target["next_pc"] in successors,
            "Lua branch no longer has the expected two legal successors")
    witness = records[0]["input_word"]
    x = z3.BitVec("X", 64)
    input_link = prove_input(records, x)
    source = first_memory(prefix[0], 1)
    require(source["before"] == witness and
            hex(source["address"]) ==
            records[-1]["hardware_watch_intervals"][1]["address"],
            "Lua VM source slot is not linked to the parsed input")
    memory, first_reads = initial_memory(prefix,
                                         [(source["address"], x, witness)])
    entry = prefix[0]["registers"]
    model = PathReplay(prefix[0], prefix,
        load_instructions((row["pc"] for row in prefix), BUNDLE),
        register_symbols={offset: z3.BitVecVal(entry[name], 64)
                          for offset, name in REGISTER_OFFSETS.items()},
        flag_symbols={offset: z3.BitVecVal((entry["eflags"] >> bit) & 1, 8)
                      for offset, bit in FLAG_OFFSETS.items()},
        memory_symbol=memory, address_guards=True)
    model.run()
    target_guards = [i for i, item in enumerate(model.guards)
                     if item["pc"] == hex(BRANCH_PC) and
                     item["kind"] == "CBRANCH"]
    require(target_guards == [len(model.guards) - 1],
            "target branch guard is ambiguous or absent")
    prior = z3.And(*(item["condition"] for item in model.guards[:-1]))
    observed_taken = target["next_pc"] == 0x415D51
    recorded = model.guards[-1]["condition"]
    raw_taken = recorded if observed_taken else z3.Not(recorded)
    require(verdict(prior, z3.Xor(raw_taken, x == 0)) == "unsat" and
            verdict(prior, x == 0) == "sat" and
            verdict(prior, x != 0) == "sat" and
            verdict(prior, x == witness) == "sat",
            "branch predicate is not independently equivalent to X == 0")
    # Inserting the observed target edge makes one side unreachable; this is
    # explicitly rejected as a vacuous proof of the target condition.
    contaminated = z3.And(prior, recorded)
    require({verdict(contaminated, x == 0),
             verdict(contaminated, x != 0)} == {"sat", "unsat"} and
            verdict(prior, z3.Xor(z3.Not(raw_taken), x == 0)) == "sat",
            "negative guard controls failed")
    try:
        initial_memory(prefix, [(source["address"], x, witness ^ 1)])
    except ValueError:
        pass
    else:
        raise ValueError("wrong symbolic input-slot witness was accepted")
    flipped = deepcopy(prefix)
    flipped[-1]["next_pc"] = next(pc for pc in successors
                                  if pc != target["next_pc"])
    opposite = PathReplay(flipped[0], flipped,
        load_instructions((row["pc"] for row in flipped), BUNDLE),
        register_symbols={offset: z3.BitVecVal(entry[name], 64)
                          for offset, name in REGISTER_OFFSETS.items()},
        flag_symbols={offset: z3.BitVecVal((entry["eflags"] >> bit) & 1, 8)
                      for offset, bit in FLAG_OFFSETS.items()},
        memory_symbol=memory, address_guards=True)
    try:
        opposite.run()
    except AssertionError:
        pass
    else:
        raise ValueError("wrong native branch successor was accepted")
    return {"input_label": label, "input_word": witness,
        "trace_sha256": digest(path), "source_native_pc": hex(prefix[0]["pc"]),
        "source_slot_address": hex(source["address"]),
        "source_slot_link": "parsed_input_to_watched_vm_source",
        "source_link_evidence": input_link,
        "first_read_bytes_fixed_except_input_slot": first_reads,
        "native_steps_through_target": len(prefix),
        "prior_guard_count": len(model.guards) - 1,
        "target_guard_excluded_from_prefix": True,
        "target_occurrence_id": f"lua_branch_{label}:branch:32",
        "native_branch_pc": hex(BRANCH_PC),
        "branch_instruction_bytes": target["bytes"],
        "jump_target": "0x415d51", "fallthrough": "0x415f36",
        "observed_successor": hex(target["next_pc"]),
        "observed_taken": observed_taken,
        "raw_taken_predicate": "X == 0",
        "prior_and_predicate_xor_candidate": "unsat",
        "prior_with_x_zero": "sat", "prior_with_x_nonzero": "sat",
        "prior_with_observed_witness": "sat",
        "negative_target_guard_contamination": "rejected_by_two_sided_sat",
        "negative_inverted_predicate": "rejected_by_sat_counterexample",
        "negative_wrong_source_witness": "rejected",
        "negative_flipped_native_successor": "rejected"}


def build():
    cases = [case(label) for label in ("x0", "x9")]
    require(cases[0]["observed_successor"] == "0x415d51" and
            cases[1]["observed_successor"] == "0x415f36" and
            cases[0]["source_slot_address"] != cases[1]["source_slot_address"],
            "Lua branch alternate-edge evidence changed")
    return {"schema_version": "lua-native-branch-predicate-v1",
        "binary_sha256": digest(LUA_BINARY),
        "bytecode_sha256": digest(LUA_BYTECODE),
        "cases": cases,
        "claim": "raw taken predicate at the observed native branch equals X == 0 under each independently fixed entry snapshot and all preceding guards",
        "scope": "two captured Lua runs; non-input entry registers, flags, first-read memory and native instruction bytes fixed",
        "limits": ["does not prove arbitrary VM entry states or uncaptured paths",
                   "does not establish that the next captured bytecode fetch is an immediate bytecode successor"]}


def main():
    doc = build()
    OUTPUT.write_text(json.dumps(doc, indent=2) + "\n")
    require(json.loads(OUTPUT.read_text()) == doc, "Lua proof artifact changed")
    print(json.dumps({"cases": len(doc["cases"]),
                      "prior_guards_each": [item["prior_guard_count"] for item in doc["cases"]],
                      "predicate": "X == 0", "two_sided_sat": True}))


if __name__ == "__main__":
    main()
