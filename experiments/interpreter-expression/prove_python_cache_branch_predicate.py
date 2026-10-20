"""Prove one CPython numeric handler cache decision in four fixed snapshots."""
from __future__ import annotations

from copy import deepcopy
import json

import z3

from apply_bounded_python_program import HOLDOUT
from audit_python_branch_candidates import conditional_successors
from build_common_program_representation import ROOT, digest
from common_program_path_il import require
from probe_python_remaining_scope import TRACES
from probe_unseen_python_path import PYTHON
from prove_cross_full_flow import load_trace, replay
from prove_cross_value_path import small_int_memory


OUTPUT = ROOT / "python_cache_branch_predicate_v1.json"
PATHS = {**TRACES, 255: HOLDOUT}
TARGET_PC = 0x5E978A
TARGET_STEP = 764
NUMERIC_ENTRY_STEP = 683


def verdict(*clauses):
    solver = z3.Solver()
    solver.set(timeout=30000)
    solver.add(*clauses)
    result = solver.check()
    require(result != z3.unknown, "Python cache branch SMT timed out")
    return str(result)


def domain(x):
    return z3.And(z3.UGE(x, z3.BitVecVal(251, 32)),
                  z3.ULE(x, z3.BitVecVal(256, 32)))


def case(witness, path):
    meta, rows, summary = load_trace(path, "python", witness, PYTHON)
    require(rows[NUMERIC_ENTRY_STEP]["pc"] == 0x56227C and
            rows[TARGET_STEP]["pc"] == TARGET_PC and
            summary["through_return"] is True,
            "Python cache target left the selected native numeric handler")
    target = rows[TARGET_STEP]
    legal = conditional_successors(target)
    require(legal == {0x5E978C, 0x5E97B0} and
            target["next_pc"] in legal,
            "Python cache branch instruction or successor changed")
    prefix = rows[NUMERIC_ENTRY_STEP:TARGET_STEP + 1]
    x = z3.BitVec("X", 32)
    memory, fixed_first_reads = small_int_memory(
        prefix, meta["entry_value_address"], witness, x)
    model, _ = replay(prefix, PYTHON, memory)
    target_guards = [i for i, guard in enumerate(model.guards)
                     if guard["pc"] == hex(TARGET_PC) and
                     guard["kind"] == "CBRANCH"]
    require(target_guards == [len(model.guards) - 1],
            "cache branch P-code guard is ambiguous")
    prior = z3.And(*(guard["condition"] for guard in model.guards[:-1]))
    observed_taken = target["next_pc"] == 0x5E97B0
    recorded = model.guards[-1]["condition"]
    raw_taken = recorded if observed_taken else z3.Not(recorded)
    candidate = z3.UGE(x, z3.BitVecVal(252, 32))
    require(verdict(domain(x), prior, z3.Xor(raw_taken, candidate)) == "unsat" and
            verdict(domain(x), prior, x == 251) == "sat" and
            verdict(domain(x), prior, x == 252) == "sat" and
            verdict(domain(x), prior, x == witness) == "sat",
            "cache branch is not independently X >= 252 in declared domain")
    # Inserting the target's observed edge into the premise must lose one
    # side. The other branch direction must remain a real counterexample to
    # an intentionally inverted candidate.
    contaminated = z3.And(domain(x), prior, recorded)
    require({verdict(contaminated, x == 251),
             verdict(contaminated, x == 252)} == {"sat", "unsat"} and
            verdict(domain(x), prior,
                    z3.Xor(z3.Not(raw_taken), candidate)) == "sat",
            "cache branch negative guard controls failed")
    try:
        small_int_memory(prefix, meta["entry_value_address"], witness ^ 1, x)
    except ValueError:
        pass
    else:
        raise ValueError("wrong Python input digit witness was accepted")
    flipped = deepcopy(prefix)
    flipped[-1]["next_pc"] = next(pc for pc in legal
                                  if pc != target["next_pc"])
    try:
        replay(flipped, PYTHON, memory)
    except AssertionError:
        pass
    else:
        raise ValueError("wrong Python native branch successor was accepted")
    return {"input": witness, "trace_sha256": digest(path),
        "binary_sha256": digest(PYTHON),
        "fixture_bytecode_sha256": meta["marker"]["bytecode_sha256"],
        "input_object_address": hex(meta["entry_value_address"]),
        "input_digit_address": hex(meta["entry_value_address"] + 24),
        "fixed_first_read_bytes_except_input_digit": fixed_first_reads,
        "native_handler_entry_step": NUMERIC_ENTRY_STEP,
        "target_occurrence_id": f"python_{witness}:branch:{TARGET_STEP}",
        "target_native_step": TARGET_STEP,
        "target_pc": hex(TARGET_PC),
        "target_instruction_bytes": target["bytes"],
        "prior_guard_count": len(model.guards) - 1,
        "target_guard_excluded_from_prefix": True,
        "jump_target": "0x5e97b0", "fallthrough": "0x5e978c",
        "observed_successor": hex(target["next_pc"]),
        "observed_taken": observed_taken,
        "raw_taken_predicate_in_domain": "X >= 252",
        "proof_domain": "251 <= X <= 256 (unsigned BV32)",
        "prior_and_predicate_xor_candidate": "unsat",
        "prior_with_x251": "sat", "prior_with_x252": "sat",
        "prior_with_observed_witness": "sat",
        "negative_current_guard_contamination": "rejected_by_two_sided_sat",
        "negative_inverted_predicate": "rejected_by_sat_counterexample",
        "negative_wrong_digit_witness": "rejected",
        "negative_wrong_native_successor": "rejected"}


def build():
    cases = [case(witness, PATHS[witness])
             for witness in (251, 252, 254, 255)]
    require(cases[0]["observed_successor"] == "0x5e978c" and
            all(case["observed_successor"] == "0x5e97b0"
                for case in cases[1:]) and
            len({case["fixture_bytecode_sha256"]["addFive"]
                 for case in cases}) == 1,
            "Python cache branch alternate observations changed")
    return {"schema_version": "python-cache-branch-predicate-v1",
        "cases": cases,
        "claim": "within 251..256, the raw native taken predicate at 0x5e978a equals X >= 252 under each independently fixed non-input entry state and preceding guards",
        "bytecode_context": "same-trace addFive numeric handler offset 6 is bound separately in control_frontier_matrix_v1.json",
        "limits": ["input object tag, other entry registers, flags and first-read memory are snapshot fixed",
                   "this is a runtime cached-integer boundary, not a Python source branch",
                   "alternate edges under other entry environments and exception exits remain unknown"]}


def main():
    doc = build()
    OUTPUT.write_text(json.dumps(doc, indent=2) + "\n")
    require(json.loads(OUTPUT.read_text()) == doc,
            "Python cache branch proof artifact changed")
    print(json.dumps({"snapshots": len(doc["cases"]),
                      "predicate": "X >= 252 within 251..256",
                      "two_sided_sat": True}))


if __name__ == "__main__":
    main()
