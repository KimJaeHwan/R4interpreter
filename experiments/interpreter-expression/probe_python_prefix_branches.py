"""Prefix-only opposite-edge worklist and concrete candidate audit.

The source object's tag, other registers and first-read memory stay fixed.
A SAT model is a candidate; only a native trace can confirm the edge.
"""
from __future__ import annotations

from collections import defaultdict, deque
from hashlib import sha256
import json

import z3

from common_program_path_il import require
from probe_connected_python_prefix import OPAQUE_START, first_read_memory, replay
from probe_connected_python_program import path_inventory
from probe_python_remaining_scope import TRACES
from probe_unseen_python_path import PYTHON, ROOT
from prove_cross_full_flow import load_trace


RESULT = ROOT / "python_prefix_branch_worklist_result.json"
ZERO = ROOT / "artifacts/cross_python_full_0.json.gz"


def query(model, x, lo, hi):
    solver = z3.Solver()
    solver.set(timeout=5000)
    solver.add(z3.UGE(x, z3.BitVecVal(lo, 32)),
               z3.ULE(x, z3.BitVecVal(hi, 32)))
    answers = []
    for index, guard in enumerate(model.guards):
        if guard["kind"] == "CBRANCH":
            solver.push()
            solver.add(z3.Not(guard["condition"]))
            verdict = solver.check()
            witness = solver.model().eval(x).as_long() if verdict == z3.sat else None
            solver.pop()
            require(verdict != z3.unknown, "prefix opposite-edge query timed out")
            answers.append({"guard_index": index, "pc": guard["pc"],
                            "opposite": str(verdict), "witness": witness})
        # Only guards strictly before the queried one constrain its question.
        solver.add(guard["condition"])
    return answers


def main():
    meta, source, _ = load_trace(TRACES[252], "python", 252, PYTHON)
    zero_meta, actual, _ = load_trace(ZERO, "python", 0, PYTHON)
    require(meta["marker"]["bytecode_sha256"] ==
            zero_meta["marker"]["bytecode_sha256"],
            "zero candidate uses a different fixture")
    rows = source[:OPAQUE_START]
    x = z3.BitVec("PREFIX_BRANCH_X", 32)
    memory, _ = first_read_memory(source[:683], meta["entry_value_address"], 252, x)
    model, _ = replay(rows, memory)
    restricted = query(model, x, 251, 256)
    widened = query(model, x, 0, 256)
    require(len(restricted) == len(widened) == 62 and
            all(item["opposite"] == "unsat" for item in restricted),
            "restricted prefix edge feasibility changed")
    candidates = [item for item in widened if item["opposite"] == "sat"]
    require(len(candidates) == 1 and candidates[0]["witness"] == 0 and
            candidates[0]["pc"] == "0x5a82b0", "zero alternate model changed")
    native = path_inventory(rows, {})["conditional_branches"]
    require(len(native) == 60, "native prefix condition count changed")
    per_pc = defaultdict(deque)
    for item in restricted:
        per_pc[item["pc"]].append(item)
    native_proofs = []
    for edge in native:
        require(per_pc[edge["pc"]],
                "native prefix branch lacks P-code certificate")
        proof = per_pc[edge["pc"]].popleft()
        require(proof["opposite"] == "unsat",
                "native prefix branch lacks P-code certificate")
        native_proofs.append({"absolute_step": edge["step_in_slice"],
                              "pc": edge["pc"],
                              "opposite_successor": edge["opposite_successor"],
                              "pcode_guard_index": proof["guard_index"],
                              "prefix_opposite": "unsat"})
    internal = [item for queue in per_pc.values() for item in queue]
    require(len(internal) == 2 and
            {item["pc"] for item in internal} == {"0x5630f6", "0x5613b8"} and
            all(item["pc"] not in {edge["pc"] for edge in native} and
                next(row["instruction"] for row in rows
                     if hex(row["pc"]) == item["pc"]).startswith("cmov")
                for item in internal),
            "P-code internal conditional count changed")
    different = next((index for index, (a, b) in enumerate(zip(source, actual))
                      if a["pc"] != b["pc"] or a["next_pc"] != b["next_pc"]), None)
    require(different == 133 and source[different]["pc"] == actual[different]["pc"] ==
            0x5A8250 and source[different]["next_pc"] != actual[different]["next_pc"] and
            not any(row["pc"] == int(candidates[0]["pc"], 16) for row in actual),
            "zero trace did not show earlier branch divergence")
    result = {"schema_version": "python-prefix-branch-worklist-v1",
              "source_trace_sha256": sha256(TRACES[252].read_bytes()).hexdigest(),
              "candidate_trace_sha256": sha256(ZERO.read_bytes()).hexdigest(),
              "binary_sha256": sha256(PYTHON.read_bytes()).hexdigest(),
              "selected_prefix_native_steps": len(rows),
              "source_fixed_environment_domain": [251, 256],
              "pcode_conditional_opposites_unsat": len(restricted),
              "native_conditional_proofs": native_proofs,
              "internal_pcode_conditionals": internal,
              "widened_domain": [0, 256],
              "candidate": {**candidates[0],
                  "native_status": "unrealized_in_default_zero_trace",
                  "first_actual_divergence_step": different,
                  "first_actual_divergence_pc": hex(source[different]["pc"]),
                  "source_successor": hex(source[different]["next_pc"]),
                  "actual_zero_successor": hex(actual[different]["next_pc"]),
                  "reason": "zero object's tag and other live-ins differ from fixed source252 object"},
              "scope": "first 513 native steps; prefix-only guard queries under source252 fixed other state",
              "does_not_close_zero_candidate": True}
    RESULT.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"native_proofs": len(native_proofs),
                      "candidate": candidates[0]["witness"],
                      "candidate_executed_at_proposed_pc": False}))


if __name__ == "__main__":
    main()
