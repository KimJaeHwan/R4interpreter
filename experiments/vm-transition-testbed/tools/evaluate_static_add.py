"""Assess the trace-free P-code path selector on two ADD bytecode programs.

Archived paths enter only after candidate construction, as comparison data.
The initial VM cutpoint snapshot is still inherited from prior training.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys

import z3

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT.parent / "interpreter-expression"))

from analyze_r4vm import TransitionPath  # noqa: E402
from logic_projection import (  # noqa: E402
    compact_expression, project_path, reduce_input_value,
)
from pcode_transition_summary import FLAG_OFFSETS, REGISTER_OFFSETS  # noqa: E402
from project_r4vm_logic import entry_state as symbolic_entry_state  # noqa: E402
from static_pcode_step import derive_step, elf_memory, entry_state  # noqa: E402
from train_r4vm import BINARY, BUNDLE, PROGRAMS, SUMMARIES, bundle_instructions  # noqa: E402


CASES = (("VMT001", 5), ("VMT001", 9), ("VMT002", 9), ("VMT002", 0))
COMPARISON_FIELDS = ("kind", "native_path", "pcode_operations", "guards", "reads",
                     "effects", "registers", "flags")


class BaselineAdapter:
    def __init__(self, summary):
        self.summary = summary

    def initial_state(self, program, input_value):
        return entry_state(self.summary, program, input_value)


def evaluate():
    summary = json.loads(SUMMARIES.read_text())
    if sha256(BINARY.read_bytes()).hexdigest() != summary["binary_sha256"]:
        raise ValueError("ELF differs from archived baseline")
    if sha256(BUNDLE.read_bytes()).hexdigest() != summary["bundle_sha256"]:
        raise ValueError("Bundle differs from archived baseline")
    instructions, binary_image = bundle_instructions(), elf_memory(BINARY)
    adapter = BaselineAdapter(summary)
    cases = []
    for name, input_value in CASES:
        program = (PROGRAMS / f"{name}.r4vm").read_bytes()
        step, candidate = derive_step(summary, instructions, binary_image, program,
                                      input_value, [name, input_value])
        # Projection uses only the newly generated candidate and entry baseline.
        path = TransitionPath(candidate)
        registers, memory = entry_state(summary, program, input_value)
        concrete_result = path.apply(registers, memory, with_reads=True)
        if concrete_result is None:
            raise ValueError(f"generated path rejects its witness: {name}/{input_value}")
        _, concrete_effects, concrete_reads = concrete_result
        symbolic = symbolic_entry_state(adapter, program)
        guards, projected_effects = project_path(path, symbolic, concrete_reads,
                                                 concrete_effects, REGISTER_OFFSETS,
                                                 FLAG_OFFSETS, {"X"})
        value, proved = reduce_input_value(symbolic.read(registers["rsp"], 8),
                                           z3.BitVec("X", 64))
        cases.append({"program": name, "input": input_value,
                      "program_sha256": sha256(program).hexdigest(),
                      "path_id": candidate["id"], "native_instructions": len(step.native_path),
                      "pcode_operations": step.operation_count,
                      "path_guards": len(candidate["guards"]),
                      "projected_nontrivial_guards": len(guards),
                      "ordered_writes": len(projected_effects),
                      "slot0_formula": compact_expression(value),
                      "slot0_formula_smt": value.sexpr(),
                      "formula_equivalence_proved": proved,
                      "next_vm_pc": compact_expression(symbolic.registers["rcx"]),
                      "candidate": candidate})
    # Frozen paths are comparison data and are first consulted here.
    references = {row["id"]: row for row in summary["paths"]}
    for case in cases:
        candidate = case.pop("candidate")
        reference = references.get(candidate["id"])
        case["archived_path_found"] = reference is not None
        case["archived_fields_equal"] = (None if reference is None else
                                         {field: candidate[field] == reference[field]
                                          for field in COMPARISON_FIELDS})
    return {"schema_version": 1,
            "method": "input-guided Bundle P-code emulation with symbolic guards/effects",
            "path_selection_uses_native_trace": False,
            "entry_baseline_from_previous_native_trace": True,
            "claim": "one ADD step on selected inputs, not full path/alias/frame coverage",
            "cases": cases}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=ROOT / "reports/static-add-evaluation.json")
    args = parser.parse_args()
    report = evaluate()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps([{"program": item["program"], "input": item["input"],
                       "formula": item["slot0_formula"], "pc": item["next_vm_pc"],
                       "matches_archived_path": all(item["archived_fields_equal"].values())}
                      for item in report["cases"]], indent=2))


if __name__ == "__main__":
    main()
