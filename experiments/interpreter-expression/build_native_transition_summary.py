"""Adapt a native instruction trace to the common transition summary format."""
from __future__ import annotations

import argparse
import csv
from hashlib import sha256
import json
from pathlib import Path
import tarfile

from pcode_transition_summary import PathReplay, REGISTER_OFFSETS, serialize_expr


def read_native_trace(path):
    with path.open(newline="") as stream:
        records = list(csv.DictReader(stream))
    if len(records) < 2:
        raise ValueError("need entry and following register snapshot")
    before, after = records[:2]
    names = list(REGISTER_OFFSETS.values()) + ["eflags"]
    registers = {name: int(before[name], 16) for name in names}
    registers_after = {name: int(after[name], 16) for name in names}
    if int(before["next_rip"], 16) != int(after["rip"], 16):
        raise AssertionError("CSV entry step is not contiguous")
    return {"type": "step", "step": 0, "pc": int(before["rip"], 16),
            "next_pc": int(before["next_rip"], 16),
            "registers": registers, "registers_after": registers_after,
            "memory": []}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("bundle", type=Path)
    parser.add_argument("csv_trace", type=Path)
    parser.add_argument("binary", type=Path)
    parser.add_argument("trace_output", type=Path)
    parser.add_argument("summary_output", type=Path, nargs="?")
    args = parser.parse_args()
    row = read_native_trace(args.csv_trace)
    args.trace_output.write_text(json.dumps({"type": "meta", "source_csv": str(args.csv_trace)}) + "\n" +
                                 json.dumps(row) + "\n")
    if args.summary_output is None:
        return
    with tarfile.open(args.bundle, "r:gz") as archive:
        member = next(m for m in archive if m.name.endswith("/function-000000.json"))
        data = json.load(archive.extractfile(member))
    instructions = {i["address"]["byte_offset"]: i for i in data["instructions"]}
    if row["pc"] not in instructions:
        raise AssertionError("native entry not in Bundle")
    replay = PathReplay({}, [row], instructions)
    replay.run()
    if replay.reads or replay.effects or replay.guards:
        raise AssertionError("native fixture expected register arithmetic only")
    report = {
        "schema_version": "transition-summary-v0-candidate",
        "semantic_model": {"architecture": "x86-64", "endian": "little", "pointer_width": 64,
                           "value_domain": "bitvector and byte-addressed memory",
                           "lifter_version": "Ghidra 12.0.4 Bundle",
                           "bundle_sha256": sha256(args.bundle.read_bytes()).hexdigest()},
        "identity": {"executable_code_sha256": sha256(args.binary.read_bytes()).hexdigest(),
                     "code_epoch": "static fixture; runtime code mutation not modeled",
                     "entry_cutpoint": hex(row["pc"]), "exit_cutpoint": hex(row["next_pc"]),
                     "specialization_dependencies": ["native ELF and Bundle"]},
        "interface": {"inputs": [{"name": "R_RDI", "sort": "BV64",
                                   "binding": {"kind": "register", "name": "rdi"}}]},
        "case": {"path_guard": [], "branch_evidence": [], "reads": [],
                 "ordered_effects": [],
                 "outputs": [{"name": "return_value", "sort": "BV64",
                              "expression": serialize_expr(replay.regs[0]),
                              "observed_binding": {"kind": "register", "name": "rax"}}],
                 "exit_kind": "native_function_body_before_return",
                 "uncovered": "function call and return edges"},
        "evidence": {"trace_sha256": sha256(args.csv_trace.read_bytes()).hexdigest(),
                     "handler_native_instructions": 1,
                     "pcode_operations_replayed": replay.operation_count,
                     "concrete_register_and_memory_checks": "passed",
                     "validation_level": "candidate: one observed path, not a full function proof"},
    }
    args.summary_output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"operations": replay.operation_count,
                      "return_expression": report["case"]["outputs"][0]["expression"]}))


if __name__ == "__main__":
    main()
