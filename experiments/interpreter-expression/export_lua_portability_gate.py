"""Export a fail-closed, language-neutral case view of the Lua experiments.

Recorded Lua paths receive conditional proofs. Other Lua bytecodes retain
their existing differential-validation grade. A new input or code identity
is unknown until its VM entry state/path has been admitted.
"""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parent
BINARY = ROOT / "lua_interpreter_fixture"
MASK = (1 << 64) - 1


def signed(word):
    word &= MASK
    return word - (1 << 64) if word >> 63 else word


def output(bytecode, argument):
    return int(subprocess.check_output([str(BINARY), str(bytecode), str(argument)], text=True))


def classify(report, binary, bytecode, argument):
    if sha256(binary.read_bytes()).hexdigest() != report["identity"]["binary_sha256"] or \
            sha256(bytecode.read_bytes()).hexdigest() != report["identity"]["program_sha256"]:
        return {"status": "unknown", "reason": "code identity mismatch"}
    if not -(1 << 63) <= argument < 1 << 63:
        return {"status": "unknown", "reason": "outside signed 64-bit input domain"}
    if str(argument) not in report["admitted_input_witnesses"]:
        return {"status": "unknown", "reason": "VM entry state and path not admitted"}
    condition = "X == 0" if argument == 0 else "X != 0"
    predicted = 10 if argument == 0 else signed(argument + 5)
    return {"status": "proved_under_preconditions", "guard": condition,
            "predicted_signed_output": predicted}


def main():
    branch_file = ROOT / "lua_branch_call.luac"
    full_path = ROOT / "lua_branch_full_flow.json"
    full = json.loads(full_path.read_text())
    if full["binary_sha256"] != sha256(BINARY.read_bytes()).hexdigest() or \
            full["bytecode_sha256"] != sha256(branch_file.read_bytes()).hexdigest() or \
            len(full["paths"]) != 6 or not full["conditional_native_result_proved_under_assumptions"]:
        raise ValueError("branch full-flow proof is missing or stale")
    for path in full["paths"]:
        if path["vm_path"]["guard_equivalence"] != "unsat" or \
                path["vm_path"]["payload_equivalence"] != "unsat" or \
                path["vm_path"]["observed_address_guard_equivalence"] != "unsat":
            raise ValueError("unproved branch VM case")
    witnesses = [int(path["witness_input"]) for path in full["paths"]]
    report = {"schema_version": "portable-guarded-expression-v0",
              "semantic_model": {"integer_sort": "BV64", "overflow": "modulo 2^64",
                                 "output_interpretation": "signed64",
                                 "memory": "byte-addressed; ordered writes",
                                 "instruction_semantics": "Ghidra Low P-code"},
              "identity": {"binary_sha256": full["binary_sha256"],
                           "program_sha256": full["bytecode_sha256"],
                           "code_epoch": "saved static ELF and bytecode fixture"},
              "interface": {"input": {"name": "X", "sort": "BV64",
                                       "binding": "native function argument after successful integer parsing"},
                            "output": {"name": "result", "sort": "BV64",
                                        "binding": "second argument to output call"}},
              "cases": [
                  {"guard": {"op": "eq", "left": "X", "right": {"bv64": "0"}},
                   "result": {"bv64": "10"}, "validation_level": "proved_under_preconditions"},
                  {"guard": {"op": "ne", "left": "X", "right": {"bv64": "0"}},
                   "result": {"op": "bvadd", "bits": 64,
                              "args": ["X", {"bv64": "5"}]},
                   "validation_level": "proved_under_preconditions"}],
              "admitted_input_witnesses": [str(item) for item in witnesses],
              "preconditions": full["assumptions"],
              "evidence": {"full_flow_sha256": sha256(full_path.read_bytes()).hexdigest(),
                           "native_path_count": len(full["paths"])},
              "uncovered": ["other VM entry states or paths", "other code identity",
                            "invalid or overflowing text input", "exceptional exits",
                            "writes not covered by the recorded native memory audit"],
              "termination_claim": "partial"}
    checks = []
    for argument in witnesses:
        decision = classify(report, BINARY, branch_file, argument)
        actual = output(branch_file, argument)
        if decision["status"] != "proved_under_preconditions" or \
                actual != decision["predicted_signed_output"]:
            raise ValueError("conditional branch output differs from execution")
        checks.append({"input": str(argument), "predicted": decision["predicted_signed_output"],
                       "observed": actual, "grade": decision["status"]})

    alternate = ROOT / "lua_chunk_two_adds.luac"
    unknown_input = classify(report, BINARY, branch_file, 2)
    unknown_program = classify(report, BINARY, alternate, 9)
    if unknown_input["status"] != "unknown" or unknown_program["status"] != "unknown":
        raise ValueError("case classifier accepted unadmitted input or bytecode")

    transition_path = ROOT / "transition_summary_validation.json"
    composition_path = ROOT / "lua_composition_validation.json"
    transition = json.loads(transition_path.read_text())
    composition = json.loads(composition_path.read_text())
    other = []
    for name in ("lua_chunk.luac", "lua_chunk_plus11.luac"):
        bytecode = ROOT / name
        rows = [row for row in transition["lua"] if row["bytecode"] == name]
        if len(rows) != 8:
            raise ValueError(f"missing differential cases for {name}")
        for row in rows:
            if output(bytecode, row["input"]) != row["predicted_signed_payload"]:
                raise ValueError(f"stored transition summary failed for {name}")
        other.append({"program_sha256": sha256(bytecode.read_bytes()).hexdigest(),
                      "validation_level": "differentially_validated",
                      "sample_count": len(rows), "evidence_sha256": sha256(transition_path.read_bytes()).hexdigest()})
    if composition["bytecode_sha256"] != sha256(alternate.read_bytes()).hexdigest() or \
            len(composition["cases"]) != 6:
        raise ValueError("two-handler composition validation is stale")
    for row in composition["cases"]:
        if output(alternate, row["input"]) != signed(row["second_payload"]):
            raise ValueError("stored two-handler composition failed")
    other.append({"program_sha256": sha256(alternate.read_bytes()).hexdigest(),
                  "validation_level": "differentially_validated",
                  "sample_count": len(composition["cases"]),
                  "evidence_sha256": sha256(composition_path.read_bytes()).hexdigest()})
    report["verification"] = {"conditional_branch_checks": checks,
                              "other_lua_programs": other,
                              "unknown_input_query": unknown_input,
                              "unknown_program_query": unknown_program,
                              "executed_fixture_cases": len(checks) + sum(item["sample_count"] for item in other)}
    (ROOT / "lua_pre_python_js_port.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"conditional_branch_cases": len(checks),
                      "other_lua_cases": sum(item["sample_count"] for item in other),
                      "unknown_queries": 2}))


if __name__ == "__main__":
    main()
