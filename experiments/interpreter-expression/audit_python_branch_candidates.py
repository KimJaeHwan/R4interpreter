"""Separate SMT branch candidates from actual native alternate-edge evidence."""
from __future__ import annotations

from hashlib import sha256
import json

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86_const import X86_OP_IMM

from common_program_path_il import fingerprint, require
from probe_python_prefix_branches import RESULT as PREFIX, ZERO
from probe_python_remaining_scope import RESULT as NUMERIC, TRACES
from probe_unseen_python_path import PYTHON, ROOT
from prove_cross_full_flow import load_trace


RESULT = ROOT / "python_branch_candidate_audit_result.json"
STATUSES = {"target_opposite_observed", "earlier_divergence",
            "target_same_edge", "target_not_reached", "fixture_mismatch",
            "binary_mismatch", "trace_invalid", "solver_timeout",
            "unsupported_binding"}


def control_shape(row, libc_base):
    # Normalize the mapped libc code range across independent ASLR runs.
    def pc_key(pc):
        return ("libc", pc - libc_base) if libc_base <= pc < libc_base + 0x200000 else (
            "image", pc)
    return pc_key(row["pc"]), row["bytes"], pc_key(row["next_pc"])


def conditional_successors(row):
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    blob = bytes.fromhex(row["bytes"])
    decoded = list(decoder.disasm(blob, row["pc"]))
    if len(decoded) != 1 or decoded[0].size != len(blob):
        return None
    instruction = decoded[0]
    if (instruction.mnemonic not in {"ja", "jae", "jb", "jbe", "je", "jg",
                                     "jge", "jl", "jle", "jne", "jno", "jnp",
                                     "jns", "jo", "jp", "js"} or
            len(instruction.operands) != 1 or
            instruction.operands[0].type != X86_OP_IMM or
            f"{instruction.mnemonic} {instruction.op_str}" != row["instruction"]):
        return None
    return {row["pc"] + instruction.size, instruction.operands[0].imm}


def classify(source, actual, target_pc):
    targets = [index for index, row in enumerate(source)
               if row["pc"] == target_pc and
               conditional_successors(row) is not None]
    require(len(targets) == 1, "ambiguous candidate native occurrence")
    target = targets[0]
    def libc_base(rows):
        matches = [row["pc"] - 0x17C080 for row in rows
                   if row["bytes"] == "62e27d487ac6" and
                   row["instruction"].startswith("vpbroadcastb")]
        require(len(matches) <= 1, "ambiguous libc mapping in candidate trace")
        return matches[0] if matches else 0
    source_libc = libc_base(source)
    actual_libc = libc_base(actual)
    for index in range(target):
        if index >= len(actual):
            return "target_not_reached", index, None
        src, dst = source[index], actual[index]
        if control_shape(src, source_libc) != control_shape(dst, actual_libc):
            return "earlier_divergence", index, src["pc"]
    if target >= len(actual) or actual[target]["pc"] != target_pc:
        return "target_not_reached", target, None
    successors = conditional_successors(source[target])
    if (actual[target]["bytes"] != source[target]["bytes"] or
            conditional_successors(actual[target]) != successors):
        return "unsupported_binding", target, target_pc
    if (source[target]["next_pc"] not in successors or
            actual[target]["next_pc"] not in successors):
        return "trace_invalid", target, target_pc
    if actual[target]["next_pc"] != source[target]["next_pc"]:
        return "target_opposite_observed", target, target_pc
    return "target_same_edge", target, target_pc


def checked_case(source_path, source_value, target_path, target_value,
                 candidate, target_pc, guard_index, source_domain):
    source_meta, source, _ = load_trace(source_path, "python", source_value, PYTHON)
    target_meta, actual, _ = load_trace(target_path, "python", target_value, PYTHON)
    require(source_meta["marker"]["bytecode_sha256"] ==
            target_meta["marker"]["bytecode_sha256"],
            "candidate fixture bytecode mismatch")
    status, step, pc = classify(source, actual, target_pc)
    require(status in STATUSES, "unknown candidate status")
    return {"source_trace_sha256": sha256(source_path.read_bytes()).hexdigest(),
            "target_trace_sha256": sha256(target_path.read_bytes()).hexdigest(),
            "source_entry_registers_sha256":
                fingerprint(source_meta["entry_registers"]),
            "target_entry_registers_sha256":
                fingerprint(target_meta["entry_registers"]),
            "source_input": source_value, "candidate_input": candidate,
            "source_fixed_input_domain": source_domain,
            "source_pcode_guard_index": guard_index,
            "query": "opposite edge with only prior path guards",
            "target_native_pc": hex(target_pc),
            "first_relevant_step": step,
            "first_relevant_pc": hex(pc) if pc is not None else None,
            "status": status,
            "control_prefix_reproduced_until_target":
                status in ("target_opposite_observed", "target_same_edge"),
            "source_fixed_entry_environment_reproduced": False,
            "native_observation_closes_candidate":
                status == "target_opposite_observed"}


def main():
    prefix = json.loads(PREFIX.read_text())
    numeric = json.loads(NUMERIC.read_text())["branch"]
    p = prefix["candidate"]
    n = numeric["first_feasible_alternate"]
    require(p["witness"] == 0 and p["opposite"] == "sat" and
            n["witness"] == 251 and n["opposite"] == "sat",
            "stored SMT candidates changed")
    cases = [checked_case(TRACES[252], 252, ZERO, 0, 0,
                          int(p["pc"], 16), p["guard_index"], [0, 256]),
             checked_case(TRACES[252], 252, TRACES[251], 251, 251,
                          int(n["pc"], 16), n["guard_index"], [251, 256])]
    require(cases[0]["status"] == "earlier_divergence" and
            cases[0]["first_relevant_step"] == 133 and
            cases[1]["status"] == "target_opposite_observed" and
            cases[1]["first_relevant_step"] == 764,
            "candidate execution classification changed")
    _, source, _ = load_trace(TRACES[252], "python", 252, PYTHON)
    require(classify(source, source[:700], int(n["pc"], 16))[0] ==
            "target_not_reached", "truncated candidate was accepted")
    _, alternate, _ = load_trace(TRACES[251], "python", 251, PYTHON)
    changed = [dict(row) for row in alternate]
    changed[764] = {**changed[764], "next_pc": 0xDEADBEEF}
    require(classify(source, changed, int(n["pc"], 16))[0] ==
            "trace_invalid", "non-successor candidate edge was accepted")
    changed[764] = {**alternate[764], "bytes": "90"}
    require(classify(source, changed, int(n["pc"], 16))[0] ==
            "unsupported_binding", "different target instruction was accepted")
    prefix_case = next(item for item in cases if item["candidate_input"] == 0)
    require(not prefix_case["native_observation_closes_candidate"],
            "earlier diverging trace closed target edge")
    report = {"schema_version": "python-branch-candidate-audit-v1",
              "binary_sha256": sha256(PYTHON.read_bytes()).hexdigest(),
              "source_smt_environment": "source252 fixed other state and prefix guards",
              "candidate_status_vocabulary": sorted(STATUSES),
              "negative_controls": {
                  "truncated_trace": "target_not_reached",
                  "earlier_divergence": "not_a_target_edge_witness",
                  "non_successor_target": "trace_invalid",
                  "different_target_instruction": "unsupported_binding"},
              "cases": cases,
              "scope": "two saved candidates; full scalar native control/bytes prefix compared with libc ASLR normalization, independent entry states",
              "complete_route_set": False}
    RESULT.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"candidate_statuses": [c["status"] for c in cases]}))


if __name__ == "__main__":
    main()
