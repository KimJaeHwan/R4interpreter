"""Resolve a supported instruction-local P-code branch on an observed path.

The native trace is used only to choose a conditional instruction path. The
chosen CMOV guard is retained as an obligation, and other internal flows stay
unknown. This module never treats a trace choice as all-input completeness.
"""
import z3

from prove_cross_full_flow import NativePathReplay
from prove_lua_full_flow import initial_memory
from prove_cross_value_path import varnode
from pcode_transition_summary import FLAG_OFFSETS, REGISTER_OFFSETS


def concrete_cmov_prefix(row, operations):
    serialized = [{"opcode": op.opcode.name,
        "inputs": [varnode(node) for node in op.inputs],
        "output": varnode(op.output) if op.output is not None else None,
        "output_present": op.output is not None} for op in operations]
    memory, _ = initial_memory([row])
    model = NativePathReplay(row, [row], {row["pc"]: {"operations": serialized}},
        register_symbols={offset: z3.BitVecVal(row["registers"][name], 64)
                          for offset, name in REGISTER_OFFSETS.items()},
        flag_symbols={offset: z3.BitVec(f"F_{bit}", 8)
                      for offset, bit in FLAG_OFFSETS.items()},
        memory_symbol=memory, address_guards=True)
    model.run()
    if row["next_pc"] != row["pc"] + len(row["bytes"]) // 2:
        raise ValueError("CMOV did not fall through to the next native instruction")
    after = row["registers_after"]
    if (any(model.regs_concrete[offset] != after[name]
            for offset, name in REGISTER_OFFSETS.items()) or
            any(model.flags_concrete[offset] != ((after["eflags"] >> bit) & 1)
                for offset, bit in FLAG_OFFSETS.items())):
        raise ValueError("CMOV complete scalar exit state differs from observation")
    branches = [item for item in model.guards if item["kind"] == "CBRANCH"]
    if len(branches) != 1 or not 0 < model.operation_count <= len(operations):
        raise ValueError("CMOV P-code local branch is unsupported")
    guard = branches[0]["condition"]
    solver = z3.Solver()
    solver.set(timeout=5000)
    solver.add(*[z3.BitVec(f"F_{bit}", 8) ==
                 z3.BitVecVal((row["registers"]["eflags"] >> bit) & 1, 8)
                 for bit in FLAG_OFFSETS.values()])
    solver.add(z3.Not(guard))
    if solver.check() != z3.unsat:
        raise ValueError("CMOV guard disagrees with observed native flags")
    return list(range(model.operation_count)), {
        "kind": "cmov_observed_guard",
        "pc": hex(row["pc"]),
        "executed_pcode_operations": model.operation_count,
        "lifted_pcode_operations": len(operations),
        "guard_smt2": z3.simplify(guard).sexpr(),
        "observed_flags_imply_guard": "unsat"}


def schedule(row, operations):
    internal = [index for index, op in enumerate(operations)
                if op.opcode.name == "CBRANCH" and index + 1 < len(operations)]
    if not internal:
        return list(range(len(operations))), None, None
    if len(internal) == 1 and row["instruction"].startswith("cmov"):
        try:
            selected, evidence = concrete_cmov_prefix(row, operations)
            return selected, evidence, None
        except (AssertionError, ValueError, KeyError, z3.Z3Exception) as error:
            return list(range(len(operations))), None, (
                f"unsupported CMOV local path: {error}")
    return list(range(len(operations))), None, (
        "unsupported instruction-local P-code control")
