"""Read-only probe of TDO v2 SSA as a source for small value expressions.

The script imports daasdmlkas's synthetic P-code builder and normalizer.
It writes its JSON report beside this script.
"""

from __future__ import annotations

import json
from pathlib import Path

import z3

from synthetic import (
    CONST,
    REG,
    RAX,
    RDI,
    FunctionBuilder,
    add,
    const,
    normalize_with_observation,
    op,
    reg,
    sub,
    tmp,
)
from pcode_interpreter import Interpreter
from tdo_v2._scope_contracts import VarnodeKindCode
from tdo_v2.call_seeds import _operation_key
from tdo_v2.memory_contracts import MemoryDefinitionKind
from tdo_v2.query import BackwardSliceQuery
from tdo_v2.span_geometry import StorageObjectKind


class UnknownExpression(Exception):
    pass


def project(function, observation, instruction_index: int, *, ordinal: int = 0,
            width: int = 1):
    """Project a JOIN-free result definition using TDO's SSA read fragments."""
    ssa = function.memory_ssa
    result_key = _operation_key(
        observation.instructions[instruction_index].address,
        ordinal,
        observation.instructions[instruction_index].operations[ordinal].opcode,
    )
    actions = {row.operation_key: (index, row) for index, row in enumerate(ssa.actions)}
    if result_key not in actions:
        raise UnknownExpression("sink operation has no SSA action")
    result_action_index, result_action = actions[result_key]
    seed = function.memory_graph.action_nodes[result_action_index]
    sliced = BackwardSliceQuery().run(function, seed)
    if sliced.reachable_unresolved_read_nodes:
        raise UnknownExpression("backward slice contains unresolved reads")
    permitted_nodes = set(sliced.reachable_nodes)
    operations = {
        _operation_key(instruction.address, ordinal, operation.opcode): operation
        for instruction in observation.instructions
        for ordinal, operation in enumerate(instruction.operations)
    }
    if len(result_action.write_definition_ids) != 1:
        raise UnknownExpression("sink has no unique SSA definition")
    result_definition = result_action.write_definition_ids[0]
    reads_by_action = {}
    for row in ssa.reads:
        reads_by_action.setdefault(row.action_id, []).append(row)
    evidence = set()
    read_evidence = set()
    active = set()
    source = z3.BitVec("x", width * 8)

    def definition_expression(definition_id: int):
        if definition_id in active:
            raise UnknownExpression("cyclic definition")
        definition = ssa.definitions[definition_id]
        if definition.kind is MemoryDefinitionKind.ENTRY:
            if (definition.span.start != RDI or definition.span.size != width
                    or definition.span.object_id.kind is not StorageObjectKind.REGISTER_FILE):
                raise UnknownExpression("an entry value other than x is required")
            return source
        if definition.kind is not MemoryDefinitionKind.DATA_WRITE:
            raise UnknownExpression(f"unsupported definition: {definition.kind}")
        key = definition.operation_key
        if key is None or key not in actions:
            raise UnknownExpression("write has no P-code action")
        action_index, _ = actions[key]
        if ssa.actions[action_index].write_definition_ids != (definition_id,):
            raise UnknownExpression("write has multiple SSA definitions")
        if function.memory_graph.action_nodes[action_index] not in permitted_nodes:
            raise UnknownExpression("write is outside the backward slice")
        operation = operations[key]
        if operation.output is None or operation.output.byte_size != definition.span.size:
            raise UnknownExpression("write width does not match P-code output")
        active.add(definition_id)
        try:
            reads = sorted(reads_by_action.get(action_index, ()), key=lambda row: row.read_ordinal)
            used_read = 0
            inputs = []
            for operand in operation.inputs:
                operand_width = operand.byte_size * 8
                if operand.kind is VarnodeKindCode.CONSTANT:
                    inputs.append(z3.BitVecVal(operand.coordinate.byte_offset, operand_width))
                    continue
                if used_read >= len(reads):
                    raise UnknownExpression("missing SSA read fragment")
                read = reads[used_read]
                used_read += 1
                if read.span.start != operand.coordinate.byte_offset or read.span.size != operand.byte_size:
                    raise UnknownExpression("operand/read order is ambiguous")
                if len(read.fragments) != 1 or read.fragments[0].span != read.span:
                    raise UnknownExpression("fragmented read is unsupported")
                (source_definition,) = read.fragments[0].definition_ids
                read_evidence.add((key, read.read_ordinal, source_definition))
                inputs.append(definition_expression(source_definition))
            if used_read != len(reads):
                raise UnknownExpression("unmatched SSA read")
            if operation.opcode == "INT_ADD" and len(inputs) == 2:
                result = inputs[0] + inputs[1]
            elif operation.opcode == "INT_SUB" and len(inputs) == 2:
                result = inputs[0] - inputs[1]
            elif operation.opcode == "COPY" and len(inputs) == 1:
                result = inputs[0]
            else:
                raise UnknownExpression(f"unsupported P-code operation: {operation.opcode}")
            if result.size() != definition.span.size * 8:
                raise UnknownExpression("expression width does not match definition")
            evidence.add(key)
            return result
        finally:
            active.remove(definition_id)

    expression = definition_expression(result_definition)
    return expression, source, {
        "sink_definition": result_definition,
        "slice_nodes": len(sliced.reachable_nodes),
        "slice_inputs": len(sliced.observed_input_nodes),
        "slice_debts": len(sliced.reachable_unresolved_read_nodes),
        "operations": sorted(evidence),
        "ssa_reads": sorted(read_evidence),
    }


def oracle_values(observation):
    values = []
    for value in range(256):
        machine = Interpreter(observation, constant_space=CONST, seed=41)
        machine.preset(REG, RDI, 1, value)
        run = machine.run()
        if not run.completed:
            raise AssertionError(f"oracle did not complete for x={value}")
        values.append(machine.final_bytes()[(REG, RAX)][0])
    return values


def compare_candidate(candidate, source, expected_values):
    return [
        value
        for value in range(256)
        if z3.simplify(z3.substitute(candidate, (source, z3.BitVecVal(value, 8)))).as_long()
        != expected_values[value]
    ]


def run_case(name, builder, sink_instruction_index, expected, mutation):
    function, observation = normalize_with_observation(builder)
    expression, source, evidence = project(function, observation, sink_instruction_index)
    solver = z3.Solver()
    solver.add(expression != expected(source))
    equivalence = str(solver.check())
    observed = oracle_values(observation)
    mismatches = compare_candidate(expression, source, observed)
    mutation_mismatches = compare_candidate(mutation(source), source, observed)
    free_variables = sorted(str(item) for item in z3.z3util.get_vars(expression))
    if equivalence != "unsat" or mismatches or not mutation_mismatches:
        raise AssertionError((name, equivalence, mismatches[:5], mutation_mismatches[:5]))
    if free_variables != ["x"]:
        raise AssertionError((name, "unexpected free variables", free_variables))
    return {
        "name": name,
        "expression": str(expression),
        "equivalence_to_fixture_spec": equivalence,
        "oracle_inputs_checked": len(observed),
        "oracle_mismatches": len(mismatches),
        "mutated_expression_mismatches": len(mutation_mismatches),
        "free_variables": free_variables,
        "guard": "true",
        "scope": "finite-domain-checked (all 256 x values)",
        "evidence": evidence,
    }


def main():
    results = [
        run_case(
            "x_plus_7",
            FunctionBuilder().ins(add(reg(RAX, 1), reg(RDI, 1), const(7, 1))).ret(),
            0,
            lambda x: x + z3.BitVecVal(7, 8),
            lambda x: x + z3.BitVecVal(8, 8),
        ),
        run_case(
            "seven_minus_x",
            FunctionBuilder().ins(sub(reg(RAX, 1), const(7, 1), reg(RDI, 1))).ret(),
            0,
            lambda x: z3.BitVecVal(7, 8) - x,
            lambda x: x - z3.BitVecVal(7, 8),
        ),
        run_case(
            "two_operation_chain",
            FunctionBuilder()
            .ins(add(tmp(0x100, 1), reg(RDI, 1), const(7, 1)))
            .ins(sub(reg(RAX, 1), tmp(0x100, 1), const(3, 1)))
            .ret(),
            1,
            lambda x: (x + z3.BitVecVal(7, 8)) - z3.BitVecVal(3, 8),
            lambda x: (x + z3.BitVecVal(7, 8)) + z3.BitVecVal(3, 8),
        ),
    ]
    plus_oracle = oracle_values(normalize_with_observation(
        FunctionBuilder().ins(add(reg(RAX, 1), reg(RDI, 1), const(7, 1))).ret()
    )[1])
    missing_truncation_mismatches = [x for x in range(256) if x + 7 != plus_oracle[x]]
    if not missing_truncation_mismatches:
        raise AssertionError("a missing 8-bit truncation went undetected")
    results[0]["missing_truncation_mismatches"] = len(missing_truncation_mismatches)
    unsupported = FunctionBuilder().ins(
        op("INT_XOR", [reg(RDI, 1), const(7, 1)], reg(RAX, 1))
    ).ret()
    function, observation = normalize_with_observation(unsupported)
    try:
        project(function, observation, 0)
    except UnknownExpression as error:
        results.append({"name": "unsupported_xor", "result": "unknown", "reason": str(error)})
    else:
        raise AssertionError("unsupported operation was reported as a complete expression")
    destination = Path(__file__).with_name("expression_probe_result.json")
    destination.write_text(json.dumps(results, indent=2, ensure_ascii=False) + "\n")
    for row in results:
        print(row["name"], row.get("expression", row.get("result")), row.get("oracle_mismatches", ""))
    print("report", destination)


if __name__ == "__main__":
    main()
