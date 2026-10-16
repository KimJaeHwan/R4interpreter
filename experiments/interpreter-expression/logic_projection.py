"""Project a conditional P-code path onto live symbolic inputs and effects.

The path supplies SMT expressions, reads, ordered writes and register outputs.
An adapter supplies an entry state and the concrete read footprint of one
observed path.  This module has no instruction or language opcode rules.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json

import z3
from z3.z3util import get_vars


MASK64 = (1 << 64) - 1


class ProjectionUnknown(ValueError):
    pass


def reduced(expr):
    return z3.simplify(expr, som=True, pull_cheap_ite=True)


def concrete_address(expr, label):
    expr = reduced(expr)
    if not z3.is_bv_value(expr):
        raise ProjectionUnknown(f"{label} depends on a symbolic address: {expr}")
    return expr.as_long()


def bit(value, width):
    return z3.BitVecVal(value, width)


def byte_value(value, index):
    return reduced(z3.Extract(index * 8 + 7, index * 8, value))


def require_inputs(expr, allowed_names):
    unexpected = sorted({var.decl().name() for var in get_vars(expr)
                         if var.decl().name() not in allowed_names})
    if unexpected:
        raise ProjectionUnknown(f"unmodeled symbolic inputs: {', '.join(unexpected)}")


@dataclass
class SymbolicState:
    registers: dict[str, z3.ExprRef]
    flags: dict[int, z3.ExprRef]
    memory: dict[int, z3.ExprRef]

    def read(self, address, width):
        if any(address + index not in self.memory for index in range(width)):
            raise ProjectionUnknown(f"missing projected memory at {address:#x}/{width}")
        parts = [self.memory[address + index] for index in range(width)]
        return reduced(parts[0] if width == 1 else z3.Concat(*reversed(parts)))

    def write(self, address, value, width):
        for index in range(width):
            self.memory[address + index] = byte_value(value, index)


def project_path(path, state, read_addresses, concrete_effects, register_names,
                 flag_names, allowed_input_names=None):
    """Apply one frozen path; refuse missing bytes or symbolic write addresses.

    ``read_addresses`` and ``concrete_effects`` come from a concrete witness
    on the same path. The projected address expressions must themselves reduce
    to these addresses, so the witness cannot silently specialize an alias.
    """
    if len(read_addresses) != len(path.reads) or len(concrete_effects) != len(path.effects):
        raise ProjectionUnknown("path footprint differs from frozen summary")
    unknown = z3.Array(f"UNBOUND_{path.record['id']}", z3.BitVecSort(64), z3.BitVecSort(8))
    memory = unknown
    for address, width in read_addresses:
        for index in range(width):
            byte_address = (address + index) & MASK64
            if byte_address not in state.memory:
                raise ProjectionUnknown(f"missing entry read at {byte_address:#x}")
            memory = z3.Store(memory, bit(byte_address, 64), state.memory[byte_address])
    bindings = [(path.decls[f"R_{name.upper()}"], value)
                for name, value in state.registers.items()
                if f"R_{name.upper()}" in path.decls]
    bindings.extend((path.decls[f"F_{offset}"], value)
                    for offset, value in state.flags.items()
                    if f"F_{offset}" in path.decls)
    if "W" in path.decls:
        bindings.append((path.decls["W"], reduced(z3.Extract(31, 0, state.registers["r12"]))))
    bindings.append((path.decls["M0"], memory))

    def substitute(expr, live=False):
        result = reduced(z3.substitute(expr, *bindings))
        if any(var.eq(unknown) for var in get_vars(result)):
            raise ProjectionUnknown("effect or guard depends on uncaptured memory")
        if live and allowed_input_names is not None:
            require_inputs(result, allowed_input_names)
        return result

    guards = []
    for (original_address, width), (witness_address, witness_width) in zip(path.reads, read_addresses):
        if width != witness_width or concrete_address(substitute(original_address, live=True), "read") != witness_address:
            raise ProjectionUnknown("symbolic read address differs from witness")
    for guard in path.guards:
        value = substitute(guard, live=True)
        if not z3.is_true(value):
            guards.append(value)
    effects = []
    for (address_expr, value_expr, width), (witness_address, _, witness_width) in zip(
            path.effects, concrete_effects):
        address = concrete_address(substitute(address_expr, live=True), "write")
        if address != witness_address or width != witness_width:
            raise ProjectionUnknown("symbolic write address differs from witness")
        effects.append((address, substitute(value_expr, live=True), width))
    next_registers = {register_names[offset]: substitute(expr)
                      for offset, expr in path.registers.items()}
    next_flags = {flag_names[offset]: substitute(expr) for offset, expr in path.flags.items()}
    for address, value, width in effects:
        state.write(address, value, width)
    state.registers.update(next_registers)
    state.flags.update(next_flags)
    return guards, effects


def compact_expression(expr, input_name="X"):
    """A readable BV64 view; SMT is kept alongside it as the exact meaning."""
    if expr.decl().kind() != z3.Z3_OP_BXOR:
        expr = reduced(expr)
    if z3.is_bv_value(expr):
        value = expr.as_long()
        return str(value - (1 << expr.size()) if value >> (expr.size() - 1) else value)
    if z3.is_const(expr):
        return input_name if expr.decl().name() == input_name else str(expr)
    kind = expr.decl().kind()
    if kind in (z3.Z3_OP_BADD, z3.Z3_OP_BSUB, z3.Z3_OP_BXOR) and expr.num_args() == 2:
        left, right = expr.children()
        if kind in (z3.Z3_OP_BADD, z3.Z3_OP_BXOR) and z3.is_bv_value(left):
            left, right = right, left
        op = {z3.Z3_OP_BADD: "+", z3.Z3_OP_BSUB: "-", z3.Z3_OP_BXOR: "^"}[kind]
        if kind == z3.Z3_OP_BADD and z3.is_bv_value(right):
            number = right.as_long()
            if number >> (right.size() - 1):
                number -= 1 << right.size()
            return (f"{compact_expression(left, input_name)} + {number}" if number >= 0
                    else f"{compact_expression(left, input_name)} - {-number}")
        return f"{compact_expression(left, input_name)} {op} {compact_expression(right, input_name)}"
    if kind == z3.Z3_OP_ITE:
        cond, yes, no = expr.children()
        return (f"({compact_expression(yes, input_name)} if {cond} else "
                f"{compact_expression(no, input_name)})")
    return str(expr)


def compact_guard(expr, input_symbol):
    expr = reduced(expr)
    if z3.is_true(expr):
        return "true"
    if z3.is_false(expr):
        return "false"
    if z3.is_not(expr):
        inner = expr.arg(0)
        if z3.is_eq(inner) and (inner.arg(0).eq(input_symbol) or inner.arg(1).eq(input_symbol)):
            other = inner.arg(1) if inner.arg(0).eq(input_symbol) else inner.arg(0)
            return f"{input_symbol} != {compact_expression(other)}"
    if z3.is_eq(expr) and (expr.arg(0).eq(input_symbol) or expr.arg(1).eq(input_symbol)):
        other = expr.arg(1) if expr.arg(0).eq(input_symbol) else expr.arg(0)
        return f"{input_symbol} == {compact_expression(other)}"
    return str(expr)


def prove_equal(left, right, timeout_ms=2000):
    solver = z3.Solver()
    solver.set(timeout=timeout_ms)
    solver.add(left != right)
    return solver.check() == z3.unsat


def reduce_input_value(expr, input_symbol):
    """Prove a short input formula equivalent to an extracted BV expression."""
    expr = reduced(expr)
    if expr.size() != input_symbol.size() or not any(
            var.eq(input_symbol) for var in get_vars(expr)):
        return expr, False
    at_zero = reduced(z3.substitute(expr, (input_symbol, bit(0, input_symbol.size()))))
    if not z3.is_bv_value(at_zero):
        return expr, False
    constant = at_zero.as_long()
    candidates = [input_symbol + bit(constant, input_symbol.size()),
                  input_symbol ^ bit(constant, input_symbol.size())]
    for candidate in candidates:
        if prove_equal(expr, candidate):
            return candidate, True
    return expr, False


def reduce_input_guard(guard, input_symbol, witness):
    """Prove common one-input predicates without assuming path completeness."""
    guard = reduced(guard)
    candidates = [input_symbol == bit(0, input_symbol.size()),
                  input_symbol != bit(0, input_symbol.size()),
                  input_symbol == bit(witness, input_symbol.size()),
                  input_symbol != bit(witness, input_symbol.size())]
    for candidate in candidates:
        if prove_equal(guard, candidate):
            return reduced(candidate), True
    return guard, False


class SerializedCasePath:
    """Adapt a transition-summary-v0 case to the shared path projector."""

    def __init__(self, summary, register_names, flag_names):
        from apply_transition_summary import declarations, expression

        self.decls = declarations(summary)
        case = summary["case"]
        digest = sha256(json.dumps(summary, sort_keys=True).encode()).hexdigest()[:16]
        self.record = {"id": digest}
        self.guards = [expression(source, "Bool", self.decls)
                       for source in case["path_guard"]]
        self.reads = [(expression(item["address"], "BV64", self.decls), item["width"])
                      for item in case["reads"]]
        self.effects = [(expression(item["address"], "BV64", self.decls),
                         expression(item["value"], f"BV{item['width'] * 8}", self.decls),
                         item["width"]) for item in case["ordered_effects"]]
        names = {name: offset for offset, name in register_names.items()}
        bits = {bit_index: offset for offset, bit_index in flag_names.items()}
        self.registers = {}
        self.flags = {}
        for item in case["outputs"]:
            name = item["name"]
            if name.startswith("R_") and name[2:].lower() in names:
                self.registers[names[name[2:].lower()]] = expression(
                    item["expression"], item["sort"], self.decls)
            elif name.startswith("F_") and int(name[2:]) in bits:
                self.flags[bits[int(name[2:])]] = expression(
                    item["expression"], item["sort"], self.decls)
