"""Evaluate one frozen x86-64 P-code segment for any interpreter adapter.

Adapters choose cutpoints, seed entry registers/flags and first-read memory,
and choose a segment sequence. The core applies guards, complete scalar state,
native read values, ordered writes and successors without opcode semantics.
"""
from __future__ import annotations

from hashlib import sha256
import json

import z3

from apply_transition_summary import declarations, expression
from pcode_transition_summary import FLAG_OFFSETS, REGISTER_OFFSETS


MASK64 = (1 << 64) - 1


def number(term):
    value = z3.simplify(term)
    if not z3.is_bv_value(value):
        raise ValueError("frozen expression depends on an unbound input")
    return value.as_long()


def path_shape(rows, mode):
    if mode == "pc_bytes_next":
        data = [[hex(row["pc"]), row["bytes"], hex(row["next_pc"])]
                for row in rows]
    elif mode == "pc_next":
        data = [[row["pc"], row["next_pc"]] for row in rows]
    else:
        raise ValueError("unsupported native path identity mode")
    return sha256(json.dumps(data, separators=(",", ":")).encode()).hexdigest()


def parse_segments(summary, expected_labels):
    decls = declarations(summary)
    parsed = {}
    for segment in summary["segments"]:
        label = segment["label"]
        if label in parsed:
            raise ValueError("duplicate segment label")
        parsed[label] = {
            "guard": expression(segment["guard"], "Bool", decls),
            "outputs": [(item["name"], expression(item["expression"],
                                                   item["sort"], decls))
                        for item in segment["outputs"]],
            "reads": [(item, expression(item["address"], "BV64", decls),
                       expression(item["value"], f"BV{item['width'] * 8}", decls))
                      for item in segment["reads"]],
            "effects": [(item, expression(item["address"], "BV64", decls),
                         expression(item["value"], f"BV{item['width'] * 8}", decls))
                        for item in segment["effects"]],
            "successor": expression(segment["successor"], "BV64", decls),
            "identity": segment["identity"],
            "evidence": segment["evidence"]}
    if set(parsed) != set(expected_labels):
        raise ValueError("frozen segment roles changed")
    return decls, parsed


def evaluate(ast, bindings):
    return number(z3.substitute(ast, *bindings))


def input_bindings(summary, decls, state, flags, memory):
    bindings = []
    for item in summary["interface"]["inputs"]:
        name = item["name"]
        if name == "M0":
            value = memory
        elif name.startswith("R_") and name[2:].lower() in state:
            value = z3.BitVecVal(state[name[2:].lower()], 64)
        elif name.startswith("F_") and int(name[2:]) in flags:
            value = z3.BitVecVal(flags[int(name[2:])], 8)
        elif item.get("binding", {}).get("kind") == "register_slice":
            binding = item["binding"]
            value = z3.BitVecVal((state[binding["name"]] >> binding["low_bit"])
                                 & ((1 << binding["width"]) - 1), binding["width"])
        else:
            raise ValueError(f"unsupported segment input {name}")
        bindings.append((decls[name], value))
    return bindings


def apply_segment(label, segment, rows, summary, decls, state, flags, memory):
    identity = segment["identity"]
    if (not rows or len(rows) != identity["native_steps"] or
            any(left["next_pc"] != right["pc"] for left, right
                in zip(rows, rows[1:])) or
            hex(rows[0]["pc"]) != identity["entry_pc"] or
            hex(rows[-1]["next_pc"]) != identity["next_pc"] or
            path_shape(rows, identity.get("path_shape_mode", "pc_bytes_next")) !=
            identity["path_shape_sha256"]):
        return None, f"unknown({label} path shape)"
    observed_entry = rows[0]["registers"]
    if (any(state[name] != observed_entry[name]
            for name in REGISTER_OFFSETS.values()) or
            any(flags[bit] != ((observed_entry["eflags"] >> bit) & 1)
                for bit in FLAG_OFFSETS.values())):
        return None, f"unknown({label} entry state)"
    for left, right in zip(rows, rows[1:]):
        if (any(left["registers_after"][name] != right["registers"][name]
                for name in REGISTER_OFFSETS.values()) or
                any(((left["registers_after"]["eflags"] >> bit) & 1) !=
                    ((right["registers"]["eflags"] >> bit) & 1)
                    for bit in FLAG_OFFSETS.values())):
            return None, f"unknown({label} trace state continuity)"
    bindings = input_bindings(summary, decls, state, flags, memory)
    if not z3.is_true(z3.simplify(z3.substitute(segment["guard"], *bindings))):
        return None, f"unknown({label} guard)"
    reads = []
    for item, address_ast, value_ast in segment["reads"]:
        address, value = evaluate(address_ast, bindings), evaluate(value_ast, bindings)
        key = (item["pc"], address, item["width"])
        if key not in [(r["pc"], r["address"], r["width"]) for r in reads]:
            reads.append({"pc": item["pc"], "address": address,
                          "width": item["width"], "value": value})
    actual_reads = [{"pc": hex(row["pc"]), "address": access["address"],
                     "width": access["size"], "value": access["before"]}
                    for row in rows for access in row["memory"] if access["access"] & 1]
    if reads != actual_reads:
        return None, f"unknown({label} read footprint/value)"
    effects = []
    for item, address_ast, value_ast in segment["effects"]:
        if item["kind"] != "Write":
            return None, f"unknown({label} effect kind)"
        effects.append({"pc": item["pc"], "address": evaluate(address_ast, bindings),
                        "width": item["width"], "value": evaluate(value_ast, bindings)})
    actual_effects = [{"pc": hex(row["pc"]), "address": access["address"],
                       "width": access["size"], "value": access["after"]}
                      for row in rows for access in row["memory"] if access["access"] & 2]
    if effects != actual_effects:
        return None, f"unknown({label} ordered effects)"
    outputs = {name: evaluate(ast, bindings) for name, ast in segment["outputs"]}
    expected_names = ({f"R_{name.upper()}" for name in REGISTER_OFFSETS.values()} |
                      {f"F_{bit}" for bit in FLAG_OFFSETS.values()})
    if set(outputs) != expected_names:
        return None, f"unknown({label} incomplete state)"
    next_state = {name: outputs[f"R_{name.upper()}"]
                  for name in REGISTER_OFFSETS.values()}
    next_flags = {bit: outputs[f"F_{bit}"] for bit in FLAG_OFFSETS.values()}
    observed = rows[-1]["registers_after"]
    if (any(next_state[name] != observed[name] for name in next_state) or
            any(next_flags[bit] != ((observed["eflags"] >> bit) & 1)
                for bit in next_flags)):
        return None, f"unknown({label} state)"
    if evaluate(segment["successor"], bindings) != rows[-1]["next_pc"]:
        return None, f"unknown({label} successor)"
    next_memory = memory
    for item in effects:
        for index in range(item["width"]):
            next_memory = z3.Store(next_memory,
                z3.BitVecVal((item["address"] + index) & MASK64, 64),
                z3.BitVecVal((item["value"] >> (8 * index)) & 255, 8))
    return (next_state, next_flags, next_memory,
            {"label": label, "native_steps": len(rows),
             "reads_checked": len(reads), "ordered_writes_checked": len(effects),
             "outputs_checked": len(outputs), "predicted_effects": effects}), None
