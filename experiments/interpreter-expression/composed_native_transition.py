"""Evaluate one frozen x86-64 P-code segment for any interpreter adapter.

Adapters choose cutpoints, seed entry registers/flags and first-read memory,
and choose a segment sequence. The core applies guards, complete scalar state,
native read values, ordered writes and successors without opcode semantics.
"""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json

import z3
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86_const import X86_REG_FS, X86_REG_GS

from apply_transition_summary import declarations, expression
from common_lifetime_effects import apply_effect, get_resource, LifetimeError
from pcode_transition_summary import FLAG_OFFSETS, REGISTER_OFFSETS


MASK64 = (1 << 64) - 1
BASE_FRAME_MNEMONICS = {
    "add", "and", "call", "cmovs", "cmp", "endbr64", "imul", "ja", "jbe",
    "je", "jle", "jmp", "jne", "jns", "js", "lea", "mov", "movsxd", "movzx",
    "cdqe", "neg", "or", "pop", "push", "ret", "sar", "shl", "shr", "sub", "test", "xor"}


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
        if any(item.get("kind") != "Write" or not
               {"pc", "width", "address", "value"} <= item.keys()
               for item in segment["effects"]):
            raise ValueError("unsupported native effect schema")
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
            "preserved_state": segment.get("preserved_state", {}),
            "logical_effect": deepcopy(segment.get("logical_effect")),
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
        elif item.get("binding", {}).get("kind") == "segment_base":
            value = z3.BitVecVal(state[item["binding"]["name"]], 64)
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
    base_inputs = {item["binding"]["name"] for item in summary["interface"]["inputs"]
                   if item.get("binding", {}).get("kind") == "segment_base"}
    frame = segment.get("preserved_state", {})
    if set(frame) != base_inputs or any(
            name not in {"fs_base", "gs_base"} or
            rule != "x86_scalar_no_base_write_v1" for name, rule in frame.items()):
        return None, f"unknown({label} segment base frame contract)"
    if frame:
        decoder = Cs(CS_ARCH_X86, CS_MODE_64)
        decoder.detail = True
        for row in rows:
            decoded = list(decoder.disasm(bytes.fromhex(row["bytes"]), row["pc"]))
            if (len(decoded) != 1 or decoded[0].size * 2 != len(row["bytes"]) or
                    decoded[0].mnemonic not in BASE_FRAME_MNEMONICS or
                    {X86_REG_FS, X86_REG_GS}.intersection(decoded[0].regs_access()[1])):
                return None, f"unknown({label} unsupported base preservation)"
            if any(name not in state or
                   row["registers"].get(name) != state[name] or
                   row["registers_after"].get(name) != state[name] for name in frame):
                return None, f"unknown({label} segment base changed)"
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
    next_state = {name: state[name] for name in frame}
    next_state.update({name: outputs[f"R_{name.upper()}"]
                       for name in REGISTER_OFFSETS.values()})
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


def apply_composed_segment(label, segment, rows, summary, decls, state, flags,
                           memory, lifetime_state, effect_evidence,
                           validated_summary_sha256, validated_proof_sha256):
    """Atomically compose a native segment and one frozen logical lifetime effect."""
    specification = segment.get("logical_effect")
    frozen = [item.get("logical_effect") for item in summary["segments"]
              if item.get("label") == label]
    if (len(frozen) != 1 or specification != frozen[0] or
            not isinstance(specification, dict) or
            specification.get("schema_version") != "common-lifetime-effect-v1" or
            specification.get("kind") not in ("Allocate", "Free") or
            specification.get("cutpoint") != "helper_return" or
            specification.get("required_native_label") != label or
            specification.get("required_return") != {"register": "rax", "value": 1} or
            not isinstance(specification.get("resource_binding"), dict) or
            specification["resource_binding"].get("kind") != "register_index" or
            specification["resource_binding"].get("register") not in state or
            not isinstance(specification["resource_binding"].get("prefix"), str) or
            not isinstance(specification.get("requested_extent"), int) or
            not rows or not rows[-1]["instruction"].startswith("ret") or
            not isinstance(effect_evidence, dict) or
            effect_evidence.get("native_summary_sha256") != validated_summary_sha256 or
            effect_evidence.get("native_refinement_sha256") != validated_proof_sha256):
        return None, f"unknown({label} lifetime effect contract)"
    native, reason = apply_segment(label, segment, rows, summary, decls,
                                   state, flags, memory)
    if reason:
        return None, reason
    next_state, next_flags, next_memory, native_evidence = native
    if next_state["rax"] != 1:
        return None, f"unknown({label} required native return)"
    binding = specification["resource_binding"]
    resource_id = binding["prefix"] + str(state[binding["register"]])
    try:
        resource = get_resource(lifetime_state, specification["domain_id"],
                                resource_id)
        request = {"kind": specification["kind"],
                   "address_space_id": specification["address_space_id"],
                   "domain_id": specification["domain_id"],
                   "resource_id": resource_id, "address": resource["base"],
                   "requested_extent": specification["requested_extent"]}
        if specification["kind"] == "Free":
            request["generation"] = resource["generation"]
        next_lifetime, canonical = apply_effect(lifetime_state, request,
                                                effect_evidence)
    except (KeyError, LifetimeError) as error:
        return None, f"unknown({label} lifetime {error})"
    return (next_state, next_flags, next_memory, next_lifetime,
            {**native_evidence, "logical_effect": canonical}), None
