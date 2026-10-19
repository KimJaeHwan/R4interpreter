"""Common concrete native P-code byte-lane backward slice.

The sink is an explicit register or memory byte set. Control guards and effects
outside the value slice remain obligations for the path certificate.
"""
from collections import Counter
import pypcode

def lanes(space, offset, size, step):
    return {(space, step if space == "unique" else 0, offset + index)
            for index in range(size)}


def node_lanes(node, step):
    kind = node.space.name
    if kind == "register":
        return lanes("register", node.offset, node.size, step)
    if kind == "unique":
        return lanes("unique", node.offset, node.size, step)
    if kind == "ram":
        return lanes("memory", node.offset, node.size, step)
    if kind == "const":
        return set()
    raise ValueError(f"unsupported P-code varnode space {kind}")


def memory_candidates(row, width, mode):
    return [entry for entry in row["memory"]
            if entry["size"] == width and entry["access"] & mode]


def selected_sources(operation, row, step, live, debts):
    name = operation.opcode.name
    if name == "STORE":
        width = operation.inputs[2].size
        candidates = memory_candidates(row, width, 2)
        touched = [(entry, lanes("memory", entry["address"], width, step) & live)
                   for entry in candidates]
        touched = [(entry, active) for entry, active in touched if active]
        if not touched:
            return False, set(), set(), []
        if len(candidates) != 1:
            debts.append({"step": step, "pc": hex(row["pc"]),
                          "reason": "ambiguous native memory write address",
                          "candidate_addresses": [hex(x["address"]) for x in candidates]})
        killed = set().union(*(active for _, active in touched))
        source = node_lanes(operation.inputs[2], step)
        return True, killed, source, [entry["address"] for entry, _ in touched]
    if operation.output is None:
        return False, set(), set(), []
    produced = node_lanes(operation.output, step)
    active = produced & live
    if not active:
        return False, set(), set(), []
    if name == "LOAD":
        candidates = memory_candidates(row, operation.output.size, 1)
        if not candidates:
            debts.append({"step": step, "pc": hex(row["pc"]),
                          "reason": "selected P-code LOAD lacks captured native read"})
            return True, active, set(), []
        if len(candidates) != 1:
            debts.append({"step": step, "pc": hex(row["pc"]),
                          "reason": "ambiguous native memory read address",
                          "candidate_addresses": [hex(x["address"]) for x in candidates]})
        source = set().union(*(lanes("memory", item["address"], item["size"], step)
                               for item in candidates))
        return True, active, source, [item["address"] for item in candidates]
    if name in {"CALLOTHER", "INDIRECT"}:
        debts.append({"step": step, "pc": hex(row["pc"]),
                      "reason": f"selected opaque P-code operation {name}"})
    source = set().union(*(node_lanes(item, step) for item in operation.inputs))
    return True, active, source, []


def caller_slice(rows, sinks=None):
    ctx = pypcode.Context("x86:LE:64:default")
    lifted = {}
    live = set(sinks) if sinks is not None else lanes("register", 0, 8, 0)
    if not live:
        raise ValueError("backward slice needs a caller-visible sink")
    selected = []
    debts = []
    return_edges = []
    step_counts = Counter()
    excluded = Counter()
    excluded_examples = {}
    selected_internal_controls = []
    raw_pcode_operations = 0
    for step in range(len(rows) - 1, -1, -1):
        row = rows[step]
        signature = (row["pc"], row["bytes"])
        if signature not in lifted:
            lifted[signature] = [op for op in ctx.translate(
                bytes.fromhex(row["bytes"]), base_address=row["pc"],
                max_instructions=1).ops if op.opcode.name != "IMARK"]
        operations = lifted[signature]
        raw_pcode_operations += len(operations)
        live_after = set(live)
        matched_native_writes = set()
        selected_ordinals = set()
        for ordinal in range(len(operations) - 1, -1, -1):
            operation = operations[ordinal]
            included, killed, source, addresses = selected_sources(
                operation, row, step, live, debts)
            if not included:
                continue
            live.difference_update(killed)
            live.update(source)
            if operation.opcode.name == "STORE":
                matched_native_writes.update(addresses)
            selected.append({"step": step, "pc": hex(row["pc"]),
                             "ordinal": ordinal, "opcode": operation.opcode.name,
                             "memory_addresses": [hex(x) for x in addresses]})
            selected_ordinals.add(ordinal)
            step_counts[step] += 1
        if selected_ordinals and any(op.opcode.name == "CBRANCH" for op in operations):
            selected_internal_controls.append({"step": step, "pc": hex(row["pc"]),
                                               "instruction": row["instruction"]})
        for access in row["memory"]:
            if (access["access"] & 2 and access["address"] not in matched_native_writes and
                    lanes("memory", access["address"], access["size"], step) & live_after):
                debts.append({"step": step, "pc": hex(row["pc"]),
                              "reason": "selected native write has no modeled P-code STORE",
                              "address": hex(access["address"])})
            elif access["access"] & 2 and access["address"] not in matched_native_writes:
                excluded["native_memory_writes_outside_value_slice"] += 1
                excluded_examples.setdefault("native_memory_writes_outside_value_slice", {
                    "step": step, "pc": hex(row["pc"]), "address": hex(access["address"])})
        for operation in operations:
            if operation.opcode.name in {"CALL", "CALLIND", "RETURN", "CBRANCH",
                                         "BRANCH", "BRANCHIND", "CALLOTHER"}:
                category = "control_or_opaque_" + operation.opcode.name.lower()
                excluded[category] += 1
                excluded_examples.setdefault(category, {"step": step,
                    "pc": hex(row["pc"]), "instruction": row["instruction"]})
        dangling = {item for item in live if item[0] == "unique" and item[1] == step}
        if dangling:
            debts.append({"step": step, "pc": hex(row["pc"]),
                          "reason": "unresolved instruction-local unique value",
                          "byte_count": len(dangling)})
            live.difference_update(dangling)
        if row["instruction"].startswith("ret") and any(
                item[0] == "register" and item[2] < 8 for item in live_after):
            return_edges.append({"step": step, "pc": hex(row["pc"]),
                                 "next_pc": hex(row["next_pc"]),
                                 "rax": hex(row["registers"]["rax"])})
    selected.sort(key=lambda item: (item["step"], item["ordinal"]))
    if selected_internal_controls:
        debts.append({"reason": "selected native instruction contains internal P-code control",
                      "examples": selected_internal_controls[:8],
                      "count": len(selected_internal_controls)})
    audit = {"excluded_counts": dict(sorted(excluded.items())),
             "raw_dynamic_pcode_operations": raw_pcode_operations,
             "selected_store_operations": sum(item["opcode"] == "STORE"
                                               for item in selected),
             "excluded_examples": excluded_examples,
             "selected_internal_control_instructions": len(selected_internal_controls),
             "interpretation": "excluded effects do not touch the demanded concrete value bytes on this recorded path; control edges and unknown-address effects are not generally proved safe"}
    return selected, debts, live, return_edges, len(lifted), len(step_counts), audit
