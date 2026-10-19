"""Engine-neutral, evidence-bearing native path ledger.

This format records observed state and byte effects across *every* native
step. It does not give an opaque interval executable semantics. In particular,
an observed state handoff is weaker than a computed transition handoff.
"""
from __future__ import annotations

from hashlib import sha256
import json


MASK64 = (1 << 64) - 1


class PathILError(ValueError):
    pass


def require(condition, reason):
    if not condition:
        raise PathILError(reason)


def fingerprint(value):
    blob = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return sha256(blob).hexdigest()


def value_dag(dag, witness):
    """Execute only the tiny typed value projection, never native effects."""
    require(dag.get("schema_version") == "bounded-value-il-v1", "wrong value IL schema")
    require(dag.get("inputs") == [{"name": "X", "sort": "BV32"}],
            "value input declaration changed")
    require(type(witness) is int and 0 <= witness < 1 << 32,
            "value input is not BV32")
    values = []
    widths = []
    for index, node in enumerate(dag["nodes"]):
        require(node.get("id") == index and node.get("sort", "").startswith("BV"),
                "value nodes are not typed/topological")
        width = int(node["sort"][2:])
        require(0 < width <= 64, "unsupported value width")
        if node["op"] == "input":
            require(node.get("name") == "X" and node["sort"] == "BV32",
                    "unsupported value input")
            value = witness
        elif node["op"] == "bv":
            value = node["value"]
            require(type(value) is int and 0 <= value < 1 << width,
                    "bitvector constant does not match declared width")
        elif node["op"] == "bvadd":
            args = node.get("args")
            require(isinstance(args, list) and len(args) == 2 and
                    all(type(i) is int and 0 <= i < index for i in args),
                    "bad value operand")
            require(widths[args[0]] == widths[args[1]] == width,
                    "mixed-width bitvector addition")
            value = values[args[0]] + values[args[1]]
        else:
            raise PathILError("unsupported value opcode")
        require(type(value) is int, "non-integer value expression")
        values.append(value & ((1 << width) - 1))
        widths.append(width)
    result = dag["result"]
    require(result.get("name") == "Y" and result.get("sort") == "BV32" and
            type(result.get("node")) is int and 0 <= result["node"] < len(values),
            "bad value result")
    require(widths[result["node"]] == 32,
            "result node width differs from declared sort")
    return values[result["node"]]


def _bytes(number, size):
    require(type(number) is int and number >= 0, "missing memory value")
    return [(number >> (8 * index)) & 255 for index in range(size)]


def native_path_ledger(rows, regions):
    """Partition a trace and conservatively preserve every observed access.

    Some masked vector stores are recorded by the tracer as access=read but
    before!=after. Their changed bytes are definite, and the entire operand
    range is a *possible* write. Neither is silently discarded.
    """
    require(rows and regions and regions[0]["begin"] == 0 and
            regions[-1]["end_exclusive"] == len(rows), "incomplete native partition")
    require(all(a["end_exclusive"] == b["begin"]
                for a, b in zip(regions, regions[1:])), "native partition gap/overlap")
    require(all(0 <= region["begin"] < region["end_exclusive"] <= len(rows)
                for region in regions), "empty or invalid native region")
    require(all(a["next_pc"] == b["pc"] and
                a["registers_after"] == b["registers"]
                for a, b in zip(rows, rows[1:])), "native state or control discontinuity")
    known = {}
    origin = {}
    version = 0
    output = []
    for region_id, region in enumerate(regions):
        part = rows[region["begin"]:region["end_exclusive"]]
        effects = []
        first_read = set()
        earlier_region_reads = set()
        reads = 0
        version_in = version
        for row in part:
            for access in row["memory"]:
                address, size = access["address"], access["size"]
                require(type(address) is int and type(size) is int and
                        0 <= address <= MASK64 and 0 < size <= 4096 and
                        address + size <= MASK64 + 1, "invalid native access extent")
                before = _bytes(access["before"], size)
                after = _bytes(access["after"], size)
                for offset, byte in enumerate(before):
                    point = address + offset
                    if point in known:
                        require(known[point] == byte,
                                f"native memory version mismatch at step {row['step']}")
                        if access["access"] & 1 and 0 <= origin[point] < region_id:
                            earlier_region_reads.add(point)
                    elif access["access"] & 1:
                        first_read.add(point)
                        known[point] = byte
                        origin[point] = -1  # fixed first-read environment byte
                if access["access"] & 1:
                    reads += 1
                explicit_write = bool(access["access"] & 2)
                observed_delta = before != after
                if explicit_write or observed_delta:
                    changed = [index for index in range(size)
                               if before[index] != after[index]]
                    effects.append({"version": version, "step": row["step"],
                                    "pc": hex(row["pc"]), "address": address,
                                    "size": size, "before": access["before"],
                                    "after": access["after"],
                                    "kind": ("NativeWrite" if explicit_write else
                                             "ObservedDeltaPossibleMaskedWrite"),
                                    "changed_byte_offsets": changed})
                    version += 1
                    # A read-only flag with changed bytes gives a definite
                    # observed delta but no authority over the mask itself.
                    for offset in range(size):
                        if explicit_write or offset in changed:
                            known[address + offset] = after[offset]
                            origin[address + offset] = region_id
        output.append({**region, "entry_pc": hex(part[0]["pc"]),
                       "exit_successor": hex(part[-1]["next_pc"]),
                       "entry_state": part[0]["registers"],
                       "exit_state": part[-1]["registers_after"],
                       "native_steps": len(part), "reads": reads,
                       "first_read_bytes": len(first_read),
                       "read_bytes_from_earlier_regions": len(earlier_region_reads),
                       "memory_version_in": version_in,
                       "memory_version_out": version,
                       "effects": effects})
    return output


def validate_partition(route, rows, expected_regions):
    require(route.get("nodes") == native_path_ledger(rows, expected_regions),
            "route native partition, state, or memory effects changed")
    require(route["nodes"][0]["memory_version_in"] == 0 and
            all(a["memory_version_out"] == b["memory_version_in"] and
                a["exit_state"] == b["entry_state"] and
                a["exit_successor"] == b["entry_pc"]
                for a, b in zip(route["nodes"], route["nodes"][1:])),
            "route memory/state handoff changed")
