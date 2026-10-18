"""Apply the shared native segment core to CPython's PyLong allocation path."""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json

from build_expanded_native_paths import ARTIFACTS, records
from common_observed_transition import python_preconditions
from composed_native_transition import apply_segment, parse_segments
from cross_dispatch_pcode import read_vaddr
from pcode_transition_summary import FLAG_OFFSETS, REGISTER_OFFSETS
from prove_cross_full_flow import PYTHON, ROOT
from prove_lua_full_flow import initial_memory
from prove_python_value_reuse import CACHE_BASE


SUMMARY = ROOT / "python_allocated_composed_summary.json"
RESULT = ROOT / "python_allocated_composed_application_result.json"
TARGETS = (252, 253, 254, 256, 251)


def final_bytes(effects):
    memory = {}
    for effect in effects:
        for index in range(effect["width"]):
            memory[effect["address"] + index] = (
                effect["value"] >> (8 * index)) & 255
    return memory


def read_final(memory, address, width):
    try:
        return int.from_bytes(bytes(memory[address + index]
                                    for index in range(width)), "little")
    except KeyError:
        return None


def pre_write_reads(rows, base, size):
    written = set()
    reads = []
    for row in rows:
        for access in row["memory"]:
            if access["access"] & 1 and any(
                    base <= access["address"] + index < base + size and
                    access["address"] + index not in written
                    for index in range(access["size"])):
                reads.append({"pc": hex(row["pc"]),
                              "address": access["address"],
                              "width": access["size"],
                              "value": access["before"]})
            if access["access"] & 2:
                written.update(access["address"] + index
                               for index in range(access["size"]))
    return reads


def apply(summary, decls, parsed, value, trace, rows_override=None):
    meta, body, observed = records(trace)
    rows = body["rows"] if rows_override is None else rows_override
    if (summary.get("schema_version") != "composed-native-segment-transition-v1" or
            summary.get("engine") != "python" or
            sha256(PYTHON.read_bytes()).hexdigest() != summary["binary_sha256"] or
            meta.get("binary_sha256") != summary["binary_sha256"] or
            meta.get("fixture_sha256") != summary["fixture_sha256"] or
            meta.get("input") != value or
            observed.get("output") != value + 5):
        return {"input": value, "status": "unknown(identity/output contract)"}
    reason = python_preconditions({"preconditions": summary["preconditions"]},
                                  meta, rows)
    if reason:
        return {"input": value, "status": reason}
    first = rows[0]["registers"]
    state = {name: first[name] for name in REGISTER_OFFSETS.values()}
    state.update({name: first[name] for name in ("fs_base", "gs_base")})
    flags = {bit: (first["eflags"] >> bit) & 1 for bit in FLAG_OFFSETS.values()}
    memory, initial_byte_count = initial_memory(rows)
    applied, reason = apply_segment("allocated_pylong_path",
        parsed["allocated_pylong_path"], rows, summary, decls,
        state, flags, memory)
    if reason:
        return {"input": value, "status": reason}
    _, _, _, evidence = applied
    effects = evidence["predicted_effects"]
    final = final_bytes(effects)
    slot_effects = [item for item in effects
                    if item["address"] == meta["output_slot"] and
                    item["width"] == 8]
    if len(slot_effects) != 1:
        return {"input": value, "status": "unknown(result slot effect)"}
    pointer = slot_effects[0]["value"]
    cache = read_vaddr(PYTHON, CACHE_BASE, CACHE_BASE + 262 * 32)
    object_layout = {"refcount": read_final(final, pointer, 8),
                     "type_pointer": read_final(final, pointer + 8, 8),
                     "size_tag": read_final(final, pointer + 16, 8),
                     "digit": read_final(final, pointer + 24, 4)}
    expected_type = int.from_bytes(cache[8:16], "little")
    if (CACHE_BASE <= pointer < CACHE_BASE + len(cache) or
            pointer & 15 or pointer in (meta["left_pointer"],
                                        meta["right_pointer"]) or
            object_layout != {"refcount": 1, "type_pointer": expected_type,
                              "size_tag": 8, "digit": value + 5} or
            read_final(final, meta["output_slot"], 8) != pointer):
        return {"input": value, "status": "unknown(predicted PyLong layout)"}
    old_reads = pre_write_reads(rows, pointer, 32)
    return {"input": value, "status": "differentially_validated",
            "native_steps": len(rows), "reads_checked": evidence["reads_checked"],
            "ordered_writes_checked": evidence["ordered_writes_checked"],
            "outputs_checked": evidence["outputs_checked"],
            "result_pointer": pointer, "result_slot": meta["output_slot"],
            "object_layout": object_layout,
            "pre_write_reads_in_object_region": old_reads,
            "initial_read_bytes": initial_byte_count,
            "target_pcode_operations_replayed": 0,
            "source_pcode_operations_replayed_at_application": 0,
            "allocation_event_proved": False}


def main():
    summary = json.loads(SUMMARY.read_text())
    decls, parsed = parse_segments(summary, {"allocated_pylong_path"})
    cases = []
    for value in TARGETS:
        trace = ARTIFACTS / f"python_holdout_{value}.json.gz"
        item = apply(summary, decls, parsed, value, trace)
        item["trace"] = trace.name
        item["trace_sha256"] = sha256(trace.read_bytes()).hexdigest()
        cases.append(item)
    trace = ARTIFACTS / "python_holdout_252.json.gz"
    _, body, _ = records(trace)
    bad_digit = deepcopy(body["rows"])
    meta = records(trace)[0]
    pointer = next(access["after"] for row in bad_digit
        for access in row["memory"] if access["access"] & 2 and
        access["address"] == meta["output_slot"] and access["size"] == 8)
    next(access for row in bad_digit for access in row["memory"]
         if access["access"] & 2 and access["address"] == pointer + 24)[
             "after"] ^= 1
    bad_fs = deepcopy(body["rows"])
    bad_fs[0]["registers"]["fs_base"] ^= 0x1000
    probes = {"wrong_digit_write": apply(summary, decls, parsed, 252,
                                          trace, bad_digit)["status"],
              "wrong_fs_base": apply(summary, decls, parsed, 252,
                                      trace, bad_fs)["status"]}
    successes = [item for item in cases if item["status"] ==
                 "differentially_validated"]
    cached_meta, cached_body, cached_output = records(
        ARTIFACTS / "python_holdout_251.json.gz")
    cached_writes = [access for row in cached_body["rows"]
                     for access in row["memory"] if access["access"] & 2 and
                     access["address"] == cached_meta["output_slot"] and
                     access["size"] == 8]
    cache_pointer = cached_writes[0]["after"] if len(cached_writes) == 1 else None
    if (cached_output["output"] != 256 or cache_pointer is None or
            not CACHE_BASE <= cache_pointer < CACHE_BASE + 262 * 32):
        raise ValueError("cached comparison witness changed")
    if (len(successes) != 4 or not cases[-1]["status"].startswith("unknown(") or
            any(not item.startswith("unknown(") for item in probes.values())):
        raise ValueError("unexpected CPython allocation applicability")
    report = {"schema_version": 1,
              "summary_sha256": sha256(SUMMARY.read_bytes()).hexdigest(),
              "cases": cases, "negative_probes": probes,
              "cached_path_comparison": {"input": 251,
                  "status": cases[-1]["status"],
                  "native_steps": len(cached_body["rows"]),
                  "result_pointer": cache_pointer,
                  "pointer_in_static_integer_cache": True,
                  "reason": "result 256 reuses the static small-int cache and has another native path"},
              "metrics": {"targets": len(cases),
                          "full_native_transitions_matched": len(successes),
                          "unknown": len(cases) - len(successes),
                          "distinct_observed_result_pointers": len({
                              item["result_pointer"] for item in successes}),
                          "target_pcode_operations_replayed": 0,
                          "source_pcode_operations_replayed_at_application": 0},
              "effect_assessment": {
                  "native_write_effects_sufficient_for_observed_transition": True,
                  "logical_allocation_event_proved": False,
                  "reason": "a logical object lifetime, freshness and alias frame are absent from Write effects; allocator reads an old value in the returned region"},
              "limits": ["exact CPython binary and observed 146-step path",
                         "native path and first-read allocator memory supplied by trace",
                         "no proof of arbitrary heap freshness or all input paths"]}
    RESULT.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report["metrics"]))


if __name__ == "__main__":
    main()
