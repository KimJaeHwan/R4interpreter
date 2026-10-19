"""Normalize three bounded native summaries and apply one expression/effect core.

Engine adapters supply entry bindings and provenance. The shared evaluator
handles SMT expressions, guards, all declared state outputs, read footprints,
ordered writes and successor cutpoints without language opcode semantics.
"""
from __future__ import annotations

from copy import deepcopy
import gzip
from hashlib import sha256
import json
from pathlib import Path
import shutil

import z3

from apply_transition_summary import declarations, expression, load_trace
from cross_dispatch_pcode import read_vaddr
from prove_cross_full_flow import PYTHON, ROOT
from prove_js_summary_reuse import concrete_value
from prove_lua_full_flow import initial_memory
from prove_python_value_reuse import CACHE_BASE, observed_operands
from pcode_transition_summary import FLAG_OFFSETS, REGISTER_OFFSETS


OUTPUT = ROOT / "common_three_engine_transitions.json"
RESULT = ROOT / "common_three_engine_application_result.json"
ARTIFACTS = ROOT / "artifacts"


def shape(rows, mode):
    if mode == "pc_bytes_next":
        fields = [[hex(row["pc"]), row["bytes"], hex(row["next_pc"])]
                  for row in rows]
    elif mode == "pc_next":
        fields = [[row["pc"], row["next_pc"]] for row in rows]
    else:
        raise ValueError("unsupported path-shape mode")
    return sha256(json.dumps(fields, separators=(",", ":")).encode()).hexdigest()


def native_inputs():
    result = [{"name": f"R_{name.upper()}", "sort": "BV64",
               "binding": {"kind": "register", "name": name}}
              for name in REGISTER_OFFSETS.values()]
    result += [{"name": f"F_{bit}", "sort": "BV8",
                "binding": {"kind": "register_bit", "name": "eflags", "bit": bit}}
               for bit in FLAG_OFFSETS.values()]
    result.append({"name": "M0", "sort": "Array(BV64,BV8)",
                   "binding": {"kind": "first_read_memory"}})
    return result


def normalize_native(source, engine, case, source_digest):
    if (source.get("schema_version") != "native-handler-transition-v1" or
            source.get("engine") != engine or case not in
            (source.get("cases", []) if engine == "javascript" else
             [source.get("case")])):
        raise ValueError("native source schema, engine or case identity changed")
    names = {item["binding"] for item in case["outputs"]}
    if len(case["outputs"]) != 21 or len(names) != 21:
        raise ValueError("native case is missing a register or modeled flag")
    outputs = []
    for item in case["outputs"]:
        name = item["binding"]
        bind = ({"kind": "register", "name": name}
                if not name.startswith("eflag") else
                {"kind": "register_bit", "name": "eflags", "bit": int(name[5:])})
        canonical = (f"F_{int(name[5:])}" if name.startswith("eflag")
                     else f"R_{name.upper()}")
        outputs.append({"name": canonical, "sort": item["sort"],
                        "expression": item["expression"],
                        "observed_binding": bind})
    identity = case["identity"]
    preconditions = case.get("preconditions")
    if preconditions is None:
        preconditions = ({"kind": "python_cached_int",
                          "cache_sha256": source["cache_sha256"],
                          "minimum_x": 5, "maximum_x": 251, "right": 5}
                         if engine == "python" else {"kind": "guard_only"})
    return {"engine": engine,
        "source_schema_version": source["schema_version"],
        "identity": {"binary_sha256": source["binary_sha256"],
                     "entry_pc": identity["entry_pc"],
                     "next_pc": identity["next_handler_pc"],
                     "path_shape_mode": "pc_bytes_next",
                     "path_shape_sha256": identity["path_shape_sha256"],
                     "native_steps": identity["native_steps"]},
        "interface": {"inputs": native_inputs() +
                      case.get("interface_extensions", [])},
        "condition": [case["guard"]],
        "reads": case["reads"],
        "effects": [{"kind": "Write", **item}
                    for item in case["ordered_effects"]],
        "outputs": outputs,
        "derived_outputs": ([{"name": "vm_cursor", "sort": "BV64",
                              "expression": case["vm_cursor"],
                              "observed_binding": {"kind": "register_add",
                                                   "names": ["r12", "r9"]}}]
                            if "vm_cursor" in case else []),
        "successor": case["successor"],
        "preconditions": preconditions,
        "source_summary_sha256": source_digest,
        "limits": source["limits"]}


def normalize_lua(source, reference_rows, source_digest):
    if (source.get("schema_version") != "transition-summary-v0-candidate" or
            source.get("semantic_model", {}).get("architecture") != "x86-64"):
        raise ValueError("Lua source schema or semantic model changed")
    identity = source["identity"]
    return {"engine": "lua",
        "source_schema_version": source["schema_version"],
        "identity": {"binary_sha256": identity["executable_code_sha256"],
                     "entry_pc": identity["entry_cutpoint"],
                     "next_pc": identity["exit_cutpoint"],
                     "path_shape_mode": "pc_next",
                     "path_shape_sha256": shape(reference_rows, "pc_next"),
                     "native_steps": len(reference_rows)},
        "interface": {"inputs": source["interface"]["inputs"]},
        "condition": source["case"]["path_guard"],
        "reads": source["case"]["reads"],
        "effects": source["case"]["ordered_effects"],
        "outputs": [item for item in source["case"]["outputs"]
                    if item["name"] != "next_code_pointer"],
        "derived_outputs": [item for item in source["case"]["outputs"]
                            if item["name"] == "next_code_pointer"],
        "successor": f"#x{int(identity['exit_cutpoint'], 16):016x}",
        "preconditions": {"kind": "lua_entry_snapshot"},
        "source_summary_sha256": source_digest,
        "limits": ["fixed Lua fixture and observed 23-step path",
                   "summary applies only where its saved guard and footprint match"]}


def bound_value(registers, binding):
    kind = binding["kind"]
    if kind == "segment_base":
        return registers[binding["name"]]
    if kind == "register_add":
        return sum(registers[name] for name in binding["names"]) & ((1 << 64) - 1)
    value = registers[binding["name"]]
    if kind == "register":
        return value
    if kind == "register_bit":
        return (value >> binding["bit"]) & 1
    if kind == "register_slice":
        return (value >> binding["low_bit"]) & ((1 << binding["width"]) - 1)
    raise ValueError(f"unsupported input/output binding {kind}")


def python_preconditions(case, meta, rows):
    pre = case["preconditions"]
    if not meta or any(meta.get(key) != pre["cache_sha256"] for key in
                       ("runtime_cache_sha256_at_entry", "runtime_cache_sha256_at_exit")):
        return "unknown(cache identity)"
    x = meta.get("input")
    if (type(x) is not int or not pre["minimum_x"] <= x <= pre["maximum_x"] or
            meta.get("left_pointer") != CACHE_BASE + (x + 5) * 32 or
            meta.get("right_pointer") != CACHE_BASE + (pre["right"] + 5) * 32):
        return "unknown(cached integer domain)"
    cache = read_vaddr(PYTHON, CACHE_BASE, CACHE_BASE + 262 * 32)
    if sha256(cache).hexdigest() != pre["cache_sha256"]:
        return "unknown(cache image)"
    try:
        operands = observed_operands(rows, cache)
    except (ValueError, KeyError):
        return "unknown(operand evidence)"
    if ([item["value"] for item in operands] != [x, pre["right"]] or
            [item["pointer"] for item in operands] !=
            [hex(meta["left_pointer"]), hex(meta["right_pointer"])] or
            meta.get("output_slot") != rows[-1]["registers_after"]["r15"] - 8):
        return "unknown(operand or result slot mismatch)"
    cache_end = CACHE_BASE + len(cache)
    if any(item["access"] & 2 and item["address"] < cache_end and
           item["address"] + item["size"] > CACHE_BASE
           for row in rows for item in row["memory"]):
        return "unknown(cache write)"
    result_effects = [item for row in rows for item in row["memory"]
                      if item["access"] & 2 and item["size"] == 8 and
                      item["address"] == meta["output_slot"]]
    if len(result_effects) != 1:
        return "unknown(numeric result slot write)"
    if pre["kind"] == "python_cached_int":
        if result_effects[0]["after"] != CACHE_BASE + (x + pre["right"] + 5) * 32:
            return "unknown(numeric result pointer)"
    else:
        pointer = result_effects[0]["after"]
        if CACHE_BASE <= pointer < cache_end or pointer & 15:
            return "unknown(allocated result pointer)"
        writes = {(item["address"] - pointer, item["size"]): item["after"]
                  for row in rows for item in row["memory"] if item["access"] & 2
                  and pointer <= item["address"] < pointer + 32}
        py_long_type = int.from_bytes(cache[8:16], "little")
        if writes != {(0, 8): 1, (8, 8): py_long_type,
                      (16, 8): 8, (24, 4): x + pre["right"]}:
            return "unknown(allocated PyLong layout)"
    return None


def javascript_string_preconditions(case, meta, rows):
    pre = case["preconditions"]
    digits = len(str(meta.get("input", ""))) if meta else 0
    long_range = "minimum_digits" in pre and "maximum_digits" in pre
    if (not meta or meta.get("input_type") != "string" or
            meta.get("fixture_sha256") != pre["fixture_sha256"] or
            not meta.get("full_handler") or
            type(meta.get("input")) is not int or
            (not pre["minimum_digits"] <= digits <= pre["maximum_digits"]
             if long_range else digits != pre["input_decimal_digits"]) or
            rows[0]["registers"]["rax"] & 1 != 1):
        return "unknown(string input contract)"
    immediate_address = (rows[0]["registers"]["r12"] +
                         rows[0]["registers"]["r9"] + 1) & ((1 << 64) - 1)
    if not any(item["address"] == immediate_address and item["size"] == 1 and
               item["access"] & 1 and item["before"] == 5
               for item in rows[0]["memory"]):
        return "unknown(AddSmi immediate)"
    string_address = rows[0]["registers"]["rax"] - 1
    reads = {(item["address"], item["size"]): item["before"]
             for row in rows for item in row["memory"] if item["access"] & 1}
    length = reads.get((string_address + 12, 4))
    if length != digits:
        return "unknown(string object/input mismatch)"
    if long_range:
        snapshot = meta.get("input_object_snapshot")
        if (not isinstance(snapshot, dict) or
                snapshot.get("object_address") != string_address or
                snapshot.get("cutpoint_pc") != rows[0]["pc"] or
                snapshot.get("length") != digits or
                snapshot.get("ascii_hex") != str(meta["input"]).encode("ascii").hex()):
            return "unknown(entry string snapshot)"
    else:
        characters = [reads.get((string_address + 16 + index, 1))
                      for index in range(digits)]
        if (any(character is None or not 48 <= character <= 57
                for character in characters) or
                int(bytes(characters).decode("ascii")) != meta["input"]):
            return "unknown(string object/input mismatch)"
    return None


def apply_case(common, case, binary, rows, meta=None):
    """Use the same typed expression/guard/effect evaluator for all engines."""
    expected_preconditions = {"lua": {("lua_entry_snapshot",
                                       "transition-summary-v0-candidate")},
                              "python": {("python_cached_int",
                                          "native-handler-transition-v1"),
                                         ("python_allocated_result",
                                          "native-handler-transition-v1")},
                              "javascript": {("guard_only",
                                              "native-handler-transition-v1"),
                                             ("javascript_string",
                                              "native-handler-transition-v1")}}
    engine = case.get("engine")
    if (common.get("schema_version") != "common-observed-transition-v1" or
            common.get("semantic_model") !=
            {"architecture": "x86-64", "endian": "little",
             "memory": "byte-addressed", "integers": "typed bitvectors",
             "expression": "SMT-LIB 2 term"} or
            case not in common.get("cases", []) or
            engine not in expected_preconditions or
            (case.get("preconditions", {}).get("kind"),
             case.get("source_schema_version")) not in expected_preconditions[engine]):
        return {"status": "unknown(summary schema or engine)"}
    identity = case["identity"]
    if sha256(binary.read_bytes()).hexdigest() != identity["binary_sha256"]:
        return {"status": "unknown(binary identity)"}
    if (not rows or any(a["next_pc"] != b["pc"] for a, b in zip(rows, rows[1:])) or
            hex(rows[0]["pc"]) != identity["entry_pc"] or
            hex(rows[-1]["next_pc"]) != identity["next_pc"] or
            len(rows) != identity["native_steps"] or
            shape(rows, identity["path_shape_mode"]) != identity["path_shape_sha256"]):
        return {"status": "unknown(path identity)"}
    expected_outputs = {f"R_{name.upper()}":
                        ("BV64", {"kind": "register", "name": name})
                        for name in REGISTER_OFFSETS.values()}
    expected_outputs.update({f"F_{bit}":
                             ("BV8", {"kind": "register_bit",
                                      "name": "eflags", "bit": bit})
                             for bit in FLAG_OFFSETS.values()})
    if (len(case["outputs"]) != len(expected_outputs) or
            {item["name"]: (item["sort"], item["observed_binding"])
             for item in case["outputs"]} != expected_outputs):
        return {"status": "unknown(incomplete state contract)"}
    expected_derived = {
        "lua": {"next_code_pointer": ("BV64",
                                      {"kind": "register", "name": "r15"})},
        "python": {},
        "javascript": {"vm_cursor": ("BV64",
                                     {"kind": "register_add",
                                      "names": ["r12", "r9"]})}}[engine]
    if (len(case.get("derived_outputs", [])) != len(expected_derived) or
            {item["name"]: (item["sort"], item["observed_binding"])
             for item in case.get("derived_outputs", [])} != expected_derived):
        return {"status": "unknown(incomplete derived output contract)"}
    if any(item.get("kind") != "Write" for item in case["effects"]):
        return {"status": "unknown(unsupported effect kind)"}
    pre = case["preconditions"]["kind"]
    if pre in ("python_cached_int", "python_allocated_result"):
        reason = python_preconditions(case, meta, rows)
        if reason:
            return {"status": reason}
    elif pre == "javascript_string":
        reason = javascript_string_preconditions(case, meta, rows)
        if reason:
            return {"status": reason}
    elif pre == "lua_entry_snapshot":
        if "entry_memory" not in rows[0]:
            return {"status": "unknown(entry memory snapshot)"}
    elif pre != "guard_only":
        return {"status": "unknown(unsupported precondition)"}
    decls = declarations(case)
    bindings = []
    for item in case["interface"]["inputs"]:
        if item["binding"]["kind"] in ("entry_memory", "first_read_memory"):
            continue
        value = bound_value(rows[0]["registers"], item["binding"])
        bindings.append((decls[item["name"]], z3.BitVecVal(
            value, decls[item["name"]].size())))
    if pre == "lua_entry_snapshot":
        snapshot = rows[0]["entry_memory"]
        data = bytes.fromhex(snapshot["bytes_hex"])
        base = snapshot["base"]
        memory = z3.K(z3.BitVecSort(64), z3.BitVecVal(0, 8))
        for index, byte in enumerate(data):
            memory = z3.Store(memory, z3.BitVecVal(base + index, 64),
                              z3.BitVecVal(byte, 8))
    else:
        memory, _ = initial_memory(rows)
    if "M0" in decls:
        bindings.append((decls["M0"], memory))
    for guard in case["condition"]:
        verdict = z3.simplify(z3.substitute(expression(guard, "Bool", decls),
                                            *bindings))
        if not z3.is_true(verdict):
            return {"status": "unknown(outside case guard)"}
    output_values = {}
    for item in case["outputs"]:
        value = concrete_value(expression(item["expression"], item["sort"], decls),
                               bindings)
        if value != bound_value(rows[-1]["registers_after"], item["observed_binding"]):
            return {"status": "unknown(state mismatch)", "binding": item["name"]}
        output_values[item["name"]] = value
    derived = {}
    for item in case.get("derived_outputs", []):
        value = concrete_value(expression(item["expression"], item["sort"], decls),
                               bindings)
        if value != bound_value(rows[-1]["registers_after"], item["observed_binding"]):
            return {"status": "unknown(derived output mismatch)"}
        derived[item["name"]] = value
    reads = []
    for item in case["reads"]:
        if item.get("memory_version", 0) != 0 and pre == "lua_entry_snapshot":
            return {"status": "unknown(unsupported read version)"}
        address = concrete_value(expression(item["address"], "BV64", decls),
                                 bindings)
        key = (item["pc"], address, item["width"])
        if key not in [(r["pc"], r["address"], r["width"]) for r in reads]:
            reads.append({"pc": item["pc"], "address": address,
                          "width": item["width"]})
    actual_reads = [{"pc": hex(row["pc"]), "address": access["address"],
                     "width": access["size"]}
                    for row in rows for access in row["memory"] if access["access"] & 1]
    if reads != actual_reads:
        return {"status": "unknown(read footprint mismatch)"}
    if pre == "lua_entry_snapshot":
        if any(r["address"] < base or r["address"] + r["width"] > base + len(data)
               for r in reads):
            return {"status": "unknown(read outside entry snapshot)"}
        if any(int.from_bytes(data[access["address"] - base:
                                   access["address"] - base + access["size"]],
                              "little") != access["before"]
               for row in rows for access in row["memory"] if access["access"] & 1):
            return {"status": "unknown(snapshot/read mismatch)"}
    effects = [{"pc": item["pc"], "address": concrete_value(
                    expression(item["address"], "BV64", decls), bindings),
                "width": item["width"],
                "value": concrete_value(expression(item["value"],
                                             f"BV{item['width'] * 8}", decls), bindings)}
               for item in case["effects"]]
    actual_effects = [{"pc": hex(row["pc"]), "address": access["address"],
                       "width": access["size"], "value": access["after"]}
                      for row in rows for access in row["memory"] if access["access"] & 2]
    if effects != actual_effects:
        return {"status": "unknown(ordered effects mismatch)"}
    successor = concrete_value(expression(case["successor"], "BV64", decls),
                               bindings)
    if successor != rows[-1]["next_pc"]:
        return {"status": "unknown(successor mismatch)"}
    return {"status": "differentially_validated",
            "engine": case["engine"], "native_steps": len(rows),
            "outputs_checked": len(output_values), "reads_checked": len(reads),
            "derived_outputs_checked": len(derived),
            "ordered_writes_checked": len(effects),
            "next_pc": hex(successor), "target_pcode_steps_replayed": 0}


def gzip_records(path):
    with gzip.open(path, "rt") as stream:
        return [json.loads(line) for line in stream]


def main():
    lua_path = ROOT / "handler_summary_plus7.json"
    python_path = ROOT / "python_binary_op_full_handler_summary.json"
    js_path = ROOT / "js_addsmi_full_handler_summary.json"
    allocated_path = ROOT / "python_allocated_result_summary.json"
    string_path = ROOT / "js_string_add_full_handler_summary.json"
    length_path = ROOT / "js_string_length_paths_summary.json"
    lua_source = json.loads(lua_path.read_text())
    python_source = json.loads(python_path.read_text())
    js_source = json.loads(js_path.read_text())
    allocated_source = json.loads(allocated_path.read_text())
    string_source = json.loads(string_path.read_text())
    length_source = json.loads(length_path.read_text())
    lua_reference = load_trace(ARTIFACTS / "lua_handler_plus7_x9.jsonl",
                               0x4164B8, 0x415B24)[1]
    common = {"schema_version": "common-observed-transition-v1",
        "semantic_model": {"architecture": "x86-64", "endian": "little",
                           "memory": "byte-addressed", "integers": "typed bitvectors",
                           "expression": "SMT-LIB 2 term"},
        "cases": ([normalize_lua(lua_source, lua_reference,
                                  sha256(lua_path.read_bytes()).hexdigest()),
                   normalize_native(python_source, "python", python_source["case"],
                                    sha256(python_path.read_bytes()).hexdigest())] +
                  [normalize_native(js_source, "javascript", item,
                                    sha256(js_path.read_bytes()).hexdigest())
                   for item in js_source["cases"]] +
                  [normalize_native(allocated_source, "python",
                                    allocated_source["case"],
                                    sha256(allocated_path.read_bytes()).hexdigest())] +
                  [normalize_native(string_source, "javascript", item,
                                    sha256(string_path.read_bytes()).hexdigest())
                   for item in string_source["cases"]] +
                  [normalize_native(length_source, "javascript", item,
                                    sha256(length_path.read_bytes()).hexdigest())
                   for item in length_source["cases"]]),
        "uncovered": "all unlisted or failing guards/paths are unknown"}
    OUTPUT.write_text(json.dumps(common, indent=2) + "\n")
    loaded = json.loads(OUTPUT.read_text())
    if loaded["schema_version"] != "common-observed-transition-v1":
        raise ValueError("common summary schema changed")
    lua_binary = ROOT / "lua_interpreter_fixture"
    node_binary = Path(shutil.which("node"))
    targets = []
    for filename in ("lua_handler_plus11_x9.jsonl", "lua_handler_plus7_zero.jsonl"):
        _, rows = load_trace(ARTIFACTS / filename, 0x4164B8, 0x415B24)
        targets.append(("lua", lua_binary, rows, None, filename, None))
    for value in (37, 251):
        filename = f"python_holdout_{value}.json.gz"
        meta, body, _ = gzip_records(ARTIFACTS / filename)
        targets.append(("python", PYTHON, body["rows"], meta, filename, None))
    for value in (37, 251, 252):
        filename = f"js_handler_holdout_{value}.json.gz"
        meta, body, _ = gzip_records(ARTIFACTS / filename)
        targets.append(("javascript", node_binary, body["rows"], meta, filename, None))
    for value in (253, 254, 256):
        filename = f"python_holdout_{value}.json.gz"
        meta, body, _ = gzip_records(ARTIFACTS / filename)
        targets.append(("python", PYTHON, body["rows"], meta, filename, None))
    for value in (38, 251):
        filename = f"js_string_full_{value}.json.gz"
        meta, body, _ = gzip_records(ARTIFACTS / filename)
        targets.append(("javascript", node_binary, body["rows"], meta, filename, None))
    for value in (0, 8, 10, 99, 252, 999, 1001, 1009, 10000):
        filename = f"js_string_full_{value}.json.gz"
        meta, body, _ = gzip_records(ARTIFACTS / filename)
        targets.append(("javascript", node_binary, body["rows"], meta, filename, None))
    filename = "js_summary_reuse_37.json.gz"
    two_adds = gzip_records(ARTIFACTS / filename)
    for section in two_adds[1:3]:
        targets.append(("javascript", node_binary, section["rows"],
                        {"input": 37}, filename, section["bytecode_offset"]))
    results = []
    for engine, binary, rows, meta, filename, bytecode_offset in targets:
        candidates = [case for case in loaded["cases"] if case["engine"] == engine]
        applications = [apply_case(loaded, case, binary, rows, meta)
                        for case in candidates]
        success = [item for item in applications if item["status"] ==
                   "differentially_validated"]
        if len(success) > 1:
            raise ValueError("overlapping common cases")
        chosen = success[0] if success else {"status": "unknown(no applicable case)",
                                             "candidate_results": applications}
        expected_application = filename not in (
            "js_handler_holdout_252.json.gz", "js_string_full_10000.json.gz")
        if (chosen["status"] == "differentially_validated") != expected_application:
            raise ValueError(f"unexpected common applicability: {filename}: {chosen}")
        results.append({"trace": filename, "engine": engine,
                        "bytecode_offset": bytecode_offset,
                        "trace_sha256": sha256((ARTIFACTS / filename).read_bytes()).hexdigest(),
                        "application": chosen})
    lua_rows = targets[0][2]
    py_meta, py_body, _ = gzip_records(ARTIFACTS / "python_holdout_37.json.gz")
    py_rows = py_body["rows"]
    js_rows = gzip_records(ARTIFACTS / "js_handler_holdout_37.json.gz")[1]["rows"]
    fused_rows = two_adds[1]["rows"]
    def changed_common(index, change):
        altered = deepcopy(loaded)
        change(altered["cases"][index])
        return altered, altered["cases"][index]
    bad_schema = deepcopy(loaded)
    bad_schema["schema_version"] = "unsupported"
    wrong_engine, wrong_engine_case = changed_common(
        2, lambda case: case.update(engine="vmp"))
    wrong_source, wrong_source_case = changed_common(
        2, lambda case: case.update(source_schema_version="unsupported"))
    missing_output, missing_output_case = changed_common(
        3, lambda case: case["outputs"].pop())
    missing_derived, missing_derived_case = changed_common(
        3, lambda case: case["derived_outputs"].pop())
    unsupported_effect, unsupported_effect_case = changed_common(
        1, lambda case: case["effects"][0].update(kind="Allocate"))
    bad_lua_rows = deepcopy(lua_rows)
    snapshot = bad_lua_rows[0]["entry_memory"]
    first_read = next(access for row in bad_lua_rows for access in row["memory"]
                      if access["access"] & 1)
    snapshot_bytes = bytearray.fromhex(snapshot["bytes_hex"])
    snapshot_bytes[first_read["address"] - snapshot["base"]] ^= 1
    snapshot["bytes_hex"] = snapshot_bytes.hex()
    bad_fused_rows = deepcopy(fused_rows)
    next(access for row in bad_fused_rows for access in row["memory"]
         if access["access"] & 2)["after"] ^= 1
    bad_js_rows = deepcopy(js_rows)
    bad_js_rows[-1]["next_pc"] = 0
    alloc_meta, alloc_body, _ = gzip_records(ARTIFACTS / "python_holdout_253.json.gz")
    alloc_rows = alloc_body["rows"]
    bad_alloc_rows = deepcopy(alloc_rows)
    alloc_pointer = next(item["after"] for row in bad_alloc_rows
                         for item in row["memory"] if item["access"] & 2
                         and item["address"] == alloc_meta["output_slot"]
                         and item["size"] == 8)
    next(item for row in bad_alloc_rows for item in row["memory"]
         if item["access"] & 2 and item["address"] == alloc_pointer + 24
         and item["size"] == 4)["after"] ^= 1
    bad_segment_rows = deepcopy(alloc_rows)
    bad_segment_rows[0]["registers"]["fs_base"] ^= 8
    string_meta, string_body, _ = gzip_records(ARTIFACTS / "js_string_full_38.json.gz")
    string_rows = string_body["rows"]
    bad_immediate_rows = deepcopy(string_rows)
    immediate_address = (string_rows[0]["registers"]["r12"] +
                         string_rows[0]["registers"]["r9"] + 1) & ((1 << 64) - 1)
    next(item for item in bad_immediate_rows[0]["memory"]
         if item["access"] & 1 and item["address"] == immediate_address
         and item["size"] == 1)["before"] = 6
    three_meta, three_body, _ = gzip_records(ARTIFACTS / "js_string_full_252.json.gz")
    bad_three_rows = deepcopy(three_body["rows"])
    three_source_char = bad_three_rows[0]["registers"]["rax"] - 1 + 16
    next(item for row in bad_three_rows for item in row["memory"]
         if item["access"] & 1 and item["address"] == three_source_char
         and item["size"] == 1)["before"] = ord("9")
    four_meta, four_body, _ = gzip_records(ARTIFACTS / "js_string_full_1001.json.gz")
    bad_four_rows = deepcopy(four_body["rows"])
    four_result_char = bad_four_rows[-1]["registers_after"]["rax"] - 1 + 16 + 3
    next(item for row in bad_four_rows for item in row["memory"]
         if item["access"] & 2 and item["address"] == four_result_char
         and item["size"] == 1)["after"] ^= 1
    probes = {
        "wrong_common_schema": apply_case(bad_schema, loaded["cases"][2],
                                          node_binary, js_rows),
        "unknown_engine": apply_case(wrong_engine, wrong_engine_case,
                                     node_binary, js_rows),
        "wrong_source_schema": apply_case(wrong_source, wrong_source_case,
                                          node_binary, js_rows),
        "missing_output": apply_case(missing_output, missing_output_case,
                                     node_binary, js_rows),
        "missing_derived_output": apply_case(missing_derived,
                                             missing_derived_case,
                                             node_binary, js_rows),
        "unsupported_effect_kind": apply_case(unsupported_effect,
                                              unsupported_effect_case,
                                              PYTHON, py_rows, py_meta),
        "corrupted_lua_snapshot": apply_case(loaded, loaded["cases"][0],
                                             lua_binary, bad_lua_rows),
        "wrong_python_operand": apply_case(
            loaded, loaded["cases"][1], PYTHON, py_rows,
            {**py_meta, "input": 38,
             "left_pointer": CACHE_BASE + (38 + 5) * 32}),
        "changed_js_write": apply_case(loaded, loaded["cases"][2],
                                       node_binary, bad_fused_rows),
        "wrong_js_successor": apply_case(loaded, loaded["cases"][3],
                                         node_binary, bad_js_rows),
        "wrong_allocated_digit": apply_case(loaded, loaded["cases"][4],
                                             PYTHON, bad_alloc_rows, alloc_meta),
        "wrong_python_segment_base": apply_case(loaded, loaded["cases"][4],
                                                  PYTHON, bad_segment_rows,
                                                  alloc_meta),
        "wrong_string_immediate": apply_case(loaded, loaded["cases"][5],
                                               node_binary, bad_immediate_rows,
                                               string_meta),
        "wrong_three_digit_source": apply_case(loaded, loaded["cases"][7],
                                                 node_binary, bad_three_rows,
                                                 three_meta),
        "wrong_four_digit_output": apply_case(loaded, loaded["cases"][8],
                                                node_binary, bad_four_rows,
                                                four_meta)}
    negative_probes = {name: item["status"] for name, item in probes.items()}
    if any(not status.startswith("unknown(") for status in negative_probes.values()):
        raise ValueError("common applier accepted an invalid case")
    report = {"summary_sha256": sha256(OUTPUT.read_bytes()).hexdigest(),
        "cases_in_summary": len(loaded["cases"]), "targets": results,
        "negative_probes": negative_probes,
        "metrics": {"engines": 3, "targets": len(results),
                    "applied_correct": sum(item["application"]["status"] ==
                                           "differentially_validated" for item in results),
                    "unknown": sum(item["application"]["status"].startswith("unknown(")
                                   for item in results),
                    "target_pcode_steps_replayed": 0},
        "limits": ["each case covers one observed native path and pinned executable",
                   "Lua source summary predates the newer native summaries",
                   "common core shares expression/guard/read/write/output evaluation; engine adapters validate entry contracts",
                   "alternative paths and full script reconstruction remain unknown"]}
    RESULT.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report["metrics"]))


if __name__ == "__main__":
    main()
