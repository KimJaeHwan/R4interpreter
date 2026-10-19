"""Cross-engine bounded integration: native proof, frozen effects, value slice, IL.

Evaluation programs are oracles only. IL is emitted from native proof records;
the source programs are never parsed for analysis or used as opcode tables.
"""
from copy import deepcopy
import gzip
from hashlib import sha256
import json
from pathlib import Path
import shutil
import subprocess

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
import z3

from apply_js_string_loop_summary import apply as apply_string_loop
from build_expanded_native_paths import records as expanded_records
from common_native_slice import caller_slice, lanes
from common_observed_transition import apply_case as apply_frozen_native
from composed_native_transition import parse_segments
from cross_dispatch_pcode import read_vaddr
from prove_cross_full_flow import (CACHE_BASE, JAVASCRIPT, PYTHON,
                                   javascript_case, load_trace, python_case,
                                   verify_cache)
from prove_lua_full_flow import (BINARY as LUA_BINARY, prove_input,
                                 prove_return, prove_vm_path, trace_records)


ROOT = Path(__file__).resolve().parent
ARTIFACTS = ROOT / "artifacts"
BRANCH_INPUT = 42
STRING_INPUTS = (42, 234567, 123456789012)
COMMON = ROOT / "common_three_engine_transitions.json"
STRING = ROOT / "js_string_loop_transition_summary.json"
REPORT = ROOT / "integrated_pipeline_result.json"
IL_OUTPUT = ROOT / "integrated_common_il.json"
SLICE_OUTPUT = ROOT / "integrated_native_slice_42.json"


def digest(path):
    return sha256(path.read_bytes()).hexdigest()


def load_json(path):
    return json.loads(path.read_text())


def require(condition, message):
    if not condition:
        raise ValueError(message)


def checked_oracle(engine, mode, value):
    input_text = str(value)
    if engine == "lua":
        command = [str(ROOT / "integrated_lua_runner"), mode, input_text,
                   str(ROOT / "integrated_case.lua")]
    elif engine == "python":
        command = [str(PYTHON), "-I", "-S", str(ROOT / "integrated_case.py"),
                   mode, input_text]
    elif engine == "javascript":
        command = [str(JAVASCRIPT), "--jitless", "--no-warnings",
                   str(ROOT / "integrated_case.js"), mode, input_text]
    else:
        raise ValueError("unknown oracle engine")
    return subprocess.check_output(command, text=True, timeout=30).rstrip("\n")


def source_proofs():
    lua_path = ROOT / "lua_branch_full_flow.json"
    cross_path = ROOT / "cross_full_flow_result.json"
    lua, cross = load_json(lua_path), load_json(cross_path)
    require(lua["conditional_native_result_proved_under_assumptions"] and
            cross["status"] == "conditional native-path proof through caller dispatch",
            "source branch certificates are absent")
    require(lua["binary_sha256"] == digest(LUA_BINARY) and
            lua["bytecode_sha256"] == digest(ROOT / "lua_branch_call.luac"),
            "source Lua executable or program changed")
    for label in ("x0", "x9"):
        row = next(item for item in lua["paths"] if item["path"] == label)
        require(row["trace_sha256"] == digest(ARTIFACTS / f"lua_branch_full_flow_{label}.jsonl"),
                "source Lua path changed")
    for engine in ("python", "javascript"):
        for witness in (0, 9):
            row = next(item for item in cross["cases"] if item["engine"] == engine
                       and item["witness"] == witness)
            require(row["trace_sha256"] == digest(
                ARTIFACTS / f"cross_{'js' if engine == 'javascript' else 'python'}_full_{witness}.json.gz"),
                "source cross-engine path changed")
            require(row["value_equivalence"] == "unsat" and
                    row["value_expression"] == ("10" if witness == 0 else "X + 5"),
                    "source value certificate changed")
    return lua, cross, {"lua": digest(lua_path), "python_javascript": digest(cross_path)}


def lua_holdout():
    path = ARTIFACTS / "integrated_lua_branch_42.jsonl"
    records = trace_records(path)
    require(records[0]["input"] == BRANCH_INPUT and
            records[0]["input_word"] == BRANCH_INPUT,
            "Lua holdout input changed")
    x, payload = z3.BitVec("X", 64), z3.BitVec("P", 64)
    prefix = prove_input(records, x)
    vm = prove_vm_path(records, x, BRANCH_INPUT + 5)
    suffix = prove_return(records, payload, BRANCH_INPUT + 5)
    require(prefix["source_expression"] == "X" and
            vm["guard"] == "X != 0" and vm["payload_expression"] == "X + 5" and
            suffix["printf_second_argument_expression"] == "P" and
            vm["guard_equivalence"] == vm["payload_equivalence"] == "unsat",
            "Lua holdout native value path changed")
    return {"engine": "lua", "input": BRANCH_INPUT, "output": BRANCH_INPUT + 5,
        "trace_sha256": digest(path), "input_prefix": prefix,
        "vm_path": vm, "return_suffix": suffix,
        "native_total_steps": records[-1]["steps"],
        "scope": "fresh conditional P-code replay; not frozen full-path application"}, records


def cross_holdouts():
    paths = {engine: ARTIFACTS / f"integrated_{'js' if engine == 'javascript' else 'python'}_branch_42.json.gz"
             for engine in ("python", "javascript")}
    result = {}
    loaded = {}
    for engine, path in paths.items():
        binary = PYTHON if engine == "python" else JAVASCRIPT
        meta, rows, summary = load_trace(path, engine, BRANCH_INPUT, binary)
        proof = (python_case(path, BRANCH_INPUT) if engine == "python"
                 else javascript_case(path, BRANCH_INPUT))
        require(proof["value_equivalence"] == "unsat" and
                proof["guard_expression"] == "5 <= X <= 251" and
                proof["value_expression"] == "X + 5" and
                proof["output"] == BRANCH_INPUT + 5,
                f"{engine} holdout native certificate changed")
        if engine == "python":
            require(proof["cache_alias_exclusion"] == BRANCH_INPUT - 5 and
                    proof["proof_domain"].endswith("X != 37"),
                    "Python fixed-cache alias exclusion is missing")
        result[engine] = proof
        loaded[engine] = (meta, rows, summary)
    return result, loaded


def bounded_numeric_segments(common, cross_rows):
    require(common["schema_version"] == "common-observed-transition-v1",
            "frozen common native summary changed")
    applied = {}
    reasons = {}
    for engine in ("python", "javascript"):
        meta, rows, summary = cross_rows[engine]
        entry = 0x56227C if engine == "python" else 0x1BB7780
        exit_pc = 0x56173B if engine == "python" else 0x1BC6F40
        start = next(i for i, row in enumerate(rows) if row["pc"] == entry)
        end = next(i for i in range(start + 1, len(rows)) if rows[i]["pc"] == exit_pc)
        segment = rows[start:end]
        case = common["cases"][1 if engine == "python" else 3]
        if engine == "python":
            cache_hash = verify_cache(meta)
            adapter = {"input": BRANCH_INPUT,
                "runtime_cache_sha256_at_entry": cache_hash,
                "runtime_cache_sha256_at_exit": cache_hash,
                "left_pointer": meta["entry_value_address"],
                "right_pointer": CACHE_BASE + 10 * 32,
                "output_slot": segment[-1]["registers_after"]["r15"] - 8}
            binary = PYTHON
        else:
            adapter, binary = None, JAVASCRIPT
        verdict = apply_frozen_native(common, case, binary, segment, adapter)
        require(verdict["status"] == "differentially_validated",
                f"{engine} frozen numeric segment did not apply: {verdict}")
        applied[engine] = verdict
        changed = deepcopy(segment)
        changed[-1]["next_pc"] ^= 1
        bad = apply_frozen_native(common, case, binary, changed, adapter)
        require(bad["status"].startswith("unknown("),
                f"{engine} tampered successor was admitted")
        reasons[f"{engine}_wrong_successor"] = bad["status"]
    return applied, reasons


def lua_value_rows(records):
    branch = next(row for row in records if row.get("type") == "replay_step" and
                  row["pc"] == 0x417E50)
    source = max((row for row in records if row.get("type") == "replay_step" and
                  row["pc"] == 0x416EA1 and row["step"] < branch["step"]),
                 key=lambda row: row["step"])
    add = next(row for row in records if row.get("type") == "step" and
               row["pc"] == 0x417CEA)
    rows = [row for row in records if row.get("type") == "replay_step" and
            source["step"] <= row["step"] < add["step"]] + [add]
    require(all(a["step"] + 1 == b["step"] and a["next_pc"] == b["pc"]
                for a, b in zip(rows, rows[1:])), "Lua VM value path has a gap")
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    for row in rows:
        raw = read_vaddr(LUA_BINARY, row["pc"], row["pc"] + 15)
        decoded = next(decoder.disasm(raw, row["pc"], count=1), None)
        require(decoded is not None, "Lua native instruction could not be lifted")
        row["bytes"] = decoded.bytes.hex()
    return rows


def native_slices(lua_records, cross_rows):
    sinks = {}
    py_meta, py_rows, py_summary = cross_rows["python"]
    js_meta, js_rows, js_summary = cross_rows["javascript"]
    sinks["lua"] = (lua_value_rows(lua_records), lanes("register", 160, 8, 0),
                    "R12 VM payload after arithmetic")
    sinks["python"] = (py_rows, lanes("memory", py_summary["exit_registers"]["r15"] - 8, 8, 0),
                       "caller-visible VM result slot")
    sinks["javascript"] = (js_rows, lanes("register", 0, 8, 0),
                           "caller-visible RAX")
    report = {}
    for engine, (rows, sink, label) in sinks.items():
        selected, debts, live, returns, lifted, selected_steps, audit = caller_slice(rows, sink)
        report[engine] = {"sink": label, "native_steps_in_slice_interval": len(rows),
            "raw_dynamic_pcode_operations": audit["raw_dynamic_pcode_operations"],
            "selected_value_pcode_operations": len(selected),
            "selected_native_steps": selected_steps,
            "selected_store_operations": audit["selected_store_operations"],
            "entry_live_byte_lanes": len(live),
            "slice_debts": debts,
            "selected_operations": selected,
            "excluded_audit": audit,
            "scope": "data-value slice only; guards and other effects remain in path certificates"}
    SLICE_OUTPUT.write_text(json.dumps({"schema_version": 1,
        "source_traces": {"lua": digest(ARTIFACTS / "integrated_lua_branch_42.jsonl"),
            "python": digest(ARTIFACTS / "integrated_python_branch_42.json.gz"),
            "javascript": digest(ARTIFACTS / "integrated_js_branch_42.json.gz")},
        "engines": report}, indent=2) + "\n")
    return {engine: {key: value for key, value in item.items()
                     if key not in ("selected_operations", "excluded_audit")}
            for engine, item in report.items()}


def expression_ir(text):
    if text == "10":
        return {"op": "const", "value": 10, "type": "int"}
    if text == "X + 5":
        return {"op": "add", "left": {"op": "input", "name": "X"},
                "right": {"op": "const", "value": 5}, "type": "int"}
    raise ValueError(f"unrecognized proved expression: {text}")


def guard_ir(text):
    if text == "X == 0":
        return {"op": "eq", "left": {"op": "input", "name": "X"},
                "right": {"op": "const", "value": 0}}
    if text == "5 <= X <= 251":
        return {"op": "range", "input": "X", "minimum": 5, "maximum": 251}
    raise ValueError(f"unrecognized proved guard: {text}")


def print_expression(node):
    if node["op"] == "const":
        return str(node["value"])
    if node["op"] == "input":
        return node["name"]
    if node["op"] == "add":
        return f"{print_expression(node['left'])} + {print_expression(node['right'])}"
    raise ValueError("unrecognized IL expression")


def print_guard(node):
    if node["op"] == "eq":
        return f"{print_expression(node['left'])} == {print_expression(node['right'])}"
    if node["op"] == "range":
        return f"{node['minimum']} <= {node['input']} && {node['input']} <= {node['maximum']}"
    raise ValueError("unrecognized IL guard")


def build_il(lua_source, cross_source, lua_holdout, cross_holdout, source_hashes,
             frozen_hash):
    lua_zero = next(row for row in lua_source["paths"] if row["path"] == "x0")
    lua_nine = next(row for row in lua_source["paths"] if row["path"] == "x9")
    certificates = [("lua", lua_zero["vm_path"]["payload_expression"],
                     lua_nine["vm_path"]["payload_expression"],
                     lua_holdout["vm_path"]["payload_expression"])]
    for engine in ("python", "javascript"):
        zero = next(row for row in cross_source["cases"] if row["engine"] == engine
                    and row["witness"] == 0)
        nine = next(row for row in cross_source["cases"] if row["engine"] == engine
                    and row["witness"] == 9)
        certificates.append((engine, zero["value_expression"],
                             nine["value_expression"],
                             cross_holdout[engine]["value_expression"]))
    require(all(zero == "10" and nine == fresh == "X + 5"
                for _, zero, nine, fresh in certificates),
            "native proof certificates disagree on common branch value")
    # The shared nonzero domain is the intersection of each engine's proved guard.
    require(lua_nine["vm_path"]["guard"] == "X != 0" and
            all(next(row for row in cross_source["cases"] if row["engine"] == engine
                     and row["witness"] == 9)["guard_expression"] == "5 <= X <= 251"
                for engine in ("python", "javascript")),
            "common guarded domain changed")
    x = z3.Int("X")
    check = z3.Solver()
    check.add(z3.And(x >= 5, x <= 251), x == 0)
    require(check.check() == z3.unsat, "bounded guard does not imply Lua nonzero path")
    cross_cases = {engine: {row["witness"]: row for row in cross_source["cases"]
                            if row["engine"] == engine}
                   for engine in ("python", "javascript")}
    require(all(cross_cases[engine][0]["call_argument"] == 5 and
                cross_cases[engine][9]["call_argument"] == "X" and
                cross_holdout[engine]["call_argument"] == "X"
                for engine in cross_cases),
            "cross-engine call-argument certificate changed")
    paths = []
    for witness in (0, 9):
        py = cross_cases["python"][witness]
        js = cross_cases["javascript"][witness]
        require(py["guard_expression"] == js["guard_expression"] and
                py["value_expression"] == js["value_expression"],
                "cross-engine value certificates disagree")
        argument = py["call_argument"]
        paths.append({"guard": guard_ir(py["guard_expression"]),
            "return_value": expression_ir(py["value_expression"]),
            "observed_child_call": {"argument": (
                {"op": "input", "name": "X"} if argument == "X" else
                {"op": "const", "value": argument}),
                "argument_evidence": "Python/JavaScript native call bridge only"}})
    pseudocode = "\n".join(f"if ({print_guard(path['guard'])}) "
                           f"return {print_expression(path['return_value'])};"
                           for path in paths) + "\nreturn unknown;"
    il = {"schema_version": "bounded-common-vm-il-v1",
        "construction": "finite certificate projection; P-code slice is an independent provenance audit",
        "input": {"name": "X", "type": "integer", "admitted": "X=0 or 5<=X<=251"},
        "paths": paths,
        "call": {"kind": "ObservedChildCall", "callee": "observed_child_call",
                 "argument_scope": "Python/JavaScript certificates; Lua native entry observed",
                 "non_value_effects": "retained in native path evidence; not eliminated"},
        "unknown": "all other input values or different native path/ABI/state",
        "pseudocode": pseudocode,
        "evidence": {"source_certificate_sha256": source_hashes,
            "frozen_native_summary_sha256": frozen_hash,
            "fresh_holdout_trace_sha256": {"lua": lua_holdout["trace_sha256"],
                "python": cross_holdout["python"]["trace_sha256"],
                "javascript": cross_holdout["javascript"]["trace_sha256"]}},
        "claim": "conditional certificate-based result-value projection; not automated SSA-to-IL generation or full effect erasure"}
    IL_OUTPUT.write_text(json.dumps(il, indent=2) + "\n")
    return il


def evaluate_il(il, value):
    require(il["schema_version"] == "bounded-common-vm-il-v1", "IL schema changed")
    def expression(node):
        if node["op"] == "const":
            return node["value"]
        if node["op"] == "input" and node["name"] == "X":
            return value
        if node["op"] == "add":
            return expression(node["left"]) + expression(node["right"])
        raise ValueError(f"unknown IL value operation {node['op']}")

    def guard(node):
        if node["op"] == "eq":
            return expression(node["left"]) == expression(node["right"])
        if node["op"] == "range" and node["input"] == "X":
            return node["minimum"] <= value <= node["maximum"]
        raise ValueError(f"unknown IL guard operation {node['op']}")

    matches = [path for path in il["paths"] if guard(path["guard"])]
    require(len(matches) <= 1, "overlapping IL paths")
    if matches:
        return expression(matches[0]["return_value"])
    return None


def string_holdouts():
    summary = load_json(STRING)
    decls, parsed = parse_segments(summary, {"prefix", "pair_continue",
        "pair_exit", "odd_tail_and_return", "even_return"})
    binary_hash = digest(JAVASCRIPT)
    require(summary["binary_sha256"] == binary_hash,
            "frozen JavaScript string binary changed")
    outcomes = []
    for value in STRING_INPUTS:
        path = ARTIFACTS / f"integrated_js_string_{value}.json.gz"
        meta, body, observed = expanded_records(path)
        result = apply_string_loop(summary, decls, parsed, value, meta,
                                   body["rows"], observed, binary_hash)
        oracles = {engine: checked_oracle(engine, "string", value)
                   for engine in ("lua", "python", "javascript")}
        require(len(set(oracles.values())) == 1 and
                all(text == observed["output"] for text in oracles.values()),
                "three string oracles disagree with observed JavaScript output")
        expected = "unknown(binary/schema/length domain)" if value == 123456789012 \
                   else "differentially_validated"
        require(result["status"] == expected, "frozen string summary admission changed")
        outcomes.append({"input_ascii": str(value), "length": len(str(value)),
                         "oracle_outputs": oracles, "native_js": result,
                         "trace_sha256": digest(path)})
    path = ARTIFACTS / "integrated_js_string_42.json.gz"
    meta, body, observed = expanded_records(path)
    changed = deepcopy(body["rows"])
    next(access for row in changed for access in row["memory"]
         if access["access"] & 2)["after"] ^= 1
    rejected = apply_string_loop(summary, decls, parsed, 42, meta, changed,
                                 observed, binary_hash)["status"]
    require(rejected.startswith("unknown("), "changed JS native write was admitted")
    return outcomes, {"changed_js_write": rejected}


def lifetime_snapshot():
    lua = load_json(ROOT / "lua_pool_common_effect_application_result.json")
    python = load_json(ROOT / "common_pool_effect_application_result.json")
    require(len(lua["cases"]) == 3 and len(python["cases"]) == 3 and
            all(case["final_live_mask"] == 0 for case in lua["cases"] + python["cases"]),
            "prior lifetime evidence is incomplete")
    return {"lua_long_string_pool": {"source_sha256": digest(
                ROOT / "lua_pool_common_effect_application_result.json"),
                "effects": sum(case["common_effects"] for case in lua["cases"]),
                "failure": "unknown(not exercised)"},
            "python_pylong_pool": {"source_sha256": digest(
                ROOT / "common_pool_effect_application_result.json"),
                "effects": sum(case["common_effects"] for case in python["cases"]),
                "failure": "observed pool exhaustion only"},
            "javascript_gc": "unknown(not analyzed)",
            "scope": "separate controlled fixtures; not lifetime effects of the branch/string benchmark programs"}


def lua_failure_retry():
    binary = ROOT / "lua_pool_failure_retry_fixture"
    source = binary.with_suffix(".c")
    output = ARTIFACTS / "integrated_lua_failure_retry.jsonl"
    raw = subprocess.check_output([str(binary)], text=True, timeout=30)
    output.write_text(raw)
    records = [json.loads(line) for line in raw.splitlines()]
    meta, result = records[0], records[-1]
    events = records[1:-1]
    require(meta["version"] == 504 and meta["slots"] == 1 and
            meta["capacity"] == 160 and meta["alignment"] == 16 and
            result == {"type": "result", "errors": 0, "final_live": 0,
                       "final_generation": 2},
            "Lua failure fixture geometry/result changed")

    def validate(history):
        live, generation, extent = 0, 0, 0
        admitted = []
        for index, event in enumerate(history):
            require(event["type"] == "event" and event["sequence"] == index and
                    event["live_before"] == live and
                    event["requested"] in (105, 121),
                    "Lua failure sequence or extent changed")
            kind = event["kind"]
            if kind == "Allocate":
                require(not live and event["requested"] <= meta["capacity"] and
                        event["pointer"] == meta["pool_base"] and
                        event["generation"] == generation + 1 and
                        event["live_after"] == 1, "Lua allocation state changed")
                generation, live, extent = generation + 1, 1, event["requested"]
            elif kind == "AllocationFailed":
                require(live and event["pointer"] == 0 and
                        event["generation"] == generation and
                        event["live_after"] == live and event["requested"] != extent,
                        "Lua failure changed ownership or extent")
            elif kind == "Free":
                require(live and event["pointer"] == meta["pool_base"] and
                        event["generation"] == generation and
                        event["requested"] == extent and
                        event["live_after"] == 0, "Lua release state changed")
                live, extent = 0, 0
            else:
                raise ValueError("unknown Lua allocator effect")
            admitted.append({"kind": kind, "requested_extent": event["requested"],
                             "generation": generation, "live_after": live})
        require((live, generation, extent) == (0, 2, 0),
                "Lua retry did not close its lifetime")
        require([row["kind"] for row in admitted] ==
                ["Allocate", "AllocationFailed", "AllocationFailed", "Free",
                 "Allocate", "Free"] and
                [row["requested_extent"] for row in admitted] ==
                [105, 121, 121, 105, 121, 121],
                "Lua expected failure/retry path changed")
        return admitted

    admitted = validate(events)
    controls = {}
    for name, index, field, replacement in (
            ("failure_changes_live_state", 1, "live_after", 0),
            ("retry_uses_stale_generation", 4, "generation", 1),
            ("release_wrong_extent", 3, "requested", 121)):
        changed = deepcopy(events)
        changed[index][field] = replacement
        try:
            validate(changed)
        except ValueError as error:
            controls[name] = str(error)
        else:
            raise ValueError(f"changed Lua failure history admitted: {name}")
    return {"binary_sha256": digest(binary), "source_sha256": digest(source),
            "observation_sha256": digest(output), "events": admitted,
            "protected_call_failure_status": "LUA_ERRMEM (checked by fixture)",
            "same_address_new_generation": True,
            "failed_allocator_callbacks_before_gc": 2,
            "successful_new_attempt_after_gc": True,
            "negative_controls": controls,
            "evidence": "controlled allocator observations; no frozen native summary for this binary"}


def main():
    lua_source, cross_source, source_hashes = source_proofs()
    lua_fresh, lua_records = lua_holdout()
    cross_fresh, cross_rows = cross_holdouts()
    frozen = load_json(COMMON)
    frozen_applied, branch_controls = bounded_numeric_segments(frozen, cross_rows)
    slices = native_slices(lua_records, cross_rows)
    il = build_il(lua_source, cross_source, lua_fresh, cross_fresh,
                  source_hashes, digest(COMMON))
    branch_cases = []
    for value in (0, 9, 42, 251, 252):
        prediction = evaluate_il(il, value)
        oracles = {engine: checked_oracle(engine, "branch", value)
                   for engine in ("lua", "python", "javascript")}
        require(len(set(oracles.values())) == 1, "branch oracles disagree")
        if prediction is not None:
            require(all(int(result) == prediction for result in oracles.values()),
                    "common IL prediction differs from an evaluation program")
        branch_cases.append({"input": value, "prediction": prediction,
                             "oracle_outputs": oracles,
                             "status": "admitted" if prediction is not None else "unknown(outside shared guard)"})
    string_cases, string_controls = string_holdouts()
    report = {"schema_version": "integrated-pipeline-result-v1",
        "benchmark": {"branch": "zero/nonzero arithmetic with one child call",
                      "string": "ASCII decimal input plus character 5",
                      "oracles": {name: digest(ROOT / name) for name in (
                          "integrated_case.lua", "integrated_case.py", "integrated_case.js")},
                      "oracle_not_analysis_input": True},
        "branch": {"source_proof_sha256": source_hashes,
            "fresh_input": BRANCH_INPUT,
            "fresh_native_certificates": {"lua": lua_fresh,
                "python": cross_fresh["python"],
                "javascript": cross_fresh["javascript"]},
            "frozen_numeric_segments": frozen_applied,
            "frozen_lua_numeric_segment": "unknown(different branch-call handler path)",
            "value_slices": slices,
            "common_il_sha256": digest(IL_OUTPUT),
            "cases": branch_cases,
            "negative_controls": branch_controls},
        "string": {"frozen_summary_sha256": digest(STRING),
                   "cases": string_cases,
                   "negative_controls": string_controls,
                   "lua_python_native_string_transition": "unknown(no frozen path)",
                   "javascript_gc": "unknown(no lifetime proof)"},
        "lifetime": {**lifetime_snapshot(),
                     "lua_failure_retry": lua_failure_retry()},
        "limits": ["native paths, source programs and runtimes are pinned to fixed binaries and ABI",
                   "fresh branch paths are re-proved; only Python/JS numeric handler segments use frozen common transition summaries",
                   "backward slice is a value projection; control dependencies and excluded effects are not erased",
                   "Lua/Python pool ownership comes from separate controlled fixtures",
                   "Lua failure/retry is allocator-observed only; no frozen native summary for that path, and JavaScript GC is unknown",
                   "all unsupported guards, path shapes, aliases and effects are unknown"]}
    REPORT.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"branch_admitted": sum(row["prediction"] is not None
                         for row in branch_cases),
        "branch_unknown": sum(row["prediction"] is None for row in branch_cases),
        "frozen_numeric_segments": len(frozen_applied),
        "string_native_matched": sum(row["native_js"]["status"] ==
                                     "differentially_validated" for row in string_cases),
        "string_native_unknown": sum(row["native_js"]["status"].startswith("unknown(")
                                     for row in string_cases)}))


if __name__ == "__main__":
    main()
