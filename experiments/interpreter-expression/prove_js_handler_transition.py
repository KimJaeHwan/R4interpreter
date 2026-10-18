"""Prove and reuse observed complete AddSmi-to-next-handler transitions.

There are two bounded cases: fused Star0 followed by AddSmi, and a direct
dispatch to Return. Each case includes all 16 GPRs and five modeled flags, ordered native memory
writes, read addresses, RAX result, VM cursor and next native handler. The
target is evaluated from the serialized source summary with no target P-code
replay. Alternate paths are unknown.
"""
from __future__ import annotations

import gzip
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import shutil

import z3

from apply_transition_summary import expression
from pcode_transition_summary import FLAG_OFFSETS, REGISTER_OFFSETS, PathReplay
from prove_cross_value_path import lifted_instructions
from prove_js_summary_reuse import concrete_bindings, concrete_value, unsat


ROOT = Path(__file__).resolve().parent
SOURCE_TRACE = ROOT / "artifacts/js_summary_reuse_9.json.gz"
TWO_ADDS_TARGET = ROOT / "artifacts/js_summary_reuse_37.json.gz"
HOLDOUTS = [ROOT / f"artifacts/js_handler_holdout_{value}.json.gz"
            for value in (37, 251, 252)]
SUMMARY = ROOT / "js_addsmi_full_handler_summary.json"
RESULT = ROOT / "js_full_handler_reuse_result.json"


def records(path):
    with gzip.open(path, "rt") as stream:
        return [json.loads(line) for line in stream]


def path_shape(rows):
    shape = [[hex(row["pc"]), row["bytes"], hex(row["next_pc"])]
             for row in rows]
    return sha256(json.dumps(shape, separators=(",", ":")).encode()).hexdigest()


def observed_accesses(rows, mode):
    return [{"pc": hex(row["pc"]), "address": access["address"],
             "width": access["size"], "value": access["after"]}
            for row in rows for access in row["memory"] if access["access"] & mode]


def make_case(rows, binary, label):
    regs = {offset: z3.BitVec(f"R_{name.upper()}", 64)
            for offset, name in REGISTER_OFFSETS.items()}
    flags = {offset: z3.BitVec(f"F_{bit}", 8)
             for offset, bit in FLAG_OFFSETS.items()}
    memory = z3.Array("M0", z3.BitVecSort(64), z3.BitVecSort(8))
    model = PathReplay(rows[0], rows, lifted_instructions(binary, rows),
                       register_symbols=regs, flag_symbols=flags,
                       memory_symbol=memory)
    model.run()
    if model.successor is None or len(model.effects) not in (0, 1):
        raise ValueError("handler has an unsupported successor or effect shape")
    native_writes = observed_accesses(rows, 2)
    if [(item["pc"], item["observed_address"], item["width"], item["observed"])
        for item in model.effects] != [
            (item["pc"], item["address"], item["width"], item["value"])
            for item in native_writes]:
        raise ValueError("P-code effect inventory differs from native memory writes")
    guard = z3.simplify(z3.And(*(item["condition"] for item in model.guards)))
    x = z3.Extract(63, 32, regs[0])
    immediate = z3.Select(memory, regs[160] + regs[136] + z3.BitVecVal(1, 64))
    domain = z3.And(z3.Extract(31, 0, regs[0]) == z3.BitVecVal(0, 32),
                    z3.UGE(x, z3.BitVecVal(5, 32)),
                    z3.ULE(x, z3.BitVecVal(251, 32)),
                    immediate == z3.BitVecVal(5, 8))
    result = z3.Concat(x + z3.BitVecVal(5, 32), z3.BitVecVal(0, 32))
    unsat(domain, guard, model.regs[0] != result)
    for item in model.effects:
        unsat(domain, guard, item["value"] != result)
    decls = {f"R_{name.upper()}": regs[offset]
             for offset, name in REGISTER_OFFSETS.items()}
    decls.update({f"F_{bit}": flags[offset]
                  for offset, bit in FLAG_OFFSETS.items()})
    decls["M0"] = memory
    if not z3.is_true(z3.simplify(z3.substitute(guard,
                                                *concrete_bindings(decls, rows)))):
        raise ValueError("source witness does not satisfy the complete path guard")
    return {"label": label,
        "identity": {"entry_pc": hex(rows[0]["pc"]),
                     "next_handler_pc": hex(rows[-1]["next_pc"]),
                     "path_shape_sha256": path_shape(rows),
                     "native_steps": len(rows)},
        "guard": z3.simplify(z3.And(domain, guard)).sexpr(),
        "outputs": ([{"binding": name, "sort": "BV64",
                      "expression": z3.simplify(model.regs[offset]).sexpr()}
                     for offset, name in REGISTER_OFFSETS.items()] +
                    [{"binding": f"eflag{bit}", "sort": "BV8",
                      "expression": z3.simplify(model.flags[offset]).sexpr()}
                     for offset, bit in FLAG_OFFSETS.items()]),
        "reads": [{"pc": item["pc"], "width": item["width"],
                   "address": z3.simplify(item["address"]).sexpr()}
                  for item in model.reads],
        "ordered_effects": [{"pc": item["pc"], "width": item["width"],
                             "address": z3.simplify(item["address"]).sexpr(),
                             "value": z3.simplify(item["value"]).sexpr()}
                            for item in model.effects],
        "vm_cursor": z3.simplify(model.regs[160] + model.regs[136]).sexpr(),
        "successor": z3.simplify(model.successor).sexpr(),
        "witness": {"entry_smi": rows[0]["registers"]["rax"] >> 32,
                    "exit_smi": rows[-1]["registers_after"]["rax"] >> 32,
                    "pcode_operations": model.operation_count,
                    "guard_count": len(model.guards),
                    "reads": len(model.reads), "native_writes": len(native_writes),
                    "semantic_counterexample": "unsat"}}


def apply_case(summary, rows, binary_hash):
    if (summary.get("schema_version") != "native-handler-transition-v1" or
            summary.get("engine") != "javascript"):
        return {"status": "unknown(summary schema or engine)"}
    if binary_hash != summary["binary_sha256"]:
        return {"status": "unknown(binary identity)"}
    if not rows or any(a["next_pc"] != b["pc"] for a, b in zip(rows, rows[1:])):
        return {"status": "unknown(path gap)"}
    candidates = [case for case in summary["cases"]
                  if case["identity"]["entry_pc"] == hex(rows[0]["pc"]) and
                  case["identity"]["native_steps"] == len(rows) and
                  case["identity"]["path_shape_sha256"] == path_shape(rows)]
    if len(candidates) != 1:
        return {"status": "unknown(path identity)"}
    case = candidates[0]
    if case["identity"]["next_handler_pc"] != hex(rows[-1]["next_pc"]):
        return {"status": "unknown(successor cutpoint)"}
    expected_outputs = {name: "BV64" for name in REGISTER_OFFSETS.values()}
    expected_outputs.update({f"eflag{bit}": "BV8" for bit in FLAG_OFFSETS.values()})
    if (len(case["outputs"]) != len(expected_outputs) or
            {item["binding"]: item["sort"] for item in case["outputs"]} != expected_outputs):
        return {"status": "unknown(incomplete output contract)"}
    decls = {f"R_{name.upper()}": z3.BitVec(f"R_{name.upper()}", 64)
             for name in REGISTER_OFFSETS.values()}
    decls.update({f"F_{bit}": z3.BitVec(f"F_{bit}", 8)
                  for bit in FLAG_OFFSETS.values()})
    decls["M0"] = z3.Array("M0", z3.BitVecSort(64), z3.BitVecSort(8))
    substitutions = concrete_bindings(decls, rows)
    guard = z3.simplify(z3.substitute(expression(case["guard"], "Bool", decls),
                                      *substitutions))
    if not z3.is_true(guard):
        return {"status": "unknown(outside case guard)"}
    predicted = {}
    for item in case["outputs"]:
        value = concrete_value(expression(item["expression"], item["sort"], decls),
                               substitutions)
        name = item["binding"]
        observed = (rows[-1]["registers_after"][name]
                    if name in REGISTER_OFFSETS.values() else
                    (rows[-1]["registers_after"]["eflags"] >> int(name[5:])) & 1)
        if value != observed:
            return {"status": "unknown(state mismatch)", "binding": name}
        predicted[name] = value
    predicted_reads = [{"pc": item["pc"],
                        "address": concrete_value(expression(item["address"], "BV64", decls),
                                                  substitutions),
                        "width": item["width"]}
                       for item in case["reads"]]
    actual_reads = [{k: item[k] for k in ("pc", "address", "width")}
                    for item in observed_accesses(rows, 1)]
    if predicted_reads != actual_reads:
        return {"status": "unknown(read footprint mismatch)"}
    predicted_effects = [{"pc": item["pc"],
                          "address": concrete_value(expression(item["address"], "BV64", decls),
                                                    substitutions),
                          "width": item["width"],
                          "value": concrete_value(expression(item["value"],
                                                     f"BV{item['width']*8}", decls),
                                                  substitutions)}
                         for item in case["ordered_effects"]]
    actual_effects = observed_accesses(rows, 2)
    if predicted_effects != actual_effects:
        return {"status": "unknown(ordered effects mismatch)"}
    successor = concrete_value(expression(case["successor"], "BV64", decls),
                               substitutions)
    cursor = concrete_value(expression(case["vm_cursor"], "BV64", decls),
                            substitutions)
    if (successor != rows[-1]["next_pc"] or
            cursor != (rows[-1]["registers_after"]["r12"] +
                       rows[-1]["registers_after"]["r9"]) & ((1 << 64) - 1)):
        return {"status": "unknown(continuation mismatch)"}
    return {"status": "differentially_validated_full_observed_path",
            "case": case["label"], "result_raw": hex(predicted["rax"]),
            "result_smi": predicted["rax"] >> 32,
            "next_handler_pc": hex(successor), "vm_cursor": hex(cursor),
            "ordered_effects": [{**item, "address": hex(item["address"]),
                                 "value": hex(item["value"])}
                                for item in predicted_effects],
            "register_and_flag_outputs_checked": len(predicted),
            "native_steps": len(rows), "target_pcode_steps_replayed": 0}


def main():
    binary = Path(shutil.which("node"))
    source = records(SOURCE_TRACE)
    target = records(TWO_ADDS_TARGET)
    binary_hash = sha256(binary.read_bytes()).hexdigest()
    fixture = ROOT / "js_summary_reuse_fixture.js"
    if (source[0]["binary_sha256"] != binary_hash or
            target[0]["binary_sha256"] != binary_hash or
            any(item[0]["fixture_sha256"] != sha256(fixture.read_bytes()).hexdigest()
                for item in (source, target)) or
            [path["bytecode_offset"] for path in source[1:3]] != [2, 6]):
        raise ValueError("source or twoAdds target trace identity changed")
    cases = [make_case(source[index]["rows"], binary, label)
             for index, label in ((1, "fused_star_then_add"),
                                  (2, "dispatch_to_return"))]
    summary = {"schema_version": "native-handler-transition-v1",
        "binary_sha256": binary_hash, "engine": "javascript",
        "scope": "two observed AddSmi-to-next-handler paths with Smi X in [5,251] and immediate 5",
        "entry_interface": "all GPRs, five modeled flags, first-read memory M0",
        "cases": cases,
        "source_trace_sha256": sha256(SOURCE_TRACE.read_bytes()).hexdigest(),
        "limits": ["observed path identities and fixed Node --jitless binary",
                   "other Smi/Number, feedback and error paths are unknown",
                   "full path ends at next native handler entry, not caller return"]}
    SUMMARY.write_text(json.dumps(summary, indent=2) + "\n")
    reloaded = json.loads(SUMMARY.read_text())
    target_paths = [({"fixture": "twoAdds", "bytecode_offset": target[i]["bytecode_offset"],
                     "trace_sha256": sha256(TWO_ADDS_TARGET.read_bytes()).hexdigest()},
                    target[i]["rows"], target[0]["binary_sha256"])
                   for i in (1, 2)]
    holdout_fixture = ROOT / "js_holdout_fixture.js"
    for holdout in HOLDOUTS:
        meta, path, result = records(holdout)
        if (not meta["full_handler"] or meta["binary_sha256"] != binary_hash or
                meta["fixture_sha256"] != sha256(holdout_fixture.read_bytes()).hexdigest() or
                result["output"] != meta["input"] + 5):
            raise ValueError("full-handler holdout trace or oracle changed")
        target_paths.append(({"fixture": "wrappedAdd", "input": meta["input"],
                             "oracle_output": result["output"],
                             "trace_sha256": sha256(holdout.read_bytes()).hexdigest()},
                            path["rows"], meta["binary_sha256"]))
    results = []
    for identity, rows, target_binary in target_paths:
        application = apply_case(reloaded, rows, target_binary)
        if application["status"].startswith("differentially_validated"):
            if ("oracle_output" in identity and
                    application["result_smi"] != identity["oracle_output"]):
                raise ValueError("summary result differs from holdout program")
        elif identity.get("input") != 252:
            raise ValueError(f"supported target was not applied: {identity} {application}")
        results.append({**identity, "application": application})
    if not results[-1]["application"]["status"].startswith("unknown("):
        raise ValueError("out-of-domain Smi was incorrectly accepted")
    first_target = target[1]["rows"]
    changed_tag = deepcopy(first_target)
    changed_tag[0]["registers"]["rax"] |= 1
    missing_output = deepcopy(reloaded)
    missing_output["cases"][0]["outputs"] = [
        item for item in missing_output["cases"][0]["outputs"]
        if item["binding"] != "r8"]
    missing_write = deepcopy(first_target)
    write_row = next(row for row in missing_write if any(
        access["access"] & 2 for access in row["memory"]))
    write_row["memory"] = [access for access in write_row["memory"]
                           if not access["access"] & 2]
    changed_write = deepcopy(first_target)
    next(access for row in changed_write for access in row["memory"]
         if access["access"] & 2)["after"] ^= 1
    extra_write = deepcopy(first_target)
    extra_write[-1]["memory"].append({"address": 0x1000, "size": 8,
                                      "access": 2, "before": 0, "after": 1})
    wrong_successor = deepcopy(first_target)
    wrong_successor[-1]["next_pc"] = 0
    bad_schema = {**reloaded, "schema_version": "unsupported-v0"}
    bad_engine = {**reloaded, "engine": "python"}
    negative_inputs = {
        "wrong_binary": (reloaded, first_target, "wrong-binary-hash"),
        "non_smi_tag": (reloaded, changed_tag, binary_hash),
        "missing_output": (missing_output, first_target, binary_hash),
        "missing_write": (reloaded, missing_write, binary_hash),
        "changed_write": (reloaded, changed_write, binary_hash),
        "extra_write": (reloaded, extra_write, binary_hash),
        "wrong_successor": (reloaded, wrong_successor, binary_hash),
        "unsupported_schema": (bad_schema, first_target, binary_hash),
        "wrong_engine": (bad_engine, first_target, binary_hash)}
    negative_probes = {name: apply_case(*arguments)["status"]
                       for name, arguments in negative_inputs.items()}
    if any(not status.startswith("unknown(") for status in negative_probes.values()):
        raise ValueError("invalid complete-handler application was accepted")
    report = {"status": "bounded complete observed AddSmi handler transitions reused",
        "summary_sha256": sha256(SUMMARY.read_bytes()).hexdigest(),
        "source_trace_sha256": summary["source_trace_sha256"],
        "cases": results,
        "negative_probes": negative_probes,
        "metrics": {"target_cases": len(results),
                    "applied_correct": sum(item["application"]["status"].startswith(
                        "differentially_validated") for item in results),
                    "unknown": sum(item["application"]["status"].startswith("unknown(")
                                   for item in results),
                    "target_pcode_steps_replayed": 0},
        "limits": summary["limits"]}
    RESULT.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report["metrics"]))


if __name__ == "__main__":
    main()
