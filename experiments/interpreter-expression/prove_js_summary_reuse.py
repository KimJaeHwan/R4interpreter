"""Build a guarded AddSmi arithmetic-prefix summary and reuse it at another site.

Only the shared native prefix through the overflow branch is summarized. The
feedback, fused Star0 and next-bytecode dispatch suffix remains uncovered.
"""
from __future__ import annotations

import gzip
from hashlib import sha256
import json
from pathlib import Path
import shutil

import z3

from apply_transition_summary import expression
from pcode_transition_summary import FLAG_OFFSETS, REGISTER_OFFSETS, PathReplay
from prove_cross_value_path import lifted_instructions
from prove_lua_full_flow import initial_memory


ROOT = Path(__file__).resolve().parent
TRACE = ROOT / "artifacts/js_summary_reuse_9.json.gz"
SUMMARY = ROOT / "js_addsmi_prefix_summary.json"
RESULT = ROOT / "js_summary_reuse_result.json"
SLICE = ROOT / "js_slice_selection_result.json"
BOUNDARY = ROOT / "js_boundary_discovery_result.json"


def unsat(*terms):
    solver = z3.Solver()
    solver.set(timeout=30000)
    solver.add(*terms)
    verdict = solver.check()
    if verdict != z3.unsat:
        raise ValueError(f"required proof is {verdict}, expected unsat")


def prefix(rows):
    report = json.loads(BOUNDARY.read_text())
    if report["reuse_trace_sha256"] != sha256(TRACE.read_bytes()).hexdigest():
        raise ValueError("boundary discovery evidence is stale")
    cut = report["prefix"]
    end = cut["end_index_in_local_paths"]
    if (len(rows) <= end or hex(rows[0]["pc"]) != cut["entry_pc"] or
            hex(rows[end]["pc"]) != cut["end_branch_pc"] or
            hex(rows[end]["next_pc"]) != cut["exit_pc"] or
            end + 1 != cut["native_steps"]):
        raise ValueError("native path does not match discovered prefix cutpoint")
    return rows[:end + 1]


def concrete_bindings(decls, rows, overrides=None):
    before = {**rows[0]["registers"], **(overrides or {})}
    memory, _ = initial_memory(rows)
    substitutions = [(decls[f"R_{name.upper()}"], z3.BitVecVal(before[name], 64))
                     for name in REGISTER_OFFSETS.values()]
    substitutions += [(decls[f"F_{bit}"],
                       z3.BitVecVal((before["eflags"] >> bit) & 1, 8))
                      for bit in FLAG_OFFSETS.values()]
    substitutions.append((decls["M0"], memory))
    return substitutions


def concrete_value(expr, substitutions):
    value = z3.simplify(z3.substitute(expr, *substitutions))
    if not z3.is_bv_value(value):
        raise ValueError("summary has an unbound output dependency")
    return value.as_long()


def check_second_site(summary, second, overrides=None):
    if (summary.get("schema_version") != "native-segment-summary-v1" or
            summary.get("case", {}).get("ordered_effects") != [] or
            summary.get("case", {}).get("frame") !=
            "P-code and native trace show no memory writes in this prefix"):
        return {"status": "unknown(effect contract)"}
    expected_outputs = {name: "BV64" for name in REGISTER_OFFSETS.values()}
    expected_outputs.update({f"eflag{bit}": "BV8" for bit in FLAG_OFFSETS.values()})
    outputs = summary["case"].get("outputs", [])
    if (len(outputs) != len(expected_outputs) or
            {item.get("binding"): item.get("sort") for item in outputs} != expected_outputs):
        return {"status": "unknown(incomplete output contract)"}
    if (second[0]["pc"] != int(summary["identity"]["entry_cutpoint"], 16) or
            second[-1]["next_pc"] != int(summary["identity"]["exit_cutpoint"], 16) or
            second[-1]["next_pc"] != int(summary["case"]["successor"], 16)):
        return {"status": "unknown(cutpoint mismatch)"}
    code_digest = sha256(b"".join(bytes.fromhex(row["bytes"]) for row in second)).hexdigest()
    if code_digest != summary["identity"]["native_prefix_sha256"]:
        return {"status": "unknown(code validity)"}
    decls = {f"R_{name.upper()}": z3.BitVec(f"R_{name.upper()}", 64)
             for name in REGISTER_OFFSETS.values()}
    decls.update({f"F_{bit}": z3.BitVec(f"F_{bit}", 8)
                  for bit in FLAG_OFFSETS.values()})
    decls["M0"] = z3.Array("M0", z3.BitVecSort(64), z3.BitVecSort(8))
    guard = expression(summary["case"]["path_guard"], "Bool", decls)
    substitutions = concrete_bindings(decls, second, overrides)
    applied_guard = z3.simplify(z3.substitute(guard, *substitutions))
    if z3.is_false(applied_guard):
        return {"status": "unknown(outside conditional path)"}
    if not z3.is_true(applied_guard):
        return {"status": "unknown(guard undecidable)"}
    predicted = {}
    for item in summary["case"]["outputs"]:
        value = concrete_value(expression(item["expression"], item["sort"], decls),
                               substitutions)
        name = item["binding"]
        observed = (second[-1]["registers_after"][name] if name in REGISTER_OFFSETS.values()
                    else (second[-1]["registers_after"]["eflags"] >> int(name[5:])) & 1)
        if value != observed:
            return {"status": "unknown(state mismatch)", "binding": name}
        predicted[name] = value
    if any(access["access"] & 2 for row in second for access in row["memory"]):
        return {"status": "unknown(unexpected native write)"}
    read_footprint = [(hex(row["pc"]), access["address"], access["size"])
                      for row in second for access in row["memory"]
                      if access["access"] & 1]
    predicted_reads = [(item["pc"], concrete_value(expression(item["address"], "BV64", decls),
                                                      substitutions), item["width"])
                       for item in summary["case"]["reads"]]
    if read_footprint != predicted_reads:
        return {"status": "unknown(read footprint mismatch)"}
    return {"status": "differentially_validated",
            "predicted_tagged_result": hex(predicted["rbx"]),
            "observed_tagged_result": hex(second[-1]["registers_after"]["rbx"]),
            "native_steps_replayed": 0,
            "register_and_flag_outputs_checked": len(predicted),
            "read_footprint": read_footprint}


def main():
    binary = Path(shutil.which("node"))
    fixture = ROOT / "js_summary_reuse_fixture.js"
    with gzip.open(TRACE, "rt") as stream:
        records = [json.loads(line) for line in stream]
    meta, first_path, second_path, last = records
    if (meta["binary_sha256"] != sha256(binary.read_bytes()).hexdigest() or
            meta["fixture_sha256"] != sha256(fixture.read_bytes()).hexdigest() or
            [p["bytecode_offset"] for p in (first_path, second_path)] != [2, 6] or
            last["paths"] != 2):
        raise ValueError("trace identity or bytecode sites changed")
    selection = json.loads(SLICE.read_text())
    if (selection["trace_sha256"] != sha256(TRACE.read_bytes()).hexdigest() or
            selection["binary_sha256"] != meta["binary_sha256"] or
            selection["boundary_discovery_sha256"] != sha256(BOUNDARY.read_bytes()).hexdigest() or
            selection["value_slice"]["unresolved_reads"] or
            {item["branch_pc"] for item in selection["predicate_producers"]} !=
            {"0x1bb779d", "0x1bb77a9"}):
        raise ValueError("backward slice evidence is stale or unresolved")
    sink = selection["sink"]
    sink_offset = next((offset for offset, name in REGISTER_OFFSETS.items()
                        if name == sink["register"]), None)
    if sink_offset is None or not any(item["native_pc"] == sink["pc"] and
                                      item["opcode"] == "INT_ADD"
                                      for item in selection["value_slice"]["selected"]):
        raise ValueError("backward slice did not select the arithmetic result")
    first, second = prefix(first_path["rows"]), prefix(second_path["rows"])
    if [(r["pc"], r["bytes"]) for r in first] != [
            (r["pc"], r["bytes"]) for r in second]:
        raise ValueError("native prefix code differs between bytecode sites")
    if any(a["next_pc"] != b["pc"] for rows in (first, second)
           for a, b in zip(rows, rows[1:])):
        raise ValueError("summary path is not contiguous")
    regs = {offset: z3.BitVec(f"R_{name.upper()}", 64)
            for offset, name in REGISTER_OFFSETS.items()}
    flags = {offset: z3.BitVec(f"F_{bit}", 8)
             for offset, bit in FLAG_OFFSETS.items()}
    memory = z3.Array("M0", z3.BitVecSort(64), z3.BitVecSort(8))
    model = PathReplay(first[0], first, lifted_instructions(binary, first),
                       register_symbols=regs, flag_symbols=flags,
                       memory_symbol=memory)
    model.run()
    if model.effects:
        raise ValueError("arithmetic prefix has an unexpected memory effect")
    native_guard = z3.simplify(z3.And(*(item["condition"] for item in model.guards)))
    x = z3.Extract(63, 32, regs[0])
    immediate = z3.Select(memory, regs[160] + regs[136] + z3.BitVecVal(1, 64))
    expected = z3.Concat(x + z3.SignExt(24, immediate), z3.BitVecVal(0, 32))
    smi = z3.Extract(31, 0, regs[0]) == z3.BitVecVal(0, 32)
    unsat(native_guard, smi, model.regs[sink_offset] != expected)
    domain = z3.And(z3.UGE(x, z3.BitVecVal(5, 32)),
                    z3.ULE(x, z3.BitVecVal(251, 32)),
                    immediate == z3.BitVecVal(5, 8))
    unsat(domain, smi, z3.Not(native_guard))
    guard = z3.simplify(z3.And(native_guard, smi, domain))
    decls = {f"R_{name.upper()}": regs[offset]
             for offset, name in REGISTER_OFFSETS.items()}
    decls.update({f"F_{bit}": flags[offset]
                  for offset, bit in FLAG_OFFSETS.items()})
    decls["M0"] = memory
    unsat(z3.Not(z3.substitute(guard, *concrete_bindings(decls, first))))
    summary = {"schema_version": "native-segment-summary-v1",
        "identity": {"binary_sha256": meta["binary_sha256"],
                     "native_prefix_sha256": sha256(b"".join(bytes.fromhex(r["bytes"])
                                                        for r in first)).hexdigest(),
                     "entry_cutpoint": hex(first[0]["pc"]),
                     "exit_cutpoint": hex(first[-1]["next_pc"]),
                     "bytecode_opcode": "0x4b", "code_epoch": "Node --jitless, fixed ELF"},
        "interface": {"registers": sorted(decls),
                      "memory": "first-read byte array M0",
                      "input_value": "tagged Smi in R_RAX",
                      "immediate": "M0[R_R12 + R_R9 + 1]"},
        "case": {"path_guard": guard.sexpr(),
                 "outputs": ([{"binding": name, "sort": "BV64",
                               "expression": z3.simplify(model.regs[offset]).sexpr()}
                              for offset, name in REGISTER_OFFSETS.items()] +
                             [{"binding": f"eflag{bit}", "sort": "BV8",
                               "expression": z3.simplify(model.flags[offset]).sexpr()}
                              for offset, bit in FLAG_OFFSETS.items()]),
                 "reads": [{"pc": item["pc"], "width": item["width"],
                            "address": z3.simplify(item["address"]).sexpr()}
                           for item in model.reads],
                 "ordered_effects": [],
                 "frame": "P-code and native trace show no memory writes in this prefix",
                 "successor": hex(first[-1]["next_pc"]),
                 "uncovered": "feedback check, Star0 fusion, dispatch and slow paths"},
        "evidence": {"source_bytecode_offset": first_path["bytecode_offset"],
                     "source_trace_sha256": sha256(TRACE.read_bytes()).hexdigest(),
                     "boundary_discovery_sha256": sha256(BOUNDARY.read_bytes()).hexdigest(),
                     "backward_slice_sha256": sha256(SLICE.read_bytes()).hexdigest(),
                     "value_slice_pcode_operations": len(selection["value_slice"]["selected"]),
                     "total_prefix_pcode_operations": selection["pcode_operations"],
                     "native_prefix_steps": len(first),
                     "pcode_operations": model.operation_count,
                     "guard_and_result_proof": "unsat counterexample",
                     "domain": "5 <= X <= 251 and immediate=5"}}
    SUMMARY.write_text(json.dumps(summary, indent=2) + "\n")
    summary = json.loads(SUMMARY.read_text())
    reused = check_second_site(summary, second)
    rejected = check_second_site(summary, second,
                                 {"rax": second[0]["registers"]["rax"] | 1})
    if rejected["status"] != "unknown(outside conditional path)":
        raise ValueError("non-Smi entry was incorrectly accepted")
    noncanonical = check_second_site(summary, second,
                                     {"rax": second[0]["registers"]["rax"] | 2})
    outside_range = check_second_site(summary, second, {"rax": 252 << 32})
    wrong_successor = check_second_site(summary,
        [*second[:-1], {**second[-1], "next_pc": 0}])
    if any(item["status"] != "unknown(outside conditional path)"
           for item in (noncanonical, outside_range)):
        raise ValueError("summary accepted an input outside its proved domain")
    if wrong_successor["status"] != "unknown(cutpoint mismatch)":
        raise ValueError("summary accepted the wrong continuation")
    result = {"status": "guarded arithmetic-prefix summary reused at second bytecode site",
        "binary_sha256": meta["binary_sha256"],
        "fixture_sha256": meta["fixture_sha256"],
        "source_offset": first_path["bytecode_offset"],
        "target_offset": second_path["bytecode_offset"],
        "source_entry": first_path["entry_smi"],
        "target_entry": second_path["entry_smi"],
        "target_output": second_path["exit_smi"],
        "summary_sha256": sha256(SUMMARY.read_bytes()).hexdigest(),
        "target_validation": reused,
        "non_smi_probe": rejected,
        "noncanonical_smi_probe": noncanonical,
        "out_of_range_probe": outside_range,
        "wrong_successor_probe": wrong_successor,
        "uncovered": summary["case"]["uncovered"]}
    RESULT.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"status": result["status"],
                      "source_offset": 2, "target_offset": 6,
                      "target_prefix_result": int(reused["predicted_tagged_result"], 16) >> 32,
                      "native_steps_replayed_at_target": 0}))


if __name__ == "__main__":
    main()
