"""Prove one bounded value IL against three observed native execution paths.

The value IL has no native effects. Each adapter retains its own binary,
path, input representation, output decode, and complete native-effect evidence.
This is conditional refinement for pinned paths, not language equivalence.
"""
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
import z3

from common_observed_transition import apply_case, shape
from cross_dispatch_pcode import read_vaddr
from discover_dispatch_intervals import (admitted, candidates, choose_summary,
                                         run_case)
from native_ast_il import Builder, reify
from pcode_transition_summary import FLAG_OFFSETS, REGISTER_OFFSETS, PathReplay
from project_lua_call_bridge import load_instructions, output_word
from prove_cross_full_flow import CACHE_BASE, JAVASCRIPT, PYTHON, load_trace
from prove_cross_value_path import lifted_instructions, small_int_memory
from prove_lua_full_flow import (BINARY as LUA, first_memory, first_step,
                                 initial_memory, trace_records)


ROOT = Path(__file__).resolve().parent
ARTIFACTS = ROOT / "artifacts"
OUTPUT = ROOT / "common_numeric_refinement_result.json"
COMMON = ROOT / "common_three_engine_transitions.json"
LUA_PROOF = ROOT / "lua_branch_full_flow.json"
SOURCE_TRACES = {
    "lua": ARTIFACTS / "lua_branch_full_flow_x9.jsonl",
    "python": ARTIFACTS / "cross_python_value_9_native.json",
    "javascript": ARTIFACTS / "cross_js_value_9_native.json"}
FRESH_TRACES = {
    "lua": ARTIFACTS / "integrated_lua_branch_42.jsonl",
    "python": ARTIFACTS / "next_boundary_py_43.json.gz",
    "javascript": ARTIFACTS / "next_boundary_js_43.json.gz"}


def digest(path):
    return sha256(path.read_bytes()).hexdigest()


def query(*clauses, want):
    solver = z3.Solver()
    solver.set(timeout=30000)
    solver.add(*clauses)
    result = solver.check()
    if result != want:
        raise ValueError(f"refinement query expected {want}, got {result}")
    return str(result)


def domain(x):
    return z3.And(z3.UGE(x, z3.BitVecVal(5, 32)),
                  z3.ULE(x, z3.BitVecVal(251, 32)))


def core_il(x, constant):
    builder = Builder([{"name": "X", "sort": "BV32"}])
    root = builder.add(x + z3.BitVecVal(constant, 32))
    il = {"schema_version": "bounded-value-il-v1", "inputs": [
        {"name": "X", "sort": "BV32"}], "nodes": builder.nodes,
        "result": {"node": root, "name": "Y", "sort": "BV32"},
        "domain": "unsigned X in [5,251]", "interpretation":
        "nonnegative integer; signed and unsigned values coincide in this domain"}
    y = reify(il, {"X": x})[root]
    query(y != x + z3.BitVecVal(constant, 32), want=z3.unsat)
    return il, y


def infer_add_constant(x, guard, decoded):
    """Propose an additive constant from one native AST model; proof follows."""
    solver = z3.Solver()
    solver.set(timeout=30000)
    solver.add(domain(x), guard, x == z3.BitVecVal(9, 32))
    if solver.check() != z3.sat:
        raise ValueError("native AST has no source witness for additive inference")
    observed = solver.model().eval(decoded, model_completion=True)
    if not z3.is_bv_value(observed):
        raise ValueError("native decoded value has an unsupported sort")
    return (observed.as_long() - 9) & 0xFFFFFFFF


def refinement(x, guard, decoded, y):
    return {"path_guard_covers_core_domain": query(domain(x), z3.Not(guard),
                                                     want=z3.unsat),
            "decoded_native_equals_value_il": query(domain(x), guard,
                                                       decoded != y, want=z3.unsat),
            "wrong_plus_six_rejected": query(domain(x), guard,
                decoded != x + z3.BitVecVal(6, 32), want=z3.sat)}


def replay(rows, binary, memory, register_symbols):
    before = rows[0]["registers"]
    model = PathReplay(rows[0], rows, lifted_instructions(binary, rows),
        register_symbols={offset: register_symbols.get(name,
            z3.BitVecVal(before[name], 64))
            for offset, name in REGISTER_OFFSETS.items()},
        flag_symbols={offset: z3.BitVecVal((before["eflags"] >> bit) & 1, 8)
                      for offset, bit in FLAG_OFFSETS.items()},
        memory_symbol=memory, address_guards=True)
    model.run()
    guard = z3.And(*(item["condition"] for item in model.guards))
    return model, guard


def frozen_path_bridge(common, engine, source_rows, source_meta, input_pointer=None):
    """Link a value proof trace to the independently frozen native path."""
    short = "python" if engine == "python" else "js"
    path = ARTIFACTS / f"integrated_{short}_branch_42.json.gz"
    binary = PYTHON if engine == "python" else JAVASCRIPT
    _, rows, _ = load_trace(path, engine, 42, binary)
    case = choose_summary(common, engine)
    identity = case["identity"]
    matching = [item for item in candidates(rows)
                if item["native_steps"] == identity["native_steps"] and
                shape(rows[item["begin"]:item["end_exclusive"]],
                      identity["path_shape_mode"]) == identity["path_shape_sha256"]]
    if len(matching) != 1:
        raise ValueError("frozen 42 path bridge is absent or ambiguous")
    item = matching[0]
    frozen = rows[item["begin"]:item["end_exclusive"]]
    if [(row["pc"], row["next_pc"]) for row in source_rows] != [
            (row["pc"], row["next_pc"]) for row in frozen]:
        raise ValueError("value proof and frozen native transition take different native paths")
    # The older value trace omitted instruction bytes. Decode them from the
    # pinned binary, then subject that very trace to the frozen full-effect
    # evaluator rather than merely comparing its length with the summary.
    lifted = deepcopy(source_rows)
    disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
    for row in lifted:
        decoded = next(disassembler.disasm(read_vaddr(binary, row["pc"],
            row["pc"] + 15), row["pc"], count=1), None)
        if decoded is None:
            raise ValueError("pinned source instruction cannot be decoded")
        row["bytes"] = decoded.bytes.hex()
    if shape(lifted, identity["path_shape_mode"]) != identity["path_shape_sha256"]:
        raise ValueError("value proof trace differs from frozen full path identity")
    adapter = None
    if engine == "python":
        cache_hash = source_meta["runtime_cache_sha256_at_sync"]
        adapter = {"input": 9, "runtime_cache_sha256_at_entry": cache_hash,
            "runtime_cache_sha256_at_exit": cache_hash,
            "left_pointer": input_pointer, "right_pointer": CACHE_BASE + 10 * 32,
            "output_slot": lifted[-1]["registers_after"]["r15"] - 8}
    applied = apply_case(common, case, binary, lifted, adapter)
    if applied["status"] != "differentially_validated":
        raise ValueError(f"value proof source did not satisfy native effects: {applied}")
    return {"same_pc_next_sequence_as_frozen_42": True,
            "pinned_binary_makes_instruction_bytes_identical": True,
            "frozen_42_trace_sha256": digest(path),
            "source_and_frozen_native_steps": len(frozen),
            "source_value_trace_frozen_transition_status": applied["status"],
            "source_value_trace_reads_checked": applied["reads_checked"],
            "source_value_trace_writes_checked": applied["ordered_writes_checked"]}


def lua_source(x):
    path = SOURCE_TRACES["lua"]
    records = trace_records(path)
    prior = json.loads(LUA_PROOF.read_text())
    source_proof = next(item for item in prior["paths"] if item["path"] == "x9")
    if (records[0]["input"] != 9 or digest(LUA) != prior["binary_sha256"] or
            source_proof["trace_sha256"] != digest(path)):
        raise ValueError("Lua source proof identity changed")
    branch = next(row for row in records if row.get("type") == "replay_step"
                  and row["pc"] == 0x417E50)
    source = max((row for row in records if row.get("type") == "replay_step"
                  and row["pc"] == 0x416EA1 and row["step"] < branch["step"]),
                 key=lambda row: row["step"])
    add = first_step(records, 0x417CEA)
    rows = [row for row in records if row.get("type") == "replay_step"
            and source["step"] <= row["step"] < add["step"]] + [add]
    if any(left["next_pc"] != right["pc"] for left, right in zip(rows, rows[1:])):
        raise ValueError("Lua source path is discontinuous")
    source_access = first_memory(source, 1)
    x64 = z3.ZeroExt(32, x)
    memory, _ = initial_memory(rows, [(source_access["address"], x64, 9)])
    before = rows[0]["registers"]
    model = PathReplay(rows[0], rows,
        load_instructions((row["pc"] for row in rows)),
        register_symbols={offset: z3.BitVecVal(before[name], 64)
                          for offset, name in REGISTER_OFFSETS.items()},
        flag_symbols={offset: z3.BitVecVal((before["eflags"] >> bit) & 1, 8)
                      for offset, bit in FLAG_OFFSETS.items()},
        memory_symbol=memory, address_guards=True)
    model.run()
    guard = z3.And(*(item["condition"] for item in model.guards))
    native = model.regs[160]
    store = first_memory(add, 2)
    decoded = z3.Extract(31, 0, native)
    constant = infer_add_constant(x, guard, decoded)
    y = x + z3.BitVecVal(constant, 32)
    query(domain(x), guard, native != z3.ZeroExt(32, y), want=z3.unsat)
    query(domain(x), guard,
          output_word(model.memory, store["address"]) != native,
          want=z3.unsat)
    proof = refinement(x, guard, decoded, y)
    return {"engine": "lua", "input_decode": "observed Lua VM source slot: zero_extend32(X)",
        "output_decode": "low32(R12 VM payload); high32 proven zero in domain",
        "inferred_additive_constant": constant,
        "native_value_sort": "BV64", "native_steps": len(rows),
        "native_reads": len(model.reads), "native_writes": len(model.effects),
        "native_pcode_operations": model.operation_count,
        "binary_sha256": digest(LUA), "source_trace_sha256": digest(path),
        "residual_contract": {"kind": "full-flow proof and original trace",
            "proof_sha256": digest(LUA_PROOF),
            "source_path_trace_hash_matches_full_flow_proof": True,
            "scope": "other native effects remain in the trace; no effect removed"},
        "proof": {**proof, "full_payload_matches_zero_extended_il": "unsat",
                  "payload_store_matches_register": "unsat"}}


def python_source(x, common):
    path = SOURCE_TRACES["python"]
    report = json.loads(path.read_text())
    if report["binary_sha256"] != digest(PYTHON) or \
            report["runtime_cache_sha256_at_sync"] != \
            common["cases"][1]["preconditions"]["cache_sha256"]:
        raise ValueError("Python source cache or binary identity changed")
    selected = [item for item in report["paths"] if
                item["entry_values"]["left"] == 9 and
                item["entry_values"]["right"] == 5]
    if len(selected) != 1:
        raise ValueError("Python source number path ambiguous")
    rows = selected[0]["rows"]
    input_pointer = int(selected[0]["entry_values"]["left_address"], 16)
    memory, _ = small_int_memory(rows, input_pointer, 9, x)
    model, guard = replay(rows, PYTHON, memory, {})
    result_store = next(item for item in model.effects
                        if item["pc"] == hex(0x562316))
    slot = result_store["observed_address"]
    pointer = output_word(model.memory, slot)
    decoded = z3.Extract(31, 0,
        z3.LShR(pointer - z3.BitVecVal(CACHE_BASE, 64), 5)) - \
        z3.BitVecVal(5, 32)
    constant = infer_add_constant(x, guard, decoded)
    y = x + z3.BitVecVal(constant, 32)
    expected = z3.BitVecVal(CACHE_BASE, 64) + \
        ((z3.ZeroExt(32, y) + z3.BitVecVal(5, 64)) << 5)
    query(domain(x), guard, pointer != expected, want=z3.unsat)
    query(domain(x), expected == z3.BitVecVal(input_pointer, 64),
          want=z3.unsat)
    # For this pinned cache image, every result object key 10..256 has the
    # matching 32-bit digit. The symbolic source object is key 9, so the
    # output cannot alias its substituted digit in the admitted domain.
    cache = read_vaddr(PYTHON, CACHE_BASE, CACHE_BASE + 262 * 32)
    if sha256(cache).hexdigest() != report["runtime_cache_sha256_at_sync"]:
        raise ValueError("Python cache image hash changed")
    for value in range(10, 257):
        offset = (value + 5) * 32
        if (int.from_bytes(cache[offset + 16:offset + 24], "little") != 8 or
                int.from_bytes(cache[offset + 24:offset + 28], "little") != value):
            raise ValueError("Python cache tag or result digit differs")
    cache_end = CACHE_BASE + len(cache)
    for effect in model.effects:
        query(domain(x), effect["address"] != z3.BitVecVal(
            effect["observed_address"], 64), want=z3.unsat)
        if (effect["observed_address"] < cache_end and CACHE_BASE <
                effect["observed_address"] + effect["width"]):
            raise ValueError("symbolic Python source path writes result cache")
    proof = refinement(x, guard, decoded, y)
    case = common["cases"][1]
    if case["engine"] != "python" or case["identity"]["native_steps"] != len(rows):
        raise ValueError("Python residual transition identity changed")
    bridge = frozen_path_bridge(common, "python", rows, report, input_pointer)
    return {"engine": "python", "input_decode":
        "32-bit digit of fixed input PyLong object; other live-ins fixed",
        "output_decode": "output stack pointer -> pinned small-int cache key -> verified PyLong digit",
        "inferred_additive_constant": constant,
        "native_value_sort": "BV32", "native_steps": len(rows),
        "native_reads": len(case["reads"]), "native_writes": len(case["effects"]),
        "native_pcode_operations": model.operation_count,
        "binary_sha256": digest(PYTHON), "source_trace_sha256": digest(path),
        "residual_contract": {"kind": "frozen full native transition",
            "source_summary_sha256": digest(COMMON), "case_index": 1,
            "successor": case["successor"],
            "value_to_frozen_path_bridge": bridge,
            "cache_sha256": sha256(cache).hexdigest(),
            "result_cache_keys_checked": "10..256",
            "source_object_alias_excluded": True},
        "proof": {**proof, "output_pointer_matches_cache_key": "unsat",
                  "source_object_alias_excluded": "unsat",
                  "cache_no_write_address_queries": len(model.effects),
                  "cache_digit_and_tag_checked": 247}}


def javascript_source(x, common):
    path = SOURCE_TRACES["javascript"]
    report = json.loads(path.read_text())
    if report["binary_sha256"] != digest(JAVASCRIPT):
        raise ValueError("JavaScript source binary changed")
    selected = [item for item in report["paths"] if
                item["entry_values"].get("accumulator_smi") == 9 and
                item["entry_values"].get("immediate") == 5]
    if len(selected) != 1:
        raise ValueError("JavaScript source number path ambiguous")
    rows = selected[0]["rows"]
    memory, _ = initial_memory(rows)
    tagged_x = z3.Concat(x, z3.BitVecVal(0, 32))
    model, guard = replay(rows, JAVASCRIPT, memory, {"rax": tagged_x})
    tagged_result = model.regs[0]
    low = z3.Extract(31, 0, tagged_result)
    query(domain(x), guard, low != z3.BitVecVal(0, 32), want=z3.unsat)
    decoded = z3.Extract(63, 32, tagged_result)
    constant = infer_add_constant(x, guard, decoded)
    y = x + z3.BitVecVal(constant, 32)
    proof = refinement(x, guard, decoded, y)
    case = common["cases"][3]
    if case["engine"] != "javascript" or case["identity"]["native_steps"] != len(rows):
        raise ValueError("JavaScript residual transition identity changed")
    bridge = frozen_path_bridge(common, "javascript", rows, report)
    return {"engine": "javascript", "input_decode":
        "high32 of Smi-tagged RAX; low32 must be zero",
        "output_decode": "high32 of Smi-tagged result RAX; low32 proven zero",
        "inferred_additive_constant": constant,
        "native_value_sort": "BV64", "native_steps": len(rows),
        "native_reads": len(case["reads"]), "native_writes": len(case["effects"]),
        "native_pcode_operations": model.operation_count,
        "binary_sha256": digest(JAVASCRIPT), "source_trace_sha256": digest(path),
        "residual_contract": {"kind": "frozen full native transition",
            "source_summary_sha256": digest(COMMON), "case_index": 3,
            "successor": case["successor"],
            "value_to_frozen_path_bridge": bridge,
            "smi_tag_mask": "0xffffffff"},
        "proof": {**proof, "output_smi_tag_valid": "unsat"}}


def decode_js_smi(raw):
    if raw & 0xFFFFFFFF:
        raise ValueError("JavaScript output is not an Smi")
    return raw >> 32


def fresh_application(common, constant):
    from run_integrated_pipeline import lua_holdout

    lua_result, _ = lua_holdout()
    if lua_result["output"] != 42 + constant:
        raise ValueError("Lua fresh path differs from value IL")
    result = {"lua": {"input": 42, "decoded_output": lua_result["output"],
        "source": "fresh P-code path proof through caller, not frozen full-path application",
        "trace_sha256": digest(FRESH_TRACES["lua"]),
        "value_il_output": 42 + constant, "status": "matched"}}
    for engine, filename in (("python", FRESH_TRACES["python"].name),
                             ("javascript", FRESH_TRACES["javascript"].name)):
        verdict = run_case(common, engine, 43, filename)
        if verdict["status"] != "differentially_validated":
            raise ValueError(f"{engine} fresh full transition not admitted")
        binary = PYTHON if engine == "python" else JAVASCRIPT
        meta, rows, summary = load_trace(FRESH_TRACES[engine], engine, 43, binary)
        boundary = verdict["boundary"]
        segment = rows[boundary["begin"]:boundary["end_exclusive"]]
        if engine == "python":
            output_slot = segment[-1]["registers_after"]["r15"] - 8
            writes = [access for row in segment for access in row["memory"]
                      if access["access"] & 2 and access["address"] == output_slot
                      and access["size"] == 8]
            if len(writes) != 1:
                raise ValueError("fresh Python numeric result slot is ambiguous")
            raw = writes[0]["after"]
        else:
            raw = segment[-1]["registers_after"]["rax"]
        if summary["output_raw"] != raw:
            raise ValueError("fresh handler result differs from caller observation")
        removed_write = None
        if engine == "python":
            cache = read_vaddr(PYTHON, CACHE_BASE, CACHE_BASE + 262 * 32)
            offset = raw - CACHE_BASE
            if offset < 0 or offset % 32 or offset + 28 > len(cache):
                raise ValueError("fresh Python output is not a cached PyLong")
            if int.from_bytes(cache[offset + 16:offset + 24], "little") != 8:
                raise ValueError("fresh Python output lacks a valid cached tag")
            decoded = int.from_bytes(cache[offset + 24:offset + 28], "little")
            changed = deepcopy(segment)
            for row in changed:
                writes = [item for item in row["memory"] if item["access"] & 2]
                if writes:
                    row["memory"].remove(writes[0])
                    break
            else:
                raise ValueError("Python effect omission needs a native write")
            removed_write = admitted(common, choose_summary(common, engine),
                                    engine, 43, meta, rows, changed)["status"]
            if not removed_write.startswith("unknown("):
                raise ValueError("removed Python native effect was admitted")
        else:
            decoded = decode_js_smi(raw)
        if decoded != 43 + constant:
            raise ValueError(f"{engine} fresh decoded output differs from value IL")
        result[engine] = {"input": 43, "decoded_output": decoded,
            "value_il_output": 43 + constant, "status": "matched",
            "trace_sha256": digest(FRESH_TRACES[engine]),
            "native_transition_status": verdict["status"],
            "native_reads_checked": verdict["reads_checked"],
            "native_writes_checked": verdict["ordered_writes_checked"],
            "handler_output_raw": hex(raw),
            "caller_observed_same_raw_output": True,
            "removed_write_status": removed_write,
            "target_pcode_steps_replayed": verdict["target_pcode_steps_replayed"]}
    return result


def main():
    common = json.loads(COMMON.read_text())
    x = z3.BitVec("X", 32)
    adapters = [lua_source(x), python_source(x, common),
                javascript_source(x, common)]
    constants = {item["inferred_additive_constant"] for item in adapters}
    if len(constants) != 1 or next(iter(constants)) != 5:
        raise ValueError("native value ASTs do not agree on the expected addition")
    constant = next(iter(constants))
    il, _ = core_il(x, constant)
    fresh = fresh_application(common, constant)
    try:
        decode_js_smi((43 + constant) << 32 | 1)
    except ValueError:
        wrong_tag = "rejected"
    else:
        raise ValueError("wrong JavaScript Smi tag was admitted")
    result = {"schema_version": "common-numeric-refinement-v1",
        "value_il": il, "adapters": adapters, "fresh_applications": fresh,
        "candidate_method": "infer X+C from each decoded native AST at X=9; prove equality on the common domain before constructing shared IL",
        "negative_controls": {"python_source_object_alias_x4":
            str(z3.simplify(domain(z3.BitVecVal(4, 32)))),
            "outside_common_domain_x252":
            str(z3.simplify(domain(z3.BitVecVal(252, 32)))),
            "javascript_wrong_output_tag": wrong_tag,
            "python_removed_native_write": fresh["python"]["removed_write_status"],
            "all_wrong_plus_six_queries": "sat"},
        "scope": ["conditional P-code value refinement on pinned observed paths",
            "Lua source and fresh path retain full-flow proof; Python and JS retain frozen full native effects",
            "Python input digit substitution uses one fixed source object; fresh real objects are separately admitted",
            "common IL has no proof of effect removability, unseen paths or language-wide semantics"],
        "source_summary_sha256": digest(COMMON)}
    OUTPUT.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"native_refinements": len(adapters),
                      "fresh_applications": len(fresh),
                      "native_steps": {a["engine"]: a["native_steps"]
                                       for a in adapters}}))


if __name__ == "__main__":
    main()
