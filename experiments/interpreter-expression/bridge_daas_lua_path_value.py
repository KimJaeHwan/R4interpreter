"""Check a daas-selected Lua arithmetic/store chain against two native paths.

The daas graph identifies the operation and its possible store dependency.
R4's Low P-code replay selects each observed path and proves its value under
that path's *own* fixed non-input entry state. The two environments are kept
separate. This never upgrades the whole-function static record to exact.
"""

from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import tempfile

import z3

from bridge_daas_operation_records import (DAAS, HERE, LUA_ARCHIVE, LUA_RECORD,
                                           RESULT as STAGE1, R4, extract_bundle,
                                           fingerprint, observed_unit)
from build_common_program_representation import lua_flow_trace
from native_ast_il import Builder, reify
from pcode_transition_summary import FLAG_OFFSETS, REGISTER_OFFSETS, PathReplay
from project_lua_call_bridge import (BINARY, BUNDLE, BYTECODE, load_instructions,
                                     output_word)
from prove_lua_full_flow import first_memory, first_step, initial_memory, trace_records
from tdo_v2.normalize import FunctionNormalizer
from tdo_v2.query import BackwardSliceQuery

OUTPUT = HERE / "daas_lua_path_value_il.json"
ARITHMETIC = 0x417CE7
COPY_STORE = 0x417CEA
ARITHMETIC_KEY = "op:1b1:417ce7:5:INT_ADD"
STORE_KEY = "op:1b1:417cea:1:STORE"
MASK = (1 << 64) - 1


def require(condition, message):
    if not condition:
        raise ValueError(message)


def verdict(*constraints):
    solver = z3.Solver()
    solver.set(timeout=30000)
    solver.add(*constraints)
    answer = solver.check()
    if answer == z3.unknown:
        raise ValueError("SMT returned unknown")
    return answer


def signature(varnode):
    if varnode is None:
        return None
    if isinstance(varnode, dict):
        return (varnode["kind_code"], varnode["space_id"],
                varnode["byte_offset"], varnode["byte_size"])
    return (varnode.kind.value, varnode.coordinate.space_id,
            varnode.coordinate.byte_offset, varnode.byte_size)


def verified_native_site(unit, instructions):
    """Match daas admitted P-code to the independently read replay archive."""
    observed = {ins.address.byte_offset: ins for ins in unit.observation.instructions}
    for pc in (ARITHMETIC, COPY_STORE):
        native = instructions[pc]["operations"]
        admitted = observed[pc].operations
        require(len(native) == len(admitted), "P-code operation count changed")
        for left, right in zip(native, admitted):
            require(left["opcode"] == right.opcode and
                    tuple(map(signature, left["inputs"])) == tuple(map(signature, right.inputs)) and
                    signature(left["output"]) == signature(right.output),
                    "replay and daas P-code disagree")
    add = instructions[ARITHMETIC]["operations"][5]
    copy, store = instructions[COPY_STORE]["operations"]
    require(add["opcode"] == "INT_ADD" and copy["opcode"] == "COPY" and
            store["opcode"] == "STORE" and
            signature(add["output"]) == signature(copy["inputs"][0]) and
            signature(copy["output"]) == signature(store["inputs"][2]) and
            add["output"]["byte_size"] == 8,
            "arithmetic result is not the stored value")
    return {"arithmetic": ARITHMETIC_KEY, "store": STORE_KEY,
            "data_chain": ["INT_ADD R12:8", "COPY R12 -> unique:8",
                           "STORE unique:8 -> [RDX]"]}


def first_read_bytes(rows):
    written = set()
    initial = {}
    for row in rows:
        for access in row["memory"]:
            address, size, mode = access["address"], access["size"], access["access"]
            if mode & 1:
                require(access["before"] is not None, "unreadable initial byte")
                for index in range(size):
                    place = (address + index) & MASK
                    if place not in written:
                        byte = (access["before"] >> (8 * index)) & 255
                        if place in initial:
                            require(initial[place] == byte, "first-read byte changed")
                        initial[place] = byte
            if mode & 2:
                written.update((address + index) & MASK for index in range(size))
    return initial


def replay_value(label):
    trace = lua_flow_trace(label)
    records = trace_records(trace)
    branch = next(row for row in records if row.get("type") == "replay_step" and
                  row["pc"] == 0x417E50)
    source = max((row for row in records if row.get("type") == "replay_step" and
                  row["pc"] == 0x416EA1 and row["step"] < branch["step"]),
                 key=lambda row: row["step"])
    end = first_step(records, COPY_STORE)
    rows = [row for row in records if row.get("type") == "replay_step" and
            source["step"] <= row["step"] < end["step"]] + [end]
    require(rows and all(left["step"] + 1 == right["step"] and
                         left["next_pc"] == right["pc"]
                         for left, right in zip(rows, rows[1:])),
            "native path has an unrecorded step")
    require(sum(row["pc"] == ARITHMETIC for row in rows) == 1 and
            sum(row["pc"] == COPY_STORE for row in rows) == 1,
            "arithmetic/store occurrence is ambiguous")
    x = z3.BitVec("X", 64)
    witness = records[0]["input_word"]
    source_access = first_memory(source, 1)
    require(source_access["before"] == witness, "symbolic source witness changed")
    initial = first_read_bytes(rows)
    memory, count = initial_memory(rows, [(source_access["address"], x, witness)])
    require(len(initial) == count, "first-read snapshot differs from replay")
    registers = rows[0]["registers"]
    instructions = load_instructions((row["pc"] for row in rows), BUNDLE)
    model = PathReplay(
        rows[0], rows, instructions,
        register_symbols={offset: z3.BitVecVal(registers[name], 64)
                          for offset, name in REGISTER_OFFSETS.items()},
        flag_symbols={offset: z3.BitVecVal((registers["eflags"] >> bit) & 1, 8)
                      for offset, bit in FLAG_OFFSETS.items()},
        memory_symbol=memory, address_guards=True)
    model.run()
    guard = z3.simplify(z3.And(*(item["condition"] for item in model.guards)))
    require(verdict(guard) == z3.sat, "path guard is empty")
    store = first_memory(end, 2)
    native_value = model.regs[160]  # R12, the admitted INT_ADD output
    stored_value = output_word(model.memory, store["address"])
    require(verdict(guard, native_value != stored_value) == z3.unsat,
            "R12 and stored value are not equal on path")
    handler = next(row for row in rows if row["pc"] == 0x4164B8)
    frame_base = handler["registers"]["rbx"]
    require(store["address"] == frame_base + 16 and
            verdict(guard, model.regs[16] != z3.BitVecVal(frame_base + 16, 64)) == z3.unsat,
            "store address is not the frame-relative result slot")
    expected_guard = None
    for name, candidate in (("X == 0", x == 0), ("X != 0", z3.Not(x == 0))):
        if verdict(z3.Xor(guard, candidate)) == z3.unsat:
            expected_guard = (name, candidate)
            break
    require(expected_guard is not None, "guard is outside supported candidate family")
    observed = store["after"]
    require(observed is not None, "result write has no witness")
    candidates = [("constant", z3.BitVecVal(observed, 64)),
                  ("additive", x + z3.BitVecVal((observed - witness) & MASK, 64))]
    chosen = next(((name, candidate) for name, candidate in candidates
                   if verdict(guard, native_value != candidate) == z3.unsat), None)
    require(chosen is not None, "constant/additive candidates were not proved")
    builder = Builder([{"name": "X", "sort": "BV64"}])
    guard_root = builder.add(expected_guard[1])
    value_root = builder.add(chosen[1])
    reconstructed = reify({"nodes": builder.nodes}, {"X": x})
    require(verdict(z3.Xor(guard, reconstructed[guard_root])) == z3.unsat and
            verdict(guard, native_value != reconstructed[value_root]) == z3.unsat,
            "serialized IL differs from native replay")
    require(verdict(guard, native_value != chosen[1] + z3.BitVecVal(1, 64)) == z3.sat,
            "wrong-result mutation was not detected")
    mutated_il = deepcopy({"nodes": builder.nodes})
    if chosen[0] == "constant":
        constant_id = value_root
    else:
        offset = (observed - witness) & MASK
        constant_id = next(node["id"] for node in mutated_il["nodes"]
                           if node["op"] == "bv" and node["sort"] == "BV64" and
                           node["value"] == offset)
    constant = mutated_il["nodes"][constant_id]
    require(constant["op"] == "bv", "IL mutation did not target a constant")
    constant["value"] = (constant["value"] + 1) & MASK
    changed_value = reify(mutated_il, {"X": x})[value_root]
    require(verdict(guard, native_value != changed_value) == z3.sat,
            "mutated serialized IL was not rejected")
    source_bytes = {source_access["address"] + index for index in range(8)}
    snapshot = {
        "entry_pc": hex(rows[0]["pc"]),
        "entry_registers": {name: registers[name] for name in REGISTER_OFFSETS.values()},
        "entry_eflags": registers["eflags"],
        "first_read_bytes": {hex(address): value for address, value in sorted(initial.items())
                             if address not in source_bytes},
        "symbolic_source_slot": {"address": hex(source_access["address"]),
                                 "size_bytes": 8, "input": "X:BV64",
                                 "witness": witness},
    }
    snapshot_id = sha256(json.dumps(snapshot, sort_keys=True,
                                    separators=(",", ":")).encode()).hexdigest()
    return {
        "label": label,
        "trace_sha256": sha256(trace.read_bytes()).hexdigest(),
        "environment_id": snapshot_id,
        "environment": snapshot,
        "scope": "one captured native PC path, fixed non-input entry state and first-read memory",
        "native_instruction_count": len(rows),
        "native_pcode_operation_count": model.operation_count,
        "path_guard_count": len(model.guards),
        "result_slot": {"frame_base_witness": hex(frame_base),
                        "offset": 16, "width_bytes": 8},
        "guard": expected_guard[0],
        "candidate_family": chosen[0],
        "il": {"schema_version": "bounded-path-value-il-v1", "inputs": [{"name": "X", "sort": "BV64"}],
               "nodes": builder.nodes, "guard_root": guard_root, "value_root": value_root},
        "proof": {"guard_equivalence": "unsat", "candidate_value_equivalence": "unsat",
                  "stored_value_equivalence": "unsat", "store_address_equivalence": "unsat",
                  "reified_il_equivalence": "unsat", "wrong_candidate_detected": "sat",
                  "mutated_serialized_il_rejected": "sat"},
        "complete_native_effects": False,
        "complete_handler_alternate_exits": False,
    }


def main():
    stage1 = json.loads(STAGE1.read_text())
    daas_commit = subprocess.check_output(["git", "-C", str(DAAS), "rev-parse", "HEAD"],
                                          text=True).strip()
    daas_dirty = bool(subprocess.check_output(["git", "-C", str(DAAS),
                                               "status", "--porcelain"], text=True).strip())
    require(stage1["daas_commit"] == daas_commit and
            stage1["daas_worktree_dirty"] == daas_dirty and not daas_dirty,
            "daas checkout changed since stage1")
    require(stage1["lua_static_root"]["bundle_archive_sha256"] ==
            sha256(LUA_ARCHIVE.read_bytes()).hexdigest() and
            stage1["lua_static_root"]["root_operation"] ==
            ARITHMETIC_KEY.removeprefix("op:") and
            stage1["lua_static_root"]["record_sha256"] ==
            fingerprint(json.loads(LUA_RECORD.read_text())), "stage1 source changed")
    prior = HERE / "lua_branch_join_v2.json"
    branch_proof = json.loads(prior.read_text())
    binary_hash = sha256(BINARY.read_bytes()).hexdigest()
    bundle_hash = sha256(BUNDLE.read_bytes()).hexdigest()
    require(branch_proof["binary_sha256"] == binary_hash and
            branch_proof["bundle_sha256"] == bundle_hash and
            branch_proof["bytecode_sha256"] == sha256(BYTECODE.read_bytes()).hexdigest(),
            "prior Lua trace evidence uses different inputs")
    prior_cases = {row["input_label"]: row for row in branch_proof["cases"]}
    for label in ("x0", "x9"):
        trace = lua_flow_trace(label)
        meta = json.loads(trace.open().readline())
        require(meta["type"] == "meta" and
                meta["binary"] == str(BINARY.relative_to(R4)) and
                meta["bytecode"] == str(BYTECODE.relative_to(R4)) and
                prior_cases[label]["trace_sha256"] == sha256(trace.read_bytes()).hexdigest(),
                "trace identity differs from prior Lua proof")
    with tempfile.TemporaryDirectory(prefix="r4-daas-lua-path-") as temp:
        bundle = extract_bundle(LUA_ARCHIVE, Path(temp))
        unit = observed_unit(bundle, 0x415440)
        require(unit.scopes.program.evidence.executable_sha256.hex() == binary_hash,
                "admitted Bundle executable differs from Lua fixture")
        normalized = FunctionNormalizer().normalize(unit)
        graph = normalized.dependencies
        store_node = graph.node_for_key(STORE_KEY)
        require(store_node is not None, "daas graph lacks Lua store")
        sliced = BackwardSliceQuery().run(normalized, store_node, include_control=False)
        keys = {graph.node(node).key for node in sliced.reachable_nodes}
        require(ARITHMETIC_KEY in keys, "daas store slice missed arithmetic operation")
        sites = verified_native_site(unit, load_instructions((ARITHMETIC, COPY_STORE), BUNDLE))
        cases = [replay_value(label) for label in ("x0", "x9")]
        require(cases[0]["environment_id"] != cases[1]["environment_id"] and
                {row["guard"] for row in cases} == {"X == 0", "X != 0"},
                "different path environments or guards were silently merged")
        report = {
            "schema_version": "daas-lua-path-value-v1",
            "daas_commit": daas_commit,
            "daas_worktree_dirty": daas_dirty,
            "bridge_sha256": sha256(Path(__file__).read_bytes()).hexdigest(),
            "bundle_archive_sha256": stage1["lua_static_root"]["bundle_archive_sha256"],
            "binary_sha256": binary_hash,
            "stage1_static_record_sha256": stage1["lua_static_root"]["record_sha256"],
            "prior_branch_proof_sha256": sha256(prior.read_bytes()).hexdigest(),
            "input_identity_verified_against_prior_proof": True,
            "daas_store_slice": {"root": STORE_KEY, "arithmetic_reached": True,
                                 "nodes": len(sliced.reachable_nodes),
                                 "unresolved_reads": len(sliced.reachable_unresolved_read_nodes),
                                 "function_unresolved_writes": len(sliced.function_unresolved_write_nodes),
                                 "complete": sliced.is_complete},
            "pcode_site_match": sites,
            "cases": cases,
            "case_environments_unified": False,
            "whole_program_complete": False,
            "limits": ["daas static slice is a locator and debt warning, not a selected path",
                       "R4 replay proves values under separate fixed non-input environments",
                       "normal/exception/call/allocator/other exit coverage is not established"],
        }
        OUTPUT.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps({"slice": report["daas_store_slice"],
                          "cases": [{"label": row["label"], "guard": row["guard"],
                                     "family": row["candidate_family"],
                                     "il_nodes": len(row["il"]["nodes"]),
                                     "proof": row["proof"]} for row in cases]}, indent=2))


if __name__ == "__main__":
    main()
