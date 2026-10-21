"""Generate bounded Lua native-window IL from replayed P-code expressions.

The code selects already evidenced native boundaries and does not inspect Lua
source text or supply an expected branch/value formula. The older path cases
have different entry states; the fixed-layout experiment separately establishes
one common partial entry state for its two native paths.
"""

from __future__ import annotations

import gzip
from hashlib import sha256
import json
from pathlib import Path
import tempfile

import z3

from bridge_daas_lua_path_value import (HERE, R4, first_read_bytes, require,
                                        verdict)
from common_program_path_il import native_path_ledger
from native_ast_il import Builder, reify
from pcode_transition_summary import FLAG_OFFSETS, REGISTER_OFFSETS, PathReplay
from project_lua_call_bridge import BINARY, BUNDLE, BYTECODE, load_instructions, output_word
from prove_lua_full_flow import first_memory, first_step, initial_memory, trace_records


SOURCE = HERE / "daas_lua_path_value_il.json"
BRANCH = HERE / "lua_branch_join_v2.json"
HOLDOUT = HERE / "artifacts/lua_branch_full_flow_x17.jsonl.gz"
FIXED_BASELINE = HERE / "artifacts/lua_fixed_x0_snapshot.jsonl.gz"
FIXED_OVERRIDE = HERE / "artifacts/lua_injected_x17_from_x0.jsonl.gz"
EXTENDED_BASELINE = HERE / "artifacts/lua_extended_base.jsonl.gz"
EXTENDED_OVERRIDE = HERE / "artifacts/lua_extended_override.jsonl.gz"
OUTPUT = HERE / "lua_native_window_generated_il.json"
READABLE = HERE / "LUA_NATIVE_WINDOW_GENERATED.md"
MASK = (1 << 64) - 1
NORMAL_RESULT_SAVE_PC = 0x401542  # run_lua_chunk cutpoint before lua_close
STATUS_OUTPUT_WRITE_PC = 0x401537  # adapter writes *status after lua_tointegerx


def digest(path):
    return sha256(path.read_bytes()).hexdigest()


def readable_value(guard, native_value, x):
    """Prove a simple display form derived from the native AST when possible."""
    zero_value = z3.simplify(z3.substitute(native_value,
                                            (x, z3.BitVecVal(0, 64))))
    if z3.is_bv_value(zero_value):
        if verdict(guard, native_value != zero_value) == z3.unsat:
            return zero_value, "proved_constant_under_guard"
        additive = x + zero_value
        if verdict(guard, native_value != additive) == z3.unsat:
            return z3.simplify(additive), "proved_additive_under_guard"
    return native_value, "direct_native_ast"


def records_from(path):
    if path.suffix != ".gz":
        return trace_records(path), digest(path)
    with tempfile.TemporaryDirectory(prefix="r4-lua-holdout-") as folder:
        temporary = Path(folder) / "trace.jsonl"
        temporary.write_bytes(gzip.decompress(path.read_bytes()))
        return trace_records(temporary), digest(temporary)


def path_rows(records, source_pc, branch_pc, store_pc):
    end = first_step(records, store_pc)
    branches = [row for row in records if row.get("type") == "replay_step" and
                row["pc"] == branch_pc and row["step"] < end["step"]]
    require(len(branches) == 1, "branch occurrence is absent or ambiguous")
    branch = branches[0]
    source = max((row for row in records if row.get("type") == "replay_step" and
                  row["pc"] == source_pc and row["step"] < branch["step"]),
                 key=lambda row: row["step"])
    rows = [row for row in records if row.get("type") == "replay_step" and
            source["step"] <= row["step"] < end["step"]] + [end]
    require(rows[0] == source and rows[-1] == end and
            all(a["step"] + 1 == b["step"] and a["next_pc"] == b["pc"]
                for a, b in zip(rows, rows[1:])),
            "native VM window is not a contiguous path")
    return rows, branch


def extend_rows(records, vm_rows, terminal_pc):
    terminal = first_step(records, terminal_pc)
    require(terminal["step"] > vm_rows[-1]["step"],
            "terminal cutpoint precedes the VM result store")
    selected = {}
    for row in records:
        if row.get("type") not in ("replay_step", "step") or not (
                vm_rows[0]["step"] <= row["step"] <= terminal["step"]):
            continue
        if row["step"] not in selected or row["type"] == "replay_step":
            selected[row["step"]] = row
    rows = [selected[step] for step in sorted(selected)]
    require(rows[0]["step"] == vm_rows[0]["step"] and
            rows[-1]["step"] == terminal["step"] and
            len(rows) == terminal["step"] - vm_rows[0]["step"] + 1 and
            all(a["step"] + 1 == b["step"] and a["next_pc"] == b["pc"]
                for a, b in zip(rows, rows[1:])),
            "native path to terminal cutpoint is not contiguous")
    return rows


def check_native_successors(rows, instructions):
    """Account for every observed successor using the admitted instruction."""
    transfers = {"BRANCH", "CBRANCH", "BRANCHIND", "CALL", "CALLIND", "RETURN"}
    for row in rows:
        instruction = instructions[row["pc"]]
        operations = instruction["operations"]
        opcodes = {item["opcode"] for item in operations}
        if instruction["fallthrough_present"] and (
                row["next_pc"] == instruction["fallthrough"]["byte_offset"]):
            continue
        require(bool(opcodes & transfers),
                f"unexplained non-fallthrough successor at {row['pc']:#x}")
        if not (opcodes & (transfers - {"CBRANCH"})):
            require(any(operation["opcode"] == "CBRANCH" and
                        operation["inputs"][0]["byte_offset"] == row["next_pc"]
                        for operation in operations),
                    f"conditional branch has an invalid successor at {row['pc']:#x}")


def entry_environment(rows, source_access, witness, common_snapshot=None):
    initial = first_read_bytes(rows)
    memory, count = initial_memory(rows, [(source_access["address"],
                                           z3.BitVec("X", 64), witness)])
    require(count == len(initial), "first-read memory snapshot changed")
    registers = rows[0]["registers"]
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
    if common_snapshot is not None:
        require(snapshot["entry_pc"] == common_snapshot["entry_pc"] and
                snapshot["entry_registers"] == common_snapshot["entry_registers"] and
                snapshot["entry_eflags"] == common_snapshot["entry_eflags"] and
                snapshot["symbolic_source_slot"]["address"] ==
                common_snapshot["symbolic_source_slot"]["address"] and
                all(common_snapshot["first_read_bytes"].get(hex(address)) == value
                    for address, value in initial.items() if address not in source_bytes),
                "path does not originate from the declared common entry bytes")
        memory = z3.Array("M0", z3.BitVecSort(64), z3.BitVecSort(8))
        for address, value in common_snapshot["first_read_bytes"].items():
            memory = z3.Store(memory, z3.BitVecVal(int(address, 16), 64),
                              z3.BitVecVal(value, 8))
        for index in range(8):
            memory = z3.Store(memory,
                              z3.BitVecVal(source_access["address"] + index, 64),
                              z3.Extract(8 * index + 7, 8 * index,
                                         z3.BitVec("X", 64)))
        snapshot = common_snapshot
    identity = sha256(json.dumps(snapshot, sort_keys=True,
                                 separators=(",", ":")).encode()).hexdigest()
    return memory, snapshot, identity


def generate_case(label, trace, stage2_case, branch_case, source_pc, branch_pc,
                  store_pc, binary_hash, bytecode_hash, common_snapshot=None,
                  terminal_pc=None):
    records, trace_hash = records_from(trace)
    meta = records[0]
    require(meta["binary"] == str(BINARY.relative_to(R4)) and
            meta["bytecode"] == str(BYTECODE.relative_to(R4)) and
            sha256(BINARY.read_bytes()).hexdigest() == binary_hash and
            sha256(BYTECODE.read_bytes()).hexdigest() == bytecode_hash,
            "native trace input identity changed")
    if stage2_case is not None:
        require(trace_hash == stage2_case["trace_sha256"] ==
                branch_case["trace_sha256"], "prior case trace changed")
    vm_rows, branch = path_rows(records, source_pc, branch_pc, store_pc)
    rows = (extend_rows(records, vm_rows, terminal_pc) if terminal_pc is not None
            else vm_rows)
    if branch_case is not None:
        require(branch["step"] == branch_case["branch_native_step"],
                "branch occurrence changed")
    source_access = first_memory(rows[0], 1)
    witness = source_access["before"]
    overrides = [item for item in records if item.get("type") == "input_override"]
    require(source_access["size"] == 8 and
            ((not overrides and witness == meta["input_word"]) or
             (len(overrides) == 1 and overrides[0]["pc"] == source_pc and
              overrides[0]["address"] == source_access["address"] and
              overrides[0]["before"] == meta["input_word"] and
              overrides[0]["after"] == witness)),
            "symbolic native input slot differs from trace input/recorded override")
    memory, environment, environment_id = entry_environment(
        rows, source_access, witness, common_snapshot)
    if stage2_case is not None:
        require(environment == stage2_case["environment"] and
                environment_id == stage2_case["environment_id"],
                "stage2 fixed native environment changed")
    registers = rows[0]["registers"]
    instructions = load_instructions((row["pc"] for row in rows), BUNDLE)
    check_native_successors(rows, instructions)
    model = PathReplay(
        rows[0], rows, instructions,
        register_symbols={offset: z3.BitVecVal(registers[name], 64)
                          for offset, name in REGISTER_OFFSETS.items()},
        flag_symbols={offset: z3.BitVecVal((registers["eflags"] >> bit) & 1, 8)
                      for offset, bit in FLAG_OFFSETS.items()},
        memory_symbol=memory, address_guards=True)
    model.run()
    guard = z3.simplify(z3.And(*(item["condition"] for item in model.guards)))
    require(verdict(guard, z3.BitVec("X", 64) == witness) == z3.sat,
            "native path excludes its witness")
    result_access = first_memory(vm_rows[-1], 2)
    require(result_access["size"] == 8, "native result store is not BV64")
    value = z3.simplify(model.regs[0] if terminal_pc is not None else
                        output_word(model.memory, result_access["address"]))
    display_value, display_grade = readable_value(guard, value, z3.BitVec("X", 64))
    observed_result = (rows[-1]["registers_after"]["rax"] if terminal_pc is not None
                       else result_access["after"])
    require(verdict(guard, z3.BitVec("X", 64) == witness,
                    value != z3.BitVecVal(observed_result, 64)) == z3.unsat,
            "directly replayed result disagrees with native witness")
    ledger = native_path_ledger(rows, [{"id": ("vm_source_to_normal_result_save"
                                               if terminal_pc is not None else
                                               "vm_source_to_result_store"),
                                        "op": "ObservedNativePath",
                                        "begin": 0, "end_exclusive": len(rows)}])[0]
    require(len(ledger["effects"]) == len(model.effects),
            "native trace and replay disagree on ordered writes")
    witness_x = z3.BitVec("X", 64) == z3.BitVecVal(witness, 64)
    witness_differences = [
        item["value_expression"] != z3.BitVecVal(item["observed"], 8 * item["width"])
        for item in model.reads
    ] + [
        z3.Or(item["address"] != z3.BitVecVal(item["observed_address"], 64),
              item["value"] != z3.BitVecVal(item["observed"], 8 * item["width"]))
        for item in model.effects
    ]
    require(verdict(guard, witness_x, z3.Or(*witness_differences)) == z3.unsat,
            "symbolic read/write effects disagree with native witness")

    interface = [{"name": "X", "sort": "BV64"}]
    declarations = {"X": z3.BitVec("X", 64)}
    if common_snapshot is not None:
        interface.append({"name": "M0", "sort": "Array(BV64,BV8)"})
        declarations["M0"] = z3.Array("M0", z3.BitVecSort(64), z3.BitVecSort(8))
    builder = Builder(interface)
    sources = []

    def root(ast):
        simplified = z3.simplify(ast)
        identifier = builder.add(simplified)
        sources.append((identifier, simplified))
        return identifier

    guard_root = root(guard)
    value_root = root(value)
    status_root = None
    observed_status = None
    if terminal_pc is not None:
        status_effects = [item for item in model.effects
                          if item["pc"] == hex(STATUS_OUTPUT_WRITE_PC) and
                          item["width"] == 4]
        require(len(status_effects) == 1,
                "normal return path did not write one status output")
        status_address = status_effects[0]["observed_address"]
        observed_status = status_effects[0]["observed"]
        status_ast = z3.Concat(*(z3.Select(model.memory,
                             z3.BitVecVal(status_address + index, 64))
                                 for index in reversed(range(4))))
        require(verdict(guard, status_ast != z3.BitVecVal(observed_status, 32)) ==
                z3.unsat, "wrapper ok output is not constant over its path")
        status_root = root(status_ast)
    reads = [{"pc": item["pc"], "ordinal": item["ordinal"],
              "width_bytes": item["width"], "memory_version": item["memory_version"],
              "address_root": root(item["address"]),
              "value_root": root(item["value_expression"]),
              "observed_address": hex(item["observed_address"])}
             for item in model.reads]
    effects = [{"pc": item["pc"], "ordinal": item["ordinal"],
                "kind": item["kind"], "width_bytes": item["width"],
                "address_root": root(item["address"]),
                "value_root": root(item["value"]),
                "memory_version_before": item["memory_version_before"],
                "memory_version_after": item["memory_version_after"],
                "observed_address": hex(item["observed_address"]),
                "observed_value": item["observed"]}
               for item in model.effects]
    output_registers = {name: root(model.regs[offset])
                        for offset, name in REGISTER_OFFSETS.items()}
    output_flags = {str(bit): root(model.flags[offset])
                    for offset, bit in FLAG_OFFSETS.items()}
    final_instruction = instructions[rows[-1]["pc"]]
    require(final_instruction["fallthrough_present"] and
            final_instruction["fallthrough"]["byte_offset"] == rows[-1]["next_pc"],
            "native successor disagrees with admitted instruction fallthrough")
    successor_root = root(z3.BitVecVal(rows[-1]["next_pc"], 64))
    if common_snapshot is not None:
        require(not any(node.get("op") == "input" and node.get("name") == "M0"
                        for node in builder.nodes),
                "selected path guard, reads, effects, or outputs depend on uncaptured memory")
    reified = reify({"nodes": builder.nodes}, declarations)
    deviations = [ast != reified[identifier] for identifier, ast in sources]
    require(verdict(guard, z3.Or(*deviations)) == z3.unsat,
            "native P-code AST and serialized typed IL disagree")
    if stage2_case is not None:
        candidate = reify(stage2_case["il"], {"X": z3.BitVec("X", 64)})
        require(verdict(guard, value != candidate[stage2_case["il"]["value_root"]]) ==
                z3.unsat, "direct native value differs from earlier proved candidate")
    return ({
        "label": label, "witness": witness, "trace_sha256": trace_hash,
        "trace_archive_sha256": digest(trace),
        "environment_id": environment_id, "environment": environment,
        "shared_entry_snapshot": common_snapshot is not None,
        "native_window": {"start_step": rows[0]["step"],
                          "end_step_inclusive": rows[-1]["step"],
                          "native_steps": len(rows),
                          "pc_sequence_sha256": sha256(json.dumps(
                              [row["pc"] for row in rows], separators=(",", ":")
                              ).encode()).hexdigest(),
                          "pcode_operations": model.operation_count,
                          "guard_events": len(model.guards),
                          "observed_ledger": ledger},
        "il": {"schema_version": "native-window-typed-il-v1",
               "inputs": interface,
               "nodes": builder.nodes, "guard_root": guard_root,
               "result_value_root": value_root,
               "result_kind": ("RAX_after_normal_conversion" if terminal_pc is not None
                               else "VM_result_slot"),
               "wrapper_ok_output_root": status_root,
               "wrapper_ok_output_address": (hex(status_address)
                                         if terminal_pc is not None else None),
               "reads": reads, "ordered_effects": effects,
               "output_registers": output_registers,
               "output_flags": output_flags,
               "successor_root": successor_root},
        "observed_result_slot": {"address": hex(result_access["address"]),
                                 "width_bytes": 8, "value": result_access["after"]},
        "observed_terminal_result": observed_result,
        "observed_wrapper_ok_output": observed_status,
        "proof": {"source": "replayed_native_pcode_ast",
                  "typed_il_roundtrip_difference": "unsat",
                  "native_witness_difference": "unsat",
                  "native_read_write_witness_difference": "unsat",
                  "display_value_equivalence_under_guard": "unsat",
                  "all_observed_reads_and_writes_accounted_for": True},
        "uncaptured_memory_frame": ("M0 absent from every emitted scalar, guard, "
                                    "address, and write-value root; ordered writes "
                                    "apply over the captured-byte overrides of M0"
                                    if common_snapshot is not None else None),
        "readable_value": {"expression": str(display_value),
                           "derivation": display_grade},
        "scope": ("contiguous native VM source-to-normal-result-save window"
                  if terminal_pc is not None else
                  "contiguous native VM source-to-result-store window"),
        "selected_native_window_replayed_under_fixed_environment": True,
        "all_alternative_exits_proved": False,
        "complete_invocation": False,
    }, guard, value, display_value)


def shared_entry_cases(source_pc, branch_pc, store_pc, binary_hash, bytecode_hash,
                       baseline_trace=FIXED_BASELINE, override_trace=FIXED_OVERRIDE,
                       terminal_pc=None):
    baseline_records, _ = records_from(baseline_trace)
    override_records, _ = records_from(override_trace)
    baseline_snapshot = next(item for item in baseline_records
                             if item.get("type") == "entry_snapshot")
    override_snapshot = next(item for item in override_records
                             if item.get("type") == "entry_snapshot")
    overrides = [item for item in override_records
                 if item.get("type") == "input_override"]
    require(len(overrides) == 1 and overrides[0]["step"] == override_snapshot["step"] and
            overrides[0]["pc"] == override_snapshot["pc"] == source_pc and
            baseline_snapshot["pc"] == source_pc and
            baseline_snapshot["bytes"].keys() == override_snapshot["bytes"].keys() and
            all(type(value) is int and 0 <= value < 256
                for value in override_snapshot["bytes"].values()),
            "fixed-layout entry snapshots or source override are incomplete")
    baseline_rows, _ = path_rows(baseline_records, source_pc, branch_pc, store_pc)
    override_rows, _ = path_rows(override_records, source_pc, branch_pc, store_pc)
    source_access = first_memory(override_rows[0], 1)
    require(overrides[0]["address"] == source_access["address"] and
            baseline_rows[0]["registers"] == override_rows[0]["registers"],
            "fixed-layout runs do not share entry registers/input slot")
    if terminal_pc is not None:
        require(baseline_snapshot["bytes"] == override_snapshot["bytes"],
                "normal-return runs do not have one captured entry memory state")
    common = {
        "scope": "same fixed GPR/flags and the union of first-read bytes, excluding X",
        "entry_pc": hex(source_pc),
        "entry_registers": {name: override_rows[0]["registers"][name]
                            for name in REGISTER_OFFSETS.values()},
        "entry_eflags": override_rows[0]["registers"]["eflags"],
        "first_read_bytes": override_snapshot["bytes"],
        "symbolic_source_slot": {"address": hex(source_access["address"]),
                                 "size_bytes": 8, "input": "X:BV64"},
        "full_process_memory_captured": False,
    }
    base_case = generate_case("fixed_base", baseline_trace, None, None,
                              source_pc, branch_pc, store_pc, binary_hash,
                              bytecode_hash, common, terminal_pc)
    alternate_case = generate_case("fixed_override", override_trace, None, None,
                                   source_pc, branch_pc, store_pc, binary_hash,
                                   bytecode_hash, common, terminal_pc)
    left, guard_left, value_left, display_left = base_case
    right, guard_right, value_right, display_right = alternate_case
    require(left["environment_id"] == right["environment_id"] and
            verdict(z3.And(guard_left, guard_right)) == z3.unsat and
            verdict(z3.Not(z3.Or(guard_left, guard_right))) == z3.unsat,
            "one declared partial native entry state does not partition X")
    candidate = z3.simplify(z3.If(guard_left, display_left, display_right))
    require(verdict(guard_left, candidate != value_left) == z3.unsat and
            verdict(guard_right, candidate != value_right) == z3.unsat,
            "shared-entry display differs from the native value")
    return {
        "schema_version": "shared-partial-entry-native-window-v1",
        "entry_scope": common["scope"],
        "fixed_layout_method": "ASLR disabled for two executions; source word changed by recorded ptrace write before its first VM read",
        "entry_environment_id": left["environment_id"],
        "entry_environment": common,
        "captured_bytes": len(common["first_read_bytes"]),
        "terminal_pc": hex(terminal_pc) if terminal_pc is not None else hex(store_pc),
        "baseline_entry_snapshot_sha256": digest(baseline_trace),
        "override_entry_snapshot_sha256": digest(override_trace),
        "baseline_and_override_snapshot_differences": [
            address for address in baseline_snapshot["bytes"]
            if baseline_snapshot["bytes"][address] != override_snapshot["bytes"][address]],
        "cases": [left, right],
        "guard_partition_over_X": {"overlap": "unsat", "uncovered": "unsat",
                                   "same_declared_first_read_environment": True,
                                   "full_process_initial_state_proved": False},
        "value_candidate_smt_readout": str(candidate),
        "selected_window_guard_partition_under_declared_partial_entry": True,
        "complete_invocation": False,
        "unresolved": ([
            "bounded path model assumes fixed executable bytes, stable mapped permissions, and no asynchronous intervention",
            "capture begins inside the VM after invocation setup and input delivery",
            "lua_close cleanup and outer function return remain outside this cutpoint",
        ] if terminal_pc is not None else [
            "partial entry snapshot does not establish all memory or allocator state for unseen paths",
            "other native branch/indirect/call exits and errors are not closed",
            "VM result STORE is earlier than protected-call return and status",
        ]),
    }


def main():
    stage2 = json.loads(SOURCE.read_text())
    branch = json.loads(BRANCH.read_text())
    require(stage2["prior_branch_proof_sha256"] == digest(BRANCH) and
            stage2["binary_sha256"] == digest(BINARY) and
            stage2["bundle_archive_sha256"] == digest(BUNDLE) and
            branch["bytecode_sha256"] == digest(BYTECODE),
            "pinned native/branch evidence changed")
    source_pc = int(stage2["cases"][0]["environment"]["entry_pc"], 16)
    store_pc = int(stage2["pcode_site_match"]["store"].split(":")[2], 16)
    branch_cases = {item["input_label"]: item for item in branch["cases"]}
    stage2_cases = {item["label"]: item for item in stage2["cases"]}
    case_data = []
    for label in ("x0", "x9"):
        branch_case = branch_cases[label]
        trace = HERE / f"artifacts/lua_branch_full_flow_{label}.jsonl"
        records, _ = records_from(trace)
        branch_pc = next(row["pc"] for row in records if row.get("type") == "replay_step"
                         and row["step"] == branch_case["branch_native_step"])
        case_data.append(generate_case(label, trace, stage2_cases[label], branch_case,
                                       source_pc, branch_pc, store_pc,
                                       stage2["binary_sha256"], branch["bytecode_sha256"]))
    (left, left_guard, left_value, left_display), (right, right_guard,
                                                  right_value, right_display) = case_data
    require(verdict(z3.And(left_guard, right_guard)) == z3.unsat and
            verdict(z3.Not(z3.Or(left_guard, right_guard))) == z3.unsat,
            "selected native guards do not partition BV64 inputs")
    require(left["environment_id"] != right["environment_id"],
            "different path environments were silently unified")
    candidate = z3.simplify(z3.If(left_guard, left_display, right_display))
    require(verdict(left_guard, candidate != left_value) == z3.unsat and
            verdict(right_guard, candidate != right_value) == z3.unsat,
            "proved display form changed the native path result")
    candidate_builder = Builder([{"name": "X", "sort": "BV64"}])
    candidate_root = candidate_builder.add(candidate)
    require(verdict(candidate != reify({"nodes": candidate_builder.nodes},
                  {"X": z3.BitVec("X", 64)})[candidate_root]) == z3.unsat,
            "combined candidate failed typed IL roundtrip")
    # A newly captured execution is verification data, never a source of the
    # two path cases or of their branch/result expressions.
    reference_trace = HERE / "artifacts/lua_branch_full_flow_x9.jsonl"
    reference_records, _ = records_from(reference_trace)
    reference_branch_pc = next(row["pc"] for row in reference_records
                               if row.get("type") == "replay_step" and
                               row["step"] == branch_cases["x9"]["branch_native_step"])
    holdout, holdout_guard, holdout_value, _ = generate_case(
        "holdout", HOLDOUT, None, None, source_pc, reference_branch_pc,
        store_pc, stage2["binary_sha256"], branch["bytecode_sha256"])
    witness = z3.BitVecVal(holdout["witness"], 64)
    require(verdict(holdout_guard, z3.BitVec("X", 64) == witness,
                    holdout_value != candidate) == z3.unsat and
            verdict(z3.Xor(holdout_guard, right_guard)) == z3.unsat and
            verdict(right_guard, holdout_value != right_value) == z3.unsat,
            "new native input does not match generated path relation")
    require(holdout["native_window"]["pc_sequence_sha256"] ==
            right["native_window"]["pc_sequence_sha256"] and
            [(item["pc"], item["ordinal"], item["width_bytes"])
             for item in holdout["il"]["ordered_effects"]] ==
            [(item["pc"], item["ordinal"], item["width_bytes"])
             for item in right["il"]["ordered_effects"]],
            "new native input used a different path or ordered effect shape")
    common_path = shared_entry_cases(source_pc, reference_branch_pc, store_pc,
                                     stage2["binary_sha256"], branch["bytecode_sha256"])
    normal_return = shared_entry_cases(
        source_pc, reference_branch_pc, store_pc, stage2["binary_sha256"],
        branch["bytecode_sha256"], EXTENDED_BASELINE, EXTENDED_OVERRIDE,
        NORMAL_RESULT_SAVE_PC)
    report = {
        "schema_version": "lua-generated-native-window-v1",
        "generator_sha256": digest(Path(__file__)),
        "binary_sha256": stage2["binary_sha256"],
        "bytecode_sha256": branch["bytecode_sha256"],
        "bundle_sha256": stage2["bundle_archive_sha256"],
        "source_stage2_sha256": digest(SOURCE),
        "source_branch_sha256": digest(BRANCH),
        "source_lua_script_read_by_generator": False,
        "expected_source_condition_or_result_used_by_generator": False,
        "inputs": [{"name": "X", "sort": "BV64"}],
        "cases": [left, right],
        "guard_partition_over_X": {"overlap": "unsat", "uncovered": "unsat",
                                   "common_initial_environment_proved": False},
        "cross_environment_value_candidate": {
            "scope": "candidate only: path environments differ",
            "nodes": candidate_builder.nodes, "result_root": candidate_root,
            "smt_readout": str(candidate)},
        "new_input_verification": {"witness": holdout["witness"],
                                   "trace_archive_sha256": holdout["trace_archive_sha256"],
                                   "trace_payload_sha256": holdout["trace_sha256"],
                                   "environment_id": holdout["environment_id"],
                                   "native_window_steps": holdout["native_window"]["native_steps"],
                                   "ordered_effects": len(holdout["il"]["ordered_effects"]),
                                   "pc_sequence_equal_to_existing_path": True,
                                   "ordered_effect_shape_equal_to_existing_path": True,
                                   "guard_equivalence_to_existing_path": "unsat",
                                   "value_equivalence_to_existing_path": "unsat",
                                   "candidate_witness_difference": "unsat"},
        "common_partial_entry_experiment": common_path,
        "normal_return_common_partial_entry_experiment": normal_return,
        "complete_invocation": False,
        "whole_program_complete": False,
        "unresolved": [
            "earlier standalone x0/x9 cases have different entry environments; use normal_return_common_partial_entry_experiment for the shared partial entry",
            "the shared-entry window begins after invocation setup and input delivery inside the Lua VM",
            "lua_close cleanup and the adapter's outer return remain outside the shared-entry window",
            "automatic discovery of boundaries and paths for other Lua programs is not established",
            "the contract assumes fixed code, stable memory permissions, and no asynchronous intervention",
        ],
    }
    OUTPUT.write_text(json.dumps(report, indent=2) + "\n")
    lines = ["# 생성된 Lua 네이티브 구간 로직과 미해결 범위", "",
             "**현재 판정: 전체 프로그램 로직 복원 미완료.** 시작점은 VM 내부 입력 로드이고 끝점은 `lua_close` 이전이다.",
             "원본 Lua 스크립트의 조건식·결과값을 읽지 않고 P-code 재생의 실제 AST에서 생성했다.",
             "먼저 생성한 두 경로는 초기 네이티브 환경이 달라 아래 병합식만으로는 전체 프로그램 계약이 아니다.", "",
             "```text", "input X: BV64"]
    for case, guard, value, display in case_data:
        lines.extend([f"when {z3.simplify(guard)}:",
                      f"    VM result slot := {z3.simplify(display)}",
                      f"    ordered native writes: {len(case['il']['ordered_effects'])}",
                      f"    fixed environment: {case['environment_id'][:16]}..."])
    lines.extend(["```", "", f"BV64 조건 병합 후보: `{candidate}`", "",
                  "새 입력의 네이티브 추적에서도 해당 경로 guard·저장값 식을 다시 생성하고 대조했다.",
                  "", "## 고정 주소 배치의 공통 부분 진입 상태", "",
                  f"두 경로가 같은 진입 레지스터·플래그와 처음 읽는 {common_path['captured_bytes']}바이트의 선언된 메모리 상태에서 출발한다.",
                  "한 실행에서는 VM 소스 단어만 추적기에서 바꾸고 대체 경로를 실제로 실행했다.",
                  f"그 상태의 선택된 구간에서 생성된 guard는 서로 배타적이며 BV64 입력을 덮는다. 결과 후보: `{common_path['value_candidate_smt_readout']}`.",
                  "이는 전체 프로세스 메모리 snapshot 또는 보호된 호출의 복귀·오류 출구 증명이 아니다.",
                  "", "## 정상 복귀 및 결과 변환 구간", "",
                  f"같은 레지스터·플래그와 캡처한 {normal_return['captured_bytes']}바이트를 가진 두 실행에서 VM 입력 X만 바꿨다. 시작점부터 `{normal_return['terminal_pc']}`까지 각각 358·402개 네이티브 명령을 연속 재생했다.",
                  f"모델에서 두 guard는 서로 배타적이고 BV64 입력을 덮으며 결과식은 `{normal_return['value_candidate_smt_readout']}`이다.",
                  "보호 호출의 정상 복귀, 정수 변환, wrapper의 성공 출력 `*ok = 1`을 포함한다. 실제 `lua_pcall` 반환 코드와 `*ok`는 다른 값이다.",
                  "미지 메모리 M0 위에 캡처한 값을 덧씌워 재생했다. guard·접근 주소·값·출력식에는 M0가 남지 않으며, 메모리 변화는 순서가 있는 쓰기로 보존한다.",
                  "이 범위의 주장은 코드와 메모리 권한이 유지되고 외부 비동기 개입이 없다는 네이티브 모델에 한정된다.",
                  "호출 준비와 입력 전달, `lua_close` 및 바깥 함수 반환은 아직 연결하지 않았다. 자동 경계 탐색과 일반 Lua 프로그램으로의 적용도 남았다.", "",
                  f"증거: [생성 IL]({OUTPUT.name})"])
    READABLE.write_text("\n".join(lines) + "\n")
    print(json.dumps({"case_guards": [str(left_guard), str(right_guard)],
                      "candidate": str(candidate),
                      "holdout_witness": holdout["witness"],
                      "holdout_steps": holdout["native_window"]["native_steps"],
                      "whole_program_complete": False}, indent=2))


if __name__ == "__main__":
    main()
