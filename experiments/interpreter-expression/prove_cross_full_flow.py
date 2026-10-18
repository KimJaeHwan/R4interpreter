"""Compose conditional branch/call/add/return proofs across Python and V8.

The input is a single-stepped native path with hardware watches, not the
fixture source or a language opcode semantics table. Each segment replays
SLEIGH Low P-code and checks the observed native state after every operation.
"""
from __future__ import annotations

import gzip
from hashlib import sha256
import json
from pathlib import Path
import shutil

import z3

from cross_dispatch_pcode import read_vaddr
from pcode_transition_summary import (Dual, FLAG_OFFSETS, PathReplay,
                                      REGISTER_OFFSETS, bv)
from prove_cross_value_path import lifted_instructions, small_int_memory
from prove_lua_full_flow import initial_memory


ROOT = Path(__file__).resolve().parent
PYTHON = Path("/usr/bin/python3.13")
JAVASCRIPT = Path(shutil.which("node"))
CACHE_BASE = 0xA42A10
TAGGED_FIVE = 5 << 32


class NativePathReplay(PathReplay):
    def read(self, node):
        if node["kind_code"] == 2 and node["byte_offset"] in (272, 280) and \
                node["byte_size"] == 8:
            name = "fs_base" if node["byte_offset"] == 272 else "gs_base"
            value = self.rows[0]["registers"][name]
            symbolic = getattr(self, "segment_base_symbols", {}).get(name,
                                                                      bv(value, 64))
            return Dual(symbolic, value)
        # SLEIGH uses a direct RAM varnode for some RIP-relative literal loads.
        # A RAM target on BRANCH/CBRANCH/CALL remains a control-flow address.
        if node["kind_code"] == 4 and self.current_opcode == "COPY":
            address = node["byte_offset"]
            return self.load(Dual(bv(address, 64), address), node["byte_size"])
        return super().read(node)


def load_trace(path, engine, witness, binary):
    with gzip.open(path, "rt") as stream:
        records = [json.loads(line) for line in stream]
    meta, summary = records[0], records[-1]
    rows = records[1:-1]
    if meta["engine"] != engine or meta["binary_sha256"] != sha256(binary.read_bytes()).hexdigest():
        raise ValueError("trace engine or executable hash mismatch")
    if meta["entry_value_raw"] != (witness if engine == "python" else witness << 32):
        raise ValueError("incorrect input witness")
    if not summary["hardware_watch_enabled"] or summary["hardware_watch_events"]:
        raise ValueError("hardware memory-access audit is incomplete")
    if summary["steps"] != len(rows) or any(row["step"] != index for index, row in enumerate(rows)):
        raise ValueError("native trace skipped a step")
    if any(a["next_pc"] != b["pc"] for a, b in zip(rows, rows[1:])):
        raise ValueError("native trace has a control-flow gap")
    if not summary.get("through_return") or int(summary["exit_pc"], 16) != (
            0x561334 if engine == "python" else 0x1A0A652):
        raise ValueError("wrong caller dispatch cutpoint")
    return meta, rows, summary


def one(rows, pc, after=-1):
    matches = [index for index, row in enumerate(rows) if index > after and row["pc"] == pc]
    if not matches:
        raise ValueError(f"native cutpoint {pc:#x} absent")
    return matches[0]


def word(memory, address):
    return z3.Concat(*reversed([
        z3.Select(memory, z3.BitVecVal(address + index, 64)) for index in range(8)]))


def replay(rows, binary, memory, register_symbols=None):
    if not rows or any(a["next_pc"] != b["pc"] for a, b in zip(rows, rows[1:])):
        raise ValueError("noncontiguous P-code segment")
    before = rows[0]["registers"]
    model = NativePathReplay(rows[0], rows, lifted_instructions(binary, rows),
        register_symbols={offset: (register_symbols or {}).get(name,
                          z3.BitVecVal(before[name], 64))
                          for offset, name in REGISTER_OFFSETS.items()},
        flag_symbols={offset: z3.BitVecVal((before["eflags"] >> bit) & 1, 8)
                      for offset, bit in FLAG_OFFSETS.items()},
        memory_symbol=memory, address_guards=True)
    model.run()
    guard = z3.And(*(item["condition"] for item in model.guards))
    return model, guard


def unsat(*conditions):
    solver = z3.Solver()
    solver.set(timeout=30000)
    solver.add(*conditions)
    verdict = solver.check()
    if verdict != z3.unsat:
        raise ValueError(f"expected UNSAT, got {verdict}")


def sat(*conditions):
    solver = z3.Solver()
    solver.set(timeout=30000)
    solver.add(*conditions)
    verdict = solver.check()
    if verdict != z3.sat:
        raise ValueError(f"expected SAT, got {verdict}")


def bounded(variable):
    return z3.And(z3.UGE(variable, z3.BitVecVal(5, 32)),
                  z3.ULE(variable, z3.BitVecVal(251, 32)))


def checked_segment(rows, binary, memory, symbols=None):
    model, guard = replay(rows, binary, memory, symbols)
    return model, guard, {"native_steps": len(rows),
                          "pcode_operations": model.operation_count,
                          "guard_count": len(model.guards)}


def check_watches(summary, labels):
    intervals = {item["label"]: item for item in summary["hardware_watch_intervals"]}
    if not labels <= intervals.keys() or summary["hardware_watch_events"]:
        raise ValueError("missing hardware watch interval")
    for label in labels:
        item = intervals[label]
        if item["start_step"] >= item["end_step"]:
            raise ValueError(f"empty hardware watch interval: {label}")
    return {label: {"watched_steps": intervals[label]["end_step"] -
                                    intervals[label]["start_step"],
                    "address": hex(intervals[label]["address"]),
                    "read_pc": intervals[label]["read_pc"]}
            for label in sorted(labels)}


def find_write(rows, address, value, before=None):
    matches = [(index, row, item) for index, row in enumerate(rows)
               for item in row["memory"] if item["address"] == address and
               item["size"] == 8 and item["after"] == value and
               item["before"] != item["after"] and
               (before is None or index < before)]
    if not matches:
        raise ValueError(f"source write {address:#x}={value:#x} absent")
    return matches[-1]


def assert_no_write(rows, address, size, start, end):
    # The hardware watch handles long intervals with implicit writes. This
    # local audit covers adjacent handler segments where P-code is replayed.
    for row in rows[start:end]:
        for item in row["memory"]:
            if item["address"] < address + size and \
                    item["address"] + item["size"] > address and \
                    (item["access"] & 2 or item["before"] != item["after"]):
                raise ValueError(f"intervening write to {address:#x} at {row['pc']:#x}")


def prove_single_live_register(model, guard, variable, register_name,
                               register_value, except_effect_address=None):
    """At a cutpoint, only one GPR and an explicitly named store may carry X."""
    unsat(bounded(variable), guard,
          model.regs[next(offset for offset, name in REGISTER_OFFSETS.items()
                          if name == register_name)] != register_value)
    for offset, name in REGISTER_OFFSETS.items():
        if name != register_name:
            unsat(bounded(variable), guard,
                  model.regs[offset] != bv(model.regs_concrete[offset], 64))
    for offset in FLAG_OFFSETS:
        unsat(bounded(variable), guard,
              model.flags[offset] != bv(model.flags_concrete[offset], 8))
    for effect in model.effects:
        if effect["observed_address"] != except_effect_address:
            unsat(bounded(variable), guard,
                  effect["value"] != bv(effect["observed"], effect["width"] * 8))


def prove_register_killed_without_read(rows, binary, first, kill, register_offset):
    if first >= kill or rows[kill]["registers"][REGISTER_OFFSETS[register_offset]] == \
            rows[kill]["registers_after"][REGISTER_OFFSETS[register_offset]]:
        raise ValueError("tainted register was not overwritten")
    instructions = lifted_instructions(binary, rows[first:kill + 1])
    for row in rows[first:kill + 1]:
        for operation in instructions[row["pc"]]["operations"]:
            for item in operation["inputs"]:
                if item["kind_code"] == 2 and \
                        item["byte_offset"] < register_offset + 8 and \
                        item["byte_offset"] + item["byte_size"] > register_offset:
                    raise ValueError(f"tainted register read before overwrite at {row['pc']:#x}")
    return {"register": REGISTER_OFFSETS[register_offset],
            "kill_pc": hex(rows[kill]["pc"]),
            "instructions_without_read": kill - first + 1}


def verify_cache(meta):
    cache = read_vaddr(PYTHON, CACHE_BASE, CACHE_BASE + 262 * 32)
    cache_hash = sha256(cache).hexdigest()
    if cache_hash != meta["runtime_cache_sha256_at_sync"]:
        raise ValueError("runtime PyLong cache differs from executable image")
    for value in (0, 5, 9, 10, 14, *range(10, 257)):
        offset = (value + 5) * 32
        tag = int.from_bytes(cache[offset + 16:offset + 24], "little")
        digit = int.from_bytes(cache[offset + 24:offset + 28], "little")
        if tag != (1 if value == 0 else 8) or digit != value:
            raise ValueError(f"invalid PyLong cache entry {value}")
    return cache_hash


def python_case(path, witness):
    meta, rows, summary = load_trace(path, "python", witness, PYTHON)
    cache_hash = verify_cache(meta)
    assert_no_write(rows, CACHE_BASE + (10 + 5) * 32,
                    (256 - 10 + 1) * 32, 0, len(rows))
    expected_output = 10 if witness == 0 else 14
    expected_pointer = CACHE_BASE + (expected_output + 5) * 32
    if summary["output_raw"] != expected_pointer:
        raise ValueError("Python returned the wrong cached PyLong object")
    labels = {"parent_local", "input_pyint_tag", "input_pyint_digit",
              "parent_call_argument", "child_parameter"}
    watches = check_watches(summary, labels)
    expected_reads = ([("input_pyint_tag", 0x5A8256),
                       ("input_pyint_digit", 0x5A8289)] if witness else [])
    expected_reads += [("parent_call_argument", 0x56036C),
                       ("child_parameter", 0x5612BF)]
    if witness:
        expected_reads += [("input_pyint_tag", 0x5E973F),
                           ("input_pyint_digit", 0x5E9769)]
    if [(item["label"], int(item["pc"], 16)) for item in
            summary["hardware_read_events"]] != expected_reads:
        raise ValueError("Python input object had unexpected native reads")
    branch_end = one(rows, 0x564F61)
    branch_rows = rows[:branch_end]
    x = z3.BitVec("PY_X", 32)
    if witness:
        memory, _ = small_int_memory(branch_rows, meta["entry_value_address"], 9, x)
    else:
        memory, _ = initial_memory(branch_rows)
    branch, branch_guard, branch_stat = checked_segment(branch_rows, PYTHON, memory)
    expected_offset = 36 if witness else 14
    if rows[branch_end]["registers"]["rbp"] - rows[0]["registers"]["rbp"] != expected_offset:
        raise ValueError("Python bytecode branch target differs")
    if witness:
        unsat(bounded(x), z3.Not(branch_guard))
        unsat(branch_guard, x == 0)
        sat(branch_guard, x == 10)
        prove_single_live_register(branch, branch_guard, x, "rsi", z3.ZeroExt(32, x))
        kill = one(rows, 0x564FD5, after=branch_end)
        gap_certificate = prove_register_killed_without_read(
            rows, PYTHON, branch_end, kill, 48)
    else:
        unsat(z3.Not(branch_guard))
        gap_certificate = None

    call = one(rows, 0x5636F9)
    child = one(rows, 0x565038, after=call)
    add = one(rows, 0x56227C, after=child)
    child_return = one(rows, 0x56173B, after=add)
    branch_return = one(rows, 0x56173B, after=child_return)
    parent_frame = rows[0]["registers"]["rbx"]
    child_frame = rows[add]["registers"]["rbx"]
    call_arg = parent_frame + 0x60
    argument_pointer = CACHE_BASE + ((9 if witness else 5) + 5) * 32
    parent_local = parent_frame + 0x48
    if meta["entry_value_address"] != CACHE_BASE + ((witness + 5) * 32):
        raise ValueError("unexpected Python entry object")

    # Replay the parent bytecode handler that places the argument on the VM stack.
    parent_producer_pc = 0x5612B0 if witness else 0x5612F0
    producer = max(index for index in range(call) if rows[index]["pc"] == parent_producer_pc)
    producer_rows = rows[producer:call]
    if witness:
        pointer_symbol = z3.BitVec("PY_OBJECT_POINTER", 64)
        memory, _ = initial_memory(producer_rows,
                                   [(parent_local, pointer_symbol, argument_pointer)])
    else:
        pointer_symbol = None
        memory, _ = initial_memory(producer_rows)
    parent_model, parent_guard, parent_stat = checked_segment(producer_rows, PYTHON, memory)
    if witness:
        unsat(pointer_symbol == bv(argument_pointer, 64), z3.Not(parent_guard))
    else:
        unsat(z3.Not(parent_guard))
    unsat(parent_guard, word(parent_model.memory, call_arg) !=
          (pointer_symbol if witness else bv(argument_pointer, 64)))

    arg_write_index, _, _ = find_write(rows, call_arg, argument_pointer, before=call)
    arg_read = one(rows, 0x56036C, after=call)
    child_store = one(rows, 0x56036F, after=arg_read)
    child_local = child_frame + 0x48
    if rows[arg_read]["memory"][0]["address"] != call_arg or \
            rows[arg_read]["memory"][0]["before"] != argument_pointer or \
            rows[child_store]["memory"][0]["address"] != child_local:
        raise ValueError("Python call argument slot mapping changed")
    if watches["parent_call_argument"]["address"] != hex(call_arg) or \
            watches["child_parameter"]["address"] != hex(child_local):
        raise ValueError("hardware call bridge watches used wrong slots")
    assert_no_write(rows, call_arg, 8, arg_write_index + 1, arg_read)
    bridge_rows = rows[arg_read:child_store + 1]
    bridge_pointer = z3.BitVec("PY_CALL_POINTER", 64)
    memory, _ = initial_memory(bridge_rows,
                               [(call_arg, bridge_pointer, argument_pointer)])
    bridge, bridge_guard, bridge_stat = checked_segment(bridge_rows, PYTHON, memory)
    unsat(bridge_pointer == bv(argument_pointer, 64), z3.Not(bridge_guard))
    unsat(bridge_guard, word(bridge.memory, child_local) != bridge_pointer)

    # LOAD_FAST and LOAD_CONST in addFive place the two PyLong pointers on its stack.
    child_load = one(rows, 0x5612B0, after=child)
    child_rows = rows[child_load:add]
    child_pointer = z3.BitVec("PY_CHILD_POINTER", 64)
    memory, _ = initial_memory(child_rows,
                               [(child_local, child_pointer, argument_pointer)])
    load_model, load_guard, load_stat = checked_segment(child_rows, PYTHON, memory)
    unsat(child_pointer == bv(argument_pointer, 64), z3.Not(load_guard))
    left_slot = rows[add]["registers"]["r15"] - 16
    right_slot = rows[add]["registers"]["r15"] - 8
    five_pointer = CACHE_BASE + (5 + 5) * 32
    unsat(load_guard, word(load_model.memory, left_slot) != child_pointer)
    unsat(load_guard, word(load_model.memory, right_slot) != bv(five_pointer, 64))
    if not any(item["address"] == child_local and item["before"] == argument_pointer
               for row in child_rows for item in row["memory"] if item["access"] & 1):
        raise ValueError("addFive did not load its argument slot")

    add_rows = rows[add:child_return]
    if witness:
        memory, _ = small_int_memory(add_rows, argument_pointer, witness, x)
    else:
        memory, _ = initial_memory(add_rows)
    add_model, add_guard, add_stat = checked_segment(add_rows, PYTHON, memory)
    output_slot = rows[child_return]["registers"]["r15"] - 8
    if witness:
        unsat(bounded(x), z3.Not(add_guard))
        expected_child_pointer = bv(CACHE_BASE, 64) + \
            ((z3.ZeroExt(32, x) + bv(10, 64)) << 5)
        unsat(bounded(x), add_guard,
              word(add_model.memory, output_slot) != expected_child_pointer)
    else:
        expected_child_pointer = bv(expected_pointer, 64)
        unsat(z3.Not(add_guard))
        unsat(word(add_model.memory, output_slot) != expected_child_pointer)

    # The child RETURN_VALUE handler writes the same object into the parent frame.
    return_rows = rows[child_return:branch_return]
    returned_pointer = z3.BitVec("PY_RETURN_POINTER", 64)
    memory, _ = initial_memory(return_rows,
                               [(output_slot, returned_pointer, expected_pointer)])
    return_model, return_guard, return_stat = checked_segment(return_rows, PYTHON, memory)
    if witness:
        unsat(bounded(x), z3.Not(z3.substitute(
            return_guard, (returned_pointer, expected_child_pointer))))
    else:
        unsat(returned_pointer == bv(expected_pointer, 64), z3.Not(return_guard))
    parent_output_slot = rows[branch_return]["registers"]["r15"] - 8
    unsat(return_guard,
          word(return_model.memory, parent_output_slot) != returned_pointer)
    if summary["function_return_raw"] != expected_pointer:
        raise ValueError("branchCall RETURN_VALUE received the wrong object")
    outer_rows = rows[branch_return:]
    outer_pointer = z3.BitVec("PY_OUTER_RETURN_POINTER", 64)
    memory, _ = initial_memory(outer_rows,
                               [(parent_output_slot, outer_pointer, expected_pointer)])
    outer_model, outer_guard, outer_stat = checked_segment(outer_rows, PYTHON, memory)
    unsat(outer_pointer == bv(expected_pointer, 64), z3.Not(outer_guard))
    caller_output_slot = summary["exit_registers"]["r15"] - 8
    unsat(outer_guard,
          word(outer_model.memory, caller_output_slot) != outer_pointer)
    return {"engine": "python", "witness": witness,
            "native_steps": len(rows), "output": expected_output,
            "branch_bytecode_offset": expected_offset,
            "call_argument": 5 if witness == 0 else "X",
            "proof_domain": "X = 0" if witness == 0 else "5 <= X <= 251",
            "cache_sha256": cache_hash,
            "hardware_watches": watches,
            "hardware_read_events": summary["hardware_read_events"],
            "gap_noninterference": gap_certificate,
            "segments": {"branch": branch_stat, "parent_argument": parent_stat,
                         "call_bridge": bridge_stat, "child_operands": load_stat,
                         "addition": add_stat, "child_return_bridge": return_stat,
                         "outer_return_bridge": outer_stat},
            "result": "conditional end-to-end proof through caller dispatch",
            "trace_sha256": sha256(path.read_bytes()).hexdigest()}


def javascript_case(path, witness):
    meta, rows, summary = load_trace(path, "javascript", witness, JAVASCRIPT)
    expected_output = 10 if witness == 0 else 14
    if summary["output_raw"] != expected_output << 32:
        raise ValueError("JavaScript function returned the wrong Smi")
    watches = check_watches(summary, {"parent_parameter", "child_parameter"})
    expected_reads = [("parent_parameter", 0x1BBFF8D)]
    if witness:
        expected_reads.append(("parent_parameter", 0x1BBDB12))
    expected_reads.append(("child_parameter", 0x1BA8D09))
    if [(item["label"], int(item["pc"], 16)) for item in
            summary["hardware_read_events"]] != expected_reads:
        raise ValueError("JS parameters had unexpected native reads")
    branch_end = one(rows, 0x1BA9780)
    branch_rows = rows[:branch_end]
    x = z3.BitVec("JS_X", 32)
    tagged_x = z3.Concat(x, bv(0, 32))
    memory, _ = initial_memory(branch_rows,
                               [(meta["entry_value_address"], tagged_x, witness << 32)])
    branch, branch_guard, branch_stat = checked_segment(branch_rows, JAVASCRIPT, memory)
    branch_offset = rows[branch_end]["registers"]["r12"] + \
                    rows[branch_end]["registers"]["r9"] - meta["target_code"]
    if branch_offset != (6 if witness == 0 else 17):
        raise ValueError("JavaScript bytecode branch target differs")
    if witness:
        unsat(bounded(x), z3.Not(branch_guard))
        unsat(branch_guard, x == 0)
    else:
        unsat(branch_guard, x != 0)
        unsat(x == 0, z3.Not(branch_guard))

    child_arg_store = one(rows, 0x1BBDB33)
    call_rows = rows[:child_arg_store + 1]
    memory, _ = initial_memory(call_rows,
                               [(meta["entry_value_address"], tagged_x, witness << 32)])
    call_model, call_guard, call_stat = checked_segment(call_rows, JAVASCRIPT, memory)
    add = one(rows, 0x1BB7780, after=child_arg_store)
    child_return = one(rows, 0x1BC6F40, after=add)
    branch_return = one(rows, 0x1BC6F40, after=child_return)
    child_slot = rows[add]["registers"]["rbp"] + 0x18
    if watches["child_parameter"]["address"] != hex(child_slot):
        raise ValueError("JS hardware watch covered the wrong child slot")
    call_value = bv(TAGGED_FIVE, 64) if witness == 0 else tagged_x
    unsat(call_guard, word(call_model.memory, child_slot) != call_value)
    if witness:
        unsat(bounded(x), z3.Not(call_guard))
        prove_single_live_register(call_model, call_guard, x, "rbx", tagged_x,
                                   except_effect_address=child_slot)
        kill = one(rows, 0x19FF01A, after=child_arg_store)
        gap_certificate = prove_register_killed_without_read(
            rows, JAVASCRIPT, child_arg_store + 1, kill, 24)
    else:
        unsat(x == 0, z3.Not(call_guard))
        gap_certificate = None
    child_read = one(rows, 0x1BA8D09, after=child_arg_store)
    if rows[child_read]["memory"][0]["address"] != child_slot or \
            rows[child_read]["memory"][0]["before"] != \
            (witness if witness else 5) << 32:
        raise ValueError("JS child argument read disagrees with call write")
    if watches["child_parameter"]["read_pc"] != hex(0x1BA8D09):
        raise ValueError("JS child slot watch did not reach the Ldar read")

    ldar = one(rows, 0x1BA8D00, after=child_arg_store)
    ldar_rows = rows[ldar:add]
    y = z3.BitVec("JS_CHILD_X", 32)
    tagged_y = z3.Concat(y, bv(0, 32))
    memory, _ = initial_memory(ldar_rows,
                               [(child_slot, tagged_y, (witness if witness else 5) << 32)])
    ldar_model, ldar_guard, ldar_stat = checked_segment(ldar_rows, JAVASCRIPT, memory)
    unsat(bounded(y), z3.Not(ldar_guard))
    unsat(ldar_guard, ldar_model.regs[0] != tagged_y)

    add_rows = rows[add:child_return]
    memory, _ = initial_memory(add_rows)
    add_model, add_guard, add_stat = checked_segment(
        add_rows, JAVASCRIPT, memory, {"rax": tagged_y})
    expected_tagged_result = z3.Concat(y + bv(5, 32), bv(0, 32))
    unsat(add_guard, add_model.regs[0] != expected_tagged_result)
    unsat(bounded(y), z3.Not(add_guard))
    unsat(add_guard, z3.Not(z3.BVAddNoOverflow(y, bv(5, 32), True)))

    return_rows = rows[child_return:branch_return]
    z = z3.BitVec("JS_RESULT", 32)
    tagged_z = z3.Concat(z, bv(0, 32))
    memory, _ = initial_memory(return_rows)
    return_model, return_guard, return_stat = checked_segment(
        return_rows, JAVASCRIPT, memory, {"rax": tagged_z})
    unsat(z3.UGE(z, bv(10, 32)), z3.ULE(z, bv(256, 32)),
          z3.Not(return_guard))
    unsat(return_guard, return_model.regs[0] != tagged_z)
    final_offset = rows[branch_return]["registers"]["r12"] + \
                   rows[branch_return]["registers"]["r9"] - meta["target_code"]
    if final_offset != (16 if witness == 0 else 24):
        raise ValueError("JS did not reach branchCall's Return bytecode")
    if summary["function_return_raw"] != expected_output << 32:
        raise ValueError("branchCall RETURN bytecode received the wrong Smi")
    outer_rows = rows[branch_return:]
    outer_z = z3.BitVec("JS_OUTER_RESULT", 32)
    outer_tag = z3.Concat(outer_z, bv(0, 32))
    memory, _ = initial_memory(outer_rows)
    outer_model, outer_guard, outer_stat = checked_segment(
        outer_rows, JAVASCRIPT, memory, {"rax": outer_tag})
    unsat(z3.UGE(outer_z, bv(10, 32)), z3.ULE(outer_z, bv(256, 32)),
          z3.Not(outer_guard))
    unsat(outer_guard, outer_model.regs[0] != outer_tag)
    return {"engine": "javascript", "witness": witness,
            "native_steps": len(rows), "output": expected_output,
            "branch_bytecode_offset": branch_offset,
            "return_bytecode_offset": final_offset,
            "call_argument": 5 if witness == 0 else "X",
            "proof_domain": "X = 0" if witness == 0 else "5 <= X <= 251",
            "hardware_watches": watches,
            "hardware_read_events": summary["hardware_read_events"],
            "gap_noninterference": gap_certificate,
            "segments": {"branch": branch_stat, "call_argument": call_stat,
                         "child_load": ldar_stat, "addition": add_stat,
                         "child_return_bridge": return_stat,
                         "outer_return_bridge": outer_stat},
            "result": "conditional end-to-end proof through caller dispatch",
            "trace_sha256": sha256(path.read_bytes()).hexdigest()}


def main():
    cases = []
    for witness in (0, 9):
        cases.append(python_case(ROOT / f"artifacts/cross_python_full_{witness}.json.gz", witness))
        cases.append(javascript_case(ROOT / f"artifacts/cross_js_full_{witness}.json.gz", witness))
    result = {"schema_version": 1, "lifter": "Ghidra SLEIGH x86:LE:64:default / pypcode",
              "shared_statement": "X=0 -> 10; 5<=X<=251 -> X+5",
              "status": "conditional native-path proof through caller dispatch",
              "scope": "fixed CPython/Node ELFs, fixture bytecode, initial VM state, "
                       "Python cached nonnegative PyLong or V8 Smi, observed path bridges",
              "cases": cases}
    target = ROOT / "cross_full_flow_result.json"
    target.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"status": result["status"],
                      "cases": [{"engine": item["engine"], "input": item["witness"],
                                 "native_steps": item["native_steps"], "output": item["output"]}
                                for item in cases]}))


if __name__ == "__main__":
    main()
