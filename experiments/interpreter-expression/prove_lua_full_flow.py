"""Compose bounded P-code input and return proofs for the Lua branch fixture.

X denotes run_lua_chunk's parsed integer argument. P denotes the 64-bit
payload written by the called VM arithmetic handler. Long intervals are
checked against the recorded native memory-write audit; libc's parsing and
the x86-64 ABI are explicit assumptions, not inferred from equal witnesses.
"""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path

import z3

from pcode_transition_summary import FLAG_OFFSETS, REGISTER_OFFSETS, PathReplay
from project_lua_call_bridge import BINARY, BUNDLE, BYTECODE, ROOT, load_instructions, output_word

MAIN_BUNDLE = ROOT / "artifacts/lua_main_bundle.tar.gz"
MASK = (1 << 64) - 1


def require_unsat(*conditions):
    solver = z3.Solver()
    solver.set(timeout=30000)
    solver.add(*conditions)
    verdict = solver.check()
    if verdict != z3.unsat:
        raise ValueError(f"expected UNSAT, got {verdict}")


def require_true(expression):
    require_unsat(z3.Not(expression))


def trace_records(path):
    records = [json.loads(line) for line in path.read_text().splitlines()]
    if records[0]["type"] != "meta" or records[-1]["type"] != "summary" or \
            not records[-1]["stopped_before_printf_call"]:
        raise ValueError("incomplete full-flow native trace")
    watch = records[-1]
    if not watch.get("hardware_watch_enabled") or \
            not watch.get("hardware_watch_self_check_passed") or watch.get("hardware_watch_events") or \
            [item["phase"] for item in watch.get("hardware_watch_intervals", [])] != [
                "initial_lua_slot", "copied_vm_source", "native_return_stack"]:
        raise ValueError("required hardware write-watch intervals are incomplete or hit")
    return records


def first_step(records, pc, after_step=-1):
    return next(row for row in records if row.get("type") == "step" and
                row["pc"] == pc and row["step"] > after_step)


def contiguous(records, start_pc, end_pc, include_end=True):
    start = first_step(records, start_pc)["step"]
    end = first_step(records, end_pc, start - 1)["step"]
    rows = [row for row in records if row.get("type") == "step" and
            start <= row["step"] <= end and (include_end or row["step"] < end)]
    if not rows or rows[0]["pc"] != start_pc or \
            (include_end and rows[-1]["pc"] != end_pc) or \
            any(a["step"] + 1 != b["step"] or a["next_pc"] != b["pc"]
                for a, b in zip(rows, rows[1:])):
        raise ValueError(f"uncaptured native steps between {start_pc:#x} and {end_pc:#x}")
    if not include_end and rows[-1]["next_pc"] != end_pc:
        raise ValueError("tail segment does not reach the expected cutpoint")
    return rows


def initial_memory(rows, symbols=()):
    """Initialize all first-read bytes and override named 8-byte live-ins."""
    written = set()
    initial = {}
    for row in rows:
        for access in row["memory"]:
            address, size, mode = access["address"], access["size"], access["access"]
            if mode & 1:
                if access["before"] is None:
                    raise ValueError("unreadable initial memory")
                for index in range(size):
                    byte_address = (address + index) & MASK
                    if byte_address not in written:
                        value = (access["before"] >> (8 * index)) & 255
                        if byte_address in initial and initial[byte_address] != value:
                            raise ValueError("first-read memory changed without a captured write")
                        initial[byte_address] = value
            if mode & 2:
                written.update((address + index) & MASK for index in range(size))
    memory = z3.K(z3.BitVecSort(64), z3.BitVecVal(0, 8))
    for address, value in initial.items():
        memory = z3.Store(memory, z3.BitVecVal(address, 64), z3.BitVecVal(value, 8))
    for address, symbol, witness in symbols:
        for index in range(8):
            byte_address = (address + index) & MASK
            if initial.get(byte_address) != (witness >> (8 * index)) & 255:
                raise ValueError("symbolic live-in lacks its first-read witness")
            memory = z3.Store(memory, z3.BitVecVal(byte_address, 64),
                              z3.Extract(index * 8 + 7, index * 8, symbol))
    return memory, len(initial)


def replay(rows, memory, symbolic_registers=None, bundle=BUNDLE):
    before = rows[0]["registers"]
    symbolic_registers = symbolic_registers or {}
    model = PathReplay(
        rows[0], rows, load_instructions((row["pc"] for row in rows), bundle),
        register_symbols={offset: symbolic_registers.get(name, z3.BitVecVal(before[name], 64))
                          for offset, name in REGISTER_OFFSETS.items()},
        flag_symbols={offset: z3.BitVecVal((before["eflags"] >> bit) & 1, 8)
                      for offset, bit in FLAG_OFFSETS.items()},
        memory_symbol=memory, address_guards=True)
    model.run()
    guard = z3.simplify(z3.And(*(item["condition"] for item in model.guards)))
    require_true(guard)
    return model


def first_memory(row, mode):
    accesses = [access for access in row["memory"] if access["access"] & mode]
    if len(accesses) != 1 or accesses[0]["size"] != 8:
        raise ValueError(f"expected one 8-byte access at {row['pc']:#x}")
    return accesses[0]


def audit_no_write(records, address, size, after_step, before_step):
    inspected = 0
    for row in records:
        if not after_step < row.get("step", -1) < before_step:
            continue
        if row["type"] not in ("step", "write"):
            continue
        for access in row["memory"]:
            if not access["access"] & 2:
                continue
            inspected += 1
            if access["address"] < address + size and address < access["address"] + access["size"]:
                raise ValueError(f"intervening write to live value at {row['pc']:#x}")
    return inspected


def prove_input(records, x):
    witness = records[0]["input_word"]
    entry = first_step(records, 0x401490)
    if entry["registers"]["rsi"] != witness:
        raise ValueError("run_lua_chunk received a different parsed argument")
    save = first_step(records, 0x40149B)
    saved = replay([save], z3.K(z3.BitVecSort(64), z3.BitVecVal(0, 8)), {"rsi": x})
    require_unsat(saved.regs[40] != x)
    push = contiguous(records, 0x4014B3, 0x402A04)
    if push[0]["registers"]["rbp"] != witness:
        raise ValueError("saved input register witness changed across allocation")
    push_memory, _ = initial_memory(push)
    pushed = replay(push, push_memory, {"rbp": x})
    a_access = first_memory(push[-1], 2)
    a = a_access["address"]
    if a_access["after"] != witness:
        raise ValueError("initial Lua slot does not contain parsed argument")
    require_unsat(output_word(pushed.memory, a) != x)

    copy = contiguous(records, 0x411B50, 0x411B54)
    a_read = first_memory(copy[0], 1)
    if a_read["address"] != a or a_read["before"] != witness:
        raise ValueError("first Lua copy reads a different value")
    a_audit = audit_no_write(records, a, 8, push[-1]["step"], copy[0]["step"])
    first_watch, second_watch, _ = records[-1]["hardware_watch_intervals"]
    if (first_watch["address"] != hex(a) or
            (first_watch["start_step"], first_watch["end_step"]) !=
            (push[-1]["step"], copy[0]["step"])):
        raise ValueError("first Lua source was not hardware-watched across its live interval")
    copy_memory, _ = initial_memory(copy, [(a, x, witness)])
    copied = replay(copy, copy_memory)
    b_access = first_memory(copy[-1], 2)
    b = b_access["address"]
    if b_access["after"] != witness:
        raise ValueError("second Lua slot has a different witness")
    require_unsat(output_word(copied.memory, b) != x)

    first_source = first_step(records, 0x416EA1, copy[-1]["step"])
    b_read = first_memory(first_source, 1)
    if b_read["address"] != b or b_read["before"] != witness:
        raise ValueError("local VM source is not the copied Lua slot")
    b_audit = audit_no_write(records, b, 8, copy[-1]["step"], first_source["step"])
    if second_watch["address"] != hex(b) or second_watch["start_step"] != copy[-1]["step"] or \
            second_watch["end_step"] < first_source["step"]:
        raise ValueError("VM source was not hardware-watched through its first read")
    source_memory, _ = initial_memory([first_source], [(b, x, witness)])
    source = replay([first_source], source_memory)
    require_unsat(source.regs[16] != x)
    return {"run_lua_entry_pc": "0x401490", "entry_register": "RSI",
            "saved_register": "RBP", "saved_register_transfer_pcode_proved": True,
            "saved_register_preserved_across_luaL_newstate": "x86-64 SysV ABI assumption; witness checked",
            "source_native_pc": "0x416ea1", "source_expression": "X",
            "source_expression_pcode_proved": True,
            "a_to_b_intervening_writes_inspected": a_audit,
            "b_to_source_intervening_writes_inspected": b_audit,
            "a_to_b_no_recorded_aliasing_write": True,
            "b_to_source_no_recorded_aliasing_write": True,
            "long_input_slots_hardware_watch_no_write": True}


def prove_return(records, p, witness):
    body = contiguous(records, 0x417CEA, 0x401542)
    result_access = first_memory(body[0], 2)
    if result_access["after"] != witness or body[0]["registers"]["r12"] != witness:
        raise ValueError("handler payload witness changed")
    body_memory, _ = initial_memory(body)
    modeled = replay(body, body_memory, {"r12": p})
    require_unsat(output_word(modeled.memory, result_access["address"]) != p)
    stack_access = first_memory(body[-1], 2)
    stack_slot = stack_access["address"]
    if stack_access["after"] != witness:
        raise ValueError("native return slot differs from VM payload")
    require_unsat(output_word(modeled.memory, stack_slot) != p)
    require_unsat(modeled.regs[0] != p)

    tail = contiguous(records, 0x40154C, 0x401388, include_end=False)
    stack_read = first_memory(tail[0], 1)
    if stack_read["address"] != stack_slot or stack_read["before"] != witness:
        raise ValueError("function epilogue reads another stack slot")
    close_audit = audit_no_write(records, stack_slot, 8, body[-1]["step"], tail[0]["step"])
    stack_watch = records[-1]["hardware_watch_intervals"][2]
    if stack_watch["address"] != hex(stack_slot) or \
            (stack_watch["start_step"], stack_watch["end_step"]) != \
            (body[-1]["step"], tail[0]["step"]):
        raise ValueError("native return slot was not hardware-watched through lua_close")
    tail_memory, _ = initial_memory(tail, [(stack_slot, p, witness)])
    modeled_tail = replay(tail, tail_memory, bundle=MAIN_BUNDLE)
    require_unsat(modeled_tail.regs[48] != p)
    printf_call = first_step(records, 0x401388)
    if printf_call["registers"]["rsi"] != witness or tail[-1]["next_pc"] != printf_call["pc"]:
        raise ValueError("printf argument witness changed")
    return {"vm_payload_write_pc": "0x417cea", "native_result_store_pc": "0x401542",
            "printf_call_pc": "0x401388", "printf_second_argument_expression": "P",
            "vm_to_native_stack_pcode_proved": True,
            "native_stack_to_printf_argument_pcode_proved": True,
            "lua_close_intervening_writes_inspected": close_audit,
            "lua_close_no_recorded_stack_aliasing_write": True,
            "native_return_slot_hardware_watch_no_write": True,
            "vm_to_native_instructions": len(body),
            "vm_to_native_pcode_operations": modeled.operation_count,
            "native_tail_instructions": len(tail),
            "native_tail_pcode_operations": modeled_tail.operation_count}


def prove_vm_path(records, x, witness_payload):
    branch = next(row for row in records if row.get("type") == "replay_step" and
                  row["pc"] == 0x417E50)
    source = max((row for row in records if row.get("type") == "replay_step" and
                  row["pc"] == 0x416EA1 and row["step"] < branch["step"]),
                 key=lambda row: row["step"])
    add = first_step(records, 0x417CEA)
    rows = [row for row in records if row.get("type") == "replay_step" and
            source["step"] <= row["step"] < add["step"]] + [add]
    if any(a["step"] + 1 != b["step"] or a["next_pc"] != b["pc"]
           for a, b in zip(rows, rows[1:])):
        raise ValueError("VM source-to-payload native path is not contiguous")
    if len([row for row in rows if row["pc"] == 0x4164B8]) != 1:
        raise ValueError("expected one called handler entry on VM path")
    source_access = first_memory(source, 1)
    witness = records[0]["input_word"]
    if source_access["before"] != witness:
        raise ValueError("local VM input witness differs from parsed input")
    memory, first_reads = initial_memory(rows, [(source_access["address"], x, witness)])
    entry = rows[0]["registers"]
    modeled = PathReplay(
        rows[0], rows, load_instructions((row["pc"] for row in rows)),
        register_symbols={offset: z3.BitVecVal(entry[name], 64)
                          for offset, name in REGISTER_OFFSETS.items()},
        flag_symbols={offset: z3.BitVecVal((entry["eflags"] >> bit) & 1, 8)
                      for offset, bit in FLAG_OFFSETS.items()},
        memory_symbol=memory, address_guards=True)
    modeled.run()
    guard = z3.simplify(z3.And(*(item["condition"] for item in modeled.guards)))
    is_zero = witness == 0
    candidate_guard = x == 0 if is_zero else x != 0
    require_unsat(z3.Xor(guard, candidate_guard))
    solver = z3.Solver()
    solver.add(guard)
    if solver.check() != z3.sat:
        raise ValueError("VM path guard is empty")
    candidate_value = z3.BitVecVal(10, 64) if is_zero else x + z3.BitVecVal(5, 64)
    store = first_memory(add, 2)
    if store["after"] != witness_payload or add["registers"]["r12"] != witness_payload:
        raise ValueError("VM payload witness changed")
    require_unsat(guard, modeled.regs[160] != candidate_value)
    require_unsat(guard, output_word(modeled.memory, store["address"]) != candidate_value)
    return {"source_native_pc": "0x416ea1", "callee_native_pc": "0x4164b8",
            "result_native_pc": "0x417cea", "guard": "X == 0" if is_zero else "X != 0",
            "guard_equivalence": "unsat", "payload_expression": "10" if is_zero else "X + 5",
            "payload_equivalence": "unsat", "observed_address_guard_equivalence": "unsat",
            "native_instructions": len(rows), "pcode_operations": modeled.operation_count,
            "pcode_reads": len(modeled.reads), "pcode_writes": len(modeled.effects),
            "initial_memory_bytes": first_reads}


def main():
    x, p = z3.BitVec("X", 64), z3.BitVec("P", 64)
    paths = []
    for label, argument, payload in (("x0", 0, 10), ("x9", 9, 14), ("one", 1, 6),
                                     ("minus1", -1, 4),
                                     ("max", (1 << 63) - 1, ((1 << 63) - 1 + 5) & MASK),
                                     ("min", -(1 << 63), (-(1 << 63) + 5) & MASK)):
        trace = ROOT / f"artifacts/lua_branch_full_flow_{label}.jsonl"
        records = trace_records(trace)
        if records[0]["input"] != argument:
            raise ValueError("full-flow trace input changed")
        paths.append({"path": label, "witness_input": str(argument),
                      "witness_payload": str(payload),
                      "input_prefix": prove_input(records, x),
                      "vm_path": prove_vm_path(records, x, payload),
                      "return_suffix": prove_return(records, p, payload),
                      "trace_sha256": sha256(trace.read_bytes()).hexdigest()})
    report = {"schema_version": 1, "kind": "bounded_native_input_and_return_flow",
              "input_interface": "X is run_lua_chunk's signed 64-bit argument, after successful strtoll parsing",
              "payload_interface": "P is the 64-bit VM arithmetic result in R12 at 0x417cea",
              "binary_sha256": sha256(BINARY.read_bytes()).hexdigest(),
              "bytecode_sha256": sha256(BYTECODE.read_bytes()).hexdigest(),
              "bundle_sha256": sha256(BUNDLE.read_bytes()).hexdigest(),
              "main_bundle_sha256": sha256(MAIN_BUNDLE.read_bytes()).hexdigest(),
              "paths": paths,
              "conditional_native_result": "X == 0 ? 10 : (X + 5) mod 2^64",
              "conditional_native_result_proved_under_assumptions": True,
              "assumptions": ["x86-64 SysV ABI preserves RBP across luaL_newstate",
                              "strtoll successfully parsed a signed 64-bit integer",
                              "long interval slot preservation is checked by hardware write watchpoints for the six witnesses, but is not universally proved for unobserved paths",
                              "other non-input registers, flags and first-read memory are fixed to each path witness"],
              "unconditional_full_script_proof": False}
    (ROOT / "lua_branch_full_flow.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"paths": [(item["path"], item["vm_path"]["guard"],
                                  item["vm_path"]["payload_expression"])
                                 for item in paths], "unconditional_full_script_proof": False}))


if __name__ == "__main__":
    main()
