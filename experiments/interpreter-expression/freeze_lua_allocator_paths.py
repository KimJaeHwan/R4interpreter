"""Freeze Lua allocator failure, internal retry, and later success cutpoints."""
import gzip
from hashlib import sha256
import json
from pathlib import Path
import subprocess

import z3

from composed_native_transition import parse_segments
from freeze_js_string_loop import make_segment
from pcode_transition_summary import FLAG_OFFSETS, REGISTER_OFFSETS


ROOT = Path(__file__).resolve().parent
BINARY = ROOT / "lua_pool_failure_retry_fixture"
SOURCE = ROOT / "artifacts/next_lua_allocator_96.json.gz"
OUTPUT = ROOT / "lua_allocator_native_paths_summary.json"
PROOF = ROOT / "lua_allocator_failure_native_proof.json"
LABELS = ("success_initial", "failure_first", "failure_internal_retry",
          "free_before_retry", "successful_new_call", "free_after_retry")


def symbols():
    lines = subprocess.check_output(["nm", "-n", str(BINARY)], text=True)
    return {fields[2]: int(fields[0], 16)
            for line in lines.splitlines() if len(fields := line.split()) == 3}


def frame_condition(decls):
    rsp = decls["R_RSP"]
    return z3.And(z3.UGT(rsp, z3.BitVecVal(0x100000000, 64)),
                  z3.ULT(rsp, z3.BitVecVal(0x800000000000, 64)))


def verdict(*conditions):
    solver = z3.Solver()
    solver.set(timeout=15000)
    solver.add(*conditions)
    result = str(solver.check())
    if result != "unsat":
        raise ValueError(f"Lua native failure condition not proved: {result}")
    return result


def memory_word(memory, address, width):
    return z3.Concat(*reversed([z3.Select(
        memory, z3.BitVecVal(address + index, 64)) for index in range(width)]))


def effect_memory(initial, effects):
    memory = initial
    for item, address, value in effects:
        for index in range(item["width"]):
            memory = z3.Store(memory, address + z3.BitVecVal(index, 64),
                              z3.Extract(8 * index + 7, 8 * index, value))
    return memory


def main():
    with gzip.open(SOURCE, "rt") as stream:
        source = json.load(stream)
    if (source["binary_sha256"] != sha256(BINARY.read_bytes()).hexdigest()
            or source["retry_length"] != 96 or len(source["calls"]) != 6
            or [call["return_raw"] == 0 for call in source["calls"]] !=
            [False, True, True, True, False, True]):
        raise ValueError("Lua allocator source trace identity changed")
    segments = [make_segment(label, call["rows"], BINARY)
                for label, call in zip(LABELS, source["calls"])]
    inputs = ([{"name": f"R_{name.upper()}", "sort": "BV64"}
               for name in REGISTER_OFFSETS.values()] +
              [{"name": f"F_{bit}", "sort": "BV8"}
               for bit in FLAG_OFFSETS.values()] +
              [{"name": "M0", "sort": "Array(BV64,BV8)"}])
    summary = {"schema_version": "controlled-lua-allocator-paths-v1",
        "binary_sha256": source["binary_sha256"],
        "fixture_source_sha256": source["source_sha256"],
        "source_trace_sha256": sha256(SOURCE.read_bytes()).hexdigest(),
        "interface": {"inputs": inputs},
        "preconditions": {"source_allocation_extents": [105, 121],
                          "target_allocation_extents": [105, 119, 120],
                          "rsp_unsigned_range_exclusive": [0x100000000,
                                                          0x800000000000],
                          "allocator_entry_pointer": 0,
                          "failure_return_value": 0},
        "segments": segments,
        "limits": ["exact fixed ELF and observed path identity",
                   "failure proof has an explicit disjoint stack frame",
                   "success/free state refinements are conditional on guard, frame and finite capacity",
                   "Lua protected-call exception unwind is outside these cutpoints"]}
    decls, parsed = parse_segments(summary, set(LABELS))
    sym = symbols()
    frame = frame_condition(decls)
    proofs = {}
    for label in LABELS[1:3]:
        segment = parsed[label]
        rax = next(ast for name, ast in segment["outputs"] if name == "R_RAX")
        details = {"zero_return": verdict(frame, segment["guard"],
                                           rax != z3.BitVecVal(0, 64))}
        for name, width in (("live", 4), ("generation", 4),
                            ("live_extent", 8)):
            base = sym[name]
            overlap = z3.Or(*[
                address + z3.BitVecVal(index, 64) ==
                z3.BitVecVal(base + byte, 64)
                for item, address, _ in segment["effects"]
                for index in range(item["width"])
                for byte in range(width)])
            details[f"no_{name}_write"] = verdict(frame, segment["guard"],
                                                   overlap)
        proofs[label] = details
    for label in ("success_initial", "successful_new_call"):
        segment = parsed[label]
        after = effect_memory(decls["M0"], segment["effects"])
        rax = next(ast for name, ast in segment["outputs"] if name == "R_RAX")
        old_generation = memory_word(decls["M0"], sym["generation"], 4)
        bounded_request = z3.And(z3.UGE(decls["R_RCX"],
                                        z3.BitVecVal(1, 64)),
                                 z3.ULE(decls["R_RCX"],
                                        z3.BitVecVal(160, 64)),
                                 old_generation != z3.BitVecVal(0xffffffff, 32))
        premises = (frame, bounded_request, segment["guard"])
        proofs[label] = {
            "storage_pointer_return": verdict(*premises,
                rax != z3.BitVecVal(sym["storage"], 64)),
            "live_set": verdict(*premises,
                memory_word(after, sym["live"], 4) != z3.BitVecVal(1, 32)),
            "extent_set": verdict(*premises,
                memory_word(after, sym["live_extent"], 8) != decls["R_RCX"]),
            "generation_incremented": verdict(*premises,
                memory_word(after, sym["generation"], 4) !=
                old_generation + z3.BitVecVal(1, 32))}
    for label in ("free_before_retry", "free_after_retry"):
        segment = parsed[label]
        after = effect_memory(decls["M0"], segment["effects"])
        rax = next(ast for name, ast in segment["outputs"] if name == "R_RAX")
        premises = (frame, segment["guard"])
        proofs[label] = {
            "null_return": verdict(*premises, rax != z3.BitVecVal(0, 64)),
            "live_cleared": verdict(*premises,
                memory_word(after, sym["live"], 4) != z3.BitVecVal(0, 32)),
            "extent_cleared": verdict(*premises,
                memory_word(after, sym["live_extent"], 8) != z3.BitVecVal(0, 64)),
            "generation_preserved": verdict(*premises,
                memory_word(after, sym["generation"], 4) !=
                memory_word(decls["M0"], sym["generation"], 4))}
    OUTPUT.write_text(json.dumps(summary, indent=2) + "\n")
    PROOF.write_text(json.dumps({"schema_version": 1,
        "summary_sha256": sha256(OUTPUT.read_bytes()).hexdigest(),
        "source_trace_sha256": sha256(SOURCE.read_bytes()).hexdigest(),
        "protected_globals": {name: hex(sym[name])
                              for name in ("live", "generation", "live_extent",
                                           "storage")},
        "conditional_proofs": proofs,
        "scope": "six native allocator cutpoints under frozen path guards and disjoint stack frame; success additionally assumes requested extent <=160 and generation != 2^32-1"},
        indent=2) + "\n")
    print(json.dumps({"segments": len(segments), "conditional_proofs": len(proofs),
                      "native_steps": [part["identity"]["native_steps"]
                                       for part in segments]}))


if __name__ == "__main__":
    main()
