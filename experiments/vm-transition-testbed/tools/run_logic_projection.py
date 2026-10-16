"""Produce readable input logic from R4VM and archived Lua P-code summaries.

This runner enumerates program binaries and archived Lua boundary traces. It
does not read the case manifest, source files, expected results or opcode map.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from analyze_r4vm import Analyzer, ROOT
from project_r4vm_logic import project_program

LUA = ROOT.parent / "interpreter-expression"
sys.path.insert(0, str(LUA))
from project_lua_handler_logic import project as project_lua
from project_lua_two_adds_logic import project as project_lua_two_adds


def run(witnesses):
    analyzer = Analyzer()
    programs = {}
    for program in sorted((ROOT / "generated/programs").glob("*.r4vm")):
        programs[program.stem] = project_program(analyzer, program.read_bytes(), witnesses)
    summary = LUA / "handler_summary_plus7.json"
    binary = LUA / "lua_interpreter_fixture"
    lua_handlers = {}
    lua_reuse = {}
    for name in ("plus7", "plus11"):
        traces = sorted((LUA / "artifacts").glob(f"lua_handler_{name}_*.jsonl"))
        seed = LUA / f"artifacts/lua_handler_{name}_x9.jsonl"
        lua_handlers[name] = project_lua(summary, seed, binary)
        lua_reuse[name] = []
        for trace in traces:
            projected = project_lua(summary, trace, binary)
            lua_reuse[name].append({
                "trace": trace.name, "trace_sha256": projected["trace_sha256"],
                "witness": projected["witness"], "word": projected["word"],
                "guard": projected["guard"], "value": projected["value"],
                "same_formula_as_seed": projected["value_smt"] == lua_handlers[name]["value_smt"]})
    bridge = LUA / "lua_handler_dispatch_bridge.json"
    bytecode = LUA / "lua_chunk_two_adds.luac"
    two_adds_seed = LUA / "artifacts/lua_two_adds_x9.jsonl"
    lua_two_adds = project_lua_two_adds(summary, bridge, binary, bytecode, two_adds_seed)
    lua_two_adds_reuse = []
    for trace in sorted((LUA / "artifacts").glob("lua_two_adds_*.jsonl")):
        projected = project_lua_two_adds(summary, bridge, binary, bytecode, trace)
        lua_two_adds_reuse.append({
            "trace": trace.name, "trace_sha256": projected["trace_sha256"],
            "witness": projected["witness"], "guard": projected["guard"],
            "first_value": projected["first_value"], "value": projected["value"],
            "same_formula_as_seed": projected["value_smt"] == lua_two_adds["value_smt"]})
    return {"schema_version": 1, "kind": "input_logic_projection_experiment",
            "common_projector": "experiments/interpreter-expression/logic_projection.py",
            "witnesses": [str(value) for value in witnesses],
            "r4vm_programs": programs, "lua_handler_paths": lua_handlers,
            "lua_handler_reuse": lua_reuse, "lua_two_adds_path": lua_two_adds,
            "lua_two_adds_reuse": lua_two_adds_reuse,
            "limits": ["R4VM path coverage is sampled and guard/frame completeness unproved",
                       "Lua projections cover handler paths and one two-handler bridge, not a full script return",
                       "Lua and R4VM path extraction remain separate upstream stages"]}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--witness", type=int, nargs="+", default=[0, 9, -1])
    parser.add_argument("--output", type=Path,
                        default=ROOT / "results/input-logic-projection.json")
    args = parser.parse_args()
    report = run(args.witness)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({
        "r4vm_programs": len(report["r4vm_programs"]),
        "r4vm_cases": sum(len(item["cases"]) for item in report["r4vm_programs"].values()),
        "r4vm_unknown": sum(case["status"] == "unknown"
                             for item in report["r4vm_programs"].values()
                             for case in item["cases"]),
        "lua_handler_paths": len(report["lua_handler_paths"]),
        "lua_reuse_traces": sum(len(rows) for rows in report["lua_handler_reuse"].values()),
        "lua_two_adds_traces": len(report["lua_two_adds_reuse"]),
        "output": str(args.output)}))


if __name__ == "__main__":
    main()
