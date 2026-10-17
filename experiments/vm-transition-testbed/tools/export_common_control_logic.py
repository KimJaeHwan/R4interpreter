"""Place new R4VM paths and archived Lua paths in one guarded relation format."""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SUITE = ROOT / "control-flow"
R4_PATHS = SUITE / "pcode-projection.json"
LUA_PATHS = ROOT / "results/input-logic-projection.json"
LUA_BRANCH = ROOT.parent / "interpreter-expression/lua_branch_call_relation.json"
FRAMES = ROOT / "frames/angr-analysis.json"
OUTPUT = SUITE / "common-logic.json"


def main():
    r4 = json.loads(R4_PATHS.read_text())
    lua = json.loads(LUA_PATHS.read_text())
    entries = []
    for case in r4["cases"]:
        entries.append({"engine": "r4vm_control", "source": case["id"],
                        "scope": "program_output", "input": "X:BV64",
                        "program_sha256": case["program_sha256"],
                        "paths": [{"guard": path["guard"],
                                   "guard_proven": True,
                                   "status": path["runtime_status"],
                                   "value": path["formula"],
                                   "output_pc": path["output_pc"],
                                   "vm_fetch_trace": path["vm_fetch_trace"]}
                                  for path in case["paths"]]})
    for name, path in lua["lua_handler_paths"].items():
        if not path["value_reduction_proved"]:
            raise ValueError(f"Lua handler value lacks reduction proof: {name}")
        entries.append({"engine": "lua_5_4_fixture", "source": name,
                        "scope": "handler_transition", "input": "X:BV64",
                        "binary_sha256": path["binary_sha256"],
                        "paths": [{"guard": path["guard"],
                                   "guard_proven": path["guard_reduction_proved"],
                                   "guard_smt": path["guard_smt"],
                                   "status": "value_written",
                                   "value": path["value"],
                                   "ordered_effect_count": path["ordered_effects"]}]})
    path = lua["lua_two_adds_path"]
    if not path["value_reduction_proved"]:
        raise ValueError("Lua two-handler value lacks reduction proof")
    entries.append({"engine": "lua_5_4_fixture", "source": "two_adds",
                    "scope": "two_handler_bridge", "input": "X:BV64",
                    "binary_sha256": path["binary_sha256"],
                    "paths": [{"guard": path["guard"],
                               "guard_proven": path["guard_reduction_proved"],
                               "guard_smt": path["guard_smt"],
                               "status": "value_written",
                               "value": path["value"]}]})
    branch = json.loads(LUA_BRANCH.read_text())
    entries.append({"engine": branch["engine"], "source": branch["source"],
                    "scope": branch["scope"], "input": branch["input"],
                    "binary_sha256": branch["binary_sha256"],
                    "program_sha256": branch["program_sha256"],
                    "paths": branch["paths"]})
    frames = json.loads(FRAMES.read_text())
    for case in frames["experiments"]:
        if not case.get("guard_coverage_proved"):
            continue
        entries.append({"engine": "r4vm_frames", "source": case["id"],
                        "scope": "program_output", "input": "X:BV64",
                        "program_sha256": case["program_sha256"],
                        "analysis_strength": "bounded_angr_native_path",
                        "paths": [{"guard": path["guard"],
                                   "guard_proven": path["guard_proven"],
                                   "status": path["status"],
                                   "value": path["formula"],
                                   "value_proven": path["formula_proven"],
                                   "output_pc": path["output_pc"],
                                   "vm_fetch_trace": path["vm_fetch_trace"]}
                                  for path in case["paths"]]})
    report = {"schema_version": 1, "format": "guarded_input_relation",
              "r4vm_pcode_projection_sha256": sha256(R4_PATHS.read_bytes()).hexdigest(),
              "archived_lua_projection_sha256": sha256(LUA_PATHS.read_bytes()).hexdigest(),
              "lua_branch_call_relation_sha256": sha256(LUA_BRANCH.read_bytes()).hexdigest(),
              "r4vm_frames_analysis_sha256": sha256(FRAMES.read_bytes()).hexdigest(),
              "entries": entries,
              "limit": "Lua relations are archived handler/bridge projections; "
                       "their guards were not proved complete. The new Lua "
                       "function-call relation has observed full-script paths "
                       "and a proved callee arithmetic value, but its full "
                       "script guards and output formulas remain unproved."}
    OUTPUT.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"entries": len(entries),
                      "r4vm": sum(e["engine"] == "r4vm_control" for e in entries),
                      "lua": sum(e["engine"] == "lua_5_4_fixture"
                                 for e in entries),
                      "r4vm_frames": sum(e["engine"] == "r4vm_frames"
                                          for e in entries)}))


if __name__ == "__main__":
    main()
