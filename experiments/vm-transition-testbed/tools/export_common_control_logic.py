"""Place new R4VM paths and archived Lua paths in one guarded relation format."""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SUITE = ROOT / "control-flow"
R4_PATHS = SUITE / "pcode-projection.json"
LUA_PATHS = ROOT / "results/input-logic-projection.json"
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
    report = {"schema_version": 1, "format": "guarded_input_relation",
              "r4vm_pcode_projection_sha256": sha256(R4_PATHS.read_bytes()).hexdigest(),
              "archived_lua_projection_sha256": sha256(LUA_PATHS.read_bytes()).hexdigest(),
              "entries": entries,
              "limit": "Lua relations are archived handler/bridge projections; "
                       "their guards were not proved complete, and no new Lua "
                       "function-call or full-script path was analyzed"}
    OUTPUT.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"entries": len(entries),
                      "r4vm": sum(e["engine"] == "r4vm_control" for e in entries),
                      "lua_archived": sum(e["engine"] == "lua_5_4_fixture"
                                          for e in entries)}))


if __name__ == "__main__":
    main()
