"""Summarize Lua's interpreter loop in the admitted Bundle."""

from __future__ import annotations

from collections import Counter
from hashlib import sha256
import json
import os
from pathlib import Path
import sys

from tdo_v2.configured_naming_contracts import CALL_NAMING_GHIDRA_VERSION, NamingBindingExpectation
from tdo_v2.integration.configured_bundle import admit_frozen_bundle
from tdo_v2.integration.observed_function_session import open_observed_function_session
from tdo_v2.normalize import FunctionNormalizer, NormalizedFunction


generation = Path(sys.argv[1])
here = Path(__file__).resolve().parent
repo = Path(os.environ.get("DAASDMLKAS_REPO", str(here.parents[2] / "daasdmlkas")))
binding = NamingBindingExpectation(
    sha256((repo / "ghidra/GhidraV2CallNaming.java").read_bytes()).digest(),
    CALL_NAMING_GHIDRA_VERSION,
)
snapshot = admit_frozen_bundle(generation)
with open_observed_function_session(snapshot, naming_binding=binding) as session:
    target = None
    for index, evidence in enumerate(session.iter_functions()):
        if evidence.unit.observation.instructions[0].address.byte_offset == 0x415440:
            target = evidence
            break
        if index > 60:
            break
if target is None:
    raise AssertionError("luaV_execute was not found before the blocked observation")
observation = target.unit.observation
function = FunctionNormalizer().normalize(target.unit)
if type(function) is not NormalizedFunction:
    raise AssertionError(f"VM normalization failed: {function}")
opcodes = Counter(op.opcode for ins in observation.instructions for op in ins.operations)
ssa = function.memory_ssa
report = {
    "function": "luaV_execute",
    "instructions": len(observation.instructions),
    "pcode_operations": sum(opcodes.values()),
    "pcode_branch_ops": {name: count for name, count in opcodes.items() if "BRANCH" in name},
    "pcode_call_ops": {name: count for name, count in opcodes.items() if "CALL" in name},
    "ssa_actions": len(ssa.actions),
    "ssa_definitions": len(ssa.definitions),
    "ssa_joins": sum(d.kind.value == "join" for d in ssa.definitions),
    "unresolved_read_nodes": len(function.memory_graph.unresolved_read_nodes),
    "unresolved_write_nodes": len(function.memory_graph.unresolved_write_nodes),
}
destination = here / "lua_vm_probe_result.json"
destination.write_text(json.dumps(report, indent=2) + "\n")
print(json.dumps(report, indent=2))
