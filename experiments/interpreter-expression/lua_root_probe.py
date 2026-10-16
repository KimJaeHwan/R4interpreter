"""Measure the selected Lua runner's return-value SSA slices."""

from __future__ import annotations

from collections import Counter
from hashlib import sha256
import json
import os
from pathlib import Path
import sys

from tdo_v2.configured_naming_contracts import CALL_NAMING_GHIDRA_VERSION, NamingBindingExpectation
from tdo_v2.graph_contracts import NodeKind
from tdo_v2.integration.configured_bundle import admit_frozen_bundle
from tdo_v2.integration.observed_function_session import open_observed_function_session
from tdo_v2.normalize import FunctionNormalizer, NormalizedFunction
from tdo_v2.query import BackwardSliceQuery


generation = Path(sys.argv[1])
here = Path(__file__).resolve().parent
repo = Path(os.environ.get("DAASDMLKAS_REPO", str(here.parents[2] / "daasdmlkas")))
binary = here / "lua_interpreter_fixture"
binding = NamingBindingExpectation(
    sha256((repo / "ghidra/GhidraV2CallNaming.java").read_bytes()).digest(),
    CALL_NAMING_GHIDRA_VERSION,
)
snapshot = admit_frozen_bundle(generation)
with open_observed_function_session(snapshot, naming_binding=binding) as session:
    evidence = next(session.iter_functions())
observation = evidence.unit.observation
function = FunctionNormalizer().normalize(evidence.unit)
if type(function) is not NormalizedFunction:
    raise AssertionError(f"root normalization failed: {function}")
query = BackwardSliceQuery()
ssa = function.memory_ssa
candidate_actions = []
for action_index, action in enumerate(ssa.actions):
    output_definitions = [ssa.definitions[i] for i in action.write_definition_ids]
    if any(d.span.start == 0 and d.span.size == 8 and d.span.object_id.kind.value == "register_file"
           for d in output_definitions):
        candidate_actions.append((action_index, action))
rows = []
for action_index, action in candidate_actions:
    seed = function.memory_graph.action_nodes[action_index]
    sliced = query.run(function, seed, include_control=True)
    kinds = Counter(function.dependencies.node(node).kind.value for node in sliced.reachable_nodes)
    operation_keys = [function.dependencies.node(node).key for node in sliced.reachable_nodes
                      if function.dependencies.node(node).kind is NodeKind.OPERATION]
    rows.append({
        "action": action.operation_key,
        "nodes": len(sliced.reachable_nodes),
        "inputs": len(sliced.observed_input_nodes),
        "debts": len(sliced.reachable_unresolved_read_nodes),
        "kinds": dict(kinds),
        "call_operations": sum(":CALL" in key for key in operation_keys),
    })
report = {
    "binary_sha256": sha256(binary.read_bytes()).hexdigest(),
    "bytecode_sha256": sha256((here / "lua_chunk.luac").read_bytes()).hexdigest(),
    "lua_source_revision": "v5.4.8 / 6e22fedb74cf0c9b6656e9fce8b7331db847c605",
    "bundle_generation": generation.name,
    "entry": "run_lua_chunk",
    "instructions": len(observation.instructions),
    "pcode_operations": sum(len(ins.operations) for ins in observation.instructions),
    "ssa_actions": len(ssa.actions),
    "rax_write_slices": rows,
}
destination = here / "lua_root_probe_result.json"
destination.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
print(json.dumps(report, indent=2, ensure_ascii=False))
