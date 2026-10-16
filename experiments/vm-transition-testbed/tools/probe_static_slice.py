"""Measure static SSA slices against archived R4VM paths without executing the ELF.

The archived paths select comparison roots only. They are not input to the
normalizer or backward query. This diagnostic does not produce a transition.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile


ROOT = Path(__file__).resolve().parents[1]
REPO = Path(os.environ.get("DAASDMLKAS_REPO", ROOT.parents[2] / "daasdmlkas"))
sys.path.insert(0, str(REPO / "src"))

from tdo_v2.configured_naming_contracts import (  # noqa: E402
    CALL_NAMING_GHIDRA_VERSION, NamingBindingExpectation,
)
from tdo_v2.integration.configured_bundle import admit_frozen_bundle  # noqa: E402
from tdo_v2.integration.observed_function_session import open_observed_function_session  # noqa: E402
from tdo_v2.normalize import FunctionNormalizer  # noqa: E402
from tdo_v2.query import BackwardSliceQuery  # noqa: E402


PATH_IDS = (
    "347cd71f1ec34c41",  # ADD, next fetch
    "a869b36587846b01",  # conditional branch, next fetch
    "c20c4af07e2fad3c",  # HALT, output
)
ADD_ANCHOR = "op:1b1:40160e:2:INT_ADD"


def bundle_data(archive_path: Path, function_index: int = 0):
    with tarfile.open(archive_path, "r:gz") as archive:
        member = next(m for m in archive
                      if m.name.endswith(f"/function-{function_index:06d}.json"))
        data = json.load(archive.extractfile(member))
    return {item["address"]["byte_offset"]: item for item in data["instructions"]}


def extract_bundle(archive_path: Path, destination: Path):
    """Extract regular members under a private directory for bundle admission."""
    with tarfile.open(archive_path, "r:gz") as archive:
        roots = {Path(m.name).parts[0] for m in archive.getmembers()}
        if len(roots) != 1:
            raise ValueError("bundle must have exactly one top-level directory")
        root_name = next(iter(roots))
        for member in archive.getmembers():
            parts = Path(member.name).parts
            if not parts or parts[0] != root_name or ".." in parts or Path(member.name).is_absolute():
                raise ValueError("unsafe bundle member path")
            target = destination.joinpath(*parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True, mode=0o700)
            elif member.isfile():
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                with archive.extractfile(member) as source, target.open("xb") as output:
                    while block := source.read(1024 * 1024):
                        output.write(block)
                target.chmod(0o600)
            else:
                raise ValueError("bundle contains unsupported member type")
    return destination / root_name


def probe_lua(binding):
    """Repeat the same static query for the archived Lua ADD handler roots."""
    archive_path = ROOT.parent / "interpreter-expression/artifacts/lua_bundle.tar.gz"
    instructions = bundle_data(archive_path, 40)
    roots = ["op:1b1:417cea:1:STORE", "op:1b1:417ced:2:STORE",
             "op:1b1:415b22:1:CBRANCH"]
    with tempfile.TemporaryDirectory(prefix="lua-static-slice-") as temp:
        bundle_dir = extract_bundle(archive_path, Path(temp))
        with open_observed_function_session(admit_frozen_bundle(bundle_dir),
                                            naming_binding=binding) as session:
            evidence = next((unit for unit in session.iter_functions()
                             if unit.unit.observation.instructions[0].address.byte_offset == 0x415440), None)
            if evidence is None:
                raise ValueError("Lua execute loop absent from admitted Bundle")
            normalized = FunctionNormalizer().normalize(evidence.unit)
        graph = normalized.dependencies
        query = BackwardSliceQuery()
        rows = []
        for root in roots:
            if graph.node_for_key(root) is None:
                raise ValueError(f"Lua root absent from SSA graph: {root}")
            modes = {}
            for follow_control in (False, True):
                sliced = query.run(normalized, graph.node_for_key(root),
                                   include_control=follow_control)
                operation_keys = {graph.node(node).key for node in sliced.reachable_nodes
                                  if graph.node(node).kind.value == "operation"}
                modes["data_and_control" if follow_control else "data_only"] = {
                    "slice_nodes": len(sliced.reachable_nodes),
                    "slice_operations": len(operation_keys),
                    "add_anchor_reached": "op:1b1:417ced:0:INT_ADD" in operation_keys,
                    "unresolved_reads": len(sliced.reachable_unresolved_read_nodes),
                    "unresolved_writes_in_function": len(sliced.function_unresolved_write_nodes),
                    "complete": sliced.is_complete,
                }
            rows.append({"root": root, "modes": modes})
    return {"bundle_sha256": sha256(archive_path.read_bytes()).hexdigest(),
            "function": "luaV_execute", "instructions": len(instructions),
            "graph": {"nodes": graph.node_count, "edges": graph.edge_count,
                      "operations": sum(graph.node(i).kind.value == "operation"
                                        for i in range(graph.node_count))},
            "roots": rows}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=ROOT / "reports/static-slice-probe.json")
    args = parser.parse_args()
    archive_path = ROOT / "artifacts/r4vm_bundle.tar.gz"
    summary_path = ROOT / "summaries/r4vm_paths.json"
    instructions = bundle_data(archive_path)
    summary = json.loads(summary_path.read_text())
    if summary["bundle_sha256"] != sha256(archive_path.read_bytes()).hexdigest():
        raise ValueError("R4VM archived paths were made from another Bundle")
    selected = {row["id"]: row for row in summary["paths"] if row["id"] in PATH_IDS}
    if set(selected) != set(PATH_IDS):
        raise ValueError("selected archived path missing")
    naming_path = REPO / "ghidra/GhidraV2CallNaming.java"
    binding = NamingBindingExpectation(sha256(naming_path.read_bytes()).digest(),
                                       CALL_NAMING_GHIDRA_VERSION)
    with tempfile.TemporaryDirectory(prefix="r4vm-static-slice-") as temp:
        bundle_dir = extract_bundle(archive_path, Path(temp))
        with open_observed_function_session(admit_frozen_bundle(bundle_dir),
                                            naming_binding=binding) as session:
            evidence = next((unit for unit in session.iter_functions()
                             if any(ins.address.byte_offset == 0x401410
                                    for ins in unit.unit.observation.instructions)), None)
            if evidence is None:
                raise ValueError("R4VM execute loop absent from admitted Bundle")
            normalized = FunctionNormalizer().normalize(evidence.unit)
        graph = normalized.dependencies
        query = BackwardSliceQuery()
        results = []
        for path_id in PATH_IDS:
            path = selected[path_id]
            pcs = [int(pc, 16) for pc in path["native_path"]]
            operation_keys = {
                f'op:{instructions[pc]["address"]["space_id"]:x}:{pc:x}:{index}:{operation["opcode"]}'
                for pc in pcs for index, operation in enumerate(instructions[pc]["operations"])
            }
            # Archived path marks effect and exit roots for this comparison.
            # The query itself sees the full static function, without this path.
            roots = sorted(key for key in operation_keys if key.endswith(":STORE"))
            last_pc = pcs[-1]
            last_ops = instructions[last_pc]["operations"]
            roots.append(f'op:{instructions[last_pc]["address"]["space_id"]:x}:'
                         f'{last_pc:x}:{len(last_ops)-1}:{last_ops[-1]["opcode"]}')
            modes = {}
            for follow_control in (False, True):
                all_nodes, all_ops, all_debts = set(), set(), set()
                for root in roots:
                    seed = graph.node_for_key(root)
                    if seed is None:
                        raise ValueError(f"root absent from SSA graph: {root}")
                    result = query.run(normalized, seed, include_control=follow_control)
                    all_nodes.update(result.reachable_nodes)
                    all_debts.update(result.reachable_unresolved_read_nodes)
                    all_ops.update(graph.node(node).key for node in result.reachable_nodes
                                   if graph.node(node).kind.value == "operation")
                modes["data_and_control" if follow_control else "data_only"] = {
                    "slice_nodes": len(all_nodes), "slice_operations": len(all_ops),
                    "operations_on_archived_path": len(all_ops & operation_keys),
                    "operations_outside_archived_path": len(all_ops - operation_keys),
                    "unresolved_reads": len(all_debts),
                    "unresolved_writes_in_function": len(normalized.memory_graph.unresolved_write_nodes),
                    "complete": not all_debts and not normalized.memory_graph.unresolved_write_nodes,
                }
                if path_id == PATH_IDS[0]:
                    modes["data_and_control" if follow_control else "data_only"]["add_anchor_reached"] = (
                        ADD_ANCHOR in all_ops)
            results.append({"path_id": path_id, "kind": path["kind"],
                            "source": path["source"], "archived_path_operations": len(operation_keys),
                            "roots": roots, "modes": modes})
    report = {
        "schema_version": 1,
        "method": "admitted Ghidra Bundle -> daasdmlkas normalized SSA -> backward slice",
        "trace_use": "archived R4VM paths choose comparison roots and measure overlap; "
                     "Lua roots come from the archived ADD handler; no ELF execution",
        "bundle_sha256": sha256(archive_path.read_bytes()).hexdigest(),
        "binary_sha256": summary["binary_sha256"],
        "graph": {"nodes": graph.node_count, "edges": graph.edge_count,
                  "operations": sum(graph.node(i).kind.value == "operation"
                                    for i in range(graph.node_count))},
        "paths": results,
        "lua": probe_lua(binding),
        "conclusion": "Static dependencies are queryable, but these slices retain off-path "
                      "operations and unresolved memory debts; no complete VM transition is proven.",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"graph": report["graph"], "paths": [
        {"id": row["path_id"], "kind": row["kind"], "modes": row["modes"]}
        for row in results], "lua": report["lua"]}, indent=2))


if __name__ == "__main__":
    main()
