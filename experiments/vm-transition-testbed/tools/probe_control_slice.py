"""Measure whole-function daasdmlkas SSA slice against CALL/RET path scopes.

The native paths identify a comparison set and a STORE root. The query itself
uses the full function graph, so off-path dependencies remain visible.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import tarfile
import tempfile

from probe_static_slice import (REPO, CALL_NAMING_GHIDRA_VERSION,
                                NamingBindingExpectation, extract_bundle,
                                open_observed_function_session, admit_frozen_bundle,
                                FunctionNormalizer, BackwardSliceQuery)
from build_control_cases import SUITE


BUNDLE = SUITE / "r4vm_control_bundle.tar.gz"
PROJECTION = SUITE / "pcode-projection.json"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=SUITE / "static-slice.json")
    args = parser.parse_args()
    projected = json.loads(PROJECTION.read_text())
    with tarfile.open(BUNDLE, "r:gz") as archive:
        function = json.load(archive.extractfile(next(
            member for member in archive if member.name.endswith("/function-000000.json"))))
    instructions = {row["address"]["byte_offset"]: row
                    for row in function["instructions"]}
    binding = NamingBindingExpectation(
        sha256((REPO / "ghidra/GhidraV2CallNaming.java").read_bytes()).digest(),
        CALL_NAMING_GHIDRA_VERSION)
    with tempfile.TemporaryDirectory(prefix="r4-control-slice-") as temp:
        bundle = extract_bundle(BUNDLE, Path(temp))
        with open_observed_function_session(admit_frozen_bundle(bundle),
                                            naming_binding=binding) as session:
            evidence = next(unit for unit in session.iter_functions()
                            if unit.unit.observation.instructions[0].address.byte_offset == 0x4013C0)
            normalized = FunctionNormalizer().normalize(evidence.unit)
        graph = normalized.dependencies
        query = BackwardSliceQuery()
        cases = []
        for case in projected["cases"]:
            paths = []
            for path in case["paths"]:
                path_ops = {
                    f'op:{instructions[pc]["address"]["space_id"]:x}:'
                    f'{pc:x}:{index}:{operation["opcode"]}'
                    for text in path["native_pcs"] for pc in [int(text, 16)]
                    for index, operation in enumerate(instructions[pc]["operations"])
                }
                roots = sorted({root for step in path["steps"]
                                for root in step["slot2_value_store_roots"]})
                modes = {}
                for follow_control in (False, True):
                    operations, unresolved = set(), set()
                    for root in roots:
                        node = graph.node_for_key(root)
                        if node is None:
                            raise ValueError(f"STORE root absent from normalized SSA: {root}")
                        sliced = query.run(normalized, node, include_control=follow_control)
                        operations.update(graph.node(i).key for i in sliced.reachable_nodes
                                          if graph.node(i).kind.value == "operation")
                        unresolved.update(sliced.reachable_unresolved_read_nodes)
                    modes["data_and_control" if follow_control else "data_only"] = {
                        "slice_operations": len(operations),
                        "operations_on_selected_path": len(operations & path_ops),
                        "operations_outside_selected_path": len(operations - path_ops),
                        "unresolved_reads": len(unresolved),
                        "complete": not unresolved and not normalized.memory_graph.unresolved_write_nodes,
                    }
                paths.append({"formula": path["formula"], "roots": roots,
                              "selected_path_operations": len(path_ops),
                              "repeated_vm_pcs": len(path["vm_fetch_trace"])
                              - len(set(path["vm_fetch_trace"])),
                              "modes": modes})
            cases.append({"id": case["id"], "paths": paths})
    report = {"schema_version": 1,
              "method": "whole-function daasdmlkas normalized SSA/backward slice",
              "bundle_sha256": sha256(BUNDLE.read_bytes()).hexdigest(),
              "graph": {"nodes": graph.node_count, "edges": graph.edge_count,
                        "unresolved_writes": len(normalized.memory_graph.unresolved_write_nodes)},
              "cases": cases,
              "limit": "whole-function slice mixes paths and repeated VM iterations; "
                       "it is diagnostic, not a path-specific output proof"}
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"graph": report["graph"],
                      "rooted_paths": sum(bool(p["roots"]) for c in cases for p in c["paths"]),
                      "paths_with_off_path_ops": sum(
                          p["modes"]["data_only"]["operations_outside_selected_path"] > 0
                          for c in cases for p in c["paths"] if p["roots"])}))


if __name__ == "__main__":
    main()
