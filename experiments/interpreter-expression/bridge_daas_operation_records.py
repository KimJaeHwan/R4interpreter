"""Project admitted daasdmlkas operation records into the shared typed value IL.

This is a deliberately bounded integration experiment. A record with an
unselected join, debt, cut, or unsupported effect is reported as unknown. The
Lua probe is an arithmetic temporary in luaV_execute; it measures whether a
whole-function static record can justify that value, without a selected path.
"""

from __future__ import annotations

from collections import Counter
from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile

import z3

HERE = Path(__file__).resolve().parent
R4 = HERE.parents[1]
DAAS = Path(os.environ.get("DAASDMLKAS_REPO", R4.parent / "daasdmlkas"))
sys.path.insert(0, str(DAAS / "src"))

from tdo_v2.configured_naming_contracts import (  # noqa: E402
    CALL_NAMING_GHIDRA_VERSION, NamingBindingExpectation,
)
from tdo_v2.integration.configured_bundle import admit_frozen_bundle  # noqa: E402
from tdo_v2.integration.observed_function_session import open_observed_function_session  # noqa: E402
from tdo_v2.interprocedural import analyze_units  # noqa: E402
from tdo_v2.normalize import FunctionNormalizer  # noqa: E402
from tdo_v2.operation_records import Limits, eligibility, root_record, run_records  # noqa: E402
from native_ast_il import Builder, reify  # noqa: E402

ELF_ARCHIVE = HERE / "artifacts/elf_bundle.tar.gz"
LUA_ARCHIVE = HERE / "artifacts/lua_bundle.tar.gz"
RESULT = HERE / "daas_operation_bridge_result.json"
LUA_RECORD = HERE / "daas_lua_static_root_record.json"


class UnknownValue(ValueError):
    """A value relation is not justified by the operation record."""


def fingerprint(value):
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def extract_bundle(archive_path, destination):
    """Extract only ordinary files from one sealed Bundle archive."""
    with tarfile.open(archive_path, "r:gz") as archive:
        members = archive.getmembers()
        roots = {Path(member.name).parts[0] for member in members}
        if len(roots) != 1:
            raise ValueError("Bundle archive has multiple roots")
        root = next(iter(roots))
        for member in members:
            parts = Path(member.name).parts
            if not parts or parts[0] != root or ".." in parts or Path(member.name).is_absolute():
                raise ValueError("unsafe Bundle member")
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
                raise ValueError("unsupported Bundle member type")
    return destination / root


def observed_unit(bundle, entry):
    name = DAAS / "ghidra/GhidraV2CallNaming.java"
    binding = NamingBindingExpectation(sha256(name.read_bytes()).digest(),
                                       CALL_NAMING_GHIDRA_VERSION)
    with open_observed_function_session(admit_frozen_bundle(bundle),
                                        naming_binding=binding) as session:
        for evidence in session.iter_functions():
            if evidence.unit.scopes.function.entry.byte_offset == entry:
                return evidence.unit
    raise ValueError(f"entry {entry:#x} is absent before the first unresolved function")


class RecordExpression:
    """Read a single exact little-endian value from a daas expression graph."""

    OPCODES = {"INT_ADD": lambda a, b: a + b,
               "INT_SUB": lambda a, b: a - b,
               "INT_XOR": lambda a, b: a ^ b,
               "INT_AND": lambda a, b: a & b,
               "INT_OR": lambda a, b: a | b}

    def __init__(self, record, *, output_size=None):
        reason = eligibility(record)
        if reason is not None:
            raise UnknownValue(f"daas record ineligible: {reason}")
        if record.get("endianness") != "little":
            raise UnknownValue("non-little-endian record")
        self.record = record
        self.nodes = {node["id"]: node for node in record["nodes"]}
        self.memo = {}
        self.active = set()
        self.inputs = {}
        self.output_size = output_size

    def parts(self, parts, width):
        if type(width) is not int or width <= 0 or width > 32:
            raise UnknownValue("unsupported value width")
        pieces = []
        occupied = set()
        for part in parts:
            if part.get("loop") or part.get("pruned") or part.get("whole"):
                raise UnknownValue("loop, pruned, or whole-node value")
            source_start, source_end = part["bytes"]
            start, end = part["at"]
            if not (0 <= start < end <= width and source_end - source_start == end - start):
                raise UnknownValue("invalid byte placement")
            cells = set(range(start, end))
            if occupied & cells:
                raise UnknownValue("overlapping byte placement")
            occupied |= cells
            source = self.node(part["node"])
            if 8 * source_end > source.size():
                raise UnknownValue("source byte range exceeds node width")
            pieces.append((start, z3.Extract(8 * source_end - 1, 8 * source_start, source)))
        if occupied != set(range(width)):
            raise UnknownValue("value has missing bytes")
        pieces.sort(reverse=True)
        return z3.Concat(*(piece for _, piece in pieces)) if len(pieces) > 1 else pieces[0][1]

    def node(self, identifier):
        if identifier in self.memo:
            return self.memo[identifier]
        if identifier in self.active:
            raise UnknownValue("cyclic operation record")
        node = self.nodes.get(identifier)
        if node is None:
            raise UnknownValue("missing operation node")
        self.active.add(identifier)
        try:
            kind = node["kind"]
            if kind == "entry":
                name = node.get("span")
                register = node.get("register")
                if not (isinstance(name, str) and name.startswith("register:") and
                        isinstance(register, dict) and register.get("size", 0) > 0):
                    raise UnknownValue("entry memory or unknown entry kind")
                width = 8 * register["size"]
                symbol = "entry_" + name.split(":", 1)[1].replace(":", "_")
                value = self.inputs.setdefault(symbol, z3.BitVec(symbol, width))
                if value.size() != width:
                    raise UnknownValue("entry name has inconsistent widths")
            elif kind == "const":
                width = 8 * node["size"]
                value = z3.BitVecVal(node["value"], width)
            elif kind == "op":
                opcode = node["opcode"]
                output = node.get("output")
                if not isinstance(output, dict) or output.get("size", 0) <= 0:
                    raise UnknownValue("operation has no sized output")
                width = 8 * output["size"]
                operands = sorted(node["operands"], key=lambda item: item["index"])
                if [item["index"] for item in operands] != list(range(len(operands))):
                    raise UnknownValue("noncontiguous operand indexes")
                args = [self.parts(item.get("parts", []), item["width"]) for item in operands]
                if opcode == "COPY" and len(args) == 1 and args[0].size() == width:
                    value = args[0]
                elif opcode in self.OPCODES and len(args) == 2 and all(
                        arg.size() == width for arg in args):
                    value = self.OPCODES[opcode](*args)
                else:
                    raise UnknownValue(f"unsupported opcode or width: {opcode}")
            else:
                raise UnknownValue(f"unselected or unresolved record node: {kind}")
            self.memo[identifier] = value
            return value
        finally:
            self.active.remove(identifier)

    def result(self):
        place = self.record.get("place")
        if isinstance(place, dict):
            if self.output_size is not None and place["size"] != self.output_size:
                raise UnknownValue("record output selector has a different width")
            size = place["size"]
        elif type(self.output_size) is int and self.output_size > 0:
            size = self.output_size
        else:
            raise UnknownValue("root record requires an explicit output selector")
        return self.parts(self.record["root"], size)


def main():
    daas_commit = subprocess.check_output(["git", "-C", str(DAAS), "rev-parse", "HEAD"],
                                          text=True).strip()
    daas_dirty = bool(subprocess.check_output(["git", "-C", str(DAAS), "status", "--porcelain"],
                                              text=True).strip())
    r4_commit = subprocess.check_output(["git", "-C", str(R4), "rev-parse", "HEAD"],
                                        text=True).strip()
    with tempfile.TemporaryDirectory(prefix="r4-daas-bridge-") as temp:
        elf_bundle = extract_bundle(ELF_ARCHIVE, Path(temp) / "elf")
        elf_unit = observed_unit(elf_bundle, 0x4011A0)
        analyzed = next(iter(analyze_units([elf_unit],
                                           assume_import_slots_hold_exports=True).values()))
        if analyzed.summary is None or analyzed.normalized is None:
            raise ValueError("ELF function did not normalize and summarize")
        candidates = [item for item in run_records(analyzed.normalized, elf_unit,
                                                   analyzed.summary, origins=analyzed.origins,
                                                   declared=analyzed.declared)
                      if item.get("span") == "register:rax" and item.get("run_kind") == "computed"]
        if len(candidates) != 1:
            raise ValueError("expected one computed RAX exit")
        record = candidates[0]
        projection = RecordExpression(record)
        expression = projection.result()
        builder = Builder([{"name": name, "sort": f"BV{value.size()}"}
                           for name, value in sorted(projection.inputs.items())])
        root = builder.add(expression)
        reified = reify({"nodes": builder.nodes}, projection.inputs)[root]
        expected = z3.BitVec("entry_rdi", 64) + z3.BitVecVal(7, 64)
        solver = z3.Solver()
        solver.add(reified != expected)
        if solver.check() != z3.unsat:
            raise ValueError("daas operation projection differs from add7")
        root_style = deepcopy(record)
        root_style.pop("place")
        root_style["record"] = "root"
        if not z3.eq(RecordExpression(root_style, output_size=8).result(), expression):
            raise ValueError("explicit root selector changed an exact record")
        mutation = deepcopy(record)
        next(item for item in mutation["nodes"] if item["kind"] == "const" and
             item["value"] == 7)["value"] = 8
        changed_projection = RecordExpression(mutation)
        changed = changed_projection.result()
        changed_builder = Builder([{"name": name, "sort": f"BV{value.size()}"}
                                   for name, value in sorted(changed_projection.inputs.items())])
        changed_root = changed_builder.add(changed)
        changed = reify({"nodes": changed_builder.nodes}, changed_projection.inputs)[changed_root]
        solver = z3.Solver()
        solver.add(changed != expected)
        if solver.check() != z3.sat:
            raise ValueError("changed native constant was not detected")
        mutation = deepcopy(record)
        mutation["truncated"] = True
        try:
            RecordExpression(mutation)
        except UnknownValue:
            cut_rejected = True
        else:
            cut_rejected = False
        if not cut_rejected:
            raise ValueError("truncated record was accepted")

        lua_bundle = extract_bundle(LUA_ARCHIVE, Path(temp) / "lua")
        lua_unit = observed_unit(lua_bundle, 0x415440)
        lua_normalized = FunctionNormalizer().normalize(lua_unit)
        selected = [action for action in lua_normalized.memory_ssa.actions
                    if action.operation_key == "1b1:417ce7:5:INT_ADD"]
        if len(selected) != 1 or len(selected[0].write_definition_ids) != 1:
            raise ValueError("Lua arithmetic cutpoint is absent or ambiguous")
        definition_id = selected[0].write_definition_ids[0]
        definition = lua_normalized.memory_ssa.definitions[definition_id]
        lua_record = root_record(lua_normalized, lua_unit,
                                 [(lua_normalized.memory_graph.definition_nodes[definition_id],
                                   (definition.span,))],
                                 limits=Limits(nodes=300, edges=2000, depth=80))
        lua_reason = eligibility(lua_record)
        if lua_reason is None:
            try:
                RecordExpression(lua_record, output_size=definition.span.size).result()
            except UnknownValue as exc:
                lua_reason = str(exc)
        if lua_reason is None:
            raise ValueError("whole-function Lua root unexpectedly became exact; reassess scope")
        LUA_RECORD.write_text(json.dumps(lua_record, indent=2) + "\n")
        report = {
            "schema_version": "daas-operation-bridge-stage1-v1",
            "daas_commit": daas_commit,
            "daas_worktree_dirty": daas_dirty,
            "r4_base_commit": r4_commit,
            "bridge_sha256": sha256(Path(__file__).read_bytes()).hexdigest(),
            "z3_version": z3.get_version_string(),
            "method": "admitted Bundle -> normalized SSA -> operation record -> typed value IL",
            "elf": {
                "bundle_archive_sha256": sha256(ELF_ARCHIVE.read_bytes()).hexdigest(),
                "binary_sha256": record["program"],
                "record_sha256": fingerprint(record),
                "analysis_options": {"assume_import_slots_hold_exports": True,
                                     "image_info_supplied": False,
                                     "assume_entry_values_not_frame": True},
                "inherited_model_assumptions": sorted(analyzed.inherited_assumptions),
                "record": record,
                "il": {"schema_version": "bounded-value-projection-v1",
                       "scope": "one native function exit value; no memory/effect claim",
                       "inputs": [{"name": name, "sort": f"BV{value.size()}"}
                                  for name, value in sorted(projection.inputs.items())],
                       "nodes": builder.nodes,
                       "result": {"node": root, "sort": "BV64", "span": "register:rax"}},
                "proof": {"equivalence_to_bv64_rdi_plus_7": "unsat",
                          "wrong_constant_detected": "sat",
                          "truncated_record_rejected": cut_rejected,
                          "explicit_root_output_selector": "accepted"},
            },
            "lua_static_root": {
                "bundle_archive_sha256": sha256(LUA_ARCHIVE.read_bytes()).hexdigest(),
                "root_operation": selected[0].operation_key,
                "output_selector": {"kind": definition.span.object_id.kind.value,
                                    "size_bytes": definition.span.size},
                "record_sha256": fingerprint(lua_record),
                "record_file": LUA_RECORD.name,
                "record_nodes": len(lua_record["nodes"]),
                "kinds": dict(sorted(Counter(item["kind"] for item in lua_record["nodes"]).items())),
                "status": "unknown",
                "reason": lua_reason,
                "whole_function_static_path_selected": False,
            },
            "whole_program_complete": False,
        }
        RESULT.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps({"elf_proof": report["elf"]["proof"],
                          "elf_il_nodes": len(builder.nodes),
                          "lua_static_root": report["lua_static_root"]}, indent=2))


if __name__ == "__main__":
    main()
