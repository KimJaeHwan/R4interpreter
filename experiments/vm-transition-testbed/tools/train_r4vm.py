"""Freeze observed execute-loop P-code paths as reusable conditional transitions."""
from __future__ import annotations

from hashlib import sha256
import io
import json
from pathlib import Path
import sys
import tarfile

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "interpreter-expression"))
from pcode_transition_summary import PathReplay, serialize_expr

from capture_native_paths import LOOP_PC, trace


ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / "build/r4vm"
PROGRAMS = ROOT / "generated/programs"
BUNDLE = ROOT / "artifacts/r4vm_bundle.tar.gz"
TRACES = ROOT / "artifacts/r4vm_training_paths.tar.gz"
SUMMARIES = ROOT / "summaries/r4vm_paths.json"
# Inputs outside the graded set; the zero-branch path uses VMT007 input 0 and
# is marked as a seed in the manifest.
SEEDS = (("VMT001", 5), ("VMT003", 5), ("VMT005", 5),
         ("VMT006", 5), ("VMT007", 0), ("VMT007", 5),
         ("VMT009", 5), ("VMT011", 5), ("VMT012", 5))


def bundle_instructions():
    with tarfile.open(BUNDLE, "r:gz") as archive:
        members = archive.getmembers()
        manifest = json.load(archive.extractfile(next(m for m in members if m.name.endswith("/manifest.json"))))
        original = next(m for m in manifest["members"] if m["id"] == "original")
        if sha256(BINARY.read_bytes()).hexdigest() != original["sha256"]:
            raise ValueError("ELF differs from the Ghidra Bundle")
        for member in members:
            if not member.name.rsplit("/", 1)[-1].startswith("function-") or not member.name.endswith(".json"):
                continue
            data = json.load(archive.extractfile(member))
            instructions = {i["address"]["byte_offset"]: i for i in data["instructions"]}
            if LOOP_PC in instructions:
                return instructions
    raise ValueError("execute-loop cutpoint absent from Bundle")


def compact_path(replay, kind, path, source):
    return {"id": sha256(bytes().join(pc.to_bytes(8, "little") for pc in path)).hexdigest()[:16],
            "kind": kind, "source": source, "native_path": [hex(pc) for pc in path],
            "native_instructions": len(path), "pcode_operations": replay.operation_count,
            "guards": [serialize_expr(g["condition"]) for g in replay.guards],
            "reads": [{"address": serialize_expr(r["address"]), "width": r["width"],
                       "memory_version": r["memory_version"]} for r in replay.reads],
            "effects": [{"address": serialize_expr(e["address"]), "width": e["width"],
                         "value": serialize_expr(e["value"])} for e in replay.effects],
            "registers": {str(offset): serialize_expr(value)
                          for offset, value in replay.regs.items()},
            "flags": {str(offset): serialize_expr(value)
                      for offset, value in replay.flags.items()}}


def train():
    instructions = bundle_instructions()
    paths = {}
    skipped = []
    baseline = None
    trace_records = []
    for case_id, x in SEEDS:
        program = PROGRAMS / f"{case_id}.r4vm"
        observed = trace(BINARY.resolve(), program.resolve(), x)
        if baseline is None:
            baseline = {"entry_registers": observed["entry_registers"],
                        "stack": observed["stack"], "code_base": observed["code"]["base"],
                        "seed_input": x}
        trace_records.append((f"{case_id}-{x}.json", json.dumps(observed, separators=(",", ":")).encode()))
        for segment in observed["segments"]:
            rows = segment["rows"]
            path = tuple(row["pc"] for row in rows)
            if not path or path in paths:
                continue
            if segment["kind"] == "opaque_call":
                skipped.append({"source": [case_id, x], "reason": "unmodeled native call"})
                continue
            try:
                replay = PathReplay({}, rows, instructions)
                replay.run()
            except (ValueError, AssertionError, KeyError) as error:
                skipped.append({"source": [case_id, x], "reason": f"{type(error).__name__}: {error}"})
                continue
            paths[path] = compact_path(replay, segment["kind"], path, [case_id, x])
    if baseline is None or not paths:
        raise RuntimeError("no P-code paths extracted")
    report = {"schema_version": 1,
              "binary_sha256": sha256(BINARY.read_bytes()).hexdigest(),
              "bundle_sha256": sha256(BUNDLE.read_bytes()).hexdigest(),
              "cutpoint": hex(LOOP_PC), "training_inputs": [list(seed) for seed in SEEDS],
              "training_trace_sha256": {name: sha256(contents).hexdigest()
                                        for name, contents in trace_records},
              "baseline": baseline, "paths": list(paths.values()), "skipped": skipped,
              "claim": "conditional observed paths; no whole-CFG or alias/frame proof"}
    TRACES.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(TRACES, "w:gz") as archive:
        for name, contents in trace_records:
            member = tarfile.TarInfo(name)
            member.size = len(contents)
            member.mode = 0o600
            archive.addfile(member, io.BytesIO(contents))
    SUMMARIES.parent.mkdir(parents=True, exist_ok=True)
    SUMMARIES.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"paths": len(paths), "skipped": skipped,
                      "native_instructions": sum(p["native_instructions"] for p in paths.values()),
                      "pcode_operations": sum(p["pcode_operations"] for p in paths.values())}))


if __name__ == "__main__":
    train()
