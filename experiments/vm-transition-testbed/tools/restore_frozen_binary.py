"""Restore the exact ELF used by the committed P-code path summaries.

The Bundle contains its original executable.  Reading this ELF for analysis
works without a compiler, Ghidra, ptrace, or the sibling daasdmlkas checkout.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import tarfile


ROOT = Path(__file__).resolve().parents[1]
BUNDLE = ROOT / "artifacts/r4vm_bundle.tar.gz"
SUMMARIES = ROOT / "summaries/r4vm_paths.json"
BINARY = ROOT / "build/r4vm"


def restore(replace: bool = False):
    summary = json.loads(SUMMARIES.read_text())
    bundle_bytes = BUNDLE.read_bytes()
    if sha256(bundle_bytes).hexdigest() != summary["bundle_sha256"]:
        raise ValueError("Ghidra Bundle hash differs from frozen summary")
    with tarfile.open(BUNDLE, "r:gz") as archive:
        members = archive.getmembers()
        manifest = json.load(archive.extractfile(next(
            m for m in members if m.name.endswith("/manifest.json") and m.isfile())))
        original = next(m for m in manifest["members"] if m["id"] == "original")
        member = next(m for m in members if m.name.endswith("/" + original["path"]) and m.isfile())
        contents = archive.extractfile(member).read()
    digest = sha256(contents).hexdigest()
    if digest != original["sha256"] or digest != summary["binary_sha256"]:
        raise ValueError("Bundle executable does not match frozen summary")
    if BINARY.exists():
        existing = sha256(BINARY.read_bytes()).hexdigest()
        if existing == digest:
            print(f"verified existing {BINARY} ({digest})")
            return
        if not replace:
            raise FileExistsError("build/r4vm differs from frozen ELF; rerun with --replace to use the archived copy")
    BINARY.parent.mkdir(parents=True, exist_ok=True)
    BINARY.write_bytes(contents)
    BINARY.chmod(0o755)
    print(f"restored {BINARY} ({digest})")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--replace", action="store_true", help="replace a different generated build/r4vm")
    args = parser.parse_args()
    restore(args.replace)


if __name__ == "__main__":
    main()
