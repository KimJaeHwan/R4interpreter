"""Restore the exact CALL/RET ELF associated with its Ghidra P-code Bundle."""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import tarfile

from build_control_cases import BINARY, SUITE


BUNDLE = SUITE / "r4vm_control_bundle.tar.gz"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--replace", action="store_true")
    args = parser.parse_args()
    with tarfile.open(BUNDLE, "r:gz") as archive:
        manifest = json.load(archive.extractfile(next(
            m for m in archive if m.name.endswith("/manifest.json"))))
        original = next(m for m in manifest["members"] if m["id"] == "original")
        contents = archive.extractfile(next(
            m for m in archive if m.name.endswith("/" + original["path"]))).read()
    digest = sha256(contents).hexdigest()
    if digest != original["sha256"]:
        raise ValueError("Bundle ELF failed hash verification")
    if BINARY.exists() and sha256(BINARY.read_bytes()).hexdigest() != digest and not args.replace:
        raise FileExistsError("build/r4vm_control differs; pass --replace for the archived ELF")
    BINARY.parent.mkdir(parents=True, exist_ok=True)
    BINARY.write_bytes(contents)
    BINARY.chmod(0o755)
    print(f"restored {BINARY} ({digest})")


if __name__ == "__main__":
    main()
