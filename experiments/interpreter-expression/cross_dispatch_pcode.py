"""Lift the observed CPython and Ignition dispatch snippets to Low P-code.

This uses pypcode's bundled Ghidra SLEIGH translator directly on exact ELF
bytes. It is a local dispatch proof, not an interpreter-wide Bundle/SSA pass.
"""
from __future__ import annotations

from collections import Counter
from hashlib import sha256
import json
from pathlib import Path
import shutil

from elftools.elf.elffile import ELFFile
import pypcode


ROOT = Path(__file__).resolve().parent
SLICES = (
    ("python", Path("/usr/bin/python3.13"), 0x561298, 0x5612AF,
     ("LOAD", "BRANCHIND"), 2,
     "bytecode word load, table target load, indirect native jump"),
    ("javascript", Path(shutil.which("node") or ""), 0x1A0A649, 0x1A0A654,
     ("LOAD", "CALLIND"), 2,
     "bytecode byte load, table target load, indirect native call"),
    ("javascript_fused_star", Path(shutil.which("node") or ""), 0x1BA97A1, 0x1BA97D5,
     ("LOAD", "STORE", "BRANCHIND"), None,
     "short register-store bytecode may be handled within predecessor native handler"),
)


def read_vaddr(binary, start, end):
    with binary.open("rb") as handle:
        elf = ELFFile(handle)
        for segment in elf.iter_segments():
            if segment["p_type"] == "PT_LOAD" and segment["p_vaddr"] <= start and \
                    end <= segment["p_vaddr"] + segment["p_filesz"]:
                handle.seek(segment["p_offset"] + start - segment["p_vaddr"])
                return handle.read(end - start)
    raise ValueError(f"native slice is absent from {binary}")


def main():
    ctx = pypcode.Context("x86:LE:64:default")
    slices = []
    for engine, binary, start, end, required, exact_loads, claim in SLICES:
        blob = read_vaddr(binary, start, end)
        translated = ctx.translate(blob, base_address=start)
        names = [op.opcode.name for op in translated.ops]
        if (exact_loads is not None and names.count("LOAD") != exact_loads) or \
                any(name not in names for name in required):
            raise ValueError(f"{engine} dispatch P-code structure changed: {Counter(names)}")
        slices.append({"engine": engine, "binary_sha256": sha256(binary.read_bytes()).hexdigest(),
                       "entry_pc": hex(start), "exit_pc": hex(end),
                       "native_bytes_hex": blob.hex(), "native_instructions": names.count("IMARK"),
                       "pcode_operations": len(names) - names.count("IMARK"),
                       "pcode": [pypcode.PcodePrettyPrinter.fmt_op(op) for op in translated.ops],
                       "claim": claim})
    report = {"schema_version": 1, "lifter": "pypcode 3.2.1 / Ghidra SLEIGH x86:LE:64:default",
              "scope": "native dispatch snippets only; no symbolic value/guard proof",
              "slices": slices}
    target = ROOT / "cross_dispatch_pcode.json"
    target.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"slices": len(slices),
                      "pcode_operations": {item["engine"]: item["pcode_operations"] for item in slices}}))


if __name__ == "__main__":
    main()
