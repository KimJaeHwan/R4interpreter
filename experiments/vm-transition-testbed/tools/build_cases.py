"""Validate the case manifest and generate VM programs plus independent expected data."""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import re
import struct
import subprocess


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "manifests/cases.json"
PROGRAMS = ROOT / "generated/programs"
EXPECTED = ROOT / "expected/cases.expected.json"
MASK = (1 << 64) - 1
OPCODES = {"move": 0x18, "movi": 0x19, "addi": 0x31, "subi": 0x37,
           "xori": 0x42, "settag": 0x4A, "opaque": 0x60, "brz": 0x70,
           "brnz": 0x71, "halt": 0x7E, "invalid": 0xFF}


def signed(value):
    value &= MASK
    return value - (1 << 64) if value >> 63 else value


def validate(manifest):
    if manifest.get("schema_version") != 1:
        raise ValueError("manifest schema_version must be 1")
    ids = set()
    for case in manifest["cases"]:
        case_id = case["id"]
        if not re.fullmatch(r"VMT\d{3}", case_id) or case_id in ids:
            raise ValueError(f"invalid or duplicate case ID {case_id}")
        ids.add(case_id)
        if case["engine"] not in manifest["engines"]:
            raise ValueError(f"unknown engine in {case_id}")
        if case["analysis_policy"] not in ("compute", "unknown_allowed"):
            raise ValueError(f"invalid analysis policy in {case_id}")
        if case.get("analysis_target", "transition") not in ("transition", "output"):
            raise ValueError(f"invalid analysis target in {case_id}")
        if not case.get("samples") or not case.get("expected_features"):
            raise ValueError(f"missing samples or features in {case_id}")
        if case["engine"] == "r4vm":
            words = case.get("instructions", [])
            if not 1 <= len(words) <= 32 or "program_file" in case:
                raise ValueError(f"invalid instruction list in {case_id}")
            for word in words:
                if word["op"] not in OPCODES:
                    raise ValueError(f"invalid operation in {case_id}")
                if not 0 <= word.get("dst", 0) < 4 or not 0 <= word.get("src", 0) < 4:
                    raise ValueError(f"invalid slot in {case_id}")
                if not -128 <= word.get("imm", 0) <= 127:
                    raise ValueError(f"invalid immediate in {case_id}")
        else:
            if "instructions" in case or not (ROOT / case["program_file"]).is_file():
                raise ValueError(f"missing Lua program in {case_id}")
        inputs = set()
        for sample in case["samples"]:
            x = int(sample["input"])
            if not -(1 << 63) <= x < 1 << 63 or x in inputs:
                raise ValueError(f"invalid or duplicate input in {case_id}")
            inputs.add(x)
            if sample.get("partition", "holdout") not in ("seed", "holdout"):
                raise ValueError(f"invalid sample partition in {case_id}")
            if sample["status"] == "ok" and "result" not in sample:
                raise ValueError(f"missing successful result in {case_id}")
            if sample["status"] != "ok" and "result" in sample:
                raise ValueError(f"error case has numeric result in {case_id}")


def encode(words):
    return b"R4VM" + bytes((1, len(words), 0, 0)) + b"".join(
        struct.pack("BBBB", OPCODES[word["op"]], word.get("dst", 0),
                    word.get("src", 0), word.get("imm", 0) & 255)
        for word in words)


def oracle(words, x):
    """Reference implementation in Python, separate from the C fixture."""
    values = [x & MASK, 0, 0, 0]
    tags = [3, 0, 0, 0]
    writes = []
    pc = 0
    for _ in range(64):
        if not 0 <= pc < len(words):
            return {"status": "pc_out_of_bounds", "result": None, "pc": pc, "writes": writes}
        word = words[pc]
        pc += 1
        op = word["op"]
        dst, src, imm = word.get("dst", 0), word.get("src", 0), word.get("imm", 0)
        if op == "halt":
            status = "ok" if tags[src] == 3 else "type_error"
            return {"status": status, "result": str(signed(values[src])) if status == "ok" else None,
                    "pc": pc, "writes": writes}
        if op in ("brz", "brnz"):
            if tags[src] != 3:
                return {"status": "type_error", "result": None, "pc": pc, "writes": writes}
            if (values[src] == 0) == (op == "brz"):
                pc += imm
            continue
        if op in ("addi", "subi", "xori", "opaque"):
            if tags[src] != 3:
                return {"status": "type_error", "result": None, "pc": pc, "writes": writes}
            if op in ("addi", "opaque"):
                values[dst] = (values[src] + imm) & MASK
            elif op == "subi":
                values[dst] = (values[src] - imm) & MASK
            else:
                values[dst] = (values[src] ^ (imm & MASK)) & MASK
            tags[dst] = 3
        elif op == "move":
            values[dst], tags[dst] = values[src], tags[src]
        elif op == "movi":
            values[dst], tags[dst] = imm & MASK, 3
        elif op == "settag":
            tags[dst] = imm & 255
        else:
            return {"status": "bad_opcode", "result": None, "pc": pc, "writes": writes}
        writes.append({"slot": dst, "value": str(signed(values[dst])), "tag": tags[dst]})
    return {"status": "step_limit", "result": None, "pc": pc, "writes": writes}


def build(manifest, check=False):
    validate(manifest)
    generated = []
    for case in manifest["cases"]:
        if case["engine"] == "r4vm":
            path = PROGRAMS / f"{case['id']}.r4vm"
            contents = encode(case["instructions"])
            if check:
                if not path.is_file() or path.read_bytes() != contents:
                    raise AssertionError(f"stale program {path}")
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(contents)
            expectation = [oracle(case["instructions"], int(sample["input"]))
                           for sample in case["samples"]]
        else:
            path = ROOT / case["program_file"]
            contents = path.read_bytes()
            expectation = [{"status": sample["status"], "result": sample.get("result"),
                            "pc": None, "writes": None} for sample in case["samples"]]
        samples = []
        for sample, actual in zip(case["samples"], expectation):
            if sample["status"] != actual["status"] or sample.get("result") != actual["result"]:
                raise AssertionError(f"manifest oracle mismatch in {case['id']} input={sample['input']}: {actual}")
            samples.append({"input": sample["input"],
                            "partition": sample.get("partition", "holdout"),
                            "expected": actual})
        generated.append({"id": case["id"], "name": case["name"], "engine": case["engine"],
                          "category": case["category"], "analysis_policy": case["analysis_policy"],
                          "analysis_target": case.get("analysis_target", "transition"),
                          "expected_features": case["expected_features"],
                          "program": str(path.relative_to(ROOT)),
                          "program_sha256": sha256(contents).hexdigest(),
                          "samples": samples})
    report = {"schema_version": 1, "generated_from": "manifests/cases.json",
              "cases": generated}
    serialized = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    if check:
        if not EXPECTED.is_file() or EXPECTED.read_text() != serialized:
            raise AssertionError("stale expected/cases.expected.json")
    else:
        EXPECTED.parent.mkdir(parents=True, exist_ok=True)
        EXPECTED.write_text(serialized)
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="verify generated files without modifying them")
    parser.add_argument("--no-compile", action="store_true")
    args = parser.parse_args()
    manifest = json.loads(MANIFEST.read_text())
    report = build(manifest, args.check)
    if not args.no_compile and not args.check:
        config = manifest["engines"]["r4vm"]
        binary = ROOT / config["binary"]
        binary.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["cc", *config["compiler_flags"], "-o", str(binary),
                        str(ROOT / config["source"])], check=True)
    print(f"{len(report['cases'])} cases, {sum(len(c['samples']) for c in report['cases'])} samples")


if __name__ == "__main__":
    main()
