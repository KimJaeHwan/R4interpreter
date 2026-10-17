"""Build a separate CALL/RET ELF and independently evaluate its bytecode cases."""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import struct
import subprocess


ROOT = Path(__file__).resolve().parents[1]
SUITE = ROOT / "control-flow"
MANIFEST = SUITE / "cases.json"
EXPECTED = SUITE / "expected.json"
PROGRAMS = SUITE / "programs"
BINARY = ROOT / "build/r4vm_control"
MASK = (1 << 64) - 1
OPCODES = {"move": 0x18, "movi": 0x19, "addi": 0x31, "subi": 0x37,
           "xori": 0x42, "settag": 0x4A, "opaque": 0x60, "brz": 0x70,
           "brnz": 0x71, "call": 0x72, "ret": 0x73, "jump": 0x74,
           "halt": 0x7E, "invalid": 0xFF}


def signed(value):
    value &= MASK
    return value - (1 << 64) if value >> 63 else value


def encode(words):
    return b"R4VM" + bytes((1, len(words), 0, 0)) + b"".join(
        struct.pack("BBBB", OPCODES[word["op"]], word.get("dst", 0),
                    word.get("src", 0), word.get("imm", 0) & 255)
        for word in words)


def oracle(words, input_value):
    slots = [input_value & MASK, 0, 0, 0]
    tags = [3, 0, 0, 0]
    returns = []
    writes = []
    fetch_trace = []
    pc = 0
    def finish(status, result=None):
        return {"status": status, "result": result, "pc": pc,
                "writes": writes, "fetch_trace": fetch_trace}
    for _ in range(64):
        fetch_trace.append(pc)
        if not 0 <= pc < len(words):
            return finish("pc_out_of_bounds")
        word = words[pc]
        pc += 1
        op = word["op"]
        dst, src, imm = (word.get(key, 0) for key in ("dst", "src", "imm"))
        if op == "call":
            if len(returns) == 4:
                return finish("call_overflow")
            returns.append(pc)
            pc = imm
            continue
        if op == "ret":
            if not returns:
                return finish("call_underflow")
            pc = returns.pop()
            continue
        if op == "jump":
            pc = imm
            continue
        if op == "halt":
            status = "ok" if tags[src] == 3 else "type_error"
            return finish(status, str(signed(slots[src])) if status == "ok" else None)
        if op in ("brz", "brnz"):
            if tags[src] != 3:
                return finish("type_error")
            if (slots[src] == 0) == (op == "brz"):
                pc += imm
            continue
        if op in ("addi", "subi", "xori", "opaque") and tags[src] != 3:
            return finish("type_error")
        if op == "move":
            slots[dst], tags[dst] = slots[src], tags[src]
        elif op == "movi":
            slots[dst], tags[dst] = imm & MASK, 3
        elif op in ("addi", "subi", "opaque"):
            slots[dst] = (slots[src] + (imm if op != "subi" else -imm)) & MASK
            tags[dst] = 3
        elif op == "xori":
            slots[dst], tags[dst] = slots[src] ^ (imm & MASK), 3
        elif op == "settag":
            tags[dst] = imm & 255
        else:
            return finish("bad_opcode")
        writes.append({"slot": dst, "value": str(signed(slots[dst])), "tag": tags[dst]})
    return finish("step_limit")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--no-compile", action="store_true")
    parser.add_argument("--check", action="store_true",
                        help="check programs and expected JSON without modifying them")
    args = parser.parse_args()
    manifest = json.loads(MANIFEST.read_text())
    if manifest["schema_version"] != 1:
        raise ValueError("invalid case schema")
    PROGRAMS.mkdir(parents=True, exist_ok=True)
    expected = {"schema_version": 1, "cases": []}
    for case in manifest["cases"]:
        words = case["instructions"]
        if not 1 <= len(words) <= 32:
            raise ValueError(f"invalid program length: {case['id']}")
        program = encode(words)
        program_file = PROGRAMS / f"{case['id']}.r4vm"
        if args.check:
            if program_file.read_bytes() != program:
                raise ValueError(f"stale program: {program_file}")
        else:
            program_file.write_bytes(program)
        samples = []
        for value in case["samples"]:
            outcome = oracle(words, int(value))
            trace = outcome.pop("fetch_trace")
            samples.append({"input": value, "expected": outcome,
                            "fetch_trace": trace})
        expected["cases"].append({"id": case["id"],
                                  "program_sha256": sha256(program).hexdigest(),
                                  "samples": samples})
    expected_text = json.dumps(expected, indent=2) + "\n"
    if args.check:
        if EXPECTED.read_text() != expected_text:
            raise ValueError("stale independent expected JSON")
    else:
        EXPECTED.write_text(expected_text)
    if not args.check and not args.no_compile:
        BINARY.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["cc", "-std=c11", "-O2", "-fno-pie", "-no-pie", "-Wall",
                        "-Wextra", "-Werror", "-o", str(BINARY),
                        str(ROOT / "fixtures/r4vm_control.c")], check=True)
    print(f"{len(expected['cases'])} cases, "
          f"{sum(len(c['samples']) for c in expected['cases'])} samples; "
          f"ELF SHA-256 {sha256(BINARY.read_bytes()).hexdigest() if BINARY.exists() else 'absent'}")


if __name__ == "__main__":
    main()
