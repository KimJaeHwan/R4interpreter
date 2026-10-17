"""Build the isolated frame/indirect-call VM cases and independent oracle."""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import struct
import subprocess

ROOT = Path(__file__).resolve().parents[1]
SUITE = ROOT / "frames"
MANIFEST = SUITE / "cases.json"
PROGRAMS = SUITE / "programs"
EXPECTED = SUITE / "expected.json"
BINARY = ROOT / "build/r4vm_frames"
MASK = (1 << 64) - 1
OPCODES = {"move": 0x18, "movi": 0x19, "addi": 0x31, "subi": 0x37, "andi": 0x45,
           "brz": 0x70, "brnz": 0x71, "call": 0x72, "ret": 0x73,
           "jump": 0x74, "icall": 0x75, "halt": 0x7e, "invalid": 0xff}


def signed(value):
    value &= MASK
    return value - (1 << 64) if value >> 63 else value


def encode(words):
    if not 1 <= len(words) <= 64:
        raise ValueError("invalid word count")
    return b"R4VM" + bytes((1, len(words), 0, 0)) + b"".join(
        struct.pack("BBBB", OPCODES[word["op"]], word.get("dst", 0),
                    word.get("src", 0), word.get("imm", 0) & 255)
        for word in words)


def oracle(words, input_value):
    frames = [{"slots": [input_value & MASK, 0, 0, 0],
               "tags": [3, 0, 0, 0], "return_pc": None, "return_slot": None}]
    pc, writes, fetches = 0, [], []

    def finish(status, result=None):
        return {"status": status, "result": result, "pc": pc,
                "writes": writes, "fetch_trace": fetches}

    for _ in range(96):
        fetches.append(pc)
        if not 0 <= pc < len(words):
            return finish("pc_out_of_bounds")
        word = words[pc]
        pc += 1
        op = word["op"]
        dst, src, imm = (word.get(key, 0) for key in ("dst", "src", "imm"))
        if dst >= 4 or src >= 4:
            return finish("bad_slot")
        frame = frames[-1]
        slots, tags = frame["slots"], frame["tags"]
        if op in ("call", "icall"):
            if len(frames) == 5:
                return finish("call_overflow")
            if op == "icall" and tags[src] != 3:
                return finish("type_error")
            target = imm if op == "call" else signed(slots[src])
            child = {"slots": [slots[dst], 0, 0, 0],
                     "tags": [tags[dst], 0, 0, 0],
                     "return_pc": pc, "return_slot": dst}
            frames.append(child)
            pc = target
            continue
        if op == "ret":
            if len(frames) == 1:
                return finish("call_underflow")
            child = frames.pop()
            returned, tag = child["slots"][src], child["tags"][src]
            slot = child["return_slot"]
            frames[-1]["slots"][slot] = returned
            frames[-1]["tags"][slot] = tag
            writes.append({"slot": slot, "value": str(signed(returned)), "tag": tag})
            pc = child["return_pc"]
            continue
        if op == "jump":
            pc = imm
            continue
        if op in ("brz", "brnz"):
            if tags[src] != 3:
                return finish("type_error")
            if (slots[src] == 0) == (op == "brz"):
                pc += imm
            continue
        if op == "halt":
            if tags[src] != 3:
                return finish("type_error")
            return finish("ok", str(signed(slots[src])))
        if op == "move":
            slots[dst], tags[dst] = slots[src], tags[src]
        elif op == "movi":
            slots[dst], tags[dst] = imm & MASK, 3
        elif op in ("addi", "subi", "andi"):
            if tags[src] != 3:
                return finish("type_error")
            slots[dst] = ((slots[src] & imm) if op == "andi" else
                          slots[src] + (imm if op == "addi" else -imm)) & MASK
            tags[dst] = 3
        else:
            return finish("bad_opcode")
        writes.append({"slot": dst, "value": str(signed(slots[dst])), "tag": tags[dst]})
    return finish("step_limit")


def main():
    subprocess.run(["cc", "-std=c11", "-O2", "-fno-pie", "-no-pie",
                    "-Wall", "-Wextra", "-Werror", "-o", str(BINARY),
                    str(ROOT / "fixtures/r4vm_frames.c")], check=True)
    cases = json.loads(MANIFEST.read_text())["cases"]
    PROGRAMS.mkdir(parents=True, exist_ok=True)
    expected = {"schema_version": 1, "cases": []}
    for case in cases:
        program = encode(case["instructions"])
        (PROGRAMS / f"{case['id']}.r4vm").write_bytes(program)
        expected["cases"].append({
            "id": case["id"], "program_sha256": sha256(program).hexdigest(),
            "samples": [{"input": value, "expected": outcome,
                         "fetch_trace": trace}
                        for value in case["samples"]
                        for result in [oracle(case["instructions"], int(value))]
                        for trace, outcome in [(result.pop("fetch_trace"), result)]]})
    EXPECTED.write_text(json.dumps(expected, indent=2) + "\n")
    failures = []
    for case in expected["cases"]:
        program = PROGRAMS / f"{case['id']}.r4vm"
        for sample in case["samples"]:
            observed = json.loads(subprocess.check_output(
                [str(BINARY), str(program), sample["input"]], text=True))
            if observed != sample["expected"]:
                failures.append({"id": case["id"], "input": sample["input"],
                                 "observed": observed, "expected": sample["expected"]})
    result = {"schema_version": 1, "samples": sum(len(c["samples"]) for c in expected["cases"]),
              "failures": failures, "binary_sha256": sha256(BINARY.read_bytes()).hexdigest()}
    (SUITE / "fixture-grade.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"samples": result["samples"], "failed": len(failures)}))
    if failures:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
