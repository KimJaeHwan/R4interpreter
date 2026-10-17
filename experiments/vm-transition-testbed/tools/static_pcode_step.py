"""Derive one R4VM transition by emulating Bundle P-code, without a native trace.

The concrete entry snapshot is still the previously observed cutpoint baseline.
Branch choices come from P-code evaluation against the requested program/input,
not from archived native paths. Symbolic guards/effects are built in parallel.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys

import z3
from elftools.elf.elffile import ELFFile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT.parent / "interpreter-expression"))
from train_r4vm import BINARY, BUNDLE, PROGRAMS, SUMMARIES, bundle_instructions, compact_path  # noqa: E402
from capture_native_paths import LOOP_PC, OUTPUT_PC, OPAQUE_PC  # noqa: E402
from pcode_transition_summary import PathReplay, Dual, bv, MASK64  # noqa: E402


def entry_state(summary, program: bytes, input_value: int):
    if program[:4] != b"R4VM" or len(program) != 8 + 4 * program[5]:
        raise ValueError("invalid R4VM program framing")
    baseline = summary["baseline"]
    registers = dict(baseline["entry_registers"])
    stack = baseline["stack"]
    memory = {stack["base"] + index: byte for index, byte in
              enumerate(bytes.fromhex(stack["bytes_hex"]))}
    memory.update({baseline["code_base"] + index: byte for index, byte in enumerate(program)})
    registers["r10"] = program[5]
    registers["rdx"] = input_value & MASK64
    for index in range(8):
        memory[registers["rsp"] + index] = (input_value >> (8 * index)) & 255
    return registers, memory


def elf_memory(binary: Path):
    result = {}
    with binary.open("rb") as stream:
        elf = ELFFile(stream)
        for segment in elf.iter_segments():
            if segment["p_type"] != "PT_LOAD":
                continue
            base = segment["p_vaddr"]
            for index, byte in enumerate(segment.data()):
                result[base + index] = byte
            for index in range(segment["p_filesz"], segment["p_memsz"]):
                result[base + index] = 0
    return result


class StaticStep(PathReplay):
    def __init__(self, registers, memory, instructions,
                 loop_pc=LOOP_PC, output_pc=OUTPUT_PC, opaque_pc=OPAQUE_PC):
        super().__init__({}, [{"registers": registers}], instructions)
        self.memory_concrete = memory
        self.native_path = []
        self.exit_kind = None
        self.exit_pc = None
        self.loop_pc = loop_pc
        self.output_pc = output_pc
        self.opaque_pc = opaque_pc

    def load(self, address, size):
        location = address.concrete & MASK64
        try:
            value = sum(self.memory_concrete[(location + index) & MASK64] << (8 * index)
                        for index in range(size))
        except KeyError as error:
            raise ValueError(f"unresolved memory read at {self.current_pc:#x}: "
                             f"{location:#x}/{size}") from error
        selected = [z3.Select(self.memory, address.symbolic + bv(index, 64))
                    for index in range(size)]
        symbolic = selected[0] if size == 1 else z3.Concat(*reversed(selected))
        self.reads.append({"pc": hex(self.current_pc), "ordinal": self.current_ordinal,
                           "address": address.symbolic, "width": size,
                           "memory_version": len(self.effects), "observed_address": location,
                           "observed": value, "value_expression": symbolic})
        return Dual(symbolic, value)

    def store(self, address, value):
        width = value.bits // 8
        location = address.concrete & MASK64
        for index in range(width):
            byte_address = address.symbolic + bv(index, 64)
            byte_value = z3.Extract(index * 8 + 7, index * 8, value.symbolic)
            self.memory = z3.Store(self.memory, byte_address, byte_value)
            self.memory_concrete[(location + index) & MASK64] = (value.concrete >> (8 * index)) & 255
        self.effects.append({"pc": hex(self.current_pc), "ordinal": self.current_ordinal,
                             "kind": "Write", "address": address.symbolic,
                             "width": width, "value": value.symbolic,
                             "observed_address": location,
                             "memory_version_before": len(self.effects),
                             "memory_version_after": len(self.effects) + 1,
                             "observed": value.concrete})

    def run_step(self, budget=200):
        pc = self.loop_pc
        for _ in range(budget):
            if pc == self.loop_pc and self.native_path:
                self.exit_kind, self.exit_pc = "next_fetch", pc
                return
            instruction = self.instructions.get(pc)
            if instruction is None:
                raise ValueError(f"no Bundle instruction at {pc:#x}")
            if instruction["flow_type"]["is_call"]:
                targets = [target["byte_offset"] for target in instruction["flow_targets"]]
                if targets == [self.output_pc]:
                    self.exit_kind, self.exit_pc = "output", pc
                    return
                if targets == [self.opaque_pc]:
                    raise ValueError("opaque call needs a call summary")
                raise ValueError(f"unmodeled call at {pc:#x}: {targets}")
            self.native_path.append(pc)
            self.current_pc = pc
            self.unique = {}
            fallthrough = instruction["fallthrough"]
            successor = None if fallthrough is None else fallthrough["byte_offset"]
            for ordinal, operation in enumerate(instruction["operations"]):
                self.current_ordinal = ordinal
                opcode = operation["opcode"]
                if opcode in ("BRANCH", "CBRANCH", "BRANCHIND"):
                    target = self.read(operation["inputs"][0]).concrete
                    if opcode == "CBRANCH":
                        condition = self.read(operation["inputs"][1]).concrete != 0
                        successor = target if condition else successor
                    else:
                        successor = target
                    self.current_row = {"next_pc": successor}
                value = self.evaluate(opcode, operation["inputs"], operation["output"])
                if operation["output_present"]:
                    self.write(operation["output"], value)
                self.operation_count += 1
            if successor is None:
                raise ValueError(f"unresolved successor at {pc:#x}")
            allowed = {target["byte_offset"] for target in instruction["flow_targets"]}
            if fallthrough is not None:
                allowed.add(fallthrough["byte_offset"])
            if not instruction["flow_type"]["is_computed"] and successor not in allowed:
                raise ValueError(f"P-code successor {successor:#x} violates CFG at {pc:#x}")
            pc = successor
        raise ValueError(f"native P-code step budget exceeded ({budget})")


def derive_step(summary, instructions, binary_image, program, input_value, source):
    registers, memory = entry_state(summary, program, input_value)
    image = dict(binary_image)
    image.update(memory)
    step = StaticStep(registers, image, instructions)
    step.run_step()
    candidate = compact_path(step, step.exit_kind, tuple(step.native_path), source)
    candidate["provenance"] = {
        "path_selection": "Bundle P-code concrete evaluation; no native execution or archived path lookup",
        "entry_state": "baseline stack/register snapshot from earlier ptrace training",
        "symbolic": "guards, ordered effects, and next register expressions retain W/M0/live-ins",
        "limitations": "one concrete-selected path; unknown entry bytes/alias and other paths unproved",
    }
    candidate["exit_native_pc"] = hex(step.exit_pc)
    return step, candidate


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("program", type=Path, nargs="?", default=PROGRAMS / "VMT001.r4vm")
    parser.add_argument("input", type=int, nargs="?", default=5)
    parser.add_argument("--output", type=Path, default=ROOT / "reports/static-add-step.json")
    args = parser.parse_args()
    summary = json.loads(SUMMARIES.read_text())
    if sha256(BINARY.read_bytes()).hexdigest() != summary["binary_sha256"]:
        raise ValueError("ELF differs from archived baseline")
    if sha256(BUNDLE.read_bytes()).hexdigest() != summary["bundle_sha256"]:
        raise ValueError("Bundle differs from archived baseline")
    step, candidate = derive_step(summary, bundle_instructions(), elf_memory(BINARY),
                                  args.program.read_bytes(), args.input,
                                  [args.program.name, args.input])
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(candidate, indent=2) + "\n")
    print(json.dumps({"id": candidate["id"], "kind": candidate["kind"],
                      "native_instructions": candidate["native_instructions"],
                      "pcode_operations": candidate["pcode_operations"],
                      "guards": len(candidate["guards"]), "writes": len(candidate["effects"]),
                      "exit_native_pc": candidate["exit_native_pc"]}))


if __name__ == "__main__":
    main()
