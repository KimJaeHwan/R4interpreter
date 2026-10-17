"""Replay every Low P-code op of one observed dispatch-to-fetch VM path.

The trace chooses a path and supplies concrete observations. The resulting
expressions keep instruction word, entry registers and memory symbolic. The
summary is a conditional candidate: other CFG paths and alias proofs are not
silently inferred from the trace.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
import tarfile

import z3


MASK64 = (1 << 64) - 1
REGISTER_OFFSETS = {
    0: "rax", 8: "rcx", 16: "rdx", 24: "rbx", 32: "rsp", 40: "rbp",
    48: "rsi", 56: "rdi", 128: "r8", 136: "r9", 144: "r10",
    152: "r11", 160: "r12", 168: "r13", 176: "r14", 184: "r15",
}
FLAG_OFFSETS = {512: 0, 514: 2, 518: 6, 519: 7, 523: 11}
VECTOR_OFFSETS = {4608: "xmm0"}
ENTRY_PC = 0x4164B8
EXIT_PC = 0x415B22


@dataclass
class Dual:
    symbolic: z3.BitVecRef
    concrete: int

    @property
    def bits(self):
        return self.symbolic.size()


def bv(value, bits):
    return z3.BitVecVal(value & ((1 << bits) - 1), bits)


def bool_dual(symbolic_bool, concrete_bool):
    return Dual(z3.If(symbolic_bool, bv(1, 8), bv(0, 8)), int(bool(concrete_bool)))


def resize(expr, bits, signed=False):
    if expr.size() == bits:
        return expr
    if expr.size() > bits:
        return z3.Extract(bits - 1, 0, expr)
    extension = bits - expr.size()
    return z3.SignExt(extension, expr) if signed else z3.ZeroExt(extension, expr)


def signed(value, bits):
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def load_observation(archive_path):
    with tarfile.open(archive_path, "r:gz") as archive:
        member = next(m for m in archive if m.name.endswith("/function-000040.json"))
        data = json.load(archive.extractfile(member))
    return {i["address"]["byte_offset"]: i for i in data["instructions"]}


def load_path(trace_path):
    records = [json.loads(line) for line in trace_path.read_text().splitlines()]
    entry = next(i for i, row in enumerate(records) if row.get("pc") == ENTRY_PC)
    rows = records[entry:]
    assert rows[-2]["pc"] == EXIT_PC and rows[-1]["type"] == "summary"
    rows = rows[:-1]
    assert all(row["type"] == "step" for row in rows)
    assert all(a["next_pc"] == b["pc"] for a, b in zip(rows, rows[1:]))
    return records[0], rows


class PathReplay:
    def __init__(self, entry, rows, instructions, register_symbols=None,
                 flag_symbols=None, memory_symbol=None):
        self.rows = rows
        self.instructions = instructions
        self.word = z3.BitVec("W", 32)
        self.memory_initial = z3.Array("M0", z3.BitVecSort(64), z3.BitVecSort(8))
        self.memory = memory_symbol if memory_symbol is not None else self.memory_initial
        self.memory_concrete = {}
        self.regs = {}
        self.regs_concrete = {}
        self.flags = {}
        self.flags_concrete = {}
        self.unique = {}
        self.vectors = {offset: Dual(z3.BitVec(f"V_{name.upper()}", 128), 0)
                        for offset, name in VECTOR_OFFSETS.items()}
        self.guards = []
        self.reads = []
        self.effects = []
        self.effect_steps = []
        self.operation_count = 0
        before = rows[0]["registers"]
        for offset, name in REGISTER_OFFSETS.items():
            self.regs[offset] = (register_symbols[offset] if register_symbols is not None else
                                 z3.ZeroExt(32, self.word) if name == "r12" else
                                 z3.BitVec(f"R_{name.upper()}", 64))
            self.regs_concrete[offset] = before[name]
        for offset, bit in FLAG_OFFSETS.items():
            self.flags[offset] = (flag_symbols[offset] if flag_symbols is not None else
                                  z3.BitVec(f"F_{bit}", 8))
            self.flags_concrete[offset] = (before["eflags"] >> bit) & 1
        self.entry_word_concrete = before["r12"] & 0xFFFFFFFF
        self.current_row = None
        self.current_pc = None
        self.touched_regs = set()
        self.touched_flags = set()

    def read(self, node):
        kind, offset, size = node["kind_code"], node["byte_offset"], node["byte_size"]
        bits = size * 8
        if kind in (1, 4):
            return Dual(bv(offset, bits), offset & ((1 << bits) - 1))
        if kind == 3:
            return self.unique[(offset, size)]
        if kind == 2 and offset in FLAG_OFFSETS:
            assert size == 1
            return Dual(self.flags[offset], self.flags_concrete[offset])
        if kind == 2 and offset in VECTOR_OFFSETS:
            assert size == 16
            return self.vectors[offset]
        if kind == 2 and offset == 648 and size == 8:
            return self.ip
        if kind == 2:
            base = next((root for root in REGISTER_OFFSETS if root <= offset < root + 8), None)
            if base is None or offset + size > base + 8:
                raise ValueError(f"unmapped register {offset:#x}/{size}")
            shift = (offset - base) * 8
            return Dual(z3.Extract(shift + bits - 1, shift, self.regs[base]),
                        (self.regs_concrete[base] >> shift) & ((1 << bits) - 1))
        raise ValueError(f"unsupported varnode kind {kind}")

    def write(self, node, value):
        kind, offset, size = node["kind_code"], node["byte_offset"], node["byte_size"]
        bits = size * 8
        assert value.bits == bits
        value.concrete &= (1 << bits) - 1
        if kind == 3:
            self.unique[(offset, size)] = value
            return
        assert kind == 2
        if offset == 648 and size == 8:
            self.ip = value
            return
        if offset in FLAG_OFFSETS:
            self.flags[offset] = value.symbolic
            self.flags_concrete[offset] = value.concrete
            self.touched_flags.add(offset)
            return
        if offset in VECTOR_OFFSETS:
            assert size == 16
            self.vectors[offset] = value
            return
        base = next((root for root in REGISTER_OFFSETS if root <= offset < root + 8), None)
        if base is None or offset + size > base + 8:
            raise ValueError(f"unmapped register write {offset:#x}/{size} at {self.current_pc:#x}")
        shift = (offset - base) * 8
        if shift == 0 and bits == 64:
            self.regs[base] = value.symbolic
            self.regs_concrete[base] = value.concrete
        else:
            old = self.regs[base]
            keep = MASK64 ^ (((1 << bits) - 1) << shift)
            self.regs[base] = (old & bv(keep, 64)) | (resize(value.symbolic, 64) << shift)
            self.regs_concrete[base] = ((self.regs_concrete[base] & keep)
                                        | (value.concrete << shift)) & MASK64
        self.touched_regs.add(base)

    def observed_memory(self, address, size):
        matches = [m for m in self.current_row["memory"]
                   if m["address"] == address and m["size"] == size]
        if len(matches) != 1:
            raise AssertionError(f"memory operand not captured at {self.current_pc:#x}: {address:#x}/{size}")
        return matches[0]

    def load(self, address, size):
        concrete_address = address.concrete & MASK64
        observed = self.observed_memory(concrete_address, size)
        before = observed["before"]
        if before is None:
            raise AssertionError("unreadable memory operand")
        value = sum((self.memory_concrete[(concrete_address + i) & MASK64]
                     if (concrete_address + i) & MASK64 in self.written_this_step
                     else (before >> (8 * i)) & 255) << (8 * i)
                    for i in range(size))
        bytes_symbolic = [z3.Select(self.memory, address.symbolic + bv(i, 64))
                          for i in range(size)]
        symbolic = bytes_symbolic[0] if size == 1 else z3.Concat(*reversed(bytes_symbolic))
        for i in range(size):
            byte_address = (concrete_address + i) & MASK64
            byte = (value >> (8 * i)) & 255
            if byte_address in self.memory_concrete and self.memory_concrete[byte_address] != byte:
                raise AssertionError(f"memory version disagreement at {self.current_pc:#x}: "
                                     f"{byte_address:#x} modeled={self.memory_concrete[byte_address]:#x} observed={byte:#x}")
            self.memory_concrete[byte_address] = byte
        self.reads.append({"pc": hex(self.current_pc), "ordinal": self.current_ordinal,
                           "address": address.symbolic, "width": size,
                           "memory_version": len(self.effects), "observed_address": concrete_address,
                           "observed": value, "value_expression": symbolic})
        return Dual(symbolic, value)

    def store(self, address, value):
        size = value.bits // 8
        concrete_address = address.concrete & MASK64
        observed = self.observed_memory(concrete_address, size)
        if observed["after"] != value.concrete:
            raise AssertionError(f"store disagrees at {self.current_pc:#x}")
        before_memory = self.memory
        for i in range(size):
            byte_addr = address.symbolic + bv(i, 64)
            byte_value = z3.Extract(8 * i + 7, 8 * i, value.symbolic)
            self.memory = z3.Store(self.memory, byte_addr, byte_value)
            self.memory_concrete[(concrete_address + i) & MASK64] = (value.concrete >> (8 * i)) & 255
            self.written_this_step.add((concrete_address + i) & MASK64)
        self.effects.append({"pc": hex(self.current_pc), "ordinal": self.current_ordinal,
                             "kind": "Write", "address": address.symbolic,
                             "width": size, "value": value.symbolic,
                             "observed_address": concrete_address,
                             "memory_version_before": len(self.effects),
                             "memory_version_after": len(self.effects) + 1,
                             "observed": value.concrete})
        self.effect_steps.append(self.current_row.get("step"))

    def evaluate(self, opcode, inputs, output):
        args = [self.read(n) for n in inputs]
        a = args[0]
        b = args[1] if len(args) > 1 else None
        if opcode == "COPY":
            return args[0]
        if opcode == "SUBPIECE":
            if inputs[1]["kind_code"] != 1:
                raise ValueError("dynamic SUBPIECE offset is not modeled")
            low = b.concrete * 8
            if low + output["byte_size"] * 8 > a.bits:
                raise ValueError("SUBPIECE outside input")
            high = low + output["byte_size"] * 8 - 1
            return Dual(z3.Extract(high, low, a.symbolic),
                        (a.concrete >> low) & ((1 << (output["byte_size"] * 8)) - 1))
        if opcode == "PIECE":
            return Dual(z3.Concat(a.symbolic, b.symbolic),
                        (a.concrete << b.bits) | b.concrete)
        if opcode == "LOAD":
            return self.load(args[1], output["byte_size"])
        if opcode == "STORE":
            self.store(args[1], args[2])
            return None
        if opcode in ("BRANCH", "CBRANCH"):
            target = args[0].concrete
            if opcode == "BRANCH":
                assert self.current_row["next_pc"] == target
                self.guards.append({"pc": hex(self.current_pc), "kind": "BRANCH",
                                    "target": hex(target), "condition": z3.BoolVal(True)})
            else:
                taken = self.current_row["next_pc"] == target
                if taken != (args[1].concrete != 0):
                    raise AssertionError(f"branch disagrees at {self.current_pc:#x}")
                condition = args[1].symbolic != bv(0, args[1].bits)
                self.guards.append({"pc": hex(self.current_pc), "kind": "CBRANCH",
                                    "target": hex(self.current_row["next_pc"]),
                                    "condition": condition if taken else z3.Not(condition)})
            return None
        if opcode in ("CALL", "RETURN"):
            target = args[0].concrete
            if self.current_row["next_pc"] != target:
                raise AssertionError(f"{opcode} target disagrees at {self.current_pc:#x}")
            self.guards.append({"pc": hex(self.current_pc), "kind": opcode,
                                "target": hex(target),
                                "condition": args[0].symbolic == bv(target, args[0].bits)})
            return None
        if opcode == "BRANCHIND":
            target = args[0].concrete
            if self.current_row["next_pc"] != target:
                raise AssertionError(f"indirect branch disagrees at {self.current_pc:#x}")
            self.guards.append({"pc": hex(self.current_pc), "kind": "BRANCHIND",
                                "target": hex(target),
                                "condition": args[0].symbolic == bv(target, args[0].bits)})
            self.successor = args[0].symbolic
            return None
        bits = output["byte_size"] * 8
        mask = (1 << bits) - 1
        if opcode == "INT_ZEXT":
            return Dual(resize(a.symbolic, bits), a.concrete & mask)
        if opcode == "INT_SEXT":
            return Dual(resize(a.symbolic, bits, signed=True), signed(a.concrete, a.bits) & mask)
        if opcode == "BOOL_NEGATE":
            return bool_dual(a.symbolic == bv(0, a.bits), a.concrete == 0)
        if opcode in ("BOOL_AND", "BOOL_OR", "BOOL_XOR"):
            left, right = a.symbolic != bv(0, a.bits), b.symbolic != bv(0, b.bits)
            symbolic = {"BOOL_AND": lambda: z3.And(left, right),
                        "BOOL_OR": lambda: z3.Or(left, right),
                        "BOOL_XOR": lambda: z3.Xor(left, right)}[opcode]()
            concrete = {"BOOL_AND": lambda: bool(a.concrete) and bool(b.concrete),
                        "BOOL_OR": lambda: bool(a.concrete) or bool(b.concrete),
                        "BOOL_XOR": lambda: bool(a.concrete) != bool(b.concrete)}[opcode]()
            return bool_dual(symbolic, concrete)
        if opcode == "POPCOUNT":
            sym = bv(0, bits)
            for index in range(a.bits):
                sym = sym + resize(z3.Extract(index, index, a.symbolic), bits)
            return Dual(sym, a.concrete.bit_count() & mask)
        if opcode in ("INT_ADD", "INT_SUB", "INT_MULT", "INT_AND", "INT_OR", "INT_XOR"):
            sym = {"INT_ADD": lambda: a.symbolic + b.symbolic,
                   "INT_SUB": lambda: a.symbolic - b.symbolic,
                   "INT_MULT": lambda: a.symbolic * b.symbolic,
                   "INT_AND": lambda: a.symbolic & b.symbolic,
                   "INT_OR": lambda: a.symbolic | b.symbolic,
                   "INT_XOR": lambda: a.symbolic ^ b.symbolic}[opcode]()
            con = {"INT_ADD": lambda: a.concrete + b.concrete,
                   "INT_SUB": lambda: a.concrete - b.concrete,
                   "INT_MULT": lambda: a.concrete * b.concrete,
                   "INT_AND": lambda: a.concrete & b.concrete,
                   "INT_OR": lambda: a.concrete | b.concrete,
                   "INT_XOR": lambda: a.concrete ^ b.concrete}[opcode]()
            return Dual(resize(sym, bits), con & mask)
        if opcode in ("INT_RIGHT", "INT_LEFT", "INT_SRIGHT"):
            shift = resize(b.symbolic, a.bits)
            sym = (z3.LShR(a.symbolic, shift) if opcode == "INT_RIGHT" else
                   a.symbolic << shift if opcode == "INT_LEFT" else
                   a.symbolic >> shift)
            con = (a.concrete >> b.concrete if opcode == "INT_RIGHT" else
                   a.concrete << b.concrete if opcode == "INT_LEFT" else
                   signed(a.concrete, a.bits) >> b.concrete)
            if b.concrete >= a.bits and opcode != "INT_SRIGHT":
                con = 0
            return Dual(resize(sym, bits), con & mask)
        if opcode in ("INT_EQUAL", "INT_NOTEQUAL", "INT_LESS", "INT_SLESS"):
            sym = {"INT_EQUAL": lambda: a.symbolic == b.symbolic,
                   "INT_NOTEQUAL": lambda: a.symbolic != b.symbolic,
                   "INT_LESS": lambda: z3.ULT(a.symbolic, b.symbolic),
                   "INT_SLESS": lambda: a.symbolic < b.symbolic}[opcode]()
            con = {"INT_EQUAL": lambda: a.concrete == b.concrete,
                   "INT_NOTEQUAL": lambda: a.concrete != b.concrete,
                   "INT_LESS": lambda: a.concrete < b.concrete,
                   "INT_SLESS": lambda: signed(a.concrete, a.bits) < signed(b.concrete, b.bits)}[opcode]()
            return bool_dual(sym, con)
        if opcode == "INT_CARRY":
            wide = z3.ZeroExt(1, a.symbolic) + z3.ZeroExt(1, b.symbolic)
            return bool_dual(z3.Extract(a.bits, a.bits, wide) == bv(1, 1),
                             a.concrete + b.concrete >= 1 << a.bits)
        if opcode in ("INT_SCARRY", "INT_SBORROW"):
            result = a.symbolic + b.symbolic if opcode == "INT_SCARRY" else a.symbolic - b.symbolic
            sign_a = z3.Extract(a.bits - 1, a.bits - 1, a.symbolic)
            sign_b = z3.Extract(b.bits - 1, b.bits - 1, b.symbolic)
            sign_result = z3.Extract(a.bits - 1, a.bits - 1, result)
            sym = (z3.And(sign_a == sign_b, sign_result != sign_a)
                   if opcode == "INT_SCARRY" else
                   z3.And(sign_a != sign_b, sign_result != sign_a))
            ra, rb = signed(a.concrete, a.bits), signed(b.concrete, b.bits)
            c = ra + rb if opcode == "INT_SCARRY" else ra - rb
            con = c < -(1 << (a.bits - 1)) or c >= 1 << (a.bits - 1)
            return bool_dual(sym, con)
        raise ValueError(f"unsupported P-code opcode {opcode} at {self.current_pc:#x}")

    def run(self):
        for row in self.rows:
            pc = row["pc"]
            if pc not in self.instructions:
                raise AssertionError(f"missing Bundle instruction {pc:#x}")
            self.current_row, self.current_pc = row, pc
            self.ip = Dual(bv(pc, 64), pc)
            self.unique = {}
            self.touched_regs, self.touched_flags = set(), set()
            self.written_this_step = set()
            read_start, effect_start = len(self.reads), len(self.effects)
            for ordinal, operation in enumerate(self.instructions[pc]["operations"]):
                self.current_ordinal = ordinal
                result = self.evaluate(operation["opcode"], operation["inputs"], operation["output"])
                if operation["output_present"]:
                    self.write(operation["output"], result)
                self.operation_count += 1
            observed_accesses = {(m["address"], m["size"], access)
                                 for m in row["memory"] for access in (1, 2)
                                 if m["access"] & access}
            modeled_accesses = ({(m["observed_address"], m["width"], 1)
                                 for m in self.reads[read_start:]} |
                                {(m["observed_address"], m["width"], 2)
                                 for m in self.effects[effect_start:]})
            # A physical operand may be loaded more than once in P-code for flags.
            if observed_accesses != modeled_accesses:
                raise AssertionError(f"unmodeled memory operand at {pc:#x}")
            for offset in self.touched_regs:
                name = REGISTER_OFFSETS[offset]
                expected = row["registers_after"][name]
                if self.regs_concrete[offset] != expected:
                    raise AssertionError(f"register {name} mismatch at {pc:#x}: "
                                         f"{self.regs_concrete[offset]:#x} != {expected:#x}")
            for offset in self.touched_flags:
                bit = FLAG_OFFSETS[offset]
                expected = (row["registers_after"]["eflags"] >> bit) & 1
                if self.flags_concrete[offset] != expected:
                    raise AssertionError(f"flag {bit} mismatch at {pc:#x}")


def serialize_expr(expression):
    return z3.simplify(expression).sexpr()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("bundle", type=Path)
    parser.add_argument("trace", type=Path)
    parser.add_argument("binary", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    meta, rows = load_path(args.trace)
    instructions = load_observation(args.bundle)
    for pc in (0x41553A, 0x415540, 0x415543):
        assert pc in instructions
    assert [op["opcode"] for op in instructions[0x41553A]["operations"]] == ["LOAD", "COPY", "INT_ZEXT"]
    assert any(op["opcode"] == "INT_AND" and any(n["kind_code"] == 1 and n["byte_offset"] == 127
               for n in op["inputs"]) for op in instructions[0x415540]["operations"])
    assert instructions[0x415543]["operations"][-1]["opcode"] == "BRANCHIND"
    replay = PathReplay(meta, rows, instructions)
    replay.run()
    dispatch_value = replay.entry_word_concrete & 127
    dispatch_guard = z3.Extract(6, 0, replay.word) == bv(dispatch_value, 7)
    inputs = [{"name": "W", "sort": "BV32", "binding": {"kind": "register_slice",
               "name": "r12", "low_bit": 0, "width": 32}},
              {"name": "M0", "sort": "Array(BV64,BV8)",
               "binding": {"kind": "entry_memory"}}]
    inputs += [{"name": f"R_{name.upper()}", "sort": "BV64",
                "binding": {"kind": "register", "name": name}}
               for name in REGISTER_OFFSETS.values() if name != "r12"]
    inputs += [{"name": f"F_{bit}", "sort": "BV8",
                "binding": {"kind": "register_bit", "name": "eflags", "bit": bit}}
               for bit in FLAG_OFFSETS.values()]
    outputs = [{"name": "next_code_pointer", "sort": "BV64",
                "expression": serialize_expr(replay.regs[184]),
                "observed_binding": {"kind": "register", "name": "r15"}}]
    outputs += [{"name": f"R_{name.upper()}", "sort": "BV64",
                 "expression": serialize_expr(replay.regs[offset]),
                 "observed_binding": {"kind": "register", "name": name}}
                for offset, name in REGISTER_OFFSETS.items()]
    outputs += [{"name": f"F_{bit}", "sort": "BV8",
                 "expression": serialize_expr(replay.flags[offset]),
                 "observed_binding": {"kind": "register_bit", "name": "eflags", "bit": bit}}
                for offset, bit in FLAG_OFFSETS.items()]
    report = {
        "schema_version": "transition-summary-v0-candidate",
        "semantic_model": {"architecture": "x86-64", "endian": "little", "pointer_width": 64,
                           "value_domain": "bitvector and byte-addressed memory",
                           "lifter_version": "Ghidra 12.0.4 Bundle",
                           "bundle_sha256": sha256(args.bundle.read_bytes()).hexdigest()},
        "identity": {"executable_code_sha256": sha256(args.binary.read_bytes()).hexdigest(),
                     "code_epoch": "static fixture; runtime code mutation not modeled",
                     "entry_cutpoint": hex(ENTRY_PC), "exit_cutpoint": hex(rows[-1]["next_pc"]),
                     "specialization_dependencies": ["native ELF and Bundle",
                                                     f"dispatch class W&127={dispatch_value}"]},
        "interface": {"inputs": inputs,
                      "entry_registers": [f"R_{name.upper()}:BV64" for name in REGISTER_OFFSETS.values()
                                          if name != "r12"],
                      "word_to_live_in": "R_R12 = ZeroExt32(W) from fetch P-code 0x41553a"},
        "case": {
            "path_guard": [serialize_expr(dispatch_guard)] +
                          [serialize_expr(g["condition"]) for g in replay.guards],
            "branch_evidence": [{k: v for k, v in g.items() if k != "condition"} for g in replay.guards],
            "reads": [{**{k: v for k, v in e.items()
                          if k not in ("address", "observed", "observed_address", "value_expression")},
                       "address": serialize_expr(e["address"])} for e in replay.reads],
            "ordered_effects": [{**{k: v for k, v in e.items()
                                    if k not in ("address", "value", "observed", "observed_address")},
                                 "address": serialize_expr(e["address"]),
                                 "value": serialize_expr(e["value"])} for e in replay.effects],
            "outputs": outputs,
            "exit_kind": "next_fetch",
            "uncovered": "other CFG paths, unknown calls and unproved alias/frame conditions",
        },
        "evidence": {"trace_sha256": sha256(args.trace.read_bytes()).hexdigest(),
                     "handler_native_instructions": len(rows),
                     "pcode_operations_replayed": replay.operation_count,
                     "concrete_register_and_memory_checks": "passed",
                     "validation_level": "candidate: one observed path, not a full handler proof"},
    }
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({"instructions": len(rows), "pcode_operations": replay.operation_count,
                      "loads": len(replay.reads), "writes": len(replay.effects),
                      "branches": len(replay.guards)}, indent=2))


if __name__ == "__main__":
    main()
