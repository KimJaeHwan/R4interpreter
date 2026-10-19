"""Checked effect of one pinned libc AVX-512 memset path, not general memset.

The 12 native instructions are abstracted by their decoded operations. The
selected path broadcasts the zero RSI byte, constructs an eight-lane mask,
stores exactly eight bytes, and returns the original destination in RAX.
Unspecified BZHI flags are left symbolic. Other libc images/paths are unknown.
"""
from __future__ import annotations

from hashlib import sha256
from pathlib import Path

import z3
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

from common_program_path_il import require
from pcode_transition_summary import FLAG_OFFSETS, REGISTER_OFFSETS
from probe_connected_python_prefix import OPAQUE_START, OPAQUE_END


LIBC = Path("/lib/x86_64-linux-gnu/libc.so.6")
LIBC_SHA256 = "9792e3cbb541c8f44c7acf5f14f4022ea62998ecc787d326bed4d8b6547dfd92"
IMAGE_ENTRY_OFFSET = 0x17C080
EXPECTED_OFFSETS = [0x17C080, 0x17C086, 0x17C089, 0x17C08D,
                    0x17C040, 0x17C046, 0x17C04C, 0x17C052,
                    0x17C059, 0x17C05E, 0x17C063, 0x17C069]
EXPECTED_MNEMONICS = ["vpbroadcastb", "mov", "cmp", "jb", "and", "cmp",
                      "ja", "mov", "bzhi", "kmovq", "vmovdqu8", "ret"]
EXPECTED_BYTES = ["62e27d487ac6", "4889f8", "4883fa40", "72b1",
                  "81e7ff0f0000", "81ffc00f0000", "0f870b010000",
                  "48c7c1ffffffff", "c4e2e8f5c9", "c4e1fb92c9",
                  "62e17f497f00", "c3"]


def number(expr, x, witness):
    value = z3.simplify(z3.substitute(expr, (x, z3.BitVecVal(witness, 32))))
    require(z3.is_bv_value(value), "bounded libc expression has unresolved input")
    return value.as_long()


def checked_image(rows, image=LIBC):
    require(len(rows) == OPAQUE_END - OPAQUE_START and image.is_file() and
            sha256(image.read_bytes()).hexdigest() == LIBC_SHA256,
            "pinned libc image unavailable or changed")
    data = image.read_bytes()
    base = rows[0]["pc"] - IMAGE_ENTRY_OFFSET
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoded = [list(decoder.disasm(data[offset:offset + len(bytes.fromhex(blob))],
                                   row["pc"]))
               for offset, blob, row in zip(EXPECTED_OFFSETS, EXPECTED_BYTES, rows)]
    require([row["pc"] - base for row in rows] == EXPECTED_OFFSETS and
            [row["instruction"].split()[0] for row in rows] == EXPECTED_MNEMONICS and
            [row["bytes"] for row in rows] == EXPECTED_BYTES and
            all(len(items) == 1 and items[0].size == len(bytes.fromhex(blob)) and
                items[0].bytes.hex() == blob and
                f"{items[0].mnemonic} {items[0].op_str}".strip() == row["instruction"]
                for items, blob, row in zip(decoded, EXPECTED_BYTES, rows)) and
            all(data[offset:offset + len(bytes.fromhex(row["bytes"]))] ==
                bytes.fromhex(row["bytes"])
                for offset, row in zip(EXPECTED_OFFSETS, rows)) and
            all(a["next_pc"] == b["pc"] for a, b in zip(rows, rows[1:])) and
            all(a["registers_after"] == b["registers"]
                for a, b in zip(rows, rows[1:])) and
            rows[-1]["next_pc"] == 0x56004D,
            "libc bytes or selected path differ")
    return {"libc_sha256": LIBC_SHA256, "base": hex(base),
            "entry_file_offset": hex(IMAGE_ENTRY_OFFSET),
            "selected_instruction_offsets": [hex(i) for i in EXPECTED_OFFSETS]}


def apply(rows, incoming, x, witness, *, image=LIBC):
    """Return computed scalar state/byte memory for the exact eight-zero path."""
    identity = checked_image(rows, image)
    entry = rows[0]["registers"]
    dst = incoming.regs[56]  # RDI
    length = incoming.regs[16]  # RDX
    fill = incoming.regs[48]  # RSI
    stack = incoming.regs[32]  # RSP
    require(number(length, x, witness) == 8 and
            number(fill, x, witness) == 0 and
            number(dst, x, witness) == entry["rdi"] and
            number(stack, x, witness) == entry["rsp"] and
            entry["rdi"] & 0xFFF <= 0xFC0 and
            entry["rdi"] + 64 <= 1 << 64 and
            entry["rsp"] + 8 <= 1 << 64 and
            (entry["rdi"] + 8 <= entry["rsp"] or
             entry["rsp"] + 8 <= entry["rdi"]) and
            entry["rdx"] == 8 and entry["rsi"] == 0,
            "bounded libc precondition differs")
    ret = z3.Concat(*reversed([
        z3.Select(incoming.memory, stack + z3.BitVecVal(i, 64))
        for i in range(8)]))
    require(number(ret, x, witness) == 0x56004D,
            "computed stack does not contain libc return address")
    store = rows[10]["memory"]
    ret_access = rows[11]["memory"]
    require(all(not row["memory"] for row in rows[:10]) and
            len(store) == 1 and store[0]["address"] == entry["rdi"] and
            store[0]["size"] == 64 and store[0]["access"] == 1 and
            len(ret_access) == 1 and
            ret_access[0]["address"] == entry["rsp"] and
            ret_access[0]["size"] == 8 and ret_access[0]["access"] == 1 and
            ret_access[0]["before"] == ret_access[0]["after"] == 0x56004D,
            "vector store or return read is unrecognized")
    # BZHI(-1, 8) gives 0xff. KMOVQ selects its low eight byte lanes.
    # A read-tagged 64-byte operand hides the mask in the tracer; compare the
    # entire before/after operand, including bytes rewritten with same value.
    before = store[0]["before"]
    after = store[0]["after"]
    require(after == before & ~((1 << 64) - 1),
            "libc vector mask/store differs from eight zero bytes")
    memory = incoming.memory
    for index in range(8):
        memory = z3.Store(memory, dst + z3.BitVecVal(index, 64),
                          z3.BitVecVal(0, 8))
    ret_after_store = z3.Concat(*reversed([
        z3.Select(memory, stack + z3.BitVecVal(i, 64))
        for i in range(8)]))
    require(number(ret_after_store, x, witness) ==
            ret_access[0]["before"],
            "libc store changed the subsequently read return address")
    reg_expr = {name: incoming.regs[offset]
                for offset, name in REGISTER_OFFSETS.items()}
    reg_expr.update(rax=dst, rcx=z3.BitVecVal(0xFF, 64),
                    rdi=dst & z3.BitVecVal(0xFFF, 64),
                    rsp=stack + z3.BitVecVal(8, 64))
    after_state = rows[-1]["registers_after"]
    require(all(number(expr, x, witness) == after_state[name]
                for name, expr in reg_expr.items()),
            "computed libc scalar output differs")
    for offset in range(64):
        observed = (before >> (8 * offset)) & 255
        actual = number(z3.Select(incoming.memory,
                       dst + z3.BitVecVal(offset, 64)), x, witness)
        require(actual == observed, "libc reads differ from computed incoming memory")
        predicted = number(z3.Select(memory,
                           dst + z3.BitVecVal(offset, 64)), x, witness)
        require(predicted == (after >> (8 * offset)) & 255,
                "libc computed memory differs from native operand")
    # BZHI defines CF, ZF, SF and clears OF here; PF remains unspecified.
    # PF may be carried only if later P-code overwrites it before use.
    flags = {0: z3.BitVecVal(0, 8), 6: z3.BitVecVal(0, 8),
             7: z3.BitVecVal(0, 8), 11: z3.BitVecVal(0, 8),
             2: z3.BitVec(f"LIBC_UNDEFINED_PF_{witness}", 8)}
    require(all(((after_state["eflags"] >> bit) & 1) == 0
                for bit in (0, 6, 7, 11)) and
            set(flags) == set(FLAG_OFFSETS.values()),
            "libc defined flag result differs")
    return {"memory": memory, "registers": reg_expr, "flags": flags,
            "evidence": {**identity, "native_steps": len(rows),
                "contract": "pinned AVX-512 eight-byte zero fill path",
                "definite_write_address": hex(entry["rdi"]),
                "definite_write_extent": 8,
                "same_value_write_lanes": sum(
                    (before >> (8 * index)) & 255 == 0 for index in range(8)),
                "same_value_writes_preserved": True,
                "computed_scalar_outputs": len(reg_expr),
                "defined_flag_bits": [0, 6, 7, 11],
                "undefined_flag_bits": [2],
                "status": "checked_exact_witness_conditional_contract"}}
