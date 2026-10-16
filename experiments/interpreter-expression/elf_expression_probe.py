"""Project add7 from a real ELF's admitted Ghidra Bundle, then check the ELF."""

from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import random
import subprocess
import sys

import z3

from expression_probe import project
from tdo_v2.configured_naming_contracts import CALL_NAMING_GHIDRA_VERSION, NamingBindingExpectation
from tdo_v2.integration.configured_bundle import admit_frozen_bundle
from tdo_v2.integration.observed_function_session import open_observed_function_session
from tdo_v2.normalize import FunctionNormalizer, NormalizedFunction


here = Path(__file__).resolve().parent
repo = Path(os.environ.get("DAASDMLKAS_REPO", str(here.parents[2] / "daasdmlkas")))
binary = here / "elf_expression_fixture"
generation = Path(sys.argv[1])
binding = NamingBindingExpectation(
    sha256((repo / "ghidra/GhidraV2CallNaming.java").read_bytes()).digest(),
    CALL_NAMING_GHIDRA_VERSION,
)
snapshot = admit_frozen_bundle(generation)
with open_observed_function_session(snapshot, naming_binding=binding) as session:
    rows = list(session.iter_functions())
if len(rows) != 1:
    raise AssertionError(f"expected exactly one exported function, got {len(rows)}")
observation = rows[0].unit.observation
function = FunctionNormalizer().normalize(rows[0].unit)
if type(function) is not NormalizedFunction:
    raise AssertionError(f"normalization failed: {function}")
candidate_sinks = [
    (index, ordinal)
    for index, instruction in enumerate(observation.instructions)
    for ordinal, operation in enumerate(instruction.operations)
    if operation.output is not None
    and operation.output.coordinate.byte_offset == 0
    and operation.output.byte_size == 8
    and operation.opcode == "COPY"
]
if len(candidate_sinks) != 1:
    raise AssertionError(f"expected one RAX result write: {candidate_sinks}")
instruction_index, ordinal = candidate_sinks[0]
expression, source, evidence = project(
    function, observation, instruction_index, ordinal=ordinal, width=8
)
expected = source + z3.BitVecVal(7, 64)
solver = z3.Solver()
solver.add(expression != expected)
equivalence = str(solver.check())
if equivalence != "unsat":
    raise AssertionError(f"projected expression differs from 64-bit x+7: {solver.model()}")
values = [0, 1, 7, 8, 2**63 - 1, 2**63, 2**64 - 8, 2**64 - 7, 2**64 - 1]
rng = random.Random(73)
values += [rng.getrandbits(64) for _ in range(128)]
mismatches = []
mutated_mismatches = []
for value in values:
    native = int(subprocess.check_output([str(binary), str(value)], text=True).strip())
    projected = z3.simplify(z3.substitute(expression, (source, z3.BitVecVal(value, 64)))).as_long()
    if projected != native:
        mismatches.append(value)
    if (value + 8) % (2**64) != native:
        mutated_mismatches.append(value)
if mismatches or not mutated_mismatches:
    raise AssertionError(("native comparison", mismatches[:5], mutated_mismatches[:5]))
report = {
    "binary": str(binary),
    "binary_sha256": sha256(binary.read_bytes()).hexdigest(),
    "bundle_generation": generation.name,
    "ghidra_version": "12.0.4",
    "compiler_flags": "gcc -O2 -fno-pie -no-pie",
    "function": "add7",
    "result_register": "RAX:8",
    "input_register": "RDI:8",
    "expression": str(expression),
    "expression_width_bits": expression.size(),
    "guard": "true",
    "assumptions": ["SysV AMD64 input in RDI and return in RAX", "Ghidra Low P-code models the selected machine instructions"],
    "scope": "JOIN-free straight-line selected function; native comparison on listed samples",
    "smt_inequivalence_to_64bit_fixture_spec": equivalence,
    "native_inputs_checked": len(values),
    "native_mismatches": mismatches,
    "mutated_plus_8_mismatches": len(mutated_mismatches),
    "boundary_inputs": values[:9],
    "evidence": evidence,
}
destination = here / "elf_expression_probe_result.json"
destination.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
print(json.dumps(report, indent=2, ensure_ascii=False))
