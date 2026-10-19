"""Connect selected Python/JS native dispatches to same-trace byte reads."""
from __future__ import annotations

from copy import deepcopy
import gzip
import json
import subprocess

import pypcode

from build_common_program_representation import ROOT, digest
from common_program_path_il import require
from cross_dispatch_pcode import read_vaddr
from discover_dispatch_intervals import JAVASCRIPT
from probe_python_remaining_scope import TRACES
from probe_unseen_python_path import PYTHON
from prove_cross_full_flow import load_trace


OUTPUT = ROOT / "cross_same_trace_cursor_v1.json"
BOUNDARIES = ROOT / "boundary_relevance_map_v1.json"
DISCOVERY = ROOT / "dispatch_interval_discovery_result.json"
PRIOR_PY = ROOT / "artifacts/cross_python_9_native.json.gz"
PY_OPCODES = ROOT / "artifacts/cross_python_9_opcodes.json"
PY_FIXTURE = ROOT / "python_branch_fixture.py"
JS_TRACE = ROOT / "artifacts/next_boundary_js_43.json.gz"


def python_fixture_manifest():
    # Run the pinned interpreter to establish the fixture's actual code bytes.
    # This oracle anchors an offset only; it supplies no opcode semantics.
    code = ("import importlib.util, dis, hashlib, json, sys; "
            "s=importlib.util.spec_from_file_location('fixture',sys.argv[1]); "
            "m=importlib.util.module_from_spec(s); s.loader.exec_module(m); "
            "f={'branchCall':m.branchCall,'addFive':m.addFive}; "
            "print(json.dumps({'hashes':{n:hashlib.sha256(v.__code__.co_code).hexdigest() for n,v in f.items()}, "
            "'lengths':{n:len(v.__code__.co_code) for n,v in f.items()}, "
            "'instructions':{n:[{'offset':r.offset,'opname':r.opname,"
            "'opcode_byte':v.__code__.co_code[r.offset],'argrepr':r.argrepr} "
            "for r in dis.get_instructions(v)] for n,v in f.items()}}))")
    result = subprocess.run([str(PYTHON), "-I", "-S", "-c", code,
                             str(PY_FIXTURE)], capture_output=True,
                            text=True, check=True)
    return json.loads(result.stdout)


def read(row, size):
    accesses = [item for item in row["memory"]
                if item["access"] & 1 and item["size"] == size]
    require(len(accesses) == 1, "expected one native fetch/table read")
    return accesses[0]


def pcode(row, binary):
    require(bytes.fromhex(row["bytes"]) ==
            read_vaddr(binary, row["pc"], row["pc"] + len(row["bytes"]) // 2),
            "recorded native instruction bytes differ from pinned executable")
    return {op.opcode.name for op in pypcode.Context("x86:LE:64:default").translate(
        bytes.fromhex(row["bytes"]), base_address=row["pc"],
        max_instructions=1).ops}


def python_binding(first, selected, table, entry, code_pointer, marker,
                   manifest):
    start = read(first, 2)
    opcode = read(selected, 2)
    dispatch = read(table, 8)
    offset = opcode["address"] - start["address"]
    opcodes = {item["offset"]: item["opcode_byte"]
               for item in manifest["instructions"]["addFive"]}
    require(marker["bytecode_sha256"]["addFive"] ==
            code_pointer["bytecode_sha256"]["addFive"] and
            first["pc"] == 0x561298 and selected["pc"] == 0x561316 and
            table["pc"] == 0x56132D and entry["pc"] == 0x56227C and
            first["registers"]["rbp"] == start["address"] and
            selected["registers"]["rbp"] == opcode["address"] and
            first["registers"]["rbx"] == selected["registers"]["rbx"] and
            start["address"] == code_pointer["address"] + 0xC8 and
            opcode["address"] == code_pointer["address"] + 0xCE and
            start["before"] & 0xFF == opcodes[0] and
            opcode["before"] & 0xFF == opcodes[offset] and
            offset == 6 and opcode["before"] & 0xFF == 0x2D and
            table["registers"]["rax"] == 0x2D and
            dispatch["address"] == 0x8659A0 + 0x2D * 8 and
            dispatch["before"] == table["next_pc"] == entry["pc"] and
            "LOAD" in pcode(first, PYTHON) and
            "LOAD" in pcode(selected, PYTHON) and
            {"LOAD", "BRANCHIND"} <= pcode(table, PYTHON),
            "Python child byte fetch/cursor/table/handler link changed")
    return offset


def python_case():
    trace = TRACES[252]
    meta, rows, _ = load_trace(trace, "python", 252, PYTHON)
    boundary = next(item for item in json.loads(BOUNDARIES.read_text())[
        "boundaries"] if item["id"] == "python_252:numeric_transition")
    with gzip.open(PRIOR_PY, "rt") as stream:
        prior = json.load(stream)
    manifest = json.loads(PY_OPCODES.read_text())
    live_manifest = python_fixture_manifest()
    require(manifest["instructions"] == live_manifest["instructions"] and
            live_manifest["hashes"] == meta["marker"]["bytecode_sha256"] and
            live_manifest["lengths"]["addFive"] == 12,
            "Python opcode manifest is not from the pinned fixture code")
    require(boundary["entry_predecessor_step"] == 682 and
            boundary["span_in_unit"][0] == 683 and
            boundary["entry_pc"] == "0x56227c" and
            boundary["trace_sha256"] == digest(trace) and
            rows[629]["memory"][0]["before"] ==
            meta["marker"]["code_pointers"]["addFive"] and
            rows[629]["memory"][0]["address"] == rows[629]["registers"]["rbx"] and
            read(rows[613], 8)["before"] == read(rows[617], 2)["address"] and
            rows[613]["registers"]["rbx"] == rows[617]["registers"]["rbx"],
            "Python selected boundary or first child bytecode cursor changed")
    pointer = {"address": meta["marker"]["code_pointers"]["addFive"],
               "bytecode_sha256": meta["marker"]["bytecode_sha256"]}
    offset = python_binding(rows[617], rows[675], rows[682], rows[683],
                            pointer, prior["marker"], live_manifest)
    return {"engine": "python", "input": 252,
        "boundary_id": boundary["id"], "trace_sha256": digest(trace),
        "binary_sha256": digest(PYTHON),
        "code_object_pointer": hex(pointer["address"]),
        "code_object_hash": pointer["bytecode_sha256"]["addFive"],
        "fixture_source_sha256": digest(PY_FIXTURE),
        "fixture_bytecode_length": live_manifest["lengths"]["addFive"],
        "first_child_fetch_step": 617,
        "first_child_fetch_address": hex(read(rows[617], 2)["address"]),
        "first_child_opcode_byte": read(rows[617], 2)["before"] & 255,
        "selected_fetch_step": 675,
        "selected_fetch_address": hex(read(rows[675], 2)["address"]),
        "selected_opcode_byte": 0x2D,
        "cursor_delta_from_first_child_fetch": offset,
        "fixture_manifest_opcode_offset": offset,
        "table_read_step": 682,
        "table_read_address": hex(read(rows[682], 8)["address"]),
        "handler_entry_step": 683, "handler_entry_pc": "0x56227c",
        "binding_grade": "same_trace_child_cursor_fetch_table_entry_with_same_hash_manifest",
        "offset_anchor": "first same-trace addFive fetch matched offset zero in pinned fixture code regenerated by CPython 3.13"}


def javascript_binding(first, first_table, first_call, first_entry,
                       selected, table, cursor_update, branch, entry):
    initial = read(first, 1)
    target = read(first_table, 8)
    byte = read(selected, 1)
    dispatch = read(table, 8)
    offset = byte["address"] - initial["address"]
    require(first["pc"] == 0x1A0A649 and first_table["pc"] == 0x1A0A64E and
            first_call["pc"] == 0x1A0A652 and first_entry["pc"] == 0x1BA8D00 and
            selected["pc"] == 0x1BA8D11 and table["pc"] == 0x1BA8D17 and
            cursor_update["pc"] == 0x1BA8D1B and branch["pc"] == 0x1BA8D1E and
            entry["pc"] == 0x1BB7780 and
            initial["address"] == first["registers"]["r12"] + first["registers"]["r9"] and
            initial["before"] == first["registers_after"]["r10"] and
            target["address"] == first_table["registers"]["r15"] + 8 * initial["before"] and
            target["before"] == first_call["registers"]["rcx"] ==
            first_call["next_pc"] == first_entry["pc"] and
            byte["address"] == selected["registers"]["r12"] +
            selected["registers"]["r9"] + 2 and offset == 2 and
            byte["before"] == table["registers"]["rdx"] == 0x4B and
            dispatch["address"] == table["registers"]["r15"] + 8 * byte["before"] and
            dispatch["before"] == cursor_update["registers"]["rcx"] ==
            branch["registers"]["rcx"] == branch["next_pc"] == entry["pc"] and
            cursor_update["registers_after"]["r9"] == branch["registers"]["r9"] and
            entry["registers"]["r12"] + entry["registers"]["r9"] == byte["address"] and
            "LOAD" in pcode(first, JAVASCRIPT) and
            "LOAD" in pcode(selected, JAVASCRIPT) and
            "LOAD" in pcode(table, JAVASCRIPT) and
            "BRANCHIND" in pcode(branch, JAVASCRIPT),
            "JavaScript child byte fetch/cursor/table/handler link changed")
    return offset


def javascript_case():
    meta, rows, _ = load_trace(JS_TRACE, "javascript", 43, JAVASCRIPT)
    discovered = next(item for item in json.loads(DISCOVERY.read_text())[
        "cases"] if item["engine"] == "javascript" and item["input"] == 43)
    boundary = discovered["boundary"]
    require(discovered["status"] == "differentially_validated" and
            discovered["trace_sha256"] == digest(JS_TRACE) and
            boundary["entry_predecessor"] == 29111 and
            boundary["begin"] == 29112 and
            boundary["entry_pc"] == "0x1bb7780" and
            meta["target_code"] == meta["entry_registers"]["r12"] +
            meta["entry_registers"]["r9"],
            "JavaScript selected other-trace boundary changed")
    offset = javascript_binding(*(rows[i] for i in
        (29101, 29102, 29103, 29104, 29108, 29109, 29110, 29111, 29112)))
    return {"engine": "javascript", "input": 43,
        "boundary_id": "other_trace_javascript_43:numeric_transition",
        "trace_sha256": digest(JS_TRACE), "binary_sha256": digest(JAVASCRIPT),
        "first_child_fetch_step": 29101,
        "first_child_fetch_address": hex(read(rows[29101], 1)["address"]),
        "first_child_opcode_byte": read(rows[29101], 1)["before"],
        "selected_fetch_step": 29108,
        "selected_fetch_address": hex(read(rows[29108], 1)["address"]),
        "selected_opcode_byte": 0x4B,
        "cursor_delta_from_first_child_fetch": offset,
        "absolute_bytecode_offset": None,
        "table_read_step": 29109,
        "table_read_address": hex(read(rows[29109], 8)["address"]),
        "handler_entry_step": 29112, "handler_entry_pc": "0x1bb7780",
        "binding_grade": "same_trace_child_cursor_fetch_table_entry_relative_offset",
        "offset_anchor": "first byte fetched for child call in same trace; bytecode array base not captured"}


def negative_controls():
    meta, py, _ = load_trace(TRACES[252], "python", 252, PYTHON)
    with gzip.open(PRIOR_PY, "rt") as stream:
        prior = json.load(stream)
    manifest = python_fixture_manifest()
    pointer = {"address": meta["marker"]["code_pointers"]["addFive"],
               "bytecode_sha256": meta["marker"]["bytecode_sha256"]}
    js = load_trace(JS_TRACE, "javascript", 43, JAVASCRIPT)[1]
    py_args = [py[i] for i in (617, 675, 682, 683)]
    js_args = [js[i] for i in (29101, 29102, 29103, 29104, 29108,
                              29109, 29110, 29111, 29112)]
    changes = {
        "python_wrong_fetch_byte": ("python", 1, "memory", "before", 0),
        "python_wrong_cursor": ("python", 1, "memory", "address", 0),
        "python_wrong_table_target": ("python", 2, "memory", "before", 0),
        "javascript_wrong_fetch_byte": ("javascript", 4, "memory", "before", 0),
        "javascript_wrong_cursor": ("javascript", 4, "memory", "address", 0),
        "javascript_wrong_table_target": ("javascript", 5, "memory", "before", 0),
    }
    outcomes = {}
    for name, (engine, index, field, key, value) in changes.items():
        args = deepcopy(py_args if engine == "python" else js_args)
        args[index][field][0][key] = value
        try:
            if engine == "python":
                python_binding(*args, pointer, prior["marker"], manifest)
            else:
                javascript_binding(*args)
        except ValueError:
            outcomes[name] = "rejected"
        else:
            outcomes[name] = "unexpectedly_accepted"
    require(all(value == "rejected" for value in outcomes.values()),
            "cross-engine cursor negative control accepted altered trace")
    return outcomes


def build():
    return {"schema_version": "cross-same-trace-cursor-v1",
           "cases": [python_case(), javascript_case()],
           "negative_controls": negative_controls(),
           "limits": ["Python offset zero is anchored by pinned fixture code regenerated in a separate CPython 3.13 process",
                      "JavaScript bytecode array base is absent, so offset is relative to first child fetch",
                      "JavaScript case is another full trace, not the local holdout-37 segment fixture",
                      "selected dispatch pairs do not establish every handler or alternate exit"]}


def main():
    doc = build()
    OUTPUT.write_text(json.dumps(doc, indent=2) + "\n")
    require(json.loads(OUTPUT.read_text()) == doc,
            "cross-engine cursor artifact changed after writing")
    print(json.dumps({"python_offset": doc["cases"][0]["fixture_manifest_opcode_offset"],
                      "javascript_relative_offset": doc["cases"][1]["cursor_delta_from_first_child_fetch"],
                      "negative_controls_rejected": len(doc["negative_controls"])}))


if __name__ == "__main__":
    main()
