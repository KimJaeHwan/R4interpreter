"""Probe cached-int boundaries and non-Smi JS inputs against saved summaries."""
from __future__ import annotations

import gzip
from hashlib import sha256
import json
from pathlib import Path
import shutil

from prove_cross_full_flow import PYTHON, ROOT
from prove_js_handler_transition import apply_case as apply_js
from prove_python_handler_transition import apply_case as apply_python


ARTIFACTS = ROOT / "artifacts"
RESULT = ROOT / "alternate_path_rejection_result.json"


def records(path):
    with gzip.open(path, "rt") as stream:
        return [json.loads(line) for line in stream]


def first_divergence(reference, alternate):
    for index, (left, right) in enumerate(zip(reference, alternate)):
        if (left["pc"], left["bytes"], left["next_pc"]) != (
                right["pc"], right["bytes"], right["next_pc"]):
            return index
    return None if len(reference) == len(alternate) else min(len(reference), len(alternate))


def main():
    js = json.loads((ROOT / "js_addsmi_full_handler_summary.json").read_text())
    python = json.loads((ROOT / "python_binary_op_full_handler_summary.json").read_text())
    py_ref = records(ARTIFACTS / "python_holdout_37.json.gz")[1]["rows"]
    js_ref = records(ARTIFACTS / "js_handler_holdout_37.json.gz")[1]["rows"]
    python_binary_hash = sha256(PYTHON.read_bytes()).hexdigest()
    node_binary_hash = sha256(Path(shutil.which("node")).read_bytes()).hexdigest()
    cases = []
    for name, path in [
            ("python_result_cache_boundary", ARTIFACTS / "python_holdout_252.json.gz"),
            ("js_outside_proved_domain", ARTIFACTS / "js_handler_holdout_252.json.gz"),
            ("js_string_concat", ARTIFACTS / "js_string_holdout_37.json.gz"),
            ("js_bigint_type_error", ARTIFACTS / "js_bigint_error_37.json.gz")]:
        meta, body, oracle = records(path)
        rows = body["rows"]
        expected_fixture = {
            "python_result_cache_boundary": ROOT / "python_holdout_fixture.py",
            "js_outside_proved_domain": ROOT / "js_holdout_fixture.js",
            "js_string_concat": ROOT / "js_string_holdout_fixture.js",
            "js_bigint_type_error": ROOT / "js_bigint_error_fixture.js"}[name]
        expected_kind = {"python_result_cache_boundary": None,
                         "js_outside_proved_domain": "number",
                         "js_string_concat": "string",
                         "js_bigint_type_error": "bigint"}[name]
        if (meta["input"] != (252 if "boundary" in name or
                              "outside_proved" in name else 37) or
                meta["fixture_sha256"] != sha256(expected_fixture.read_bytes()).hexdigest() or
                meta.get("input_type") != expected_kind or
                not rows or any(row["step"] != index for index, row in enumerate(rows)) or
                any(left["next_pc"] != right["pc"] for left, right in zip(rows, rows[1:]))):
            raise ValueError(f"alternate trace provenance or continuity changed: {name}")
        if name.startswith("python"):
            if (meta["binary_sha256"] != python_binary_hash or
                    oracle["output"] != 257 or len(rows) != 146 or
                    rows[-1]["next_pc"] != 0x56173B or
                    meta["left_pointer"] != 0xA42A10 + (252 + 5) * 32):
                raise ValueError("Python alternate trace identity changed")
            application = apply_python(python, meta, rows)
            reference = py_ref
        else:
            if (meta["binary_sha256"] != js["binary_sha256"] or
                    meta["binary_sha256"] != node_binary_hash or
                    meta["full_handler"] != (name == "js_outside_proved_domain") or
                    (len(rows) != 23 if name == "js_outside_proved_domain"
                     else len(rows) != 11 or rows[0]["registers"]["rax"] & 1 != 1)):
                raise ValueError("JS alternate trace binary changed")
            application = apply_js(js, rows, meta["binary_sha256"])
            reference = js_ref
        if not application["status"].startswith("unknown("):
            raise ValueError(f"alternate case was incorrectly accepted: {name}")
        if name == "js_string_concat" and oracle["output"] != "375":
            raise ValueError("string concatenation oracle changed")
        if name == "js_bigint_type_error" and oracle["error"] != "TypeError":
            raise ValueError("BigInt error oracle changed")
        if name == "js_outside_proved_domain" and oracle["output"] != 257:
            raise ValueError("JS numeric boundary oracle changed")
        divergence = first_divergence(reference, rows)
        if ((name == "js_outside_proved_domain" and divergence is not None) or
                (name != "js_outside_proved_domain" and divergence is None)):
            raise ValueError("alternate native path divergence changed")
        cases.append({"name": name,
                      "trace_sha256": sha256(path.read_bytes()).hexdigest(),
                      "binary_sha256": meta["binary_sha256"],
                      "fixture_sha256": meta["fixture_sha256"],
                      "input": meta["input"],
                      "input_type": meta.get("input_type", "integer"),
                      "oracle": oracle,
                      "trace_scope": ("first_11_native_steps" if name in
                                      ("js_string_concat", "js_bigint_type_error")
                                      else "through_next_handler"),
                      "native_steps_recorded": len(rows),
                      "reference_native_steps": len(reference),
                      "first_different_native_step": divergence,
                      "application": application})
    result = {"status": "four alternate cases rejected by bounded summaries",
              "cases": cases,
              "limits": ["JS non-Smi probes record only the first 11 native steps",
                         "unknown is a refusal to apply, not a recovered alternate semantics",
                         "Python 252 records through next handler; JS 252 records through next handler"]}
    RESULT.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"cases": len(cases),
                      "unknown": sum(item["application"]["status"].startswith(
                          "unknown(") for item in cases)}))


if __name__ == "__main__":
    main()
