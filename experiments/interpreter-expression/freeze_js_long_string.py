"""Freeze the observed V8 long-string path as one guarded native transition.

The entry string bytes are captured at the native cutpoint because this path
creates a cons string without reading every source character in the handler.
"""
from hashlib import sha256
import json
from pathlib import Path
import shutil

from build_expanded_native_paths import make_case, records
from common_observed_transition import normalize_native


ROOT = Path(__file__).resolve().parent
TRACE = ROOT / "artifacts/next_js_long_source_12.json.gz"
NATIVE = ROOT / "js_long_string_native_summary.json"
COMMON = ROOT / "js_long_string_common_summary.json"


def main():
    node = Path(shutil.which("node"))
    meta, body, output = records(TRACE)
    rows = body["rows"]
    if (meta["input"] != 123456789012 or meta["input_type"] != "string" or
            meta["binary_sha256"] != sha256(node.read_bytes()).hexdigest() or
            meta["fixture_sha256"] != sha256(
                (ROOT / "js_string_holdout_fixture.js").read_bytes()).hexdigest() or
            meta.get("input_object_snapshot", {}).get("ascii_hex") !=
                b"123456789012".hex() or
            len(rows) != 182 or output["output"] != "1234567890125"):
        raise ValueError("long-string source trace contract changed")
    pre = {"kind": "javascript_string", "fixture_sha256": meta["fixture_sha256"],
           "minimum_digits": 12, "maximum_digits": 18,
           "entry_object_bytes": "captured at native entry cutpoint",
           "result_kind": "observed_cons_string_path"}
    case = make_case(rows, node, "long_string_cons_path_12_to_18", pre)
    source = {"schema_version": "native-handler-transition-v1",
        "engine": "javascript", "binary_sha256": meta["binary_sha256"],
        "scope": "observed Node --jitless long-string cons path; digits 12..18",
        "cases": [case], "source_trace_sha256": sha256(TRACE.read_bytes()).hexdigest(),
        "limits": ["exact runtime and 182-step path identity",
                   "entry object characters come from a ptrace snapshot, not native handler reads",
                   "GC lifetime, flattening and final string serialization are outside this native segment"]}
    NATIVE.write_text(json.dumps(source, indent=2) + "\n")
    common = {"schema_version": "common-observed-transition-v1",
        "semantic_model": {"architecture": "x86-64", "endian": "little",
                           "memory": "byte-addressed", "integers": "typed bitvectors",
                           "expression": "SMT-LIB 2 term"},
        "cases": [normalize_native(source, "javascript", case,
                                   sha256(NATIVE.read_bytes()).hexdigest())],
        "uncovered": "other string lengths, native shapes and effects are unknown"}
    COMMON.write_text(json.dumps(common, indent=2) + "\n")
    print(json.dumps({"native_steps": len(rows),
                      "pcode_operations": case["evidence"]["pcode_operations"],
                      "reads": len(case["reads"]),
                      "ordered_writes": len(case["ordered_effects"]),
                      "summary_sha256": sha256(COMMON.read_bytes()).hexdigest()}))


if __name__ == "__main__":
    main()
