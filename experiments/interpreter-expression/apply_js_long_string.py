"""Apply one frozen 12..18-digit V8 native path and reject outside contracts."""
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import shutil

from build_expanded_native_paths import records
from common_observed_transition import apply_case
from freeze_js_long_string import COMMON, NATIVE, ROOT, TRACE


RESULT = ROOT / "js_long_string_application_result.json"
HOLDOUTS = (987654321012, 98765432109876543, 123456789012345678)
NEGATIVE = (12345678901, 1234567890123456789)


def run_case(common, case, node, value, path):
    meta, body, output = records(path)
    rows = body["rows"]
    if meta["input"] != value or output["output"] != f"{value}5":
        raise ValueError("JavaScript long-string oracle changed")
    verdict = apply_case(common, case, node, rows, meta)
    return {"input_ascii": str(value), "length": len(str(value)),
            "trace_sha256": sha256(path.read_bytes()).hexdigest(),
            "status": verdict["status"],
            "native_steps": len(rows),
            "ordered_writes_checked": verdict.get("ordered_writes_checked"),
            "output_oracle": output["output"],
            "target_pcode_steps_replayed": verdict.get("target_pcode_steps_replayed")}


def main():
    common = json.loads(COMMON.read_text())
    native = json.loads(NATIVE.read_text())
    case = common["cases"][0]
    node = Path(shutil.which("node"))
    if (case["source_summary_sha256"] != sha256(NATIVE.read_bytes()).hexdigest()
            or native["source_trace_sha256"] != sha256(TRACE.read_bytes()).hexdigest()
            or case["identity"]["binary_sha256"] != sha256(node.read_bytes()).hexdigest()):
        raise ValueError("frozen long-string source identity changed")
    positive = [run_case(common, case, node, value,
                ROOT / "artifacts" / f"next_js_long_{value}.json.gz")
                for value in HOLDOUTS]
    outside = [run_case(common, case, node, value,
               ROOT / "artifacts" / f"next_js_long_{value}.json.gz"
               if value != 12345678901 else
               ROOT / "artifacts" / "js_string_full_12345678901.json.gz")
               for value in NEGATIVE]
    if any(row["status"] != "differentially_validated" or
           row["ordered_writes_checked"] != 28 or
           row["target_pcode_steps_replayed"] != 0 for row in positive):
        raise ValueError("fresh long-string path did not reuse frozen summary")
    if any(not row["status"].startswith("unknown(") for row in outside):
        raise ValueError("out-of-range long-string path was admitted")
    path = ROOT / "artifacts" / f"next_js_long_{HOLDOUTS[0]}.json.gz"
    meta, body, output = records(path)
    controls = {}
    for name, mutate in (
            ("wrong_entry_bytes", lambda m, r: m["input_object_snapshot"].update(
                ascii_hex=b"000000000000".hex())),
            ("wrong_ordered_write", lambda m, r: next(
                item for row in r for item in row["memory"] if item["access"] & 2)
                .update(after=0)),
            ("wrong_successor", lambda m, r: r[-1].update(
                next_pc=r[-1]["next_pc"] ^ 1))):
        bad_meta, bad_rows = deepcopy(meta), deepcopy(body["rows"])
        mutate(bad_meta, bad_rows)
        verdict = apply_case(common, case, node, bad_rows, bad_meta)
        if not verdict["status"].startswith("unknown("):
            raise ValueError(f"long-string negative control admitted: {name}")
        controls[name] = verdict["status"]
    RESULT.write_text(json.dumps({"schema_version": 1,
        "native_summary_sha256": sha256(NATIVE.read_bytes()).hexdigest(),
        "common_summary_sha256": sha256(COMMON.read_bytes()).hexdigest(),
        "source_trace_sha256": sha256(TRACE.read_bytes()).hexdigest(),
        "positive": positive, "outside_domain": outside,
        "negative_controls": controls,
        "scope": "same 182-step native path and captured entry string object; GC and final serialization unknown"},
        indent=2) + "\n")
    print(json.dumps({"matched": len(positive), "unknown": len(outside),
                      "negative_controls": len(controls)}))


if __name__ == "__main__":
    main()
