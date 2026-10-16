"""Translate existing Lua experiment predictions into benchmark result records."""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path

from build_cases import EXPECTED, ROOT, signed


EXPERIMENT = ROOT.parent / "interpreter-expression"
OUTPUT = ROOT / "reports/current-lua-analysis.json"


def main():
    cases = json.loads(EXPECTED.read_text())["cases"]
    wanted = {(case["id"], sample["input"])
              for case in cases if case["engine"] == "lua_5_4_fixture"
              for sample in case["samples"]}
    singles = json.loads((EXPERIMENT / "transition_summary_validation.json").read_text())
    composed = json.loads((EXPERIMENT / "lua_composition_validation.json").read_text())
    handler_digest = sha256((EXPERIMENT / "handler_summary_plus7.json").read_bytes()).hexdigest()
    bridge_digest = sha256((EXPERIMENT / "lua_handler_dispatch_bridge.json").read_bytes()).hexdigest()
    if singles["lua_summary_sha256"] != handler_digest or composed["handler_summary_sha256"] != handler_digest:
        raise ValueError("Lua report refers to a different handler summary")
    if composed["bridge_summary_sha256"] != bridge_digest:
        raise ValueError("Lua report refers to a different dispatch bridge")
    results = []
    for row in singles["lua"]:
        case_id = {"lua_chunk.luac": "VMT013", "lua_chunk_plus11.luac": "VMT014"}.get(row["bytecode"])
        key = (case_id, str(row["input"]))
        if key in wanted:
            results.append({"id": case_id, "input": key[1], "status": "computed",
                            "result": str(row["predicted_signed_payload"]),
                            "evidence": {"summary_sha256": handler_digest,
                                         "trace_sha256": row["trace_sha256"]}})
    for row in composed["cases"]:
        key = ("VMT015", str(row["input"]))
        if key in wanted:
            if not row["predicted_second_entry_matches_trace"] or row["second_entry_snapshot_used_as_input"]:
                raise ValueError("composition report does not meet boundary independence requirement")
            results.append({"id": "VMT015", "input": key[1], "status": "computed",
                            "result": str(signed(row["second_payload"])),
                            "evidence": {"summary_sha256": handler_digest,
                                         "bridge_sha256": bridge_digest,
                                         "trace_sha256": row["trace_sha256"]}})
    if {(item["id"], item["input"]) for item in results} != wanted:
        raise ValueError("existing Lua results do not cover benchmark Lua samples")
    output = {"schema_version": 1, "provenance": "prior R4 Lua path summaries; not a new generic analyzer",
              "results": results}
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(output, indent=2) + "\n")
    print(f"imported {len(results)} Lua sample predictions")


if __name__ == "__main__":
    main()
