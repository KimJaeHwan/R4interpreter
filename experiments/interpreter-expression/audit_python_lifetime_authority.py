"""Keep CPython object writes distinct from an authorized Allocate effect."""
from __future__ import annotations

from hashlib import sha256
import json

from common_program_path_il import require
from probe_python_remaining_scope import (RESULT as PRIOR, TRACES,
                                          allocator_audit)
from probe_unseen_python_path import GENERATED, PYTHON, ROOT
from prove_cross_full_flow import load_trace


RESULT = ROOT / "python_default_allocator_authority_result.json"


def assess(value, path, rows, summary_bundle, supplied_authority=None):
    observed = allocator_audit(rows, summary_bundle, value)
    require(observed["logical_allocate"] == "unknown" and
            observed["freshness_and_nonaliasing"] == "unknown" and
            len(observed["object_field_writes"]) == 4 and
            observed["first_read_before_field_write"],
            "allocator observation changed")
    # A text claim or a certificate from a different fixture cannot establish
    # ownership of this returned CPython address. No default allocator
    # authority verifier exists yet; even matching metadata alone is not one.
    authority_status = "absent"
    if supplied_authority is not None:
        if (supplied_authority.get("binary_sha256") !=
                sha256(PYTHON.read_bytes()).hexdigest() or
                supplied_authority.get("trace_sha256") !=
                sha256(path.read_bytes()).hexdigest() or
                supplied_authority.get("allocator_domain") !=
                "default_cpython_allocator"):
            authority_status = "foreign_or_mismatched"
        else:
            authority_status = "metadata_only_unverified"
    return {"input": value,
            "trace_sha256": sha256(path.read_bytes()).hexdigest(),
            "object_pointer": observed["object_pointer"],
            "native_evidence": {"helper_call_observed":
                                observed["helper_call_observed"],
                                "field_writes": observed["object_field_writes"],
                                "prior_read_count":
                                len(observed["first_read_before_field_write"])},
            "authority_status": authority_status,
            "effect": "unknown(Write evidence does not establish Allocate)",
            "missing": observed["missing_authority"]}


def main():
    bundle = json.loads(GENERATED.read_text())
    prior = json.loads(PRIOR.read_text())
    cases = []
    for value in (252, 254):
        _, rows, _ = load_trace(TRACES[value], "python", value, PYTHON)
        observed = allocator_audit(rows, bundle, value)
        require(observed == next(item for item in prior["allocator"]
                                 if item["input"] == value),
                "prior allocator observation changed")
        cases.append(assess(value, TRACES[value], rows, bundle))
    foreign = assess(252, TRACES[252],
        load_trace(TRACES[252], "python", 252, PYTHON)[1], bundle,
        {"binary_sha256": "0" * 64,
         "trace_sha256": sha256(TRACES[252].read_bytes()).hexdigest(),
         "allocator_domain": "controlled_obj_pool"})
    counterfeit = assess(252, TRACES[252],
        load_trace(TRACES[252], "python", 252, PYTHON)[1], bundle,
        {"binary_sha256": sha256(PYTHON.read_bytes()).hexdigest(),
         "trace_sha256": sha256(TRACES[252].read_bytes()).hexdigest(),
         "allocator_domain": "default_cpython_allocator",
         "claimed_extent": 32, "claimed_generation": 1})
    require(foreign["authority_status"] == "foreign_or_mismatched" and
            counterfeit["authority_status"] == "metadata_only_unverified" and
            all(item["effect"].startswith("unknown")
                for item in (foreign, counterfeit, *cases)),
            "unsupported lifetime promotion accepted")
    result = {"schema_version": "python-default-allocator-authority-v1",
              "binary_sha256": sha256(PYTHON.read_bytes()).hexdigest(),
              "cases": cases,
              "negative_controls": {
                  "foreign_controlled_pool_authority": foreign["authority_status"],
                  "matching_metadata_without_allocator_proof":
                      counterfeit["authority_status"]},
              "scope": "native object writes and pre-reads verified; default allocator ownership unproved",
              "logical_allocate_authorized": False}
    RESULT.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"candidate_objects": len(cases),
                      "logical_allocate_authorized": False}))


if __name__ == "__main__":
    main()
