"""One fail-closed evaluator for the Lua v0 and typed cross-engine v1 views.

This evaluates already recorded candidate expressions. It does not derive
them or increase their evidence level.
"""
from __future__ import annotations

import math


MASK64 = (1 << 64) - 1


def sort_of(report):
    return report["semantic_model"].get("value_sort", report["semantic_model"].get("integer_sort"))


def coerce(value, sort):
    if sort == "BV64":
        return value & MASK64
    if sort == "Z":
        return int(value)
    if sort == "F64":
        return float(value)
    raise ValueError(f"unsupported value sort {sort}")


def expression(node, x, sort):
    if node == "X":
        return coerce(x, sort)
    if "bv64" in node:
        if sort != "BV64":
            raise ValueError("BV64 constant in a non-BV64 case")
        return coerce(int(node["bv64"]), sort)
    if "const" in node:
        if node["sort"] != sort:
            raise ValueError("typed constant sort mismatch")
        return coerce(int(node["const"]), sort)
    if node["op"] in ("add", "bvadd"):
        if node.get("sort", "BV64") != sort:
            raise ValueError("arithmetic sort mismatch")
        args = [expression(item, x, sort) for item in node["args"]]
        return coerce(args[0] + args[1], sort)
    if node["op"] in ("eq", "ne"):
        left = expression(node["left"], x, sort)
        right = expression(node["right"], x, sort)
        return left == right if node["op"] == "eq" else left != right
    raise ValueError(f"unsupported expression: {node}")


def classify(report, binary_sha256, program_sha256, x):
    identity = report["identity"]
    if binary_sha256 != identity["binary_sha256"] or \
            program_sha256 != identity["program_sha256"]:
        return {"status": "unknown", "reason": "code identity mismatch"}
    if not isinstance(x, int):
        return {"status": "unknown", "reason": "non-integer input or object effects"}
    sort = sort_of(report)
    if sort == "BV64" and not -(1 << 63) <= x < 1 << 63:
        return {"status": "unknown", "reason": "outside signed 64-bit input domain"}
    bounds = report.get("input_integer_bounds")
    if bounds and not bounds[0] <= x <= bounds[1]:
        return {"status": "unknown", "reason": "outside admitted exact-integer domain"}
    if str(x) not in report["admitted_input_witnesses"]:
        return {"status": "unknown", "reason": "entry state and path not admitted"}
    matching = [case for case in report["cases"] if expression(case["guard"], x, sort)]
    if len(matching) != 1:
        return {"status": "unknown", "reason": "case guard coverage/overlap unresolved"}
    result = expression(matching[0]["result"], x, sort)
    if sort == "BV64" and result & (1 << 63):
        result -= 1 << 64
    if sort == "F64" and (not math.isfinite(result) or not result.is_integer()):
        return {"status": "unknown", "reason": "non-finite/non-integer result"}
    if sort == "F64":
        result = int(result)
    return {"status": matching[0]["validation_level"], "predicted_output": result}
