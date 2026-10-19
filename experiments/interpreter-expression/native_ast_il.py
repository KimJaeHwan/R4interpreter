"""Translate frozen native SMT transitions into one typed, shared expression DAG.

The source is a P-code replay summary, not source-language code. Every guard,
read address, ordered write, output, and successor is checked against the DAG.
Unimplemented SMT operations fail closed.
"""
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path

import z3

from apply_transition_summary import declarations, expression


ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / "common_three_engine_transitions.json"
LONG_SOURCE = ROOT / "js_long_string_common_summary.json"
OUTPUT = ROOT / "native_ast_il.json"
RESULT = ROOT / "native_ast_il_result.json"
CASE_INDICES = (0, 1, 3)
OPERATIONS = {"=", "if", "bvadd", "bvsub", "bvmul", "bvor", "bvand",
              "bvxor", "bvnot", "bvule", "bvsle", "bvult", "bvslt",
              "select", "store", "extract", "concat", "and", "or", "not",
              "zero_extend", "sign_extend", "bvshl", "bvlshr", "bvashr"}


def sort_name(sort):
    if sort.kind() == z3.Z3_BOOL_SORT:
        return "Bool"
    if sort.kind() == z3.Z3_BV_SORT:
        return f"BV{sort.size()}"
    if sort.kind() == z3.Z3_ARRAY_SORT and sort.domain().kind() == z3.Z3_BV_SORT \
            and sort.range().kind() == z3.Z3_BV_SORT:
        return f"Array(BV{sort.domain().size()},BV{sort.range().size()})"
    raise ValueError(f"unsupported native expression sort {sort}")


class Builder:
    def __init__(self, interface):
        self.interface = {item["name"]: item["sort"] for item in interface}
        self.nodes = []
        self.ids = {}

    def add(self, ast):
        key = ast.get_id()
        if key in self.ids:
            return self.ids[key]
        sort = sort_name(ast.sort())
        if z3.is_true(ast) or z3.is_false(ast):
            node = {"op": "bool", "sort": sort, "value": z3.is_true(ast)}
        elif z3.is_bv_value(ast):
            node = {"op": "bv", "sort": sort, "value": ast.as_long()}
        elif z3.is_const(ast):
            name = ast.decl().name()
            if self.interface.get(name) != sort:
                raise ValueError(f"unbound or wrongly sorted native input {name}")
            node = {"op": "input", "sort": sort, "name": name}
        else:
            op = ast.decl().name()
            if op not in OPERATIONS:
                raise ValueError(f"unsupported native SMT operation {op}")
            node = {"op": op, "sort": sort,
                    "args": [self.add(child) for child in ast.children()]}
            if ast.decl().params():
                node["params"] = list(ast.decl().params())
        index = len(self.nodes)
        self.nodes.append({"id": index, **node})
        self.ids[key] = index
        return index


def reify(il, decls):
    values = []
    for index, node in enumerate(il["nodes"]):
        if node["id"] != index:
            raise ValueError("IL nodes are not in topological order")
        op = node["op"]
        args = [values[item] for item in node.get("args", [])]
        params = node.get("params", [])
        if op == "bool":
            value = z3.BoolVal(node["value"])
        elif op == "bv":
            value = z3.BitVecVal(node["value"], int(node["sort"][2:]))
        elif op == "input":
            value = decls[node["name"]]
        elif op == "=":
            value = args[0] == args[1]
        elif op == "if":
            value = z3.If(*args)
        elif op in ("bvadd", "bvmul", "bvor", "bvand", "bvxor"):
            operation = {"bvadd": lambda a, b: a + b,
                         "bvmul": lambda a, b: a * b,
                         "bvor": lambda a, b: a | b,
                         "bvand": lambda a, b: a & b,
                         "bvxor": lambda a, b: a ^ b}[op]
            value = args[0]
            for item in args[1:]:
                value = operation(value, item)
        elif op == "bvsub":
            value = args[0] - args[1]
        elif op == "bvnot":
            value = ~args[0]
        elif op in ("bvule", "bvsle", "bvult", "bvslt"):
            value = {"bvule": z3.ULE, "bvsle": lambda a, b: a <= b,
                     "bvult": z3.ULT, "bvslt": lambda a, b: a < b}[op](*args)
        elif op == "select":
            value = z3.Select(*args)
        elif op == "store":
            value = z3.Store(*args)
        elif op == "extract":
            value = z3.Extract(params[0], params[1], args[0])
        elif op == "concat":
            value = z3.Concat(*args)
        elif op == "and":
            value = z3.And(*args)
        elif op == "or":
            value = z3.Or(*args)
        elif op == "not":
            value = z3.Not(args[0])
        elif op in ("zero_extend", "sign_extend"):
            value = (z3.ZeroExt if op == "zero_extend" else z3.SignExt)(
                params[0], args[0])
        elif op in ("bvshl", "bvlshr", "bvashr"):
            value = {"bvshl": lambda a, b: a << b,
                     "bvlshr": z3.LShR,
                     "bvashr": lambda a, b: a >> b}[op](*args)
        else:
            raise ValueError(f"unsupported IL operation {op}")
        if sort_name(value.sort()) != node["sort"]:
            raise ValueError(f"IL sort changed at node {index}")
        values.append(value)
    return values


def source_roots(case, decls):
    roots = []
    for term in case["condition"]:
        roots.append(({"kind": "Guard"}, expression(term, "Bool", decls)))
    for item in case["reads"]:
        roots.append(({"kind": "ReadAddress", "pc": item["pc"],
                       "width": item["width"],
                       "memory_version": item.get("memory_version", "unknown")},
                      expression(item["address"], "BV64", decls)))
    for order, item in enumerate(case["effects"]):
        if item["kind"] != "Write":
            raise ValueError("unsupported frozen native effect")
        shared = {"pc": item["pc"], "width": item["width"], "order": order,
                  "memory_version_before": item.get("memory_version_before", "unknown"),
                  "memory_version_after": item.get("memory_version_after", "unknown")}
        roots.append(({"kind": "WriteAddress", **shared},
                      expression(item["address"], "BV64", decls)))
        roots.append(({"kind": "WriteValue", **shared},
                      expression(item["value"], f"BV{item['width'] * 8}", decls)))
    for group in ("outputs", "derived_outputs"):
        for item in case[group]:
            roots.append(({"kind": "Output", "name": item["name"],
                           "group": group, "binding": item["observed_binding"]},
                          expression(item["expression"], item["sort"], decls)))
    roots.append(({"kind": "Successor"},
                  expression(case["successor"], "BV64", decls)))
    return roots


def equivalent(left, right):
    solver = z3.Solver()
    solver.set(timeout=15000)
    solver.add(left != right)
    return str(solver.check())


def convert(case):
    decls = declarations(case)
    source = source_roots(case, decls)
    builder = Builder(case["interface"]["inputs"])
    roots = [{**meta, "node": builder.add(ast)} for meta, ast in source]
    il = {"schema_version": "typed-native-ast-il-v1",
          "engine": case["engine"], "native_identity": case["identity"],
          "interface": case["interface"], "preconditions": case["preconditions"],
          "nodes": builder.nodes, "roots": roots,
          "scope": "complete frozen scalar transition AST; no source-level call or exception inference"}
    restored = reify(il, decls)
    verdicts = [equivalent(ast, restored[meta["node"]])
                for meta, ast in zip(roots, (term for _, term in source))]
    if any(verdict != "unsat" for verdict in verdicts):
        raise ValueError(f"native AST to IL differs: {verdicts}")
    mutated = deepcopy(il)
    successor = next(root for root in mutated["roots"] if root["kind"] == "Successor")
    original_node = successor["node"]
    original = next(term for meta, term in source if meta["kind"] == "Successor")
    one = len(mutated["nodes"])
    mutated["nodes"].append({"id": one, "op": "bv", "sort": "BV64", "value": 1})
    successor["node"] = len(mutated["nodes"])
    mutated["nodes"].append({"id": successor["node"], "op": "bvadd",
                             "sort": "BV64", "args": [original_node, one]})
    if equivalent(original, reify(mutated, decls)[successor["node"]]) != "sat":
        raise ValueError("changed native successor escaped IL equivalence check")
    return il, {"engine": case["engine"], "source_native_steps":
                case["identity"]["native_steps"],
                "typed_nodes": len(il["nodes"]), "roots_checked": len(roots),
                "guards": len(case["condition"]), "reads": len(case["reads"]),
                "ordered_writes": len(case["effects"]),
                "outputs": len(case["outputs"]) + len(case["derived_outputs"]),
                "all_root_equivalence": "unsat",
                "changed_successor_equivalence": "sat"}


def main():
    common = json.loads(SOURCE.read_text())
    long_common = json.loads(LONG_SOURCE.read_text())
    if common["schema_version"] != "common-observed-transition-v1":
        raise ValueError("frozen common native summary changed")
    if long_common["schema_version"] != "common-observed-transition-v1" or \
            len(long_common["cases"]) != 1:
        raise ValueError("frozen long-string native summary changed")
    cases = []
    metrics = []
    selected = [(SOURCE.name, index, common["cases"][index])
                for index in CASE_INDICES]
    selected.append((LONG_SOURCE.name, 0, long_common["cases"][0]))
    for filename, index, native_case in selected:
        il, metric = convert(native_case)
        il["source_summary"] = filename
        il["source_case_index"] = index
        metric["source_summary"] = filename
        cases.append(il)
        metrics.append(metric)
    source_hashes = {path.name: sha256(path.read_bytes()).hexdigest()
                     for path in (SOURCE, LONG_SOURCE)}
    OUTPUT.write_text(json.dumps({"schema_version": "typed-native-ast-il-bundle-v1",
        "source_summaries_sha256": source_hashes,
        "cases": cases}, indent=2) + "\n")
    RESULT.write_text(json.dumps({"schema_version": 1,
        "il_sha256": sha256(OUTPUT.read_bytes()).hexdigest(),
        "source_summaries_sha256": source_hashes,
        "cases": metrics,
        "limits": ["SMT equivalence checks the typed IL against frozen P-code terms",
                   "source P-code proof and target applicability remain separate evidence",
                   "native call/exception semantics are not reduced by this translator",
                   "unknown memory alias and missing path branches remain unknown"]},
        indent=2) + "\n")
    print(json.dumps(metrics))


if __name__ == "__main__":
    main()
