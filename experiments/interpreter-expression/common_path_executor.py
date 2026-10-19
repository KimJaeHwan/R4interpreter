"""Small engine-neutral node sequencer for a bounded native path IL.

Handlers must consume the previous computed state/memory and return the next.
The sequencer never initializes memory or fills an unsupported node from a
trace. Unknown is a result, not a successful empty transition.
"""
from __future__ import annotations


def execute(nodes, initial, handlers, *, expected_end):
    if (not nodes or nodes[0]["begin"] != 0 or
            nodes[-1]["end_exclusive"] != expected_end):
        return {"status": "unknown(incomplete node partition)", "node": None}
    state = initial
    certificates = []
    for index, node in enumerate(nodes):
        if index and (nodes[index - 1]["end_exclusive"] != node["begin"] or
                      nodes[index - 1]["exit_successor"] != node["entry_pc"]):
            return {"status": "unknown(node partition or successor gap)",
                    "node": node["id"]}
        handler = handlers.get(node["op"])
        if handler is None:
            return {"status": "unknown(unsupported node operation)",
                    "node": node["id"]}
        next_state, evidence, reason = handler(node, state)
        if reason is not None:
            return {"status": f"unknown({reason})", "node": node["id"]}
        if next_state is None or evidence is None or not isinstance(evidence, dict):
            return {"status": "unknown(handler supplied no computed transition)",
                    "node": node["id"]}
        certificates.append({"node": node["id"], "op": node["op"], **evidence})
        state = next_state
    return {"status": "bounded_path_applied", "nodes_applied": len(nodes),
            "certificates": certificates, "_state": state}
