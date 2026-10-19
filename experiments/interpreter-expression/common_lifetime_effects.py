"""Language-neutral lifetime effects composed beside native byte-memory effects.

The initial implementation uses finite, owned reservations. A resource is
identified by (domain_id, resource_id, generation), never by its address.
Input states are never mutated; an invalid transition raises LifetimeError.
"""
from copy import deepcopy


MAX_ADDRESS = 1 << 64
MAX_GENERATION = MAX_ADDRESS - 1
KINDS = {"Allocate", "Free", "AllocationFailed"}
EVIDENCE_MODES = {"native_refined", "observed"}


class LifetimeError(ValueError):
    pass


def digest(value):
    return (isinstance(value, str) and len(value) == 64 and
            all(character in "0123456789abcdef" for character in value))


def integer(value, minimum, maximum, name):
    if type(value) is not int or not minimum <= value <= maximum:
        raise LifetimeError(f"invalid {name}")
    return value


def resource_key(resource):
    return resource["domain_id"], resource["resource_id"]


def get_resource(state, domain_id, resource_id):
    matches = [resource for resource in state["resources"]
               if resource_key(resource) == (domain_id, resource_id)]
    if len(matches) != 1:
        raise LifetimeError("resource is not owned by this domain")
    return matches[0]


def validate_inventory(resources):
    seen = set()
    for item in resources:
        if any(not isinstance(item.get(name), str) or not item[name]
               for name in ("address_space_id", "domain_id", "resource_id")):
            raise LifetimeError("invalid resource identity")
        key = resource_key(item)
        if key in seen:
            raise LifetimeError("duplicate resource identity")
        seen.add(key)
        base = integer(item.get("base"), 0, MAX_ADDRESS - 1, "resource base")
        capacity = integer(item.get("capacity"), 1, MAX_ADDRESS - 1, "capacity")
        alignment = integer(item.get("alignment"), 1, MAX_ADDRESS - 1, "alignment")
        if (alignment & (alignment - 1) or base % alignment or
                base + capacity > MAX_ADDRESS):
            raise LifetimeError("misaligned or wrapping resource")
        generation = integer(item.get("generation"), 0, MAX_GENERATION, "generation")
        if type(item.get("live")) is not bool:
            raise LifetimeError("invalid live state")
        extent = integer(item.get("requested_extent"), 0, capacity,
                         "requested extent")
        if (item["live"] and (generation == 0 or extent == 0)) or (
                not item["live"] and extent != 0):
            raise LifetimeError("inconsistent initial lifetime")
    for index, left in enumerate(resources):
        for right in resources[index + 1:]:
            if (left["address_space_id"] == right["address_space_id"] and
                    left["base"] < right["base"] + right["capacity"] and
                    right["base"] < left["base"] + left["capacity"]):
                raise LifetimeError("overlapping owned reservations")


def initialize(resources, authority):
    """Admit a caller-supplied finite ownership contract, with its provenance."""
    if (authority.get("kind") != "static_reservations_v1" or
            not digest(authority.get("source_sha256")) or
            authority.get("initial_state") != "declared_reservations"):
        raise LifetimeError("missing static ownership authority")
    copied = deepcopy(resources)
    validate_inventory(copied)
    return {"schema_version": "common-lifetime-state-v1", "resources": copied,
            "authority": deepcopy(authority), "events": []}


def check_evidence(evidence, kind):
    if (not isinstance(evidence, dict) or
            evidence.get("mode") not in EVIDENCE_MODES or
            evidence.get("cutpoint") not in ("helper_return", "allocator_failure") or
            not digest(evidence.get("trace_sha256"))):
        raise LifetimeError("missing effect evidence")
    if kind == "AllocationFailed":
        if (evidence["mode"] != "observed" or
                evidence["cutpoint"] != "allocator_failure" or
                evidence.get("native_refinement_sha256") is not None):
            raise LifetimeError("failure has unsupported native proof claim")
    elif (evidence["mode"] != "native_refined" or
          evidence["cutpoint"] != "helper_return" or
          not digest(evidence.get("native_summary_sha256")) or
          not digest(evidence.get("native_refinement_sha256")) or
          evidence.get("preconditions_checked") is not True or
          evidence.get("binding") != "observed"):
        raise LifetimeError("successful effect lacks native and binding evidence")


def apply_effect(state, request, evidence):
    """Atomically return (new_state, canonical_effect). No byte memory is changed."""
    if state.get("schema_version") != "common-lifetime-state-v1":
        raise LifetimeError("unsupported lifetime state")
    validate_inventory(state["resources"])
    kind = request.get("kind")
    if kind not in KINDS:
        raise LifetimeError("unsupported lifetime effect")
    check_evidence(evidence, kind)
    integer(request.get("requested_extent"), 1, MAX_ADDRESS - 1,
            "requested extent")
    updated = deepcopy(state)
    if kind == "AllocationFailed":
        if (not isinstance(request.get("domain_id"), str) or
                not request["domain_id"] or
                not isinstance(request.get("reason"), str) or
                not request["reason"] or
                request["domain_id"] not in
                {resource["domain_id"] for resource in updated["resources"]}):
            raise LifetimeError("failure has no owned domain or reason")
        canonical = {"kind": kind, "domain_id": request["domain_id"],
                     "requested_extent": request["requested_extent"],
                     "reason": request["reason"],
                     "lifetime_state_preserved": True}
    else:
        if (not isinstance(request.get("address_space_id"), str) or
                not isinstance(request.get("domain_id"), str) or
                not isinstance(request.get("resource_id"), str)):
            raise LifetimeError("missing resource identity")
        resource = get_resource(updated, request["domain_id"], request["resource_id"])
        address = integer(request.get("address"), 0, MAX_ADDRESS - 1,
                          "effect address")
        extent = request["requested_extent"]
        if (resource["address_space_id"] != request["address_space_id"] or
                address != resource["base"] or extent > resource["capacity"] or
                address + extent > MAX_ADDRESS or
                address % resource["alignment"]):
            raise LifetimeError("effect violates resource extent or alignment")
        if kind == "Allocate":
            if resource["live"] or resource["generation"] == MAX_GENERATION:
                raise LifetimeError("resource occupied or generation overflow")
            for other in updated["resources"]:
                if (other is not resource and other["live"] and
                        other["address_space_id"] == resource["address_space_id"] and
                        address < other["base"] + other["requested_extent"] and
                        other["base"] < address + extent):
                    raise LifetimeError("allocation aliases a live resource")
            resource["generation"] += 1
            resource["live"] = True
            resource["requested_extent"] = extent
        else:
            generation = integer(request.get("generation"), 1, MAX_GENERATION,
                                 "object generation")
            if (not resource["live"] or generation != resource["generation"] or
                    extent != resource["requested_extent"]):
                raise LifetimeError("stale, free, or mismatched object")
            resource["live"] = False
            resource["requested_extent"] = 0
        canonical = {"kind": kind, "address_space_id": resource["address_space_id"],
                     "domain_id": resource["domain_id"],
                     "resource_id": resource["resource_id"],
                     "generation": resource["generation"],
                     "address": address, "requested_extent": extent,
                     "identity": [resource["domain_id"], resource["resource_id"],
                                  resource["generation"]]}
    canonical["evidence"] = deepcopy(evidence)
    updated["events"].append(canonical)
    return updated, canonical


def access(state, address_space_id, domain_id, resource_id, generation,
           offset=0, width=1):
    resource = get_resource(state, domain_id, resource_id)
    integer(generation, 1, MAX_GENERATION, "object generation")
    integer(offset, 0, MAX_ADDRESS - 1, "access offset")
    integer(width, 1, MAX_ADDRESS - 1, "access width")
    if (resource["address_space_id"] != address_space_id or
            not resource["live"] or resource["generation"] != generation or
            offset + width > resource["requested_extent"]):
        raise LifetimeError("stale or out-of-bounds object access")
    return resource["base"] + offset
