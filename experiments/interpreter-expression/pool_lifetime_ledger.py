"""A small ownership ledger for the explicitly scoped CPython object pool."""
from copy import deepcopy


class LedgerError(ValueError):
    pass


class PoolLedger:
    def __init__(self, meta):
        if (meta["slots"] != 4 or meta["capacity"] != 32 or
                meta["requested"] != 32 or meta["alignment"] != 16 or
                meta["initial_live"] != 0 or
                meta["pool_base"] % meta["alignment"] or
                meta["pool_base"] + meta["slots"] * meta["capacity"] > 1 << 64):
            raise LedgerError("unsupported pool geometry or initial state")
        self.meta = meta
        self.live = 0
        self.generations = [0] * meta["slots"]
        self.active = {}
        self.allocation_keys = set()
        self.sequence = 0
        self.failed_allocations = 0
        self.reuse = []

    def pointer(self, slot):
        if not isinstance(slot, int) or not 0 <= slot < self.meta["slots"]:
            raise LedgerError("slot outside pool")
        return self.meta["pool_base"] + slot * self.meta["capacity"]

    def access(self, pointer, generation, offset=0, width=1):
        base = self.meta["pool_base"]
        capacity = self.meta["capacity"]
        if (not isinstance(pointer, int) or pointer < base or
                pointer >= base + self.meta["slots"] * capacity or
                (pointer - base) % capacity or
                offset < 0 or width <= 0 or offset + width > capacity):
            raise LedgerError("invalid pointer or object extent")
        slot = (pointer - base) // capacity
        if (not isinstance(generation, int) or not 1 <= generation < 1 << 64 or
                slot not in self.active or self.active[slot] != generation):
            raise LedgerError("stale or unowned object generation")
        return slot

    def step(self, event):
        if event["sequence"] != self.sequence or event["live_before"] != self.live:
            raise LedgerError("incomplete or inconsistent event history")
        if event["requested"] != self.meta["requested"]:
            raise LedgerError("request differs from fixed slot extent")
        kind = event["kind"]
        slot = event["slot"]
        if kind == "AllocationFailed":
            if (self.live != (1 << self.meta["slots"]) - 1 or
                    slot != self.meta["slots"] or event["pointer"] != 0 or
                    event["generation"] != 0 or event["live_after"] != self.live):
                raise LedgerError("failure changed or misreported pool state")
            self.failed_allocations += 1
        elif kind in ("Allocate", "Free"):
            pointer = self.pointer(slot)
            if event["pointer"] != pointer:
                raise LedgerError("event pointer is not the slot base")
            bit = 1 << slot
            if kind == "Allocate":
                if self.live & bit or self.generations[slot] == (1 << 64) - 1:
                    raise LedgerError("occupied slot or generation overflow")
                self.generations[slot] += 1
                if event["generation"] != self.generations[slot]:
                    raise LedgerError("allocation generation mismatch")
                key = (slot, event["generation"])
                if key in self.allocation_keys:
                    raise LedgerError("duplicate object identity")
                if event["generation"] > 1:
                    self.reuse.append({"slot": slot, "pointer": pointer,
                                       "new_generation": event["generation"]})
                self.allocation_keys.add(key)
                self.active[slot] = event["generation"]
                self.live |= bit
            else:
                self.access(pointer, event["generation"])
                del self.active[slot]
                self.live &= ~bit
            if event["live_after"] != self.live:
                raise LedgerError("event state transition mismatch")
        else:
            raise LedgerError("unsupported event kind")
        self.sequence += 1


def verify_history(records, input_value):
    if records[0]["type"] != "meta" or records[-1]["type"] != "result":
        raise LedgerError("missing fixture boundaries")
    meta, result = records[0], records[-1]
    if (meta["base_value"] != input_value or meta["version"] != "3.13.5" or
            result["errors"] != 0 or result["cached_path_pool_allocations"] != 0):
        raise LedgerError("fixture or CPython ABI identity changed")
    events = [r for r in records if r["type"] == "event"]
    objects = [r for r in records if r["type"] == "object"]
    if len(events) != 11 or len(objects) != 5 or len(records) != 18:
        raise LedgerError("incomplete controlled fixture history")
    ledger = PoolLedger(meta)
    active_keys = set()
    for event in events:
        ledger.step(event)
        key = (event["slot"], event["generation"])
        if event["kind"] == "Allocate":
            active_keys.add(key)
        elif event["kind"] == "Free":
            active_keys.remove(key)
    if (ledger.live or active_keys or result["final_live"] or
            ledger.failed_allocations != 1 or len(ledger.reuse) != 1 or
            ledger.reuse[0]["slot"] != 0):
        raise LedgerError("pool lifecycle did not close")
    allocation_events = {(e["slot"], e["generation"]): e for e in events
                         if e["kind"] == "Allocate"}
    object_keys = [(o["slot"], o["generation"]) for o in objects]
    if (len(allocation_events) != len(objects) or
            len(set(object_keys)) != len(object_keys) or
            set(object_keys) != set(allocation_events)):
        raise LedgerError("missing constructed object")
    types = {o["type_pointer"] for o in objects}
    if len(types) != 1 or 0 in types:
        raise LedgerError("inconsistent observed PyLong type pointer")
    for index, obj in enumerate(objects):
        key = obj["slot"], obj["generation"]
        if (key not in allocation_events or
                obj["pointer"] != allocation_events[key]["pointer"] or
                obj["value"] != input_value + index or
                obj["refcount"] != 1 or obj["size_tag"] != 16 or
                obj["digit_low"] != obj["value"] & ((1 << 30) - 1) or
                obj["digit_high"] != obj["value"] >> 30):
            raise LedgerError("observed object does not match its lifetime")
    return ledger, {"events": len(events), "constructed_objects": len(objects),
                    "failed_allocations": ledger.failed_allocations,
                    "same_address_new_generation": ledger.reuse,
                    "final_live": ledger.live,
                    "observed_object_bytes": 32 * len(objects)}


def rejection_controls(records):
    events = [r for r in records if r["type"] == "event"]
    meta = records[0]
    probes = {}

    def reject(name, changed):
        try:
            ledger = PoolLedger(meta)
            for event in changed:
                ledger.step(event)
        except LedgerError as error:
            probes[name] = str(error)
            return
        raise LedgerError(f"invalid history admitted: {name}")

    changed = deepcopy(events)
    changed[1]["sequence"] += 1
    reject("missing_event", changed)
    changed = deepcopy(events)
    changed[0]["pointer"] += 1
    reject("interior_pointer", changed)
    changed = deepcopy(events)
    changed[0]["requested"] = 33
    reject("oversized_request", changed)
    changed = deepcopy(events)
    duplicate = deepcopy(events[0])
    duplicate.update(sequence=1, live_before=1, live_after=1, generation=2)
    reject("overlapping_allocation", [changed[0], duplicate])
    changed = deepcopy(events)
    changed.insert(3, deepcopy(events[2]))
    changed[3]["sequence"] = 3
    changed[3]["live_before"] = 2
    changed[3]["live_after"] = 2
    reject("double_release", changed[:4])
    changed = deepcopy(events)
    changed[3]["generation"] = 1
    reject("reuse_without_generation_increment", changed[:4])
    changed = deepcopy(events)
    changed[6]["live_after"] = 0
    reject("failure_changed_state", changed[:7])
    changed = deepcopy(events)
    changed[0]["live_after"] = 2
    reject("incorrect_live_mask", changed[:1])
    ledger = PoolLedger(meta)
    for event in events[:4]:
        ledger.step(event)
    try:
        ledger.access(events[0]["pointer"], events[0]["generation"])
    except LedgerError as error:
        probes["stale_generation_access"] = str(error)
    else:
        raise LedgerError("stale object identity admitted")
    try:
        ledger.access(ledger.pointer(3), None)
    except LedgerError as error:
        probes["inactive_slot_null_generation"] = str(error)
    else:
        raise LedgerError("inactive slot with null generation admitted")
    try:
        ledger.access(events[3]["pointer"], events[3]["generation"], offset=31, width=2)
    except LedgerError as error:
        probes["out_of_bounds_access"] = str(error)
    else:
        raise LedgerError("out-of-bounds object access admitted")
    overflow = PoolLedger(meta)
    overflow.generations[0] = (1 << 64) - 1
    try:
        overflow.step(events[0])
    except LedgerError as error:
        probes["generation_overflow"] = str(error)
    else:
        raise LedgerError("generation overflow admitted")
    changed_records = deepcopy(records)
    snapshots = [item for item in changed_records if item["type"] == "object"]
    snapshots[2]["slot"] = snapshots[0]["slot"]
    snapshots[2]["generation"] = snapshots[0]["generation"]
    snapshots[2]["pointer"] = snapshots[0]["pointer"]
    try:
        verify_history(changed_records, meta["base_value"])
    except LedgerError as error:
        probes["duplicate_object_snapshot"] = str(error)
    else:
        raise LedgerError("duplicate object snapshot admitted")
    return probes
