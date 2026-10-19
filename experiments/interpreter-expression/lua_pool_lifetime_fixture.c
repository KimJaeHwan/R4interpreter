/* Controlled Lua 5.4 allocator experiment. Only long-string reservations in
 * storage belong to this fixture; other Lua allocations use libc malloc. */
#include <inttypes.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lua.h"

enum { SLOTS = 4, CAPACITY = 128, LENGTH = 80, EVENTS = 32 };
struct PoolState { uint64_t live, generation[SLOTS]; };
struct Event {
    const char *kind;
    uint64_t slot, generation, before, after, requested, pointer;
};
struct Object {
    uint64_t pointer, data, slot, generation, length, checksum;
};
_Alignas(16) static unsigned char storage[SLOTS][CAPACITY];
static struct PoolState pool_state;
static struct Event events[EVENTS];
static struct Object objects[3];
static unsigned event_count, object_count, errors, scoped, target_calls;
static size_t target_request;

/* Same ABI and state layout as the CPython helper, lifted separately here. */
__attribute__((noinline)) int r4_pool_transition(struct PoolState *s,
                                                uint64_t slot, uint64_t op) {
    if (slot >= SLOTS) return 0;
    uint64_t bit = UINT64_C(1) << slot;
    if (op == 1) {
        if ((s->live & bit) || s->generation[slot] == UINT64_MAX) return 0;
        s->generation[slot] += 1;
        s->live |= bit;
        return 1;
    }
    if (op == 2) {
        if (!(s->live & bit)) return 0;
        s->live &= ~bit;
        return 1;
    }
    return 0;
}

static int slot_of(void *pointer) {
    uintptr_t p = (uintptr_t)pointer, base = (uintptr_t)storage;
    if (p < base || p >= base + sizeof(storage)) return -1;
    if ((p - base) % CAPACITY) return -2;
    return (int)((p - base) / CAPACITY);
}

static void record(const char *kind, unsigned slot, size_t size,
                   uint64_t before, void *pointer) {
    if (event_count == EVENTS) { errors++; return; }
    events[event_count++] = (struct Event){kind, slot, pool_state.generation[slot],
        before, pool_state.live, size, (uintptr_t)pointer};
}

static void *allocator(void *ud, void *pointer, size_t osize, size_t nsize) {
    (void)ud;
    /* On allocation Lua may pass a type tag; on free it is the old extent. */
    int slot = pointer ? slot_of(pointer) : -1;
    if (slot == -2) { errors++; return NULL; }
    if (nsize == 0) {
        if (slot < 0) { free(pointer); return NULL; }
        if (osize != target_request) { errors++; return NULL; }
        uint64_t before = pool_state.live;
        if (!r4_pool_transition(&pool_state, slot, 2)) { errors++; return NULL; }
        record("Free", slot, osize, before, pointer);
        return NULL;
    }
    if (slot >= 0) { errors++; return NULL; } /* Unexpected pool realloc. */
    if (!scoped) return realloc(pointer, nsize);
    target_calls++;
    if (pointer || target_calls != 1 || nsize != target_request) {
        errors++;
        return NULL;
    }
    for (unsigned i = 0; i < SLOTS; i++) {
        if (!(pool_state.live & (UINT64_C(1) << i))) {
            uint64_t before = pool_state.live;
            if (!r4_pool_transition(&pool_state, i, 1)) { errors++; return NULL; }
            record("Allocate", i, nsize, before, storage[i]);
            return storage[i];
        }
    }
    errors++;
    return NULL;
}

static uint64_t checksum(const unsigned char *bytes, size_t length) {
    uint64_t result = UINT64_C(1469598103934665603);
    for (size_t i = 0; i < length; i++) result = (result ^ bytes[i]) * UINT64_C(1099511628211);
    return result;
}

static void push_target(lua_State *L, unsigned seed, unsigned index) {
    unsigned char input[LENGTH];
    for (unsigned i = 0; i < LENGTH; i++) input[i] = 'A' + (seed + i * 7 + index * 11) % 26;
    if (seed == 2 && index == 1) input[17] = 0;
    target_calls = 0;
    scoped = 1;
    const char *data = lua_pushlstring(L, (const char *)input, LENGTH);
    scoped = 0;
    size_t length = 0;
    const char *actual = lua_tolstring(L, -1, &length);
    if (!data || data != actual || length != LENGTH ||
            memcmp(actual, input, LENGTH) || target_calls != 1) { errors++; return; }
    /* The object-start offset is an observed fixed-build value, checked for
     * every string. The C data pointer itself is never treated as a GC root. */
    uintptr_t object = (uintptr_t)data - 24;
    int slot = slot_of((void *)object);
    if (slot < 0 || object_count == 3) { errors++; return; }
    objects[object_count++] = (struct Object){object, (uintptr_t)data, slot,
        pool_state.generation[slot], length, checksum((const unsigned char *)actual, length)};
}

int main(int argc, char **argv) {
    if (argc != 2 || strlen(argv[1]) != 1 || argv[1][0] < '0' || argv[1][0] > '2') return 2;
    unsigned seed = argv[1][0] - '0';
    target_request = 24 + LENGTH + 1;
    lua_State *L = lua_newstate(allocator, NULL);
    if (!L) return 3;
    if (getenv("R4_TRACE_STOP")) raise(SIGSTOP);
    lua_gc(L, LUA_GCSTOP);
    push_target(L, seed, 0);
    push_target(L, seed, 1);
    lua_copy(L, 2, 1); /* Drop only the first root. */
    lua_settop(L, 1);
    lua_gc(L, LUA_GCCOLLECT);
    if (pool_state.live != 2) errors++;
    push_target(L, seed, 2);
    if (object_count != 3 || objects[0].pointer != objects[2].pointer ||
            objects[0].generation + 1 != objects[2].generation) errors++;
    size_t retained_length = 0;
    const char *retained = lua_tolstring(L, 1, &retained_length);
    if (!retained || retained_length != LENGTH ||
            checksum((const unsigned char *)retained, retained_length) != objects[1].checksum) errors++;
    lua_settop(L, 0);
    lua_gc(L, LUA_GCCOLLECT);
    if (pool_state.live || event_count != 6 || object_count != 3) errors++;
    lua_close(L);
    printf("{\"type\":\"meta\",\"version\":504,\"seed\":%u,\"pool_base\":%" PRIuPTR
           ",\"slots\":4,\"capacity\":128,\"requested\":%zu,\"alignment\":16,\"initial_live\":0}\n",
           seed, (uintptr_t)storage, target_request);
    for (unsigned i = 0; i < event_count; i++) {
        struct Event *e = &events[i];
        printf("{\"type\":\"event\",\"sequence\":%u,\"kind\":\"%s\",\"slot\":%" PRIu64
               ",\"generation\":%" PRIu64 ",\"live_before\":%" PRIu64
               ",\"live_after\":%" PRIu64 ",\"requested\":%" PRIu64
               ",\"pointer\":%" PRIu64 "}\n", i, e->kind, e->slot,
               e->generation, e->before, e->after, e->requested, e->pointer);
    }
    for (unsigned i = 0; i < object_count; i++) {
        struct Object *o = &objects[i];
        printf("{\"type\":\"object\",\"pointer\":%" PRIu64 ",\"data\":%" PRIu64
               ",\"slot\":%" PRIu64 ",\"generation\":%" PRIu64 ",\"length\":%" PRIu64
               ",\"checksum\":%" PRIu64 "}\n", o->pointer, o->data,
               o->slot, o->generation, o->length, o->checksum);
    }
    printf("{\"type\":\"result\",\"errors\":%u,\"final_live\":%" PRIu64 "}\n",
           errors, pool_state.live);
    return errors ? 1 : 0;
}
