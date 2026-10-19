/* Controlled Lua 5.4 long-string allocation failure, GC release, and retry. */
#include <inttypes.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lua.h"
#include "lauxlib.h"

enum { CAPACITY = 160, EVENTS = 8 };
_Alignas(16) static unsigned char storage[CAPACITY];
static unsigned live, generation, scoped, errors, event_count;
static size_t target_request, live_extent;
static size_t retry_length = 96;
static struct Event {
    const char *kind;
    unsigned generation, before, after;
    size_t requested;
    uintptr_t pointer;
} events[EVENTS];

static void record(const char *kind, unsigned before, size_t size, void *pointer) {
    if (event_count >= EVENTS) { errors++; return; }
    events[event_count++] = (struct Event){kind, generation, before, live,
                                          size, (uintptr_t)pointer};
}

static void *allocator(void *unused, void *pointer, size_t old_size, size_t size) {
    (void)unused;
    if (pointer == storage) {
        if (size || !live || old_size != live_extent) { errors++; return NULL; }
        unsigned before = live;
        live = 0;
        live_extent = 0;
        record("Free", before, old_size, pointer);
        return NULL;
    }
    if (size == 0) { free(pointer); return NULL; }
    if (scoped && pointer == NULL && size == target_request) {
        unsigned before = live;
        if (live) {
            record("AllocationFailed", before, size, NULL);
            return NULL;
        }
        generation++;
        live = 1;
        live_extent = size;
        record("Allocate", before, size, storage);
        return storage;
    }
    return realloc(pointer, size);
}

static int push_target(lua_State *L) {
    unsigned id = (unsigned)lua_tointeger(L, lua_upvalueindex(1));
    size_t length = id == 0 ? 80 : retry_length;
    char data[96];
    for (size_t i = 0; i < length; i++) data[i] = 'A' + (id + i * 7) % 26;
    target_request = 24 + length + 1;
    scoped = 1;
    lua_pushlstring(L, data, length);
    scoped = 0;
    return 1;
}

static int attempt(lua_State *L, unsigned id, int expected_status) {
    lua_pushinteger(L, id);
    lua_pushcclosure(L, push_target, 1);
    int status = lua_pcall(L, 0, 1, 0);
    scoped = 0; /* A failed protected call long-jumps over the callback reset. */
    if (status != expected_status) { errors++; return status; }
    if (status == LUA_OK) {
        size_t length;
        const char *data = lua_tolstring(L, -1, &length);
        if (!data || length != (id == 0 ? 80u : retry_length) ||
                (uintptr_t)data != (uintptr_t)storage + 24) errors++;
    }
    return status;
}

int main(int argc, char **argv) {
    if (argc > 2) return 2;
    if (argc == 2) {
        char *end = NULL;
        unsigned long requested_length = strtoul(argv[1], &end, 10);
        if (!end || *end || requested_length < 94 || requested_length > 96)
            return 2;
        retry_length = requested_length;
    }
    lua_State *L = lua_newstate(allocator, NULL);
    if (!L) return 2;
    if (getenv("R4_TRACE_STOP")) raise(SIGSTOP);
    lua_gc(L, LUA_GCSTOP);
    attempt(L, 0, LUA_OK); /* slot 0, generation 1 */
    attempt(L, 1, LUA_ERRMEM); /* slot occupied; previous root still exists */
    if (lua_gettop(L) != 2 || !live || generation != 1) errors++;
    lua_settop(L, 0);
    lua_gc(L, LUA_GCCOLLECT);
    if (live) errors++;
    attempt(L, 1, LUA_OK); /* same address, generation 2, larger extent */
    lua_settop(L, 0);
    lua_gc(L, LUA_GCCOLLECT);
    if (live) errors++;
    lua_close(L);
    printf("{\"type\":\"meta\",\"version\":504,\"pool_base\":%" PRIuPTR
           ",\"slots\":1,\"capacity\":160,\"alignment\":16,"
           "\"retry_length\":%zu}\n", (uintptr_t)storage, retry_length);
    for (unsigned i = 0; i < event_count; i++) {
        struct Event *e = &events[i];
        printf("{\"type\":\"event\",\"sequence\":%u,\"kind\":\"%s\","
               "\"generation\":%u,\"live_before\":%u,\"live_after\":%u,"
               "\"requested\":%zu,\"pointer\":%" PRIuPTR "}\n",
               i, e->kind, e->generation, e->before, e->after,
               e->requested, e->pointer);
    }
    printf("{\"type\":\"result\",\"errors\":%u,\"final_live\":%u,"
           "\"final_generation\":%u}\n", errors, live, generation);
    return errors ? 1 : 0;
}
