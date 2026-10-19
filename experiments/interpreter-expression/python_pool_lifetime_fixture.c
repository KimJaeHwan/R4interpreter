/* Public CPython C API declarations, pinned to the recorded 3.13 shared ABI.
 * The allocator wraps the installed allocator and owns only this static pool.
 * No Python object layout is used to implement allocation or release. */
#include <inttypes.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct _object PyObject;
typedef struct {
    void *ctx;
    void *(*malloc)(void *, size_t);
    void *(*calloc)(void *, size_t, size_t);
    void *(*realloc)(void *, void *, size_t);
    void (*free)(void *, void *);
} PyMemAllocatorEx;
extern void Py_Initialize(void);
extern int Py_FinalizeEx(void);
extern const char *Py_GetVersion(void);
extern PyObject *PyLong_FromLong(long);
extern long PyLong_AsLong(PyObject *);
extern void Py_DecRef(PyObject *);
extern PyObject *PyErr_Occurred(void);
extern void PyErr_Clear(void);
extern void PyMem_GetAllocator(int, PyMemAllocatorEx *);
extern void PyMem_SetAllocator(int, PyMemAllocatorEx *);

/* Two base-2^30 digits avoid CPython's compact-int freelist. */
enum { SLOTS = 4, CAPACITY = 32, REQUESTED = 32, EVENTS = 64 };
struct PoolState { uint64_t live; uint64_t generation[SLOTS]; };
struct Event {
    const char *kind;
    uint64_t slot, generation, before, after, requested, pointer;
};
struct Observation { uint64_t pointer, slot, generation, value, fields[4]; };
_Alignas(16) static unsigned char storage[SLOTS][CAPACITY];
static struct PoolState pool_state;
static struct Event history[EVENTS];
static struct Observation observations[8];
static unsigned event_count, observation_count, errors, target_calls, scoped;
static PyMemAllocatorEx original;

/* Native proof boundary: op=1 takes an exact slot; op=2 releases it.
 * Rejected transitions leave every state byte unchanged. */
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

static void record(const char *kind, uint64_t slot, uint64_t request,
                   uint64_t before, uint64_t pointer) {
    if (event_count >= EVENTS) { errors++; return; }
    struct Event *e = &history[event_count++];
    *e = (struct Event){kind, slot, slot < SLOTS ? pool_state.generation[slot] : 0,
                       before, pool_state.live, request, pointer};
}

/* -1 is external ownership, -2 is an invalid interior pool pointer. */
static int slot_of(void *pointer) {
    uintptr_t p = (uintptr_t)pointer, base = (uintptr_t)storage;
    if (p < base || p >= base + sizeof(storage)) return -1;
    if ((p - base) % CAPACITY) return -2;
    return (int)((p - base) / CAPACITY);
}

static void *wrapped_malloc(void *ctx, size_t size) {
    (void)ctx;
    if (!scoped) return original.malloc(original.ctx, size);
    target_calls++;
    if (target_calls != 1 || size != REQUESTED) { errors++; return NULL; }
    for (uint64_t slot = 0; slot < SLOTS; slot++) {
        if (!(pool_state.live & (UINT64_C(1) << slot))) {
            uint64_t before = pool_state.live;
            if (!r4_pool_transition(&pool_state, slot, 1)) { errors++; return NULL; }
            void *pointer = storage[slot];
            record("Allocate", slot, size, before, (uintptr_t)pointer);
            return pointer;
        }
    }
    record("AllocationFailed", SLOTS, size, pool_state.live, 0);
    /* Exception construction is delegated outside the target scope. */
    scoped = 0;
    return NULL;
}

static void *wrapped_calloc(void *ctx, size_t count, size_t size) {
    (void)ctx;
    if (scoped) { errors++; return NULL; }
    return original.calloc(original.ctx, count, size);
}

static void *wrapped_realloc(void *ctx, void *pointer, size_t size) {
    (void)ctx;
    if (slot_of(pointer) != -1 || scoped) { errors++; return NULL; }
    return original.realloc(original.ctx, pointer, size);
}

static void wrapped_free(void *ctx, void *pointer) {
    (void)ctx;
    int slot = slot_of(pointer);
    if (slot == -1) { original.free(original.ctx, pointer); return; }
    if (slot < 0) { errors++; return; }
    uint64_t before = pool_state.live;
    if (!r4_pool_transition(&pool_state, (uint64_t)slot, 2)) { errors++; return; }
    record("Free", (uint64_t)slot, REQUESTED, before, (uintptr_t)pointer);
}

static PyObject *make(long value, int expect_failure) {
    target_calls = 0;
    scoped = 1;
    PyObject *object = PyLong_FromLong(value);
    scoped = 0;
    if (expect_failure) {
        if (object || target_calls != 1 || !PyErr_Occurred()) errors++;
        if (object) Py_DecRef(object);
        PyErr_Clear();
        return NULL;
    }
    if (!object || target_calls != 1 || PyErr_Occurred()) {
        errors++; PyErr_Clear(); return object;
    }
    int slot = slot_of(object);
    if (slot < 0 || observation_count >= 8 || PyLong_AsLong(object) != value) {
        errors++; return object;
    }
    struct Observation *o = &observations[observation_count++];
    *o = (struct Observation){(uintptr_t)object, (uint64_t)slot,
                             pool_state.generation[slot], (uint64_t)value, {0}};
    memcpy(&o->fields[0], (unsigned char *)object, 8);
    memcpy(&o->fields[1], (unsigned char *)object + 8, 8);
    memcpy(&o->fields[2], (unsigned char *)object + 16, 8);
    memcpy(&o->fields[3], (unsigned char *)object + 24, 8);
    return object;
}

int main(int argc, char **argv) {
    long base = argc > 1 ? strtol(argv[1], NULL, 10) : 1073741824L;
    if (base < 1073741824L || base > 1074741824L) return 2;
    Py_Initialize();
    if (getenv("R4_TRACE_STOP")) raise(SIGSTOP);
    PyMem_GetAllocator(2, &original); /* PYMEM_DOMAIN_OBJ */
    PyMemAllocatorEx wrapper = {NULL, wrapped_malloc, wrapped_calloc,
                               wrapped_realloc, wrapped_free};
    PyMem_SetAllocator(2, &wrapper);
    PyObject *a = make(base, 0), *b = make(base + 1, 0);
    uintptr_t first_address = (uintptr_t)a;
    if (a) Py_DecRef(a);
    PyObject *c = make(base + 2, 0);
    if ((uintptr_t)c != first_address) errors++;
    PyObject *d = make(base + 3, 0), *e = make(base + 4, 0);
    make(base + 5, 1); /* Complete pool exhaustion, no new object identity. */
    if (b) Py_DecRef(b);
    if (c) Py_DecRef(c);
    if (d) Py_DecRef(d);
    if (e) Py_DecRef(e);
    target_calls = 0;
    scoped = 1;
    PyObject *cached = PyLong_FromLong(256);
    scoped = 0;
    if (!cached || target_calls || slot_of(cached) != -1) errors++;
    if (cached) Py_DecRef(cached);
    if (pool_state.live || event_count != 11 || observation_count != 5) errors++;
    /* Restore only after every pool-owned object was released. */
    PyMem_SetAllocator(2, &original);
    printf("{\"type\":\"meta\",\"version\":\"%.6s\",\"base_value\":%ld,"
           "\"pool_base\":%" PRIuPTR ",\"slots\":4,\"capacity\":32,"
           "\"requested\":32,\"alignment\":16,\"initial_live\":0}\n",
           Py_GetVersion(), base, (uintptr_t)storage);
    for (unsigned i = 0; i < event_count; i++) {
        struct Event *v = &history[i];
        printf("{\"type\":\"event\",\"sequence\":%u,\"kind\":\"%s\","
               "\"slot\":%" PRIu64 ",\"generation\":%" PRIu64 ","
               "\"live_before\":%" PRIu64 ",\"live_after\":%" PRIu64 ","
               "\"requested\":%" PRIu64 ",\"pointer\":%" PRIu64 "}\n",
               i, v->kind, v->slot, v->generation, v->before, v->after,
               v->requested, v->pointer);
    }
    for (unsigned i = 0; i < observation_count; i++) {
        struct Observation *o = &observations[i];
        printf("{\"type\":\"object\",\"pointer\":%" PRIu64 ",\"slot\":%" PRIu64
               ",\"generation\":%" PRIu64 ",\"value\":%" PRIu64
               ",\"refcount\":%" PRIu64 ",\"type_pointer\":%" PRIu64
               ",\"size_tag\":%" PRIu64 ",\"digit_low\":%" PRIu64
               ",\"digit_high\":%" PRIu64 "}\n",
               o->pointer, o->slot, o->generation, o->value,
               o->fields[0], o->fields[1], o->fields[2],
               o->fields[3] & UINT32_MAX, o->fields[3] >> 32);
    }
    printf("{\"type\":\"result\",\"errors\":%u,\"final_live\":%" PRIu64
           ",\"cached_path_pool_allocations\":%u}\n", errors,
           pool_state.live, target_calls);
    int final = Py_FinalizeEx();
    return errors || final < 0 ? 1 : 0;
}
