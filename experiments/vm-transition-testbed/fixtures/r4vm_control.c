/* Separate CALL/RET fixture; the archived r4vm.c ELF and P-code stay frozen.
 * The analyzer receives the built ELF and .r4vm programs, not this source.
 */
#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { SLOT_COUNT = 4, MAX_WORDS = 32, MAX_STEPS = 64, MAX_CALL_DEPTH = 4,
       TAG_INTEGER = 3 };
enum {
    OP_MOVE = 0x18, OP_MOVE_IMMEDIATE = 0x19, OP_ADD_IMMEDIATE = 0x31,
    OP_SUB_IMMEDIATE = 0x37, OP_XOR_IMMEDIATE = 0x42, OP_SET_TAG = 0x4a,
    OP_OPAQUE_CALL = 0x60, OP_BRANCH_ZERO = 0x70,
    OP_BRANCH_NONZERO = 0x71, OP_CALL = 0x72, OP_RETURN = 0x73,
    OP_JUMP = 0x74, OP_HALT = 0x7e
};

typedef struct {
    uint64_t value;
    uint8_t tag;
} Slot;

typedef struct {
    uint8_t slot;
    uint64_t value;
    uint8_t tag;
} Write;

static int64_t signed_bits(uint64_t value) {
    int64_t result;
    memcpy(&result, &value, sizeof(result));
    return result;
}

__attribute__((noinline)) static uint64_t opaque_add(uint64_t value, int8_t increment) {
    volatile uint64_t retained = value;
    return retained + (uint64_t)(int64_t)increment;
}

static void output(const char *status, int has_result, uint64_t result, int pc,
                   const Write *writes, size_t count) {
    printf("{\"status\":\"%s\",\"result\":", status);
    if (has_result) printf("\"%" PRId64 "\"", signed_bits(result));
    else printf("null");
    printf(",\"pc\":%d,\"writes\":[", pc);
    for (size_t i = 0; i < count; ++i) {
        if (i) putchar(',');
        printf("{\"slot\":%u,\"value\":\"%" PRId64 "\",\"tag\":%u}",
               writes[i].slot, signed_bits(writes[i].value), writes[i].tag);
    }
    puts("]}");
}

__attribute__((noinline)) static void execute(const uint8_t *bytes, int count, uint64_t input) {
    Slot slots[SLOT_COUNT] = {{0}};
    Write writes[MAX_STEPS] = {{0}};
    size_t write_count = 0;
    int pc = 0;
    int returns[MAX_CALL_DEPTH] = {0};
    int depth = 0;
    slots[0].value = input;
    slots[0].tag = TAG_INTEGER;

    for (int step = 0; step < MAX_STEPS; ++step) {
        if (pc < 0 || pc >= count) {
            output("pc_out_of_bounds", 0, 0, pc, writes, write_count);
            return;
        }
        const uint8_t *word = bytes + 8 + pc * 4;
        uint8_t op = word[0], dst = word[1], src = word[2];
        int8_t imm = (int8_t)word[3];
        ++pc;
        if (dst >= SLOT_COUNT || src >= SLOT_COUNT) {
            output("bad_slot", 0, 0, pc, writes, write_count);
            return;
        }
        if (op == OP_CALL) {
            if (depth == MAX_CALL_DEPTH) {
                output("call_overflow", 0, 0, pc, writes, write_count);
                return;
            }
            returns[depth++] = pc;
            pc = imm;
            continue;
        }
        if (op == OP_RETURN) {
            if (depth == 0) {
                output("call_underflow", 0, 0, pc, writes, write_count);
                return;
            }
            pc = returns[--depth];
            continue;
        }
        if (op == OP_JUMP) {
            pc = imm;
            continue;
        }
        switch (op) {
        case OP_MOVE:
            slots[dst] = slots[src];
            break;
        case OP_MOVE_IMMEDIATE:
            slots[dst].value = (uint64_t)(int64_t)imm;
            slots[dst].tag = TAG_INTEGER;
            break;
        case OP_SET_TAG:
            slots[dst].tag = (uint8_t)imm;
            break;
        case OP_ADD_IMMEDIATE:
        case OP_SUB_IMMEDIATE:
        case OP_XOR_IMMEDIATE:
        case OP_OPAQUE_CALL:
            if (slots[src].tag != TAG_INTEGER) {
                output("type_error", 0, 0, pc, writes, write_count);
                return;
            }
            if (op == OP_ADD_IMMEDIATE)
                slots[dst].value = slots[src].value + (uint64_t)(int64_t)imm;
            else if (op == OP_SUB_IMMEDIATE)
                slots[dst].value = slots[src].value - (uint64_t)(int64_t)imm;
            else if (op == OP_XOR_IMMEDIATE)
                slots[dst].value = slots[src].value ^ (uint64_t)(int64_t)imm;
            else
                slots[dst].value = opaque_add(slots[src].value, imm);
            slots[dst].tag = TAG_INTEGER;
            break;
        case OP_BRANCH_ZERO:
        case OP_BRANCH_NONZERO:
            if (slots[src].tag != TAG_INTEGER) {
                output("type_error", 0, 0, pc, writes, write_count);
                return;
            }
            if ((slots[src].value == 0) == (op == OP_BRANCH_ZERO)) pc += imm;
            continue;
        case OP_HALT:
            if (slots[src].tag != TAG_INTEGER) {
                output("type_error", 0, 0, pc, writes, write_count);
                return;
            }
            output("ok", 1, slots[src].value, pc, writes, write_count);
            return;
        default:
            output("bad_opcode", 0, 0, pc, writes, write_count);
            return;
        }
        writes[write_count++] = (Write){dst, slots[dst].value, slots[dst].tag};
    }
    output("step_limit", 0, 0, pc, writes, write_count);
}

int main(int argc, char **argv) {
    if (argc != 3) return 2;
    errno = 0;
    char *end = NULL;
    intmax_t number = strtoimax(argv[2], &end, 10);
    if (errno || end == argv[2] || *end != '\0' || number < INT64_MIN || number > INT64_MAX)
        return 2;
    FILE *stream = fopen(argv[1], "rb");
    if (!stream) return 2;
    uint8_t bytes[8 + MAX_WORDS * 4 + 1] = {0};
    size_t size = fread(bytes, 1, sizeof(bytes), stream);
    int read_error = ferror(stream);
    fclose(stream);
    if (read_error || size < 8 || memcmp(bytes, "R4VM", 4) || bytes[4] != 1 ||
        bytes[5] > MAX_WORDS || bytes[6] != 0 || bytes[7] != 0 ||
        size != 8 + 4 * (size_t)bytes[5])
        return 2;
    execute(bytes, bytes[5], (uint64_t)(int64_t)number);
    return 0;
}
