/* Separate experiment: VM local frames and a computed call target. */
#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { SLOT_COUNT = 4, MAX_WORDS = 64, MAX_STEPS = 96,
       MAX_CALL_DEPTH = 4, TAG_INTEGER = 3 };
enum { OP_MOVE = 0x18, OP_MOVI = 0x19, OP_ADDI = 0x31,
       OP_SUBI = 0x37, OP_ANDI = 0x45, OP_BRZ = 0x70, OP_BRNZ = 0x71,
       OP_CALL = 0x72, OP_RET = 0x73, OP_JUMP = 0x74,
       OP_ICALL = 0x75, OP_HALT = 0x7e };
typedef struct { uint64_t value; uint8_t tag; } Slot;
typedef struct { Slot slots[SLOT_COUNT]; int return_pc; uint8_t return_slot; } Frame;
typedef struct { uint8_t slot; uint64_t value; uint8_t tag; } Write;

static int64_t signed_bits(uint64_t value) {
    int64_t result;
    memcpy(&result, &value, sizeof(result));
    return result;
}

__attribute__((noinline)) static void output(const char *status, int has_result,
        uint64_t result, int pc, const Write *writes, size_t count) {
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

__attribute__((noinline)) static void execute(const uint8_t *bytes, int count,
                                               uint64_t input) {
    Frame frames[MAX_CALL_DEPTH + 1] = {0};
    Write writes[MAX_STEPS] = {{0}};
    size_t write_count = 0;
    int pc = 0, depth = 0;
    frames[0].slots[0] = (Slot){input, TAG_INTEGER};
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
        Frame *frame = &frames[depth];
        if (op == OP_CALL || op == OP_ICALL) {
            if (depth == MAX_CALL_DEPTH) {
                output("call_overflow", 0, 0, pc, writes, write_count);
                return;
            }
            if (op == OP_ICALL && frame->slots[src].tag != TAG_INTEGER) {
                output("type_error", 0, 0, pc, writes, write_count);
                return;
            }
            int target = op == OP_CALL ? imm : (int)frame->slots[src].value;
            uint64_t argument = frame->slots[dst].value;
            uint8_t tag = frame->slots[dst].tag;
            frames[depth + 1] = (Frame){0};
            frames[depth + 1].return_pc = pc;
            frames[depth + 1].return_slot = dst;
            frames[++depth].slots[0] = (Slot){argument, tag};
            pc = target;
            continue;
        }
        if (op == OP_RET) {
            if (depth == 0) {
                output("call_underflow", 0, 0, pc, writes, write_count);
                return;
            }
            Slot returned = frame->slots[src];
            int return_pc = frame->return_pc;
            uint8_t return_slot = frame->return_slot;
            frames[--depth].slots[return_slot] = returned;
            writes[write_count++] = (Write){return_slot, returned.value, returned.tag};
            pc = return_pc;
            continue;
        }
        if (op == OP_JUMP) { pc = imm; continue; }
        if (op == OP_BRZ || op == OP_BRNZ) {
            if (frame->slots[src].tag != TAG_INTEGER) {
                output("type_error", 0, 0, pc, writes, write_count);
                return;
            }
            if ((frame->slots[src].value == 0) == (op == OP_BRZ)) pc += imm;
            continue;
        }
        if (op == OP_HALT) {
            if (frame->slots[src].tag != TAG_INTEGER) {
                output("type_error", 0, 0, pc, writes, write_count);
                return;
            }
            output("ok", 1, frame->slots[src].value, pc, writes, write_count);
            return;
        }
        if (op == OP_MOVE) frame->slots[dst] = frame->slots[src];
        else if (op == OP_MOVI) frame->slots[dst] = (Slot){(uint64_t)(int64_t)imm, TAG_INTEGER};
        else if (op == OP_ADDI || op == OP_SUBI || op == OP_ANDI) {
            if (frame->slots[src].tag != TAG_INTEGER) {
                output("type_error", 0, 0, pc, writes, write_count);
                return;
            }
            uint64_t amount = (uint64_t)(int64_t)imm;
            frame->slots[dst] = (Slot){op == OP_ADDI ? frame->slots[src].value + amount :
                                       op == OP_SUBI ? frame->slots[src].value - amount :
                                       frame->slots[src].value & amount, TAG_INTEGER};
        } else {
            output("bad_opcode", 0, 0, pc, writes, write_count);
            return;
        }
        writes[write_count++] = (Write){dst, frame->slots[dst].value,
                                         frame->slots[dst].tag};
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
        size != 8 + 4 * (size_t)bytes[5]) return 2;
    execute(bytes, bytes[5], (uint64_t)(int64_t)number);
    return 0;
}
