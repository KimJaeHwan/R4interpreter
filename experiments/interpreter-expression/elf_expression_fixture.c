#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

__attribute__((noinline)) uint64_t add7(uint64_t x) { return x + 7; }

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    char *end = NULL;
    uint64_t x = strtoull(argv[1], &end, 0);
    if (*end != '\0') return 2;
    printf("%" PRIu64 "\n", add7(x));
    return 0;
}
