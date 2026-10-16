/* Single-step one entry of a fixed-address x86-64 ELF function.
 * Usage: trace START_HEX MAX_STEPS OUTPUT.csv PROGRAM [ARG ...]
 * This records registers, instruction addresses, and candidate 8-byte memory
 * words at RAX/RDX. It does not decode arbitrary memory operands or infer
 * value expressions.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

static void fail(const char *message) {
    perror(message);
    exit(1);
}

static int stopped(pid_t child) {
    int status = 0;
    if (waitpid(child, &status, 0) < 0) fail("waitpid");
    if (WIFEXITED(status)) {
        fprintf(stderr, "child exited: %d\n", WEXITSTATUS(status));
        return 0;
    }
    if (WIFSIGNALED(status)) {
        fprintf(stderr, "child signaled: %d\n", WTERMSIG(status));
        return 0;
    }
    if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP) {
        fprintf(stderr, "unexpected stop: %#x\n", status);
        return 0;
    }
    return 1;
}

static void peek_word(pid_t child, uint64_t address, char result[24]) {
    errno = 0;
    long value = ptrace(PTRACE_PEEKDATA, child, (void *)(uintptr_t)address, NULL);
    if (value == -1 && errno) snprintf(result, 24, "NA");
    else snprintf(result, 24, "%#lx", (unsigned long)value);
}

int main(int argc, char **argv) {
    if (argc < 5) {
        fprintf(stderr, "usage: %s START_HEX MAX_STEPS OUTPUT.csv PROGRAM [ARG ...]\n", argv[0]);
        return 2;
    }
    uint64_t start = strtoull(argv[1], NULL, 16);
    uint64_t limit = strtoull(argv[2], NULL, 10);
    FILE *out = fopen(argv[3], "w");
    if (!out) fail("fopen");
    pid_t child = fork();
    if (child < 0) fail("fork");
    if (child == 0) {
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) fail("PTRACE_TRACEME");
        execv(argv[4], argv + 4);
        fail("execv");
    }
    if (!stopped(child)) return 1;
    if (ptrace(PTRACE_SETOPTIONS, child, NULL, (void *)(uintptr_t)PTRACE_O_EXITKILL) < 0)
        fail("PTRACE_SETOPTIONS");
    errno = 0;
    long original = ptrace(PTRACE_PEEKTEXT, child, (void *)(uintptr_t)start, NULL);
    if (original == -1 && errno) fail("PTRACE_PEEKTEXT");
    long trap_word = (original & ~0xffL) | 0xccL;
    if (ptrace(PTRACE_POKETEXT, child, (void *)(uintptr_t)start,
               (void *)(uintptr_t)trap_word) < 0) fail("PTRACE_POKETEXT trap");
    if (ptrace(PTRACE_CONT, child, NULL, NULL) < 0) fail("PTRACE_CONT");
    if (!stopped(child)) return 1;
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, child, NULL, &regs) < 0) fail("PTRACE_GETREGS entry");
    if (regs.rip != start + 1) {
        fprintf(stderr, "unexpected breakpoint: %#llx\n", regs.rip);
        return 1;
    }
    if (ptrace(PTRACE_POKETEXT, child, (void *)(uintptr_t)start,
               (void *)(uintptr_t)original) < 0) fail("PTRACE_POKETEXT restore");
    regs.rip = start;
    if (ptrace(PTRACE_SETREGS, child, NULL, &regs) < 0) fail("PTRACE_SETREGS");
    errno = 0;
    long return_address = ptrace(PTRACE_PEEKDATA, child, (void *)(uintptr_t)regs.rsp, NULL);
    if (return_address == -1 && errno) fail("PTRACE_PEEKDATA return address");
    fprintf(out, "step,rip,next_rip,rax,rbx,rcx,rdx,rsi,rdi,rbp,rsp,r8,r9,r10,r11,r12,r13,r14,r15,eflags,mem_rax_before,mem_rax_after,mem_rdx_before,mem_rdx_after\n");
    uint64_t steps = 0;
    int returned = 0;
    for (; steps < limit; ++steps) {
        struct user_regs_struct before = regs;
        char mem_rax_before[24], mem_rax_after[24];
        char mem_rdx_before[24], mem_rdx_after[24];
        peek_word(child, before.rax, mem_rax_before);
        peek_word(child, before.rdx, mem_rdx_before);
        if (ptrace(PTRACE_SINGLESTEP, child, NULL, NULL) < 0) fail("PTRACE_SINGLESTEP");
        if (!stopped(child)) break;
        if (ptrace(PTRACE_GETREGS, child, NULL, &regs) < 0) fail("PTRACE_GETREGS step");
        peek_word(child, before.rax, mem_rax_after);
        peek_word(child, before.rdx, mem_rdx_after);
        fprintf(out, "%" PRIu64 ",%#llx,%#llx", steps, before.rip, regs.rip);
#define EMIT_REG(field) fprintf(out, ",%#llx", before.field)
        EMIT_REG(rax); EMIT_REG(rbx); EMIT_REG(rcx); EMIT_REG(rdx);
        EMIT_REG(rsi); EMIT_REG(rdi); EMIT_REG(rbp); EMIT_REG(rsp);
        EMIT_REG(r8); EMIT_REG(r9); EMIT_REG(r10); EMIT_REG(r11);
        EMIT_REG(r12); EMIT_REG(r13); EMIT_REG(r14); EMIT_REG(r15);
        EMIT_REG(eflags);
#undef EMIT_REG
        fprintf(out, ",%s,%s,%s,%s\n", mem_rax_before, mem_rax_after,
                mem_rdx_before, mem_rdx_after);
        if (regs.rip == (uint64_t)return_address) {
            returned = 1;
            ++steps;
            break;
        }
    }
    fflush(out);
    if (fclose(out) != 0) fail("fclose");
    fprintf(stderr, "trace: start=%#" PRIx64 " return=%#lx steps=%" PRIu64 " returned=%d\n",
            start, (unsigned long)return_address, steps, returned);
    if (ptrace(PTRACE_DETACH, child, NULL, NULL) < 0) fail("PTRACE_DETACH");
    int status = 0;
    if (waitpid(child, &status, 0) < 0) fail("waitpid after detach");
    if (!WIFEXITED(status)) return 1;
    return WEXITSTATUS(status);
}
