#define _GNU_SOURCE
#include <sched.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>

#define GET_CPU_ERROR (-19984LL)
#define SET_CPU_ERROR (-19983LL)
#define ASM_ERROR (-19990LL)
#define MAX_CPUS 1024
struct cpu_mask { unsigned char bits[128]; };
struct cache_state {
    struct cpu_mask saved;
    struct cpu_mask online;
    int cursor;
};
_Static_assert(sizeof(cpu_set_t) == sizeof(struct cpu_mask), "helper affinity ABI");
static int parse_cpu(const char **text, unsigned *out) {
    const char *p = *text;
    unsigned n = 0;
    if (*p < '0' || *p > '9') return 0;
    do {
        n = n * 10 + (unsigned)(*p++ - '0');
        if (n >= MAX_CPUS) return 0;
    } while (*p >= '0' && *p <= '9');
    *out = n;
    *text = p;
    return 1;
}
static int online_mask(struct cpu_mask *out) {
    char text[8192];
    long fd = syscall(__NR_openat, -100, "/sys/devices/system/cpu/online", 0x80000, 0);
    if (fd < 0) return 0;
    long n = syscall(__NR_read, fd, text, sizeof(text) - 1);
    char extra;
    long tail = n > 0 ? syscall(__NR_read, fd, &extra, 1) : -1;
    long closed = syscall(__NR_close, fd);
    if (n <= 0 || tail != 0 || closed != 0) return 0;
    text[n] = 0;
    const char *p = text;
    for (;;) {
        unsigned first, last;
        if (!parse_cpu(&p, &first)) return 0;
        last = first;
        if (*p == '-') {
            ++p;
            if (!parse_cpu(&p, &last) || last < first) return 0;
        }
        for (unsigned cpu = first; cpu <= last; ++cpu)
            out->bits[cpu / 8] |= (unsigned char)(1u << (cpu % 8));
        if (*p != ',') break;
        ++p;
    }
    if (*p == '\n') ++p;
    return *p == 0;
}
long long maplesu_helper_icache_begin(struct cache_state **out) {
    *out = 0;
    struct cache_state *state = malloc(sizeof(*state));
    if (!state) return ASM_ERROR;
    for (unsigned i = 0; i < sizeof(*state); ++i) ((unsigned char *)state)[i] = 0;
    if (sched_getaffinity(0, sizeof(state->saved), (cpu_set_t *)&state->saved) != 0 ||
        !online_mask(&state->online)) {
        free(state);
        return GET_CPU_ERROR;
    }
    *out = state;
    return 0;
}
long long maplesu_helper_icache_next(struct cache_state *state) {
    for (; state->cursor < MAX_CPUS; ++state->cursor) {
        int cpu = state->cursor;
        if (!(state->online.bits[cpu / 8] & (1u << (cpu % 8)))) continue;
        ++state->cursor;
        struct cpu_mask one = {{0}};
        one.bits[cpu / 8] = (unsigned char)(1u << (cpu % 8));
        if (sched_setaffinity(0, sizeof(one), (cpu_set_t *)&one) != 0) return SET_CPU_ERROR;
        __atomic_thread_fence(__ATOMIC_SEQ_CST);
        if (sched_getcpu() != cpu) return SET_CPU_ERROR;
        return 0;
    }
    return 1;
}
long long maplesu_helper_icache_finish(struct cache_state *state, long long error) {
    long long result = error;
    if (sched_setaffinity(0, sizeof(state->saved), (cpu_set_t *)&state->saved) != 0) {
        result = SET_CPU_ERROR;
    } else {
        struct cpu_mask actual = {{0}};
        __atomic_thread_fence(__ATOMIC_SEQ_CST);
        if (sched_getaffinity(0, sizeof(actual), (cpu_set_t *)&actual) != 0) {
            result = SET_CPU_ERROR;
        } else {
            for (unsigned i = 0; i < sizeof(actual); ++i)
                if (actual.bits[i] != state->saved.bits[i]) { result = SET_CPU_ERROR; break; }
        }
    }
    free(state);
    return result;
}

