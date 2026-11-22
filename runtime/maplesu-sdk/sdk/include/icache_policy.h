// icache policy implementation.
//
#pragma once
#include <cstdint>

namespace maple_icache {
using Error = long long;
constexpr Error kGetCpu = -19984;
constexpr Error kSetCpu = -19983;
constexpr Error kAsm = -19990;
constexpr int kMaxCpus = 1024;
struct alignas(8) Mask { unsigned char bits[kMaxCpus / 8] = {}; };
inline void set(Mask& m, int n) { m.bits[n / 8] |= 1u << (n % 8); }
inline bool has(const Mask& m, int n) { return m.bits[n / 8] & (1u << (n % 8)); }

inline bool parse_cpu(const char*& p, int& cpu) {
    if (*p < '0' || *p > '9') return false;
    cpu = 0;
    do {
        cpu = cpu * 10 + (*p++ - '0');
        if (cpu >= kMaxCpus) return false;
    } while (*p >= '0' && *p <= '9');
    return true;
}

inline bool parse_online(const char* p, Mask& out) {
    out = Mask{};
    for (;;) {
        int first, last;
        if (!parse_cpu(p, first)) return false;
        last = first;
        if (*p == '-') {
            ++p;
            if (!parse_cpu(p, last) || last < first) return false;
        }
        for (int cpu = first; cpu <= last; ++cpu) set(out, cpu);
        if (*p != ',') break;
        ++p;
    }
    if (*p == '\n') ++p;
    return *p == '\0';
}

// Host seam and Android wrapper share this exact control flow. Ops::save/bind/
// restore are non-throwing syscalls; execute may throw while building SDK code.
template<class Ops> Error run(Ops& o) {
    Mask original{};
    Error result = o.save(original);
    if (result != 0) return result; // No mutation occurred without a snapshot.
    try {
        Mask online{};
        result = o.online(online);
        if (result == 0) {
            bool visited = false;
            for (int cpu = 0; cpu < kMaxCpus; ++cpu) {
                if (!has(online, cpu)) continue;
                visited = true;
                result = o.bind(cpu);
                if (result != 0) break;
                if (o.current() != cpu) { result = kSetCpu; break; }
                result = o.execute();
                if (result != 0) break;
            }
            if (!visited) result = kGetCpu;
        }
    } catch (...) {
        result = kAsm;
    }
    const Error restore_result = o.restore(original);
    // A known leaked affinity is more urgent than the preceding work error.
    return restore_result != 0 ? restore_result : result;
}
}
