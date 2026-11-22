// Production m034 generator + shared policy, with OS/kernel execution seams.
#include <algorithm>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>
#include "kernel_module_kit_umbrella.h"
#include "icache_policy.h"

extern "C" long long maple_icache_execute_once();
namespace kernel_module { KModErr icache_invalidate_all_cpus(); }

namespace {
std::vector<uint8_t> captured;
long long execution_status;
uint64_t initial_output;
bool execution_throws;
int start_calls, end_calls, execute_calls;

struct FakeOps {
    maple_icache::Mask original{}, online_mask{};
    std::vector<std::string> events;
    long long save_error = 0, online_error = 0, restore_error = 0;
    long long execute_error = -19995;
    int bind_fail = -1, mismatch = -1, execute_fail = -1, throw_cpu = -1;
    int cpu = -1;
    bool restored_snapshot = false;
    FakeOps() {
        maple_icache::set(original, 1);
        maple_icache::set(original, 7);
        for (int n : {0, 2, 4}) maple_icache::set(online_mask, n);
    }
    long long save(maple_icache::Mask& out) noexcept {
        events.emplace_back("save"); out = original; return save_error;
    }
    long long online(maple_icache::Mask& out) {
        events.emplace_back("online"); out = online_mask; return online_error;
    }
    long long bind(int n) noexcept {
        events.push_back("bind:" + std::to_string(n)); cpu = n;
        return n == bind_fail ? maple_icache::kSetCpu : 0;
    }
    int current() noexcept {
        events.push_back("current:" + std::to_string(cpu));
        return cpu == mismatch ? -1 : cpu;
    }
    long long execute() {
        events.push_back("execute:" + std::to_string(cpu));
        if (cpu == throw_cpu) throw std::runtime_error("injected generator failure");
        return cpu == execute_fail ? execute_error : 0;
    }
    long long restore(const maple_icache::Mask& snapshot) noexcept {
        events.emplace_back("restore");
        restored_snapshot = std::memcmp(&snapshot, &original, sizeof(snapshot)) == 0;
        return restore_error;
    }
};

std::vector<std::string> prefix() { return {"save", "online"}; }
void visit(std::vector<std::string>& e, int cpu, bool current = true, bool execute = true) {
    e.push_back("bind:" + std::to_string(cpu));
    if (current) e.push_back("current:" + std::to_string(cpu));
    if (execute) e.push_back("execute:" + std::to_string(cpu));
}
int cases = 0, failed = 0;
void check(const std::string& name, bool passed) {
    ++cases;
    if (!passed) { ++failed; std::cerr << "FAIL " << name << '\n'; }
}
void policy_case(const std::string& name, FakeOps o, long long expected,
                 std::vector<std::string> events, bool restore = true) {
    if (restore) events.emplace_back("restore");
    const auto result = maple_icache::run(o);
    check(name, result == expected && o.events == events && o.restored_snapshot == restore);
}
void policy_tests() {
    auto full = prefix();
    for (int cpu : {0, 2, 4}) visit(full, cpu);
    policy_case("all online CPUs, not original affinity subset", FakeOps{}, 0, full);
    FakeOps o; o.save_error = maple_icache::kGetCpu;
    policy_case("save failure makes no mutation", o, maple_icache::kGetCpu, {"save"}, false);
    o = FakeOps{}; o.online_error = maple_icache::kGetCpu;
    policy_case("online read failure restores", o, maple_icache::kGetCpu, prefix());
    o = FakeOps{}; o.online_mask = {};
    policy_case("empty online mask restores", o, maple_icache::kGetCpu, prefix());
    for (int cpu : {0, 2}) {
        o = FakeOps{}; o.bind_fail = cpu;
        auto e = prefix(); if (cpu == 2) visit(e, 0); visit(e, cpu, false, false);
        policy_case("bind failure " + std::to_string(cpu), o, maple_icache::kSetCpu, e);
        o = FakeOps{}; o.mismatch = cpu;
        e = prefix(); if (cpu == 2) visit(e, 0); visit(e, cpu, true, false);
        policy_case("current mismatch " + std::to_string(cpu), o, maple_icache::kSetCpu, e);
        o = FakeOps{}; o.execute_fail = cpu;
        e = prefix(); if (cpu == 2) visit(e, 0); visit(e, cpu);
        policy_case("execute failure " + std::to_string(cpu), o, o.execute_error, e);
        o = FakeOps{}; o.throw_cpu = cpu;
        policy_case("generator throw " + std::to_string(cpu), o, maple_icache::kAsm, e);
    }
    o = FakeOps{}; o.restore_error = maple_icache::kSetCpu;
    policy_case("restore failure after success", o, maple_icache::kSetCpu, full);
    o.execute_fail = 0;
    auto first = prefix(); visit(first, 0);
    policy_case("restore failure precedes execution error", o, maple_icache::kSetCpu, first);
    o.execute_fail = -1; o.throw_cpu = 0;
    policy_case("restore failure precedes generator throw", o, maple_icache::kSetCpu, first);
    o = FakeOps{}; o.execute_fail = 0; o.execute_error = 0x100000007LL;
    policy_case("execution error remains i64", o, o.execute_error, first);
    o = FakeOps{}; o.online_mask = {}; maple_icache::set(o.online_mask, 1023);
    auto last = prefix(); visit(last, 1023);
    policy_case("CPU 1023 boundary", o, 0, last);

    for (const auto* text : {"0", "0-7\n", "0,2,5-7,1023\n"}) {
        maple_icache::Mask mask{};
        const bool parsed = maple_icache::parse_online(text, mask);
        const bool exact = std::string(text) == "0" ? maple_icache::has(mask, 0) && !maple_icache::has(mask, 1)
            : (std::string(text) == "0-7\n" ? maple_icache::has(mask, 0) && maple_icache::has(mask, 7) && !maple_icache::has(mask, 8)
            : maple_icache::has(mask, 0) && !maple_icache::has(mask, 1) && maple_icache::has(mask, 2) && maple_icache::has(mask, 7) && maple_icache::has(mask, 1023));
        check(std::string("parse valid ") + text, parsed && exact);
    }
    for (const auto* text : {"", "1-", "3-2", "1024", "9999999999999999999", "1,\n", "1\n2", " 1", "1 ", "1,,2"}) {
        maple_icache::Mask mask{};
        check(std::string("reject invalid ") + text, !maple_icache::parse_online(text, mask));
    }
}
}

namespace kernel_module {
// Definitions use source slices extracted verbatim from the current production
// m025 TU. The runner wraps them only to count the original calls.
void production_frame_start(asmjit::a64::Assembler*);
void production_frame_end(asmjit::a64::Assembler*);
void arm64_module_asm_func_start(asmjit::a64::Assembler* a) {
    ++start_calls; production_frame_start(a);
}
void arm64_module_asm_func_end(asmjit::a64::Assembler* a) {
    ++end_calls; production_frame_end(a);
}
KModErr execute_kernel_asm_func(const std::vector<uint8_t>& bytes, uint64_t& output) {
    ++execute_calls; captured = bytes; initial_output = output;
    if (execution_throws) throw std::runtime_error("injected execution failure");
    output = 0xfedcba9876543210ULL;
    return static_cast<KModErr>(execution_status);
}
}

int main(int argc, char** argv) {
    if (argc > 1 && std::string(argv[1]) == "generator") {
        execution_status = argc > 2 ? std::stoll(argv[2]) : 0;
        const auto result = maple_icache_execute_once();
        std::cout << result << ' ' << initial_output << ' ' << start_calls << ' '
                  << end_calls << ' ' << execute_calls << ' ';
        for (auto byte : captured) std::cout << std::hex << std::setw(2)
            << std::setfill('0') << static_cast<unsigned>(byte);
        std::cout << '\n';
        return 0;
    }
    policy_tests();
    check("Android wrapper save failure reaches shared policy",
          kernel_module::icache_invalidate_all_cpus() == KModErr::ERR_MODULE_GET_CPU && execute_calls == 0);
    execution_throws = true;
    try { maple_icache_execute_once(); check("generator propagates execution exception", false); }
    catch (const std::runtime_error&) { check("generator propagates execution exception", true); }
    std::cout << cases << ' ' << failed << '\n';
    return failed ? 1 : 0;
}
