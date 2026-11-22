#pragma once
#include "kernel_payload_loader.h"
#include <algorithm>
#include <array>
#include <cassert>
#include <cstring>
#include <functional>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>
using namespace maplesu::module_policy;
namespace {
constexpr uint64_t kernel_base = 0xffff800040000000ULL;
const char* hook_names[] = {"sel_write_context", "sel_write_access", "selinux_setprocattr", "sel_open_handle_status",
    "sel_read_handle_status", "sel_mmap_handle_status", "sk_filter_trim_cap", "commit_creds", "__skb_try_recv_datagram"};
struct Io final : PolicyKernelIo {
    std::map<std::string, uint64_t> symbols;
    std::vector<std::string> events;
    std::vector<uint8_t> memory;
    std::map<uint64_t, std::array<uint8_t, 16>> native_bytes;
    uint64_t allocation = kernel_base;
    std::string missing, failed_call;
    int bad_hook = -1, bad_dispatch = -1;
    bool conflict = false, alias = false, bad_readback = false, prepare_error = false;
    uint64_t activation = 0;
    bool activation_enabled = false, activation_error = false;
    bool change_entry_after_prepare = false, prepared = false;
    int dynamic_enabled = 0;
    bool scs_patch_missing = false, scs_patch_error = false;
    bool scs_patch_extra_write = false;
    unsigned expected_scs_arguments = 2;
    bool alternatives_error = false;
    std::vector<uint32_t> scs_sites;
    unsigned hooks = 0, releases = 0, allocations = 0;
    std::function<void(const Io&)> inspect_prepare;
    std::string last_phase;
    void progress(std::string_view phase) noexcept override { last_phase = phase; }
    uint64_t lookup(const char* name) override {
        events.push_back(std::string("lookup:") + name);
        if (missing == name) return 0;
        if (alias && std::string(name) == hook_names[1]) return lookup(hook_names[0]);
        return symbols.emplace(name, 0xffff800020000000ULL + symbols.size() * 256).first->second;
    }
    uint64_t allocate(uint32_t size) override {
        ++allocations; events.emplace_back("allocate"); memory.resize(size); return allocation;
    }
    void release(uint64_t address) override {
        assert(address == allocation); ++releases; events.emplace_back("release");
    }
    void read(uint64_t address, std::span<uint8_t> bytes) override {
        if (auto found = native_bytes.find(address); found != native_bytes.end()) {
            assert(bytes.size() == found->second.size());
            std::copy(found->second.begin(), found->second.end(), bytes.begin());
            events.emplace_back("native-read");
            return;
        }
        if (address >= allocation && address - allocation <= memory.size() &&
            bytes.size() <= memory.size() - (address - allocation)) {
            memcpy(bytes.data(), memory.data() + address - allocation, bytes.size());
            if (bad_readback && !bytes.empty()) bytes[0] ^= 1;
            events.emplace_back("readback");
        } else {
            for (auto& b : bytes) b = conflict || (change_entry_after_prepare && prepared) ? 1 : 0;
            events.emplace_back("hook-read");
        }
    }
    void write(uint64_t address, std::span<const uint8_t> bytes) override {
        assert(address >= allocation && address - allocation <= memory.size() &&
            bytes.size() <= memory.size() - (address - allocation));
        memcpy(memory.data() + address - allocation, bytes.data(), bytes.size());
        events.emplace_back("write");
    }
    uint64_t call(uint64_t function, std::span<const uint64_t> args) override {
        if (function >= kernel_base) {
            if (inspect_prepare) inspect_prepare(*this);
            prepared = true;
            events.emplace_back("prepare"); return prepare_error ? uint64_t(-12) : 0;
        }
        for (const auto& [name, address] : symbols) if (address == function) {
            events.push_back("call:" + name);
            if (failed_call == name) throw std::runtime_error("injected kernel call failure");
            if (name == "static_key_count") {
                assert(args.size() == 1 && args[0] == symbols.at("dynamic_scs_enabled"));
                return uint64_t(dynamic_enabled);
            }
            if (name == "__pi_scs_patch") {
                assert(args.size() == expected_scs_arguments);
                if (args.size() == 3) assert(args[2] == 1);
                if (scs_patch_error) return uint64_t(-8);
                if (!scs_patch_missing) for (auto site : scs_sites) {
                    uint32_t insn;
                    memcpy(&insn, memory.data() + site, 4);
                    insn = insn == 0xd503233f ? 0xf800865eU : 0xf85f8e5eU;
                    memcpy(memory.data() + site, &insn, 4);
                }
                if (scs_patch_extra_write) memory[0] ^= 1;
            }
            if (name == "apply_alternatives_module" && alternatives_error) return uint64_t(-8);
            return 0;
        }
        assert(false); return 0;
    }
    std::vector<uint8_t> dispatch(unsigned operation, uint64_t predicate, uint64_t handler, uint64_t gate) override {
        activation = gate;
        assert(gate >= kernel_base && !(gate & (4096 - 1)));
        assert(predicate >= kernel_base && handler >= kernel_base);
        events.emplace_back("dispatch");
        return bad_dispatch == int(operation) ? std::vector<uint8_t>{1} : std::vector<uint8_t>{0, 0, 0, 0};
    }
    void activate(uint64_t address, bool enabled) override {
        assert(address == activation);
        activation_enabled = enabled;
        events.emplace_back(enabled ? "activate" : "deactivate");
        if (enabled && activation_error) throw std::runtime_error("injected activation transport failure");
    }
    void hook(uint64_t, const std::vector<uint8_t>&) override {
        events.emplace_back("hook");
        if (bad_hook == int(hooks++)) throw std::runtime_error("injected hook failure");
    }
};
}
