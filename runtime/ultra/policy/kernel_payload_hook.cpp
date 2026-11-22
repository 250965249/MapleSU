// SPDX-License-Identifier: GPL-3.0-only
#include "kernel_payload_hook.h"
#include "module_policy_config.h"
#include <algorithm>
#include <array>
#include <cerrno>
#include <climits>
#include <cstring>
#include <elf.h>
#include <fcntl.h>
#include <optional>
#include <stdexcept>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace maplesu::module_policy {
namespace {
[[noreturn]] void fail(const char* operation, int error = 0) {
    throw std::runtime_error(std::string("MODULE_POLICY_HOOK_") + operation +
        (error ? ":" + std::to_string(error) : ""));
}
msu_policy_hook_request packet(unsigned command) {
    msu_policy_hook_request request{};
    request.version = MSU_POLICY_HOOK_VERSION;
    request.command = command;
    return request;
}
struct Descriptor {
    uint32_t version, operation;
    uint64_t predicate, handler, activation;
};
constexpr const char* targets[] = {
    "sel_write_context", "sel_write_access", "selinux_setprocattr", "sel_open_handle_status",
    "sel_read_handle_status", "sel_mmap_handle_status", "sk_filter_trim_cap", "commit_creds",
    "__skb_try_recv_datagram", "copy_process", "selnl_notify_policyload", "sel_write_load"
};
static_assert(sizeof(Descriptor) == 32 && sizeof(msu_policy_hook_request) == 248);
void validate(const msu_policy_hook_request& request, unsigned command) {
    if (request.version != MSU_POLICY_HOOK_VERSION || request.command != command ||
        request.installed > MSU_POLICY_HOOK_COUNT || request.enabled > 1 ||
        request.prepared > 1 || request.pinned > 1 || request.status == INT_MIN) fail("RESPONSE");
    if (request.status) fail("BACKEND", request.status);
}
std::optional<msu_policy_hook_request> resident_control(msu_policy_hook_request request, bool probing) {
    const auto command = request.command;
    request.status = INT_MIN;
    const auto result = prctl(4, static_cast<unsigned long>(MSU_POLICY_HOOK_OP),
        static_cast<unsigned long>(MSU_POLICY_HOOK_TAG_LO),
        static_cast<unsigned long>(MSU_POLICY_HOOK_TAG_HI), &request);
    if (result) {
        // Only an untouched native rejection permits discovery of the legacy
        // proc transport. No mutation, busy reply or lost receipt is replayed.
        if (probing && request.status == INT_MIN && (errno == EINVAL || errno == ENOSYS)) return {};
        fail("RESIDENT_TRANSPORT", errno);
    }
    validate(request, command);
    return request;
}
}
HookKernelIo::HookKernelIo() {
    if (getuid() || geteuid()) fail("ROOT_REQUIRED");
    if (resident_control(packet(MSU_PH_QUERY), true)) return;
    fd_ = open(MSU_POLICY_HOOK_PATH, O_RDWR | O_NOFOLLOW | O_CLOEXEC);
    if (fd_ < 0) fail("BACKEND_OPEN", errno);
    struct stat st{};
    if (fstat(fd_, &st) || !S_ISREG(st.st_mode) || st.st_uid || (st.st_mode & 0777) != 0600) {
        close(fd_); fd_ = -1; fail("BACKEND_OWNER");
    }
    try { (void)query(); }
    catch (...) { close(fd_); fd_ = -1; throw; }
}
HookKernelIo::~HookKernelIo() { if (fd_ >= 0) close(fd_); }
msu_policy_hook_request HookKernelIo::transact(msu_policy_hook_request request) {
    const auto command = request.command;
    if (fd_ < 0) return *resident_control(request, false);
    // Do not replay a mutating ioctl after EINTR or a lost acknowledgement.
    // Query recovers resident state without a second allocation or kernel call.
    if (ioctl(fd_, MSU_POLICY_HOOK_IOCTL, &request)) fail("TRANSPORT", errno);
    validate(request, command);
    return request;
}
msu_policy_hook_request HookKernelIo::query() { return transact(packet(MSU_PH_QUERY)); }
void HookKernelIo::select_bundle(const KernelPolicyBundle& bundle) {
    auto payload = parse_policy_payload(bundle.image, bundle.page_size);
    const auto found = payload.exports.find("maplesu_policy_view_transition");
    if (found == payload.exports.end()) fail("PAYLOAD_TRANSITION_MISSING");
    const auto at = found->second;
    if ((at & 3) || std::none_of(payload.segments.begin(), payload.segments.end(), [&](const auto& segment) {
            return (segment.flags & PF_X) && at >= segment.offset && at - segment.offset <= segment.size &&
                8 <= segment.size - (at - segment.offset);
        })) fail("PAYLOAD_TRANSITION_RANGE");
    transition_offset_ = at;
    prepare_offset_ = payload.exports.at("maplesu_policy_view_prepare");
    handles_offset_ = payload.exports.at("maplesu_policy_view_handles");
    const auto guard = payload.exports.find("maplesu_policy_view_fork_guard");
    if (guard == payload.exports.end()) fail("PAYLOAD_FORK_GUARD_MISSING");
    fork_guard_offset_ = guard->second;
    for (const char* name : {"maplesu_policy_view_module_write", "maplesu_policy_view_policyload", "maplesu_policy_view_reload"})
        if (!payload.exports.contains(name)) fail("PAYLOAD_RELOAD_MISSING");
    module_write_offset_ = payload.exports.at("maplesu_policy_view_module_write");
    policyload_offset_ = payload.exports.at("maplesu_policy_view_policyload");
    reload_offset_ = payload.exports.at("maplesu_policy_view_reload");
    // The exact native copy_process ABI is qualified by the image builder.
    if (!lookup("copy_process")) fail("FORK_TARGET_MISSING");
    for (const char* name : {"selnl_notify_policyload", "sel_write_load", "ksys_write"})
        if (!lookup(name)) fail("RELOAD_TARGET_MISSING");
}
void HookKernelIo::progress(std::string_view phase) noexcept {
    try { Store::open(false).record_compatibility("schema=1 operation=hook-install boot=" + current_boot_id() +
        "\nphase=" + std::string(phase) + "\nEND\n"); } catch (...) {}
}
uint64_t HookKernelIo::lookup(const char* name) {
    auto r = packet(MSU_PH_LOOKUP);
    const auto length = strlen(name);
    if (!length || length >= sizeof(r.name)) fail("SYMBOL_NAME");
    memcpy(r.name, name, length + 1);
    return transact(r).result;
}
uint64_t HookKernelIo::allocate(uint32_t bytes) {
    auto r = packet(MSU_PH_ALLOCATE); r.bytes = bytes;
    return transact(r).result;
}
void HookKernelIo::release(uint64_t address) {
    auto r = packet(MSU_PH_RELEASE); r.address = address; (void)transact(r);
}
void HookKernelIo::read(uint64_t address, std::span<uint8_t> bytes) {
    while (!bytes.empty()) {
        const auto count = std::min<size_t>(bytes.size(), MSU_POLICY_HOOK_CHUNK);
        auto r = packet(MSU_PH_READ); r.address = address; r.bytes = count;
        r.data = reinterpret_cast<uintptr_t>(bytes.data()); (void)transact(r);
        bytes = bytes.subspan(count); address += count;
    }
}
void HookKernelIo::write(uint64_t address, std::span<const uint8_t> bytes) {
    while (!bytes.empty()) {
        const auto count = std::min<size_t>(bytes.size(), MSU_POLICY_HOOK_CHUNK);
        auto r = packet(MSU_PH_WRITE); r.address = address; r.bytes = count;
        r.data = reinterpret_cast<uintptr_t>(bytes.data()); (void)transact(r);
        bytes = bytes.subspan(count); address += count;
    }
}
uint64_t HookKernelIo::call(uint64_t function, std::span<const uint64_t> args) {
    if (args.size() > 3) fail("ARGUMENTS");
    if (image_base_ && function == image_base_ + prepare_offset_) {
        entries_[9] = {lookup("copy_process"), predicate_, image_base_ + fork_guard_offset_,
                           activation_, MSU_POLICY_QUERY_HOOK_COUNT, 0};
        entries_[10] = {lookup("selnl_notify_policyload"), predicate_, image_base_ + policyload_offset_, activation_, 10, 0};
        entries_[11] = {lookup("sel_write_load"), predicate_, image_base_ + reload_offset_, activation_, 11, 0};
        auto bind = packet(MSU_PH_BIND);
        bind.address = function; bind.handler = transition_; bind.predicate = predicate_;
        bind.activation = activation_; bind.bytes = sizeof(entries_);
        bind.args[0] = image_base_ + module_write_offset_;
        bind.data = reinterpret_cast<uintptr_t>(entries_.data());
        (void)transact(bind);
    }
    auto r = packet(MSU_PH_CALL); r.address = function; r.bytes = args.size();
    std::copy(args.begin(), args.end(), r.args);
    return transact(r).result;
}
std::vector<uint8_t> HookKernelIo::dispatch(unsigned operation, uint64_t predicate,
    uint64_t handler, uint64_t activation) {
    if (operation >= MSU_POLICY_QUERY_HOOK_COUNT || predicate < handles_offset_) fail("DISPATCH");
    const auto transition = predicate - handles_offset_ + transition_offset_;
    if (!transition_offset_ || (transition_ && transition_ != transition)) fail("DISPATCH_IMAGE");
    transition_ = transition;
    image_base_ = predicate - handles_offset_;
    predicate_ = predicate;
    activation_ = activation;
    entries_[operation] = {lookup(targets[operation]), predicate, handler, activation, operation, 0};
    const Descriptor descriptor{MSU_POLICY_HOOK_VERSION, operation, predicate, handler, activation};
    const auto* data = reinterpret_cast<const uint8_t*>(&descriptor);
    return {data, data + sizeof(descriptor)};
}
void HookKernelIo::hook(uint64_t address, const std::vector<uint8_t>& bytes) {
    if (bytes.size() != sizeof(Descriptor)) fail("DISPATCH_SIZE");
    Descriptor d; memcpy(&d, bytes.data(), sizeof(d));
    if (d.version != MSU_POLICY_HOOK_VERSION || d.operation >= MSU_POLICY_HOOK_COUNT) fail("DISPATCH_VERSION");
    auto r = packet(MSU_PH_INSTALL); r.address = address; r.operation = d.operation;
    r.predicate = d.predicate; r.handler = d.handler; r.activation = d.activation; (void)transact(r);
}
void HookKernelIo::activate(uint64_t address, bool enabled) {
    if (!transition_) fail("TRANSITION_NOT_BOUND");
    auto r = packet(MSU_PH_ACTIVATE); r.address = address; r.result = enabled;
    r.handler = transition_; r = transact(r);
    if (bool(r.enabled) != enabled || (enabled && r.installed != MSU_POLICY_HOOK_COUNT)) fail("ACTIVATION_READBACK");
    std::array<uint8_t, 4> gate{}; read(address, gate);
    if (gate != std::array<uint8_t, 4>{uint8_t(enabled),0,0,0}) fail("ACTIVATION_MEMORY_READBACK");
}
void HookKernelIo::resume(bool enabled) {
    auto state = query();
    if (!state.prepared || !state.address || !state.handler) fail("RESIDENT_NOT_READY");
    transition_ = state.handler;
    activate(state.address, enabled);
}
void HookKernelIo::abort() { (void)transact(packet(MSU_PH_CANCEL)); }
ssize_t HookKernelIo::write_policy(int fd, const void* bytes, size_t size) {
    auto r = packet(MSU_PH_POLICY_WRITE);
    r.args[0] = static_cast<unsigned>(fd); r.data = reinterpret_cast<uintptr_t>(bytes); r.bytes = size;
    r = transact(r);
    // A bounded evidence write must never convert a committed kernel write
    // into a reported failure which a caller might replay.
    if (r.args[1]) try {
        Store::open(false).record_compatibility("schema=1 operation=hook-runtime boot=" + current_boot_id() +
            "\nresult=load-fallback reason=" + std::to_string(static_cast<int64_t>(r.args[1])) +
            " restore=" + std::to_string(static_cast<int64_t>(r.args[2])) + "\nEND\n");
    } catch (...) {}
    const auto result = static_cast<int64_t>(r.result);
    if (result < 0) { errno = static_cast<int>(-result); return -1; }
    return static_cast<ssize_t>(result);
}
bool hook_policy_backend_present() {
    if (getuid() || geteuid()) fail("ROOT_REQUIRED");
    if (resident_control(packet(MSU_PH_QUERY), true)) return true;
    struct stat status{};
    if (lstat(MSU_POLICY_HOOK_PATH, &status)) {
        if (errno == ENOENT) return false;
        fail("BACKEND_STAT", errno);
    }
    // Opening and QUERY also verify the proc entry's live ABI and permissions.
    HookKernelIo io;
    return true;
}
unsigned prepare_hook_kernel_policy(Mode mode, bool allow_unverified) {
    HookKernelIo io;
    auto state = io.query();
    if (mode != Mode::Hide) {
        io.abort();
        state = io.query();
        if (state.enabled || state.installed || state.args[2]) fail("CANCEL_READBACK");
        if (state.result && !state.prepared && !state.pinned) io.release(state.result);
        return 1;
    }
    if (state.prepared) {
        io.resume(true);
        return 3;
    }
    if (state.predicate && state.handler && state.address) {
        // A failed preparation left its complete immutable entry contract.
        // QUERY's prepared bit distinguishes that from a lost success reply.
        if (static_cast<int32_t>(io.call(state.predicate, {}))) fail("PREPARE");
        io.resume(true);
        return 3;
    }
    if (state.result) {
        if (state.pinned || state.installed) fail("RESIDENT_INCOMPLETE");
        io.abort();
        io.release(state.result);
    }
    return prepare_policy_view_with(io, false, allow_unverified);
}
State observe_hook_policy_state(State state, bool hook_owned) {
    if (!hook_owned || !state.effective || state.effective->mode != Mode::Hide) return state;
    try {
        if (!hook_policy_backend_present()) fail("BACKEND_MISSING");
        HookKernelIo io;
        const auto live = io.query();
        if (live.args[2]) {
            state.hide_failed = true;
            state.effective.reset();
        } else if (live.args[1] || !live.enabled || live.installed != MSU_POLICY_HOOK_COUNT) {
            state.hide_failed = true;
            state.effective = BootState{Mode::Load, 1, state.effective->boot_id};
        }
    } catch (const std::exception&) {
        // A persisted receipt is not proof of a current backend. Missing, old
        // or unreadable control state stays unconfirmed until actual recovery.
        state.hide_failed = true;
        state.effective.reset();
    }
    if (state.hide_failed) state.can_try_unverified = false;
    return state;
}
}
