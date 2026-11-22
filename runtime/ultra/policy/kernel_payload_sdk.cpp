#include "kernel_payload_loader.h"
#include "module_policy_config.h"
#include "kernel_module_kit_umbrella.h"
#include <array>
#include <cerrno>
#include <fcntl.h>
#include <stdexcept>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <ctime>
#include <unistd.h>
#include <zlib.h>

namespace maplesu::module_policy {
namespace {
uint64_t installed_activation = 0;
void check(const char* operation, KModErr error) {
    if (is_failed(error)) throw std::runtime_error(std::string("MODULE_POLICY_SDK_") + operation +
        ":" + std::to_string(static_cast<int64_t>(error)));
}
class SdkIo final : public PolicyKernelIo {
    void progress(std::string_view phase) noexcept override {
        try {
            Store::open(false).record_compatibility("schema=1 time=" + std::to_string(time(nullptr)) +
                " operation=install-phase boot=" + current_boot_id() + "\nphase=" +
                std::string(phase) + "\nEND\n");
        } catch (...) { }
    }
    uint64_t lookup(const char* name) override {
        uint64_t address = 0;
        check("LOOKUP", kernel_module::kallsyms_lookup_name(name, address));
        return address;
    }
    uint64_t allocate(uint32_t size) override {
        uint64_t address = 0;
        check("ALLOCATE", kernel_module::alloc_kernel_mem(size, address));
        return address;
    }
    void release(uint64_t address) override { check("RELEASE", kernel_module::free_kernel_mem(address)); }
    void read(uint64_t address, std::span<uint8_t> bytes) override {
        check("READ", kernel_module::read_kernel_mem(address, bytes.data(), bytes.size()));
    }
    void write(uint64_t address, std::span<const uint8_t> bytes) override {
        check("WRITE", kernel_module::write_kernel_mem(address, bytes.data(), bytes.size(), kernel_module::KernMemProt::KMP_RW));
    }
    uint64_t call(uint64_t function, std::span<const uint64_t> args) override {
        using namespace kernel_module;
        using namespace asmjit::a64;
        if (args.size() > 3) throw std::runtime_error("MODULE_POLICY_SDK_ARGUMENTS");
        auto context = init_aarch64_asm();
        auto a = context.assembler();
        arm64_module_asm_func_start(a);
        for (unsigned i = 0; i < args.size(); ++i) a->mov(x(i), asmjit::Imm(args[i]));
        a->mov(x16, asmjit::Imm(function));
        a->blr(x16);
        arm64_module_asm_func_end(a, x0);
        auto bytes = aarch64_asm_to_bytes(a);
        if (context.has_error() || bytes.empty()) throw std::runtime_error("MODULE_POLICY_SDK_ASSEMBLY");
        uint64_t result = 0;
        check("EXECUTE", execute_kernel_asm_func(bytes, result));
        return result;
    }
    std::vector<uint8_t> dispatch(unsigned operation, uint64_t predicate, uint64_t handler, uint64_t activation) override {
        return emit_policy_query_dispatch(operation, predicate, handler, activation);
    }
public:
    void activate(uint64_t address, bool enabled) override {
        using namespace kernel_module;
        using namespace asmjit::a64;
        if (address < 0xffff000000000000ULL || (address & 3))
            throw std::runtime_error("MODULE_POLICY_SDK_ACTIVATION_ADDRESS");
        if (enabled) {
            // Commit before activation, so a later process can cancel even if
            // execution succeeded but its transport/publication was interrupted.
            Store::open(false).remember_activation(current_boot_id(), address);
            installed_activation = address;
        }
        auto context = init_aarch64_asm();
        auto a = context.assembler();
        arm64_module_asm_func_start(a);
        a->mov(x16, asmjit::Imm(address));
        a->mov(w17, asmjit::Imm(enabled ? 1 : 0));
        a->stlr(w17, ptr(x16));
        a->mov(x0, xzr);
        arm64_module_asm_func_end(a, x0);
        auto bytes = aarch64_asm_to_bytes(a);
        if (context.has_error() || bytes.empty())
            throw std::runtime_error("MODULE_POLICY_SDK_ACTIVATION_ASSEMBLY");
        uint64_t result = 0;
        auto error = execute_kernel_asm_func(bytes, result);
        if (!enabled && is_failed(error)) {
            // A transport failure must not strand an enabled gate. A zero write
            // needs no publication barrier; verify it through the same SDK.
            const std::array<uint8_t, 4> disabled{};
            write(address, disabled);
        } else check("ACTIVATION", error);
        std::array<uint8_t, 4> observed{};
        read(address, observed);
        if (observed != std::array<uint8_t, 4>{uint8_t(enabled), 0, 0, 0})
            throw std::runtime_error("MODULE_POLICY_SDK_ACTIVATION_READBACK");
        if (!enabled && installed_activation == address) installed_activation = 0;
    }
    void hook(uint64_t target, const std::vector<uint8_t>& bytes) override {
        check("HOOK", kernel_module::install_kernel_function_before_hook(target, bytes));
    }
};
}
std::vector<uint8_t> emit_policy_query_dispatch(unsigned operation, uint64_t predicate, uint64_t handler, uint64_t activation) {
    using namespace kernel_module;
    using namespace asmjit::a64;
    if (operation > 8 || predicate < 0xffff000000000000ULL || handler < 0xffff000000000000ULL ||
        (activation && (activation < 0xffff000000000000ULL || (activation & 3))))
        throw std::runtime_error("MODULE_POLICY_SDK_DISPATCH_ARGUMENTS");
    auto context = init_aarch64_asm();
    auto a = context.assembler();
    auto original = a->newLabel(), done = a->newLabel();
    arm64_before_hook_start(a);
    // The nonblocking datagram dequeue has six arguments. Keep original values
    // across the predicate, including the current-context name for setprocattr.
    a->sub(sp, sp, asmjit::Imm(48));
    a->stp(x0, x1, ptr(sp));
    a->stp(x2, x3, ptr(sp, 16));
    a->stp(x4, x5, ptr(sp, 32));
    if (activation) {
        a->mov(x16, asmjit::Imm(activation));
        a->ldar(w16, ptr(x16));
        a->cbz(w16, original);
    }
    if (operation == 6) {
        a->mov(x2, x1);
        a->mov(x1, x0);
    } else {
        if (operation == 2 || operation == 7 || operation == 8) a->mov(x1, x0); else a->mov(x1, xzr);
        a->mov(x2, xzr);
    }
    a->mov(x0, asmjit::Imm(operation));
    a->mov(x16, asmjit::Imm(predicate));
    a->blr(x16);
    a->cbz(x0, original);
    a->ldp(x0, x1, ptr(sp));
    a->ldp(x2, x3, ptr(sp, 16));
    a->ldp(x4, x5, ptr(sp, 32));
    a->add(sp, sp, asmjit::Imm(48));
    if (operation == 7) {
        // Credentials are already committed when mappings change. Preserve
        // the native return value and never execute commit_creds twice.
        arm64_emit_call_original(a);
        a->sub(sp, sp, asmjit::Imm(16));
        a->str(x0, ptr(sp));
        a->mov(x16, asmjit::Imm(handler));
        a->blr(x16);
        a->ldr(x0, ptr(sp));
        a->add(sp, sp, asmjit::Imm(16));
    } else if (operation == 8) {
        auto receive = a->newLabel(), received = a->newLabel();
        // Keep native __skb_recv_datagram's timeout and signal loop intact;
        // only repeat its nonblocking dequeue, never restart a receive timeout.
        a->sub(sp, sp, asmjit::Imm(64));
        a->stp(x0, x1, ptr(sp));
        a->stp(x2, x3, ptr(sp, 16));
        a->stp(x4, x5, ptr(sp, 32));
        a->mov(w9, asmjit::Imm(8));
        a->str(w9, ptr(sp, 56));
        a->bind(receive);
        a->ldp(x0, x1, ptr(sp));
        a->ldp(x2, x3, ptr(sp, 16));
        a->ldp(x4, x5, ptr(sp, 32));
        arm64_emit_call_original(a);
        a->cbz(x0, received);
        a->mov(x1, x0);
        a->ldr(x0, ptr(sp));
        a->ldr(w2, ptr(sp, 16));
        a->mov(x16, asmjit::Imm(handler));
        a->blr(x16);
        a->cbnz(x0, received);
        // Discard only hidden POLICYLOAD datagrams, including MSG_PEEK.
        // Bound draining under a stream of reloads instead of spinning.
        a->ldr(w9, ptr(sp, 56));
        a->sub(w9, w9, asmjit::Imm(1));
        a->str(w9, ptr(sp, 56));
        a->cbnz(w9, receive);
        a->ldr(x2, ptr(sp, 32));
        a->mov(w9, asmjit::Imm(uint32_t(-EAGAIN)));
        a->str(w9, ptr(x2));
        a->mov(x0, xzr);
        a->bind(received);
        a->add(sp, sp, asmjit::Imm(64));
    } else {
        a->mov(x16, asmjit::Imm(handler));
        a->blr(x16);
    }
    a->b(done);
    a->bind(original);
    a->ldp(x0, x1, ptr(sp));
    a->ldp(x2, x3, ptr(sp, 16));
    a->ldp(x4, x5, ptr(sp, 32));
    a->add(sp, sp, asmjit::Imm(48));
    arm64_emit_call_original(a);
    a->bind(done);
    // Exactly one SDK return slot; no double original call or second epilogue.
    arm64_before_hook_end(a, false);
    auto bytes = aarch64_asm_to_bytes(a);
    if (context.has_error() || bytes.empty()) throw std::runtime_error("MODULE_POLICY_SDK_DISPATCH_ASSEMBLY");
    return bytes;
}

void cancel_hidden_kernel_policy() {
    auto address = installed_activation ? std::optional<uint64_t>{installed_activation} :
        Store::open(false).activation(current_boot_id());
    if (address) SdkIo().activate(*address, false);
}
bool hidden_kernel_policy_supported() {
    try { return preflight_hidden_kernel_policy() == 3; }
    catch (const std::exception&) { return false; }
}
unsigned preflight_hidden_kernel_policy() { SdkIo io; return prepare_policy_view_with(io, true); }
unsigned prepare_hidden_kernel_policy(bool allow_unverified) { SdkIo io; return prepare_policy_view_with(io, false, allow_unverified); }
}
