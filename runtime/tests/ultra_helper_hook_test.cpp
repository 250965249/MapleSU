#include <cassert>
#include <cstdlib>
#include <initializer_list>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>
#include "../ultra/panic/helper_hook.cpp"
namespace {

constexpr uint64_t Entry = 0xffff000000001000ULL, Flag = Entry + 0x1000;
constexpr uint32_t Original = 0xd503201f, Branch = 0x14000040;
struct Action { char op; int64_t status = 0; bool mutate = true; bool throws = false; uint32_t read = 0; };
std::vector<Action> script;
std::size_t at;
uint32_t current;
uint8_t disabled;
int entry_writes, callback_before_ready;
bool fail_allocation;
Action next(char op) {
    if (at >= script.size() || script[at].op != op) throw std::logic_error("fixture script mismatch");
    return script[at++];
}
}
void* operator new(std::size_t size) {
    if (fail_allocation && size == sizeof(HookContext)) throw std::bad_alloc();
    if (void* result = std::malloc(size)) return result;
    throw std::bad_alloc();
}
void operator delete(void* value) noexcept { std::free(value); }
extern "C" int64_t original_read_kernel_mem(uint64_t addr, void* out, uint32_t len) {
    auto action = next('r');
    if (action.throws) throw std::runtime_error("read");
    if (!action.status) {
        assert(addr == Entry && len == 4);
        *static_cast<uint32_t*>(out) = action.read ? action.read : current;
    }
    return action.status;
}
extern "C" int64_t original_write_kernel_mem(uint64_t addr, const void* value, uint32_t len, uint8_t prot) {
    bool code = addr == Entry;
    auto action = next(code ? 'w' : 'f');
    if (code) {
        ++entry_writes;
        assert(len == 4 && prot == 2);
        if (action.mutate) {
            current = *static_cast<const uint32_t*>(value);
            if (current == Branch && !disabled) ++callback_before_ready;
        }
    } else {
        assert(addr == Flag && len == 1 && prot == 1);
        if (action.mutate) disabled = *static_cast<const uint8_t*>(value);
    }
    if (action.throws) throw std::runtime_error("write");
    return action.status;
}
int main() {
    int tests = 0, failures = 0;
    auto run = [&](const char* name, std::initializer_list<Action> steps, int64_t expected,
                   uint32_t final_code, int expected_flag, bool context_expected, bool allocation = false,
                   bool null_output = false) {
        ++tests; pending.store(false); publishing.clear(); script = steps; at = 0; current = Original; disabled = 0;
        entry_writes = callback_before_ready = 0; fail_allocation = allocation;
        HookContext* context = reinterpret_cast<HookContext*>(uintptr_t(1));
        const int64_t result = maplesu_helper_publish_hook(Entry, &Branch, Original, Entry+0x3000,
                                                           128, Flag, null_output ? nullptr : &context);
        bool ok = result == expected && current == final_code && disabled == expected_flag &&
                  callback_before_ready == 0 && at == script.size() &&
                  (null_output || (context != nullptr) == context_expected);
        if (!null_output && context && context != reinterpret_cast<HookContext*>(uintptr_t(1))) {
            ok = ok && context->entry == Entry && context->original == Original &&
                 context->trampoline == Entry+0x3000 && context->size == 128 && context->disable_flag == Flag &&
                 context->enabled == (disabled ? 0 : 1);
            delete context;
        }
        if (!ok) ++failures;
        std::cout << (ok?"PASS ":"FAIL ") << name << " result=" << result << " expected=" << expected
                  << " steps=" << at << '/' << script.size() << " writes=" << entry_writes
                  << " disabled=" << int(disabled) << " early_callback=" << callback_before_ready << '\n';
        if (result == to_num(KModErr::ERR_MODULE_MUST_UNINSTALL)) {
            HookContext saved{};
            const bool retained = maplesu_helper_pending_hook(&saved) == 1 && saved.entry == Entry &&
                                  saved.original == Original && saved.disable_flag == Flag && saved.trampoline == Entry+0x3000 &&
                                  saved.size == 128 && saved.enabled == (disabled ? 0 : 1);
            const auto previous_step = at;
            HookContext* second = nullptr;
            const auto again = maplesu_helper_publish_hook(Entry, &Branch, Original, Entry+0x3000, 128, Flag, &second);
            if (!retained || again != result || at != previous_step || second != nullptr) {
                ++failures; std::cout << "FAIL pending retention / repeat blocked\n";
            }
        }
        fail_allocation = false;
    };
    const int64_t Asm = to_num(KModErr::ERR_MODULE_ASM);
    const int64_t Pending = to_num(KModErr::ERR_MODULE_MUST_UNINSTALL);
    run("successful_publish", {{'r'},{'f'},{'w'},{'r'},{'f'}}, 0, Branch, 0, true);
    run("public_no_handle", {{'r'},{'f'},{'w'},{'r'},{'f'}}, 0, Branch, 0, false, false, true);
    run("allocation_fails_before_mutation", {}, to_num(KModErr::ERR_NO_MEM), Original, 0, false, true);
    run("read_fails_before_mutation", {{'r',-100}}, -100, Original, 0, false);
    run("unexpected_entry_rejected", {{'r',0,true,false,0xd503245f}}, to_num(KModErr::ERR_MODULE_DUPLICATE), Original, 0, false);
    run("guard_fail_before_publish", {{'r'},{'f',-101,false}}, -101, Original, 0, false);
    run("entry_error_before_store", {{'r'},{'f'},{'w',-102,false},{'f'},{'w'},{'r'}}, -102, Original, 1, false);
    run("entry_error_after_store", {{'r'},{'f'},{'w',-103,true},{'f'},{'w'},{'r'}}, -103, Original, 1, false);
    run("publish_readback_error", {{'r'},{'f'},{'w'},{'r',-104},{'f'},{'w'},{'r'}}, -104, Original, 1, false);
    run("publish_readback_mismatch", {{'r'},{'f'},{'w',0,false},{'r'},{'f'},{'w'},{'r'}}, Asm, Original, 1, false);
    run("activation_error_before_store", {{'r'},{'f'},{'w'},{'r'},{'f',-105,false},{'f'},{'w'},{'r'}}, -105, Original, 1, false);
    run("activation_error_after_store", {{'r'},{'f'},{'w'},{'r'},{'f',-106,true},{'f'},{'w'},{'r'}}, -106, Original, 1, false);
    run("rollback_error_keeps_pending", {{'r'},{'f'},{'w',-107},{'f'},{'w',-108,false},{'r'}}, Pending, Branch, 1, true);
    run("rollback_cache_error_is_pending", {{'r'},{'f'},{'w',-107},{'f'},{'w',-108,true},{'r'}}, Pending, Original, 1, true);
    run("rollback_readback_error_is_pending", {{'r'},{'f'},{'w',-107},{'f'},{'w'},{'r',-109}}, Pending, Original, 1, true);
    run("rollback_readback_mismatch", {{'r'},{'f'},{'w',-107},{'f'},{'w',0,false},{'r'}}, Pending, Branch, 1, true);
    run("read_exception_before_mutation", {{'r',0,true,true}}, Asm, Original, 0, false);
    run("entry_exception_after_store", {{'r'},{'f'},{'w',0,true,true},{'f'},{'w'},{'r'}}, Asm, Original, 1, false);
    run("rollback_exception_retains_pending", {{'r'},{'f'},{'w',-107},{'f'},{'w',0,false,true}}, Pending, Branch, 1, true);
    run("disable_and_rollback_fail_report_active_pending", {{'r'},{'f'},{'w'},{'r'},{'f',-106,true},{'f',-110,false},{'w',-108,false},{'r'}}, Pending, Branch, 0, true);
    run("nullptr_rollback_failure_retained", {{'r'},{'f'},{'w',-107},{'f'},{'w',-108,false},{'r'}}, Pending, Branch, 1, false, false, true);
    run("nullptr_double_failure_retained", {{'r'},{'f'},{'w'},{'r'},{'f',-106,true},{'f',-110,false},{'w',-108,false},{'r'}}, Pending, Branch, 0, false, false, true);
    pending.store(false); publishing.test_and_set();
    HookContext* concurrent = nullptr;
    ++tests;
    if (maplesu_helper_publish_hook(Entry, &Branch, Original, Entry+0x3000, 128, Flag, &concurrent) != to_num(KModErr::ERR_MODULE_DUPLICATE) || concurrent) ++failures;
    else std::cout << "PASS concurrent_publication_rejected\n";
    publishing.clear();
    std::cout << "TOTAL=" << tests << " FAILURES=" << failures << '\n';
    return failures ? 1 : 0;
}



