// Replay the shared-cred response channel observed by thread-reply-probe.cpp.
// The request encoder, reply decoder and allocation checks are the production IR.
#include <cassert>
#include <cerrno>
#include <condition_variable>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <mutex>
#include <thread>
#include <linux/capability.h>
#include <sys/syscall.h>
#include "module_err_def.h"

extern "C" int64_t test_alloc(uint32_t, uint64_t*);
namespace {
struct Cred { uint32_t suid = 10000, sgid = 10000; };
std::shared_ptr<Cred> inherited;
thread_local std::shared_ptr<Cred> cred;
thread_local int caller;
std::mutex mutex;
std::condition_variable changed;
bool first_sent, second_sent;
unsigned sent, detached;
int fail_at;
constexpr uint64_t addresses[] = {0xffffff8001234000ULL, 0xffffff8005678000ULL};
}

extern "C" const char* __get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW() {
    return "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
}
extern "C" size_t __strlen_chk(const char* text, size_t limit) {
    const auto size = strlen(text); assert(size < limit); return size;
}
extern "C" int __wrap_getresuid(unsigned* r, unsigned* e, unsigned* s) {
    std::lock_guard lock(mutex); *r = *e = 0; *s = cred->suid; return 0;
}
extern "C" int __wrap_getresgid(unsigned* r, unsigned* e, unsigned* s) {
    std::lock_guard lock(mutex); *r = *e = 0; *s = cred->sgid; return 0;
}
extern "C" long __wrap_syscall(long number, ...) {
    va_list args; va_start(args, number);
    if (number == SYS_capget || number == SYS_capset) {
        auto* header = va_arg(args, __user_cap_header_struct*);
        auto* data = va_arg(args, __user_cap_data_struct*);
        va_end(args);
        assert(header->version == _LINUX_CAPABILITY_VERSION_3 && header->pid == 0);
        if (fail_at == (number == SYS_capget ? 1 : 2)) { errno = EPERM; return -1; }
        if (number == SYS_capget) {
            for (int i = 0; i < 2; ++i) data[i] = {0x12345678u, 0x23456789u, 0x3456789au};
        } else {
            for (int i = 0; i < 2; ++i)
                assert(data[i].effective == 0x12345678u && data[i].permitted == 0x23456789u &&
                       data[i].inheritable == 0x3456789au);
            std::lock_guard lock(mutex);
            cred = std::make_shared<Cred>(*cred); ++detached;
        }
        return 0;
    }
    assert(number == 221);
    const auto* name = va_arg(args, const unsigned char*);
    va_end(args);
    unsigned char request[18];
    for (int i = 0; i < 18; ++i) request[i] = name[48 + i] + name[66 + i];
    assert(request[0] == 48 && name[84] == 0);
    std::unique_lock lock(mutex);
    ++sent;
    if (caller == 1) changed.wait(lock, [] { return first_sent; });
    const auto value = addresses[caller];
    cred->suid = uint32_t(value); cred->sgid = uint32_t(value >> 32);
    if (caller == 0) {
        first_sent = true; changed.notify_all();
        changed.wait(lock, [] { return second_sent; });
    } else { second_sent = true; changed.notify_all(); }
    errno = ENOENT; return -1; // The intercepted execve return is not the reply.
}
namespace kernel_module { int32_t get_page_size() { return 4096; } }

int main() {
    inherited = std::make_shared<Cred>();
    uint64_t outputs[2]{}; int64_t results[2]{};
    std::thread workers[2];
    for (int i = 0; i < 2; ++i) workers[i] = std::thread([&, i] {
        caller = i; cred = inherited;
        results[i] = test_alloc(4096, &outputs[i]);
    });
    for (auto& thread : workers) thread.join();
    if (results[0] || results[1] || outputs[0] != addresses[0] || outputs[1] != addresses[1]) {
        fprintf(stderr, "FAIL concurrent allocation replies: A=%#llx B=%#llx; A expected=%#llx\n",
                (unsigned long long)outputs[0], (unsigned long long)outputs[1], (unsigned long long)addresses[0]);
        return 1;
    }
    assert(inherited->suid == 10000 && inherited->sgid == 10000 && detached == 2 && sent == 2);
    puts("PASS parallel SDK allocation replies are private; inherited credentials unchanged");
    for (int round = 0; round < 2; ++round) {
        caller = 0; cred = inherited; // Model sharing the credentials again after fork.
        uint64_t output = 0;
        const auto copies = detached;
        assert(test_alloc(4096, &output) == 0 && output == addresses[0]);
        assert(detached == copies + 1 && inherited->suid == 10000 && inherited->sgid == 10000);
    }
    puts("PASS credentials are detached on every request after sharing again");
    for (fail_at = 1; fail_at <= 2; ++fail_at) {
        cred = inherited; uint64_t output = 0x1234;
        const auto before = sent;
        const auto expected = fail_at == 1 ? KModErr::ERR_MODULE_GET_CAPS : KModErr::ERR_MODULE_CRED_DANGER;
        assert(test_alloc(4096, &output) == static_cast<int64_t>(expected) && output == 0x1234 && sent == before);
    }
    puts("PASS capget/capset failure returns before kernel allocation; output unchanged");
}
