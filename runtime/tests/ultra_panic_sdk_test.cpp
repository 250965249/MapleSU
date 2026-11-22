#include <cassert>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cerrno>
#include <initializer_list>

#ifdef MAPLESU_TEST_REQUEST
extern "C" int64_t test_request(uint64_t, uint32_t, uint64_t&);
static uint64_t reply;
static bool convert_invalid_id = true;
static unsigned requests;
extern "C" size_t __strlen_chk(const char* value, size_t size) { const auto n = strlen(value); assert(n < size); return n; }
extern "C" const char* __get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW() {
    return "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
}
extern "C" long __wrap_syscall(long number, ...) {
    assert(number == 221);
    ++requests;
    va_list args; va_start(args, number);
    const auto* name = va_arg(args, const unsigned char*);
    assert(static_cast<unsigned char>(name[48] + name[66]) == '3');
    va_end(args);
    errno = ENOENT; return -1; // Execve's historical result is not the channel ACK.
}
static unsigned munged(unsigned id) { return convert_invalid_id && id == UINT32_MAX ? 65534 : id; }
extern "C" int __wrap_getresuid(unsigned* r, unsigned* e, unsigned* s) { *r = *e = 0; *s = munged(uint32_t(reply)); return 0; }
extern "C" int __wrap_getresgid(unsigned* r, unsigned* e, unsigned* s) { *r = *e = 0; *s = munged(uint32_t(reply >> 32)); return 0; }
namespace kernel_module { int32_t get_page_size() { return 4096; } }
int main() {
    uint64_t result = 0;
    reply = uint64_t(-19999);
    assert(test_request(0x1234000, 4, result) == -19999 && result == 0x0000fffeffffb1e1);
    convert_invalid_id = false;
    assert(test_request(0x1234000, 4, result) == -19999 && result == reply);
    for (uint64_t value : {0x123456789abcde00ULL, 0x12345678ffffb1e1ULL, 0x0000fffeffffb1e0ULL}) {
        reply = value;
        assert(test_request(0x1234000, 4, result) == 0 && result == reply);
    }
    requests = 0;
    for (uint32_t size : {0u, 0xfffff001u, 0xffffffffu}) {
        result = 0x1234;
        assert(test_request(0x1234000, size, result) == -19999 && result == 0x1234);
    }
    assert(test_request(0, 4, result) == -19999);
    assert(requests == 0);
    puts("PASS native request: mapped/legacy errors; intact successes; invalid execution stopped before syscall");
}
#else
extern "C" int64_t test_executor(const uint8_t*, uint32_t, uint64_t&);
static unsigned allocations, releases, executions;
static int stage;
namespace kernel_module {
int64_t request_kernel_alloc_mem(uint32_t, uint64_t& out) { ++allocations; out = 0x1234000; return stage == 1 ? -19995 : 0; }
int64_t unsafe_request_kernel_write_mem(uint64_t at, const void*, uint32_t) { assert(at == 0x1234000); return stage == 2 ? -20000 : 0; }
int64_t unsafe_request_kernel_exec_mem(uint64_t at, uint32_t, uint64_t& out) {
    assert(at == 0x1234000); ++executions; out = 0x123456789abcde00;
    return stage == 3 ? -19999 : 0;
}
}
extern "C" int64_t maplesu_release_staging(uint64_t at) { assert(at == 0x1234000); ++releases; return 0; }
extern "C" int prctl(int option, ...) { assert(option == 27); return 0x7654; }
int main() {
    const uint8_t code[] = {0xc0, 0x03, 0x5f, 0xd6};
    for (stage = 0; stage < 4; ++stage) {
        allocations = releases = executions = 0;
        uint64_t out = 0;
        const auto result = test_executor(code, sizeof(code), out);
        assert(allocations == 1);
        assert(releases == (stage == 2 ? 1u : 0u));
        assert(executions == (stage == 0 || stage == 3 ? 1u : 0u));
        assert((result == 0) == (stage == 0));
        assert(out == (stage == 0 ? 0x76543456789abcde : 0));
    }
    puts("PASS staging copy failure released exactly once; execution owns cleanup; errors propagated");
}
#endif
