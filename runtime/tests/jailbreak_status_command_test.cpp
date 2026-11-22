// Execute the real native command through wrapped file/syscall boundaries.
#include "../ultra/policy/jailbreak_status_layout.h"
#include <algorithm>
#include <cassert>
#include <cerrno>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <system_error>
#include <unistd.h>
#include <vector>
int jailbreak_selinux_hide(int, char **);
namespace {
std::vector<unsigned char> btf;
msu_selinux_hide state{};
msu_selinux_status baseline{1, 6, 1, 42, 0};
unsigned uid, page_bytes, calls, btf_reads, baseline_reads, position[3];
int btf_error, btf_read_error;
bool pending, complete, ack, requested;
std::string output;
unsigned passed;
void reset() {
    state = {}; state.available = MSU_STATUS_AVAILABLE | MSU_STATUS_CAN_SET;
    auto &a = state.anchors;
    a.page_function = 0x1000; a.enforce_function = 0x2000; a.mutex_lock = 0x3000;
    for (unsigned i = 0; i < 2; ++i) {
        auto code = i ? a.enforce_code : a.page_code;
        auto address = i ? a.enforce_function : a.page_function;
        code[0] = 0xaa0003f3; // mov x19, x0
        code[1] = 0x91006260; // add x0, x19, #24
        code[2] = 0x94000000 | ((a.mutex_lock - address - 8) / 4);
    }
    uid = 0; page_bytes = 4096; calls = btf_reads = baseline_reads = 0;
    for (auto &p : position) p = 0;
    btf_error = btf_read_error = 0; pending = requested = false; complete = ack = true; output.clear();
}
void run(bool initialize = true) {
    char name[] = "maplesu-policy", command[] = "jailbreak-hide";
    char file[] = "/fixture/baseline", enabled[] = "1";
    char *argv[] = {name, command, file, enabled};
    assert(jailbreak_selinux_hide(initialize ? 4 : 2, argv) == 0);
}
void set(bool enabled) {
    char name[] = "maplesu-policy", command[] = "jailbreak-hide", operation[] = "set";
    char value[] = "0"; value[0] = enabled ? '1' : '0';
    char *args[] = {name, command, operation, value};
    assert(jailbreak_selinux_hide(4, args) == 0);
}

template<class F> void fails(F fn, const char *reason) {
    bool caught = false;
    try { fn(); } catch (const std::exception &e) { caught = true; if (std::string(e.what()).find(reason) == std::string::npos) std::fprintf(stderr, "expected %s; got %s\n", reason, e.what()); assert(std::string(e.what()).find(reason) != std::string::npos); }
    assert(caught); ++passed;
}
}
extern "C" uid_t __wrap_getuid() { return uid; }
extern "C" uid_t __wrap_geteuid() { return uid; }
extern "C" long __wrap_sysconf(int key) { assert(key == _SC_PAGESIZE); return page_bytes; }
extern "C" int __wrap_open(const char *path, int, ...) {
    if (!strcmp(path, "/sys/kernel/btf/vmlinux")) {
        ++btf_reads;
        if (btf_error) { errno = btf_error; return -1; }
        return 10001;
    }
    if (!strcmp(path, "/fixture/baseline")) { ++baseline_reads; position[1] = 0; return 10002; }
    assert(!strcmp(path, "/sys/fs/selinux/status")); position[2] = 0; return 10003;
}
extern "C" int __wrap_close(int fd) { assert(fd >= 10001 && fd <= 10003); return 0; }
extern "C" ssize_t __wrap_read(int fd, void *buffer, size_t size) {
    assert(fd >= 10001 && fd <= 10003);
    const void *source = &baseline; size_t bytes = sizeof(baseline);
    if (fd == 10001) {
        if (btf_read_error) { errno = btf_read_error; return -1; }
        source = btf.data(); bytes = btf.size();
    }
    if (fd == 10003 && pending && complete) { pending = false; state.initialized = 1; state.effective = requested; state.after = baseline; }
    auto &at = position[fd - 10001];
    const auto count = std::min(size, bytes - at);
    memcpy(buffer, static_cast<const unsigned char *>(source) + at, count); at += count;
    return count;
}
extern "C" int __wrap_prctl(int option, ...) {
    va_list args; va_start(args, option);
    assert(option == 4 && va_arg(args, unsigned long) == MSU_STATUS_OP);
    assert(va_arg(args, unsigned long) == MSU_STATUS_TAG_LO);
    assert(va_arg(args, unsigned long) == MSU_STATUS_TAG_HI);
    auto p = va_arg(args, msu_selinux_hide *); va_end(args); ++calls;
    assert(p->version == MSU_STATUS_VERSION);
    if (p->command == MSU_STATUS_INITIALIZE) {
        assert(msu_status_layout_valid(&p->layout));
        assert(!memcmp(&p->baseline, &baseline, sizeof(baseline)) && p->requested == 1);
        state.layout = p->layout; state.baseline = state.before = p->baseline; pending = requested = true;
    } else if (p->command == 2) {
        assert(state.initialized); requested = p->requested; pending = true; state.initialized = 0;
    } else assert(p->command == MSU_STATUS_QUERY);
    const auto command = p->command; *p = state; p->command = command;
    p->version = MSU_STATUS_VERSION; p->acknowledged = ack ? MSU_STATUS_ACK : 0;
    errno = EINVAL; return -1; // The packet, not this result, is authoritative.
}
extern "C" int __wrap_printf(const char *format, ...) {
    char text[2048]; va_list args; va_start(args, format);
    const int n = vsnprintf(text, sizeof(text), format, args); va_end(args);
    assert(n >= 0 && unsigned(n) < sizeof(text)); output += text; return n;
}
int main(int argc, char **argv) {
    assert(argc == 2); std::ifstream input(argv[1], std::ios::binary); assert(input);
    btf.assign(std::istreambuf_iterator<char>(input), {});
    for (auto page : {4096U, 16384U, 65536U}) {
        reset(); page_bytes = page; run();
        assert(calls == 3 && btf_reads == 1 && baseline_reads == 1 && state.initialized);
        assert(state.layout.source == MSU_STATUS_RUNTIME_BTF && state.layout.page_bytes == page);
        assert(output.find("\"layoutSource\":1") != std::string::npos); ++passed;
    }
    for (int error : {EACCES, EPERM, ENOENT, ENOTDIR}) {
        reset(); btf_error = error; run();
        assert(calls == 3 && state.layout.source == MSU_STATUS_RUNTIME_ANCHORS);
        assert(output.find("\"btfReadErrno\":" + std::to_string(error)) != std::string::npos); ++passed;
    }
    for (int error : {EACCES, EPERM}) {
        reset(); btf_read_error = error; run();
        assert(calls == 3 && state.layout.source == MSU_STATUS_RUNTIME_ANCHORS);
        assert(output.find("\"btfReadErrno\":" + std::to_string(error)) != std::string::npos); ++passed;
    }
    reset(); btf_read_error = EIO; fails([] { run(); }, "JAILBREAK_SELINUX_READ"); assert(calls == 1 && !pending);
    reset(); btf_error = EIO; fails([] { run(); }, "JAILBREAK_SELINUX_OPEN"); assert(calls == 1 && !pending);
    reset(); auto original = btf[0]; btf[0] ^= 0xff; fails([] { run(); }, "LAYOUT_HEADER"); btf[0] = original; assert(calls == 1);
    reset(); complete = false; fails([] { run(); }, "INITIALIZATION_PENDING"); assert(calls == 3);
    reset(); ack = false; fails([] { run(); }, "BACKEND_UNAVAILABLE"); assert(!btf_reads);
    reset(); uid = 10000; fails([] { run(); }, "ROOT_REQUIRED"); assert(!calls);
    reset(); state.initialized = state.effective = 1; run(); assert(calls == 1 && !btf_reads && !baseline_reads); ++passed;
    reset(); run(false); assert(calls == 1 && !btf_reads && !baseline_reads && !pending); ++passed;
    reset(); state.initialized = state.effective = 1; set(false);
    assert(calls == 3 && !state.effective && !btf_reads && !baseline_reads); ++passed;
    reset(); state.initialized = 1; set(true);
    assert(calls == 3 && state.effective && !btf_reads && !baseline_reads); ++passed;
    reset(); state.available = 1; state.initialized = state.effective = 1;
    fails([] { set(false); }, "SWITCH_UNSUPPORTED"); assert(calls == 1);
    reset(); fails([] { set(true); }, "NOT_INITIALIZED"); assert(calls == 1 && !baseline_reads);
    reset(); state.initialized = state.effective = 1; set(true);
    assert(calls == 1 && !btf_reads && !baseline_reads); ++passed;
    reset(); state.initialized = state.effective = 1; complete = false;
    fails([] { set(false); }, "INITIALIZATION_PENDING");
    reset(); run(false);
    assert(output.find("\"observedSequence\":6") != std::string::npos); ++passed;
    std::puts(("PASS " + std::to_string(passed) + " real status command cases (BTF, anchors, three page sizes, root boundary, packet ACK, deferred read and I/O errors)").c_str());
}
