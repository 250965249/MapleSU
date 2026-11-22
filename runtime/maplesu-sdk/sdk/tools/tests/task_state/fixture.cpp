#include "fixture.h"
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <pthread.h>
#include <string>
#include <system_error>

namespace {
constexpr uint64_t task_address = 0xfff0000012340000ULL;
std::string mode;
std::atomic<int> pipe_read{-1}, pipe_write{-1};
std::atomic<unsigned> opened{0}, closed{0}, created{0}, joined{0}, active{0};
std::atomic<unsigned> read_calls{0}, write_calls{0}, current_calls{0};
std::atomic<bool> read_started{false}, read_finished{false};
unsigned cache_get = 0, cache_put = 0, kernel_reads = 0, stored = 0;
uint32_t candidate = 0;
bool contract = true;

int descriptors() {
    DIR* directory = ::opendir("/proc/self/fd");
    if (directory == nullptr) return -1;
    int count = 0;
    while (auto* entry = ::readdir(directory))
        if (std::strcmp(entry->d_name, ".") && std::strcmp(entry->d_name, "..")) ++count;
    ::closedir(directory);
    return count;
}

bool cached() { return mode == "cache-zero" || mode == "cache-hit"; }
bool match() {
    return mode != "blocked256" && mode != "unchanged" && mode != "ambiguous" && mode != "zero-spurious"
            && mode != "cache-read-mutates-failure";
}
uint32_t expected_candidate() { return mode == "offset-zero" ? 0 : mode == "offset-last" ? 124 : 12; }
}

extern "C" int __real_pipe(int*);
extern "C" ssize_t __real_read(int, void*, size_t);
extern "C" ssize_t __real___read_chk(int, void*, size_t, size_t);
extern "C" ssize_t __real_write(int, const void*, size_t);
extern "C" int __real_close(int);
extern "C" int __real_pthread_create(pthread_t*, const pthread_attr_t*, void* (*)(void*), void*);
extern "C" int __real_pthread_join(pthread_t, void**);

extern "C" int __wrap_pipe(int* fds) {
    if (mode == "pipe-error") { errno = EMFILE; return -1; }
    int result = __real_pipe(fds);
    if (result == 0) { pipe_read = fds[0]; pipe_write = fds[1]; opened += 2; }
    return result;
}
extern "C" int __wrap_close(int fd) {
    int result = __real_close(fd);
    if (result == 0 && (fd == pipe_read || fd == pipe_write)) {
        ++closed;
        if (fd == pipe_read) pipe_read = -1;
        else pipe_write = -1;
    }
    return result;
}
extern "C" ssize_t __wrap_read(int fd, void* buffer, size_t size) {
    if (fd != pipe_read) return __real_read(fd, buffer, size);
    unsigned call = ++read_calls;
    if ((mode == "worker-read-eintr" || mode == "both-eintr") && call == 1) { errno = EINTR; return -1; }
    read_started = true;
    ssize_t result;
    if (mode == "worker-read-error") { errno = EIO; result = -1; }
    else if (mode == "worker-read-zero") result = 0;
    else result = __real_read(fd, buffer, size);
    read_finished = true;
    return result;
}
extern "C" ssize_t __wrap___read_chk(int fd, void* buffer, size_t size, size_t available) {
    if (size > available) return __real___read_chk(fd, buffer, size, available);
    return __wrap_read(fd, buffer, size);
}
extern "C" ssize_t __wrap_write(int fd, const void* buffer, size_t size) {
    if (fd != pipe_write) return __real_write(fd, buffer, size);
    unsigned call = ++write_calls;
    if ((mode == "wake-eintr" || mode == "both-eintr") && call == 1) { errno = EINTR; return -1; }
    if (mode == "wake-error") { errno = EIO; return -1; }
    if (mode == "wake-zero") return 0;
    return __real_write(fd, buffer, size);
}

namespace {
struct Start { void* (*entry)(void*); void* argument; };
void* start(void* argument) {
    auto* saved = static_cast<Start*>(argument);
    auto entry = saved->entry;
    void* context = saved->argument;
    delete saved;
    ++active;
    void* result = entry(context);
    --active;
    return result;
}
}
extern "C" int __wrap_pthread_create(pthread_t* thread, const pthread_attr_t* attrs,
                                      void* (*entry)(void*), void* argument) {
    if (mode == "thread-error") return EAGAIN;
    auto* saved = new Start{entry, argument};
    int result = __real_pthread_create(thread, attrs, start, saved);
    if (result == 0) ++created;
    else delete saved;
    return result;
}
extern "C" int __wrap_pthread_join(pthread_t thread, void** value) {
    int result = __real_pthread_join(thread, value);
    if (result == 0) ++joined;
    return result;
}

namespace kernel_module {
KModErr get_offset_cache(const char* key, uint32_t& offset) {
    ++cache_get;
    contract &= std::string(key) == "task_struct_state";
    if (cached()) { offset = mode == "cache-zero" ? 0 : 144; return KModErr::OK; }
    if (mode == "cache-read-mutates" || mode == "cache-read-mutates-failure") offset = 77;
    return mode == "cache-read-error" || mode == "cache-read-mutates" || mode == "cache-read-mutates-failure"
            ? KModErr::ERR_MODULE_OFFSET_CACHE_READ : KModErr::ERR_MODULE_OFFSET_CACHE_NOT_FOUND;
}
KModErr put_offset_cache(const char* key, uint32_t offset) {
    ++cache_put; candidate = offset;
    contract &= std::string(key) == "task_struct_state";
    if (mode == "cache-write-error") return KModErr::ERR_MODULE_OFFSET_CACHE_WRITE;
    ++stored;
    return KModErr::OK;
}
KModErr read_kernel_mem(uint64_t address, void* buffer, uint32_t size) {
    ++kernel_reads;
    contract &= address == task_address && size == 128 && kernel_reads <= 3;
    if ((mode == "read1-error" && kernel_reads == 1) ||
        (mode == "read2-error" && kernel_reads == 2) ||
        (mode == "read3-error" && kernel_reads == 3)) return KModErr::ERR_MODULE_TEST_CHANNEL;
    if (kernel_reads == 1) contract &= !read_started;
    if (kernel_reads == 2) contract &= read_started && !read_finished;
    if (kernel_reads == 3) contract &= read_finished;
    auto* words = static_cast<uint32_t*>(buffer);
    std::fill(words, words + 32, mode == "zero-spurious" || mode == "cache-write-error" ? 0x200U : 0U);
    unsigned index = expected_candidate() / 4;
    if (mode == "zero-spurious") words[index] = 0;
    else {
        words[index] = 0;
        if (mode != "unchanged" && mode != "cache-read-mutates-failure" && kernel_reads == 2) {
            words[index] = mode == "blocked255" ? 255 : mode == "blocked256" ? 256 : 1;
            if (mode == "ambiguous") words[9] = 1;
        }
    }
    return KModErr::OK;
}
}
KModErr shellcode_current_task(uint64_t& task) {
    ++current_calls;
    if (mode == "current-error") return KModErr::ERR_MODULE_NOT_KADDR;
    task = mode == "current-zero" ? 0 : task_address;
    return KModErr::OK;
}

int main(int argc, char** argv) {
    if (argc != 2) return 2;
    mode = argv[1];
    int before_fds = descriptors();
    std::printf("{\"phase\":\"start\",\"case\":\"%s\"}\n", mode.c_str()); std::fflush(stdout);
    uint32_t offset = 999;
    KModErr actual = KModErr::ERR_MODULE_PARAM;
    bool thread_exception = false;
    try { actual = kernel_module::get_task_struct_state_offset(offset); }
    catch (const std::system_error&) { thread_exception = true; }
    KModErr expected = KModErr::OK;
    if (!match() || mode == "current-zero") expected = KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
    if (mode == "current-error") expected = KModErr::ERR_MODULE_NOT_KADDR;
    if (mode == "read1-error" || mode == "read2-error" || mode == "read3-error") expected = KModErr::ERR_MODULE_TEST_CHANNEL;
    if (mode == "worker-read-error" || mode == "worker-read-zero") expected = KModErr::ERR_MODULE_READ_FILE;
    if (mode == "wake-error" || mode == "wake-zero") expected = KModErr::ERR_MODULE_WRITE_FILE;
    if (mode == "pipe-error") expected = KModErr::ERR_MODULE_OPEN_FILE;
    if (mode == "cache-write-error") expected = KModErr::ERR_MODULE_OFFSET_CACHE_WRITE;
    if (mode == "thread-error") expected = KModErr::ERR_MODULE_PARAM;
    unsigned expected_put = is_ok(expected) && !cached() ? 1 : mode == "cache-write-error" ? 1 : 0;
    uint32_t expected_offset = is_ok(expected) ? (cached() ? (mode == "cache-zero" ? 0 : 144) : expected_candidate()) : 999;
    bool resources = opened == closed && active == 0 && created == joined && descriptors() == before_fds;
    bool calls = cache_get == 1 && cache_put == expected_put && stored == (is_ok(expected) && !cached() ? 1U : 0U);
    if (expected_put) calls &= candidate == expected_candidate();
    if (cached() || mode == "pipe-error" || mode == "thread-error") calls &= current_calls == 0 && kernel_reads == 0;
    else calls &= current_calls == 1;
    if (mode == "current-error" || mode == "current-zero") calls &= kernel_reads == 0;
    if (mode == "read1-error") calls &= kernel_reads == 1;
    if (mode == "read2-error") calls &= kernel_reads == 2;
    if (mode == "read3-error") calls &= kernel_reads == 3;
    if (mode == "worker-read-eintr" || mode == "both-eintr") calls &= read_calls == 2;
    if (mode == "wake-eintr" || mode == "both-eintr") calls &= write_calls == 2;
    bool passed = actual == expected && offset == expected_offset && resources && contract && calls
            && thread_exception == (mode == "thread-error");
    std::printf("{\"phase\":\"complete\",\"case\":\"%s\",\"passed\":%s,\"error\":%zd,\"expectedError\":%zd,"
                "\"offset\":%u,\"expectedOffset\":%u,\"opened\":%u,\"closed\":%u,\"created\":%u,\"joined\":%u,"
                "\"active\":%u,\"fdBefore\":%d,\"fdAfter\":%d,\"kernelReads\":%u,\"cachePut\":%u,"
                "\"stored\":%u,\"readCalls\":%u,\"writeCalls\":%u,\"threadException\":%s,\"contract\":%s}\n",
                mode.c_str(), passed ? "true" : "false", to_num(actual), to_num(expected), offset, expected_offset,
                opened.load(), closed.load(), created.load(), joined.load(), active.load(), before_fds, descriptors(),
                kernel_reads, cache_put, stored, read_calls.load(), write_calls.load(),
                thread_exception ? "true" : "false", contract ? "true" : "false");
    return passed ? 0 : 1;
}
