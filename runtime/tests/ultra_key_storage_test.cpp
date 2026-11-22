#include <atomic>
#include <cassert>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>
#include <vector>
#include <pthread.h>
#include <sys/wait.h>
#include <unistd.h>

extern "C" void __set_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW(const char*);
extern "C" const char* __get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW();
extern "C" void __set_current_module_id32_1b0494ae8a788541db46b82cc1f0577c(const char*);
extern "C" const char* __get_current_module_id32_1b0494ae8a788541db46b82cc1f0577c();

namespace {
void set_key(const char* key) {
    __set_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW(key);
}
const char* get_key() {
    return __get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW();
}
#if !defined(MAPLESU_TEST_ATFORK_FAILURE) && !defined(MAPLESU_TEST_MUTEX_FAILURE)
bool repeated_key(const char* key) {
    if (std::strlen(key) != 1023 || (key[0] != 'A' && key[0] != 'B')) return false;
    for (size_t i = 1; i < 1023; ++i) if (key[i] != key[0]) return false;
    return true;
}
#endif
}

#ifdef MAPLESU_TEST_ATFORK_FAILURE
extern "C" int __wrap_pthread_atfork(void (*)(), void (*)(), void (*)()) { return ENOMEM; }
#endif
#ifdef MAPLESU_TEST_MUTEX_FAILURE
bool fail_mutex = false;
extern "C" int __real_pthread_mutex_lock(pthread_mutex_t*);
extern "C" int __wrap_pthread_mutex_lock(pthread_mutex_t* mutex) {
    return fail_mutex ? EBUSY : __real_pthread_mutex_lock(mutex);
}
#endif

int main() {
#ifdef MAPLESU_TEST_ATFORK_FAILURE
    errno = 0;
    set_key("0123456789abcdef");
    assert(errno == ENOMEM);
    errno = 0;
    const char* unavailable = get_key();
    assert(unavailable && unavailable[0] == '\0' && errno == ENOMEM);
    set_key(unavailable);
    assert(get_key()[0] == '\0');
    std::thread reader([] {
        errno = 0;
        assert(get_key()[0] == '\0' && errno == ENOMEM);
    });
    reader.join();
    puts("PASS key storage registration failure returns empty identity and errno");
    return 0;
#elif defined(MAPLESU_TEST_MUTEX_FAILURE)
    set_key("original-key-context");
    const char* borrowed = get_key();
    fail_mutex = true;
    errno = 0;
    set_key("unpublished-key-context");
    assert(errno == EBUSY && std::strcmp(borrowed, "original-key-context") == 0);
    errno = 0;
    assert(get_key()[0] == '\0' && errno == EBUSY);
    fail_mutex = false;
    assert(std::strcmp(get_key(), "original-key-context") == 0);
    puts("PASS failed storage locks preserve authority and report an empty getter identity");
    return 0;
#else
    assert(get_key() && get_key()[0] == '\0');
    for (size_t size : {size_t(0), size_t(1), size_t(16), size_t(48), size_t(1023), size_t(1024), size_t(2048)}) {
        const std::string input(size, 'K');
        errno = EDOM;
        set_key(input.c_str());
        const char* actual = get_key();
        assert(std::strlen(actual) == (size < 1023 ? size : 1023));
        assert(std::string(actual) == input.substr(0, 1023));
        assert(errno == EDOM);
    }
    set_key(nullptr);
    assert(get_key()[0] == '\0');
    char unterminated[1023];
    std::memset(unterminated, 'N', sizeof(unterminated));
    set_key(unterminated);
    assert(std::strlen(get_key()) == sizeof(unterminated));
    set_key("short");
    const char* padded = get_key();
    for (size_t i = 5; i < 1024; ++i) assert(padded[i] == '\0');

    const std::string first(48, 'A'), second(48, 'B');
    set_key(first.c_str());
    const char* borrowed = get_key();
    std::thread publisher([&] { set_key(second.c_str()); });
    publisher.join();
    assert(std::strcmp(borrowed, first.c_str()) == 0);
    // Self-set must copy the borrowed identity before publishing it globally.
    set_key(borrowed);
    assert(std::strcmp(get_key(), first.c_str()) == 0);
    set_key(second.c_str());
    assert(std::strcmp(borrowed, first.c_str()) == 0);
    assert(get_key() == borrowed && std::strcmp(borrowed, second.c_str()) == 0);
    std::thread worker([&] { assert(std::strcmp(get_key(), second.c_str()) == 0); });
    worker.join();
    puts("PASS legacy lengths, truncation, null clearing, stable snapshot and global worker context");

    __set_current_module_id32_1b0494ae8a788541db46b82cc1f0577c("module-context");
    assert(std::strcmp(__get_current_module_id32_1b0494ae8a788541db46b82cc1f0577c(), "module-context") == 0);

    const std::string a(1023, 'A'), b(1023, 'B');
    set_key(a.c_str());
    std::atomic<bool> start{false};
    std::atomic<unsigned> failures{0};
    std::vector<std::thread> threads;
    for (const auto* value : {&a, &b}) threads.emplace_back([&, value] {
        while (!start.load(std::memory_order_acquire)) std::this_thread::yield();
        for (unsigned i = 0; i < 10000; ++i) set_key(value->c_str());
    });
    for (unsigned n = 0; n < 2; ++n) threads.emplace_back([&] {
        while (!start.load(std::memory_order_acquire)) std::this_thread::yield();
        for (unsigned i = 0; i < 10000; ++i) {
            const char* snapshot = get_key();
            if (!repeated_key(snapshot)) failures.fetch_add(1, std::memory_order_relaxed);
            std::this_thread::yield();
            if (!repeated_key(snapshot)) failures.fetch_add(1, std::memory_order_relaxed);
        }
    });
    start.store(true, std::memory_order_release);
    for (auto& thread : threads) thread.join();
    assert(failures.load() == 0);
    puts("PASS concurrent readers observe whole identities without torn bytes");

    std::atomic<bool> stop{false};
    std::thread writer([&] {
        while (!stop.load(std::memory_order_acquire)) {
            set_key(a.c_str());
            set_key(b.c_str());
        }
    });
    for (unsigned i = 0; i < 16; ++i) {
        const pid_t child = fork();
        assert(child >= 0);
        if (child == 0) {
            alarm(2);
            if (!repeated_key(get_key())) _exit(1);
            set_key("child-key-context");
            _exit(std::strcmp(get_key(), "child-key-context") == 0 ? 0 : 2);
        }
        int status = 0;
        pid_t waited;
        do { waited = waitpid(child, &status, 0); } while (waited < 0 && errno == EINTR);
        assert(waited == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
        assert(repeated_key(get_key()));
    }
    stop.store(true, std::memory_order_release);
    writer.join();
    set_key(first.c_str());
    assert(std::strcmp(get_key(), first.c_str()) == 0);
    puts("PASS fork children and parent continue reads and writes during concurrent publication");
#endif
}
