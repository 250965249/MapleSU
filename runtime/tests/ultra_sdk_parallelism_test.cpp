#include <atomic>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <chrono>
#include <future>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>
#include <sys/wait.h>
#include <unistd.h>
#include "module_err_def.h"
#include "maplesu_sdk/maplesu_su_auth.h"

#ifdef MAPLESU_TEST_CALL_SCOPE
#include "sdk_call_scope.h"
#endif

extern "C" void __set_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW(const char*);
extern "C" const char* __get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW();

namespace maplesu::sdk {
KModErr get_su_auth_list_with_cb(const char*, void (*)(const su_auth_item*));
}
// Only kernel/root I/O is substituted; list framing, fork and callback replay are SDK IR.
namespace default_modules::module_root { KModErr set_current_root(bool) { return KModErr::OK; } }
unsigned query_delay_us = 0;
bool query_failed = false;
namespace default_modules::module_su_redirect {
KModErr get_su_allowlist(void (*callback)(const maplesu::sdk::su_auth_item*)) {
    if (query_delay_us) usleep(query_delay_us);
    if (query_failed) return KModErr::ERR_MODULE_PARAM;
    maplesu::sdk::su_auth_item item;
    std::strncpy(item.app_package_name, __get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW(), 255);
    callback(&item);
    return KModErr::OK;
}
}
thread_local std::string callback_result;

void check_fork_context(const char* key) {
    const pid_t child = fork();
    assert(child >= 0);
    if (child == 0) _exit(std::strcmp(__get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW(), key) == 0 ? 0 : 1);
    int status = 0;
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

int main() {
    constexpr const char* legacy = "legacy-module-key";
    __set_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW(legacy);
    std::atomic<int> entered{0};
    std::atomic<int> mismatches{0};
    auto read = [&](const char* key) {
#ifdef MAPLESU_TEST_CALL_SCOPE
        maplesu::SdkCallScope scope("get_su_auth_list");
        assert(scope.acquired());
#endif
        __set_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW(key);
        entered.fetch_add(1);
        while (entered.load() < 2) std::this_thread::yield();
        if (std::strcmp(__get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW(), key))
            mismatches.fetch_add(1);
#ifdef MAPLESU_TEST_CALL_SCOPE
        check_fork_context(key);
        for (int i = 0; i < 20; ++i) {
            callback_result.clear();
            assert(maplesu::sdk::get_su_auth_list_with_cb(key, [](const maplesu::sdk::su_auth_item* item) {
                callback_result = item->app_package_name;
            }) == KModErr::OK);
            assert(callback_result == key);
        }
#endif
    };
    std::thread first(read, "first-query-key-01");
    std::thread second(read, "second-query-key-02");
    first.join(); second.join();
    assert(mismatches.load() == 0 && "SDK root key crossed between concurrent queries");
    assert(std::strcmp(__get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW(), legacy) == 0);
    puts("PASS concurrent SDK key isolation / legacy module context preserved");
#ifdef MAPLESU_TEST_CALL_SCOPE
    puts("PASS fork inheritance / 40 real SDK list transports and callbacks isolated");
    using namespace std::chrono_literals;
    std::promise<void> release_read;
    auto release = release_read.get_future().share();
    std::promise<void> started;
    auto reader = std::async(std::launch::async, [&] {
        maplesu::SdkCallScope scope("get_all_modules_list");
        assert(scope.acquired()); started.set_value(); release.wait();
    });
    started.get_future().wait();
    auto busy = std::async(std::launch::async, [&] {
        maplesu::SdkCallScope scope("install_module");
        return scope.acquired();
    });
    assert(busy.wait_for(100ms) == std::future_status::timeout);
    assert(!busy.get());
    {
        maplesu::SdkCallScope local("get_sdk_build_identity"); assert(local.acquired());
        maplesu::SdkCallScope second_read("get_su_auth_list"); assert(second_read.acquired());
        auto third = std::async(std::launch::async, [] {
            maplesu::SdkCallScope scope("get_module_control"); return scope.acquired();
        });
        assert(!third.get());
    }
    release_read.set_value(); reader.get();
    {
        maplesu::SdkCallScope writer("uninstall_maplesu_environment"); assert(writer.acquired());
        auto read_during_write = std::async(std::launch::async, [] {
            maplesu::SdkCallScope scope("get_all_modules_list"); return scope.acquired();
        });
        assert(!read_during_write.get());
        maplesu::SdkCallScope local("get_system_status"); assert(local.acquired());
    }
    try {
        maplesu::SdkCallScope scope("get_su_auth_list"); assert(scope.acquired());
        __set_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW("exception-query-key");
        throw std::runtime_error("fixture");
    } catch (const std::runtime_error&) {}
    assert(std::strcmp(__get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW(), legacy) == 0);
    {
        maplesu::SdkCallScope last("unknown-operation"); assert(last.acquired());
    }
    assert(maplesu::sdk_call_access("unknown-operation") == maplesu::SdkCallAccess::Exclusive);
    puts("PASS two-reader limit / writes exclude reads / local status bypass / timeout and exception cleanup");
    auto query = [] {
        maplesu::SdkCallScope scope("get_su_auth_list"); assert(scope.acquired());
        callback_result.clear();
        const auto error = maplesu::sdk::get_su_auth_list_with_cb("benchmark-query-key", [](const maplesu::sdk::su_auth_item* item) {
            callback_result = item->app_package_name;
        });
        if (!is_failed(error)) assert(callback_result == "benchmark-query-key");
        else assert(callback_result.empty());
        return error;
    };
    query_failed = true; assert(query() == KModErr::ERR_MODULE_PARAM);
    query_failed = false; assert(query() == KModErr::OK);
    puts("PASS SDK error preserved / next read succeeds without replay");
    query_delay_us = 200000;
    auto start = std::chrono::steady_clock::now();
    assert(query() == KModErr::OK); assert(query() == KModErr::OK);
    const auto serial = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();
    start = std::chrono::steady_clock::now();
    auto a = std::async(std::launch::async, query);
    auto b = std::async(std::launch::async, query);
    assert(a.get() == KModErr::OK && b.get() == KModErr::OK);
    const auto parallel = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();
    printf("BENCH real SDK transport, controlled 200ms I/O per query: serial=%lldms parallel=%lldms\n",
        static_cast<long long>(serial), static_cast<long long>(parallel));
    query_delay_us = 0;
    {
        maplesu::SdkCallScope writer("install_module"); assert(writer.acquired());
        __set_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW("legacy-worker-key");
        std::thread module_worker([] {
            assert(std::strcmp(__get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW(), "legacy-worker-key") == 0);
        });
        module_worker.join();
    }
    puts("PASS exclusive legacy work retains process context for its worker threads");
#endif
}
