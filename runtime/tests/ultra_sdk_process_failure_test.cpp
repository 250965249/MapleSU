// Real archived SDK framing/fork path; only libc failure boundaries are controlled.
#include <cassert>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <dlfcn.h>
#include <future>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdexcept>
#include <sys/wait.h>
#include <unistd.h>
#include "module_err_def.h"
#include "maplesu_sdk/maplesu_su_auth.h"
#include "sdk_call_scope.h"
#ifdef MAPLESU_TEST_JNI_RECEIPTS
#include "jni_test_utf8.h"
#include "../ultra/bridge/native_lib_ultra.cpp"
#endif

namespace maplesu::sdk {
KModErr get_su_auth_list_with_cb(const char*, void (*)(const su_auth_item*));
}
namespace default_modules::module_root { KModErr set_current_root(bool) { return KModErr::OK; } }
bool gate_query_child = false;
int ready_pipe[2] = {-1, -1}, release_pipe[2] = {-1, -1};
namespace default_modules::module_su_redirect {
KModErr get_su_allowlist(void (*)(const maplesu::sdk::su_auth_item*)) {
    if (gate_query_child) {
        char token = 1;
        assert(write(ready_pipe[1], &token, 1) == 1);
        assert(read(release_pipe[0], &token, 1) == 1);
    }
    return KModErr::OK;
}
}
namespace {
thread_local bool fail_fork = false;
thread_local int fail_pipe_at = 0;
thread_local int pipe_calls = 0;
thread_local bool interrupt_wait = false;
thread_local pid_t sdk_child = -1;
using Fork = pid_t (*)();
using Pipe = int (*)(int*, int);
using Wait = pid_t (*)(pid_t, int*, int);
Fork real_fork = reinterpret_cast<Fork>(dlsym(RTLD_NEXT, "fork"));
Pipe real_pipe = reinterpret_cast<Pipe>(dlsym(RTLD_NEXT, "pipe2"));
Wait real_wait = reinterpret_cast<Wait>(dlsym(RTLD_NEXT, "waitpid"));
int open_fds() {
    DIR* directory = opendir("/proc/self/fd"); assert(directory);
    int count = 0;
    while (readdir(directory)) ++count;
    closedir(directory); return count;
}
pid_t finished_fixture() {
    const pid_t child = real_fork(); assert(child >= 0);
    if (child == 0) _exit(0);
    siginfo_t state{};
    assert(waitid(P_PID, child, &state, WEXITED | WNOWAIT) == 0 && state.si_pid == child);
    return child;
}
}

extern "C" pid_t fork() noexcept(noexcept(::fork())) {
    if (fail_fork) { fail_fork = false; errno = EAGAIN; return -1; }
    const pid_t child = real_fork();
    if (child > 0) sdk_child = child;
    return child;
}
extern "C" int pipe2(int* fds, int flags) noexcept(noexcept(::pipe2(fds, flags))) {
    if (++pipe_calls == fail_pipe_at) { errno = EMFILE; return -1; }
    return real_pipe(fds, flags);
}
extern "C" pid_t waitpid(pid_t child, int* status, int flags) {
    if (interrupt_wait) { interrupt_wait = false; errno = EINTR; return -1; }
    return real_wait(child, status, flags);
}

#ifdef MAPLESU_TEST_JNI_RECEIPTS
namespace maplesu::sdk {
KModErr environment_channel_error = KModErr::OK;
unsigned int environment_channel_queries = 0;
KModErr test_maplesu_basics_with_cb(const char*, BasicItem item, void (*)(const char*)) {
    assert(item == BasicItem::Channel);
    ++environment_channel_queries;
    return environment_channel_error;
}
// Mirror the archive's enum-only state return when subprocess transport fails.
MapleSUEnvState get_maplesu::sdkironment_state(const char* key) {
    get_su_auth_list_with_cb(key, [](const su_auth_item*) {});
    return MapleSUEnvState::NotInstalled;
}
}
void check_environment_channel_receipts() {
    std::string output;
    static std::string* result = &output;
    result = &output;
    JNINativeInterface table{};
    table.NewStringUTF = [](JNIEnv*, const char* text) -> jstring { *result = text; return nullptr; };
    table.NewString = [](JNIEnv*, const jchar* characters, jsize length) -> jstring {
        *result = jni_test_utf16_to_utf8(characters, length);
        return nullptr;
    };
    table.GetStringUTFChars = [](JNIEnv*, jstring text, jboolean*) -> const char* { return reinterpret_cast<const char*>(text); };
    table.ReleaseStringUTFChars = [](JNIEnv*, jstring, const char*) {};
    JNIEnv environment{&table};
    const auto key = reinterpret_cast<jstring>(const_cast<char*>("environment-query-key"));
    for (const auto error : {KModErr::OK, KModErr::ERR_MODULE_NO_BOOT,
                            KModErr::ERR_MODULE_ROOT_KEY, KModErr::ERR_MODULE_TEST_CHANNEL}) {
        maplesu::sdk::environment_channel_error = error;
        Java_dev_maplesu_manager_runtime_ultra_bridge_NativeBridge_getEnvironmentState(&environment, nullptr, key);
        cJSON* root = cJSON_Parse(output.c_str()); assert(root);
        assert(cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(root, "ok")));
        assert(std::strcmp(cJSON_GetObjectItemCaseSensitive(root, "sdkError")->valuestring,
                           "OK") == 0);
        assert(std::strcmp(cJSON_GetObjectItemCaseSensitive(
            cJSON_GetObjectItemCaseSensitive(root, "data"), "state")->valuestring, "NotInstalled") == 0);
        assert(maplesu::sdk::environment_channel_queries == 0 &&
               "NotInstalled must not trigger a second independent Channel query");
        cJSON_Delete(root);
    }
    std::puts("PASS environment-channel: genuine NotInstalled performs no duplicate Channel query; transport failures are checked separately");
}
void check_jni_receipts(const char* mode) {
    std::string output;
    static std::string* receipt_output = nullptr;
    receipt_output = &output;
    JNINativeInterface table{};
    table.NewStringUTF = [](JNIEnv*, const char* text) -> jstring { *receipt_output = text; return nullptr; };
    table.NewString = [](JNIEnv*, const jchar* characters, jsize length) -> jstring {
        *receipt_output = jni_test_utf16_to_utf8(characters, length);
        return nullptr;
    };
    table.GetStringUTFChars = [](JNIEnv*, jstring text, jboolean*) -> const char* { return reinterpret_cast<const char*>(text); };
    table.ReleaseStringUTFChars = [](JNIEnv*, jstring, const char*) {};
    JNIEnv environment{&table};
    const auto key = reinterpret_cast<jstring>(const_cast<char*>("jni-process-query-key"));
    for (int entry : {0, 1, 2}) {
        fail_fork = std::strcmp(mode, "fork") == 0;
        fail_pipe_at = std::strcmp(mode, "pipe1") == 0 ? 1 : std::strcmp(mode, "pipe2") == 0 ? 2 : 0;
        interrupt_wait = std::strcmp(mode, "eintr") == 0;
        pipe_calls = 0;
        if (entry == 0) Java_dev_maplesu_manager_runtime_ultra_bridge_NativeBridge_getSuAuthList(&environment, nullptr, key);
        else if (entry == 1) Java_dev_maplesu_manager_runtime_ultra_bridge_NativeBridge_getEnvironmentState(&environment, nullptr, key);
        else guarded(&environment, "install_module", [&](cJSON* root) {
            const auto result = maplesu::sdk::get_su_auth_list_with_cb("jni-exclusive-key", [](const maplesu::sdk::su_auth_item*) {});
            if (is_failed(result)) mark_sdk_error(root, result, "fixture transport failed"); else mark_ok(root);
        });
        cJSON* root = cJSON_Parse(output.c_str()); assert(root);
        const bool success = std::strcmp(mode, "eintr") == 0;
        assert(cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(root, "ok")) == success);
        const auto error = cJSON_GetObjectItemCaseSensitive(root, "sdkError");
        assert(cJSON_IsString(error) && std::strcmp(error->valuestring, success ? "OK" : "MAPLESU_SDK_PROCESS_ERROR") == 0);
        int errors = 0, codes = 0, reasons = 0;
        for (auto field = root->child; field; field = field->next) {
            errors += std::strcmp(field->string, "sdkError") == 0;
            codes += std::strcmp(field->string, "sdkErrorCode") == 0;
            reasons += std::strcmp(field->string, "reason") == 0;
        }
        assert(errors == 1 && codes == 1 && reasons == (success ? 0 : 1));
        if (!success) {
            assert(cJSON_GetObjectItemCaseSensitive(root, "sdkErrorCode")->valueint == -1006);
            assert(!cJSON_HasObjectItem(root, "data"));
        }
        cJSON_Delete(root);
    }
    std::printf("PASS %s: production read/exclusive guard receipts / no duplicate fields / failed enum query is not NotInstalled\n", mode);
}
#endif

void check_concurrent_failure() {
    assert(pipe(ready_pipe) == 0 && pipe(release_pipe) == 0);
    gate_query_child = true;
    auto healthy = std::async(std::launch::async, [] {
        maplesu::SdkCallScope scope("get_su_auth_list"); assert(scope.acquired());
        const auto result = maplesu::sdk::get_su_auth_list_with_cb("healthy-query-key-01", [](const maplesu::sdk::su_auth_item*) {});
#ifdef MAPLESU_TEST_PROCESS_FAILURE_FIX
        assert(scope.process_error() == 0);
#endif
        return result;
    });
    char token;
    assert(read(ready_pipe[0], &token, 1) == 1);
    {
        maplesu::SdkCallScope scope("get_su_auth_list"); assert(scope.acquired());
        fail_fork = true;
        assert(is_failed(maplesu::sdk::get_su_auth_list_with_cb("failed-query-key-02", [](const maplesu::sdk::su_auth_item*) {})));
#ifdef MAPLESU_TEST_PROCESS_FAILURE_FIX
        assert(scope.process_error() == EAGAIN);
#endif
        assert(healthy.wait_for(std::chrono::milliseconds(0)) == std::future_status::timeout);
    }
    assert(write(release_pipe[1], &token, 1) == 1);
    assert(healthy.get() == KModErr::OK);
    gate_query_child = false;
    for (int fd : {ready_pipe[0], ready_pipe[1], release_pipe[0], release_pipe[1]}) close(fd);
    std::puts("PASS concurrent: failed read returns while healthy SDK child remains running / errors stay isolated");
}

void check_inherited_pipes() {
    int orphan[2], later[2], report[2], release[2];
    assert(pipe(report) == 0 && pipe(release) == 0);
    std::promise<void> first_ready, second_ready, child_created;
    auto first_ready_signal = first_ready.get_future();
    auto second_ready_signal = second_ready.get_future();
    auto child_created_signal = child_created.get_future();
    auto first = std::async(std::launch::async, [&] {
        maplesu::SdkCallScope scope("get_su_auth_list"); assert(scope.acquired());
        assert(pipe2(orphan, O_CLOEXEC) == 0);
        first_ready.set_value();
        second_ready_signal.wait();
        child_created_signal.wait();
        close(orphan[1]);
        pollfd event{orphan[0], POLLIN, 0};
        const bool eof = poll(&event, 1, 200) > 0 && (event.revents & POLLHUP);
        close(orphan[0]);
        return eof;
    });
    first_ready_signal.wait();
    auto second = std::async(std::launch::async, [&] {
        maplesu::SdkCallScope scope("get_su_auth_list"); assert(scope.acquired());
        assert(pipe2(later, O_CLOEXEC) == 0);
        second_ready.set_value();
        const pid_t child = fork(); assert(child >= 0);
        if (child == 0) {
            char token = 1;
            // This worker stays alive while the other query loses its writer.
            if (write(report[1], &token, 1) != 1) _exit(1);
            if (read(release[0], &token, 1) != 1) _exit(1);
            _exit(0);
        }
        child_created.set_value();
        int status = 0;
        assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
        close(later[0]); close(later[1]);
    });
    char token;
    assert(read(report[0], &token, 1) == 1);
    const bool eof = first.get();
    assert(write(release[1], &token, 1) == 1);
    second.get();
    for (int fd : {report[0], report[1], release[0], release[1]}) close(fd);
    assert(eof && "sibling SDK worker kept another query's pipe writer open");
    std::puts("PASS inherited-pipes: sibling worker closes foreign SDK pipes / EOF arrives before sibling exits");
}

void check_child_unwind() {
    for (const char* operation : {"get_su_auth_list", "install_module"}) {
        pid_t child = -1;
        try {
            maplesu::SdkCallScope scope(operation); assert(scope.acquired());
            child = fork(); assert(child >= 0);
            if (child == 0) throw std::runtime_error("worker fixture");
        } catch (const std::runtime_error&) {
            // A bridge exception handler would continue into JNI/JVM here.
            if (child == 0) _exit(0);
            throw;
        }
        int status = 0;
        assert(waitpid(child, &status, 0) == child);
        assert(WIFEXITED(status) && WEXITSTATUS(status) == 125 && "SDK child exception escaped back into its caller");
    }
    std::puts("PASS child-unwind: read and exclusive SDK worker exceptions terminate before parent locks or JNI");
}

int main(int argc, char** argv) {
    #ifdef MAPLESU_TEST_JNI_RECEIPTS
    if (argc == 2 && std::strcmp(argv[1], "environment-channel") == 0) { check_environment_channel_receipts(); return 0; }
    #endif
    assert(argc == 2 && real_fork && real_pipe && real_wait);
    if (std::strcmp(argv[1], "concurrent") == 0) { check_concurrent_failure(); return 0; }
    if (std::strcmp(argv[1], "inherited-pipes") == 0) { check_inherited_pipes(); return 0; }
    if (std::strcmp(argv[1], "child-unwind") == 0) { check_child_unwind(); return 0; }
    const bool exclusive = std::strncmp(argv[1], "exclusive-", 10) == 0;
    const char* mode = argv[1] + (exclusive ? 10 : 0);
    const bool interrupted = std::strcmp(mode, "eintr") == 0;
    const pid_t unrelated = finished_fixture();
    const int fds = open_fds();
    {
        maplesu::SdkCallScope scope(exclusive ? "install_module" : "get_su_auth_list"); assert(scope.acquired());
        fail_fork = std::strcmp(mode, "fork") == 0;
        fail_pipe_at = std::strcmp(mode, "pipe1") == 0 ? 1 : std::strcmp(mode, "pipe2") == 0 ? 2 : 0;
        interrupt_wait = interrupted;
        pipe_calls = 0;
        const auto result = maplesu::sdk::get_su_auth_list_with_cb("failure-query-key", [](const maplesu::sdk::su_auth_item*) {});
        assert(interrupted ? result == KModErr::OK : is_failed(result));
#ifdef MAPLESU_TEST_PROCESS_FAILURE_FIX
        assert(scope.process_error() == (interrupted ? 0 : fail_pipe_at ? EMFILE : EAGAIN));
#endif
        int status = 0;
        assert(real_wait(unrelated, &status, WNOHANG) == unrelated && "SDK failure consumed another task's child");
        if (interrupted) {
            errno = 0;
            assert(real_wait(sdk_child, &status, WNOHANG) == -1 && errno == ECHILD && "interrupted SDK wait left its child unreaped");
        }
    }
    assert(open_fds() == fds);
    {
        maplesu::SdkCallScope scope(exclusive ? "install_module" : "get_su_auth_list"); assert(scope.acquired());
#ifdef MAPLESU_TEST_PROCESS_FAILURE_FIX
        assert(scope.process_error() == 0);
#endif
        fail_pipe_at = 0;
        assert(maplesu::sdk::get_su_auth_list_with_cb("next-query-key-01", [](const maplesu::sdk::su_auth_item*) {}) == KModErr::OK);
    }
#ifdef MAPLESU_TEST_JNI_RECEIPTS
    check_jni_receipts(mode);
#endif
    // Healthy exclusive calls retain legacy process-group wait semantics.
    {
        maplesu::SdkCallScope scope("install_module"); assert(scope.acquired());
        for (const pid_t group : {0, -1}) {
            const pid_t legacy = finished_fixture();
            int status = 0;
            assert(waitpid(group, &status, WNOHANG) == legacy);
            assert(scope.process_error() == 0);
            errno = 0;
            assert(waitpid(group, &status, WNOHANG) == -1 && errno == ECHILD);
            assert(scope.process_error() == 0 && "legacy group-wait completion is not a failed SDK transport");
        }
        const pid_t legacy = finished_fixture();
        int status = 0;
        interrupt_wait = true;
        assert(waitpid(0, &status, WNOHANG) == -1 && errno == EINTR);
        assert(scope.process_error() == 0);
        assert(waitpid(0, &status, WNOHANG) == legacy);
    }
    // Calls outside SDK admission also keep libc semantics.
    const pid_t legacy = finished_fixture();
    int status = 0;
    assert(waitpid(0, &status, WNOHANG) == legacy);
    std::printf("PASS %s: own child only / fd cleanup / next query / legacy wait preserved\n", argv[1]);
}

