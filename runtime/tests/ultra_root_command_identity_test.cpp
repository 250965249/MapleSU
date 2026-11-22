// Production JNI bodies/guards are extracted by test-root-command-identity.py.
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>
#include "cJSON.h"
#include "urlEncodeUtils.h"
#include "sdk_call_scope.h"
#include "sdk_error_receipt.h"
#include "manager_owner_identity.h"
#include "manager_owner_root_probe.h"
#include "maplesu_root_command_private.h"

using jstring = const char*;
using jclass = void*;
using jchar = uint16_t;
using jsize = int;
#define JNIEXPORT
#define JNICALL
struct JNIEnv {
    std::string answer;
    bool exception = false;
    const char* GetStringUTFChars(jstring value, void*) { return value; }
    void ReleaseStringUTFChars(jstring, const char*) {}
    bool ExceptionCheck() const { return exception; }
    jstring NewStringUTF(const char* value) { answer = value; return answer.c_str(); }
    jstring NewString(const jchar* value, jsize size) {
        answer.clear();
        for (int index = 0; index < size; ++index) answer += static_cast<char>(value[index]);
        return answer.c_str();
    }
};

namespace fixture {
int failures, calls, mode_sets, restores, allocation_after = -1;
bool null_key, throw_sdk, acquired = true;
int process_error;
std::string key, command;
kernel_module::RequestAuthMode mode = kernel_module::RequestAuthMode::LegacyKey;
KModErr sdk_error = KModErr::OK, select_error = KModErr::OK, restore_error = KModErr::OK;
maplesu::sdk::RootCommandResult diagnostic;
void* allocate(size_t size) {
    if (allocation_after == 0) { allocation_after = -1; return nullptr; }
    if (allocation_after > 0) --allocation_after;
    return std::malloc(size);
}
char* print(cJSON* value) {
    // The allocation sweep targets JSON assembly, before VM/string serialization.
    allocation_after = -1;
    return cJSON_PrintUnformatted(value);
}
int allocation_offset = -1;
void reset() {
    calls = mode_sets = restores = process_error = 0;
    null_key = throw_sdk = false; acquired = true;
    key.clear(); command.clear(); mode = kernel_module::RequestAuthMode::LegacyKey;
    sdk_error = select_error = restore_error = KModErr::OK;
    allocation_after = allocation_offset = -1;
    diagnostic = {};
    diagnostic.phase = maplesu::sdk::RootCommandPhase::VendorOplusGuard;
    diagnostic.error = KModErr::ERR_MODULE_OPEN_FILE;
    diagnostic.system_error = 13;
    diagnostic.child_status = 0;
    diagnostic.child_status_valid = true;
    diagnostic.receipt_complete = true;
}
void check(bool value, const char* message) {
    if (!value) { ++failures; std::cerr << "FAIL: " << message << '\n'; }
}
}

namespace kernel_module {
uint64_t maplesu_request_auth_state() { return static_cast<uint64_t>(fixture::mode); }
KModErr maplesu_request_set_auth_mode(RequestAuthMode requested) {
    ++fixture::mode_sets;
    const bool restoring = requested == RequestAuthMode::LegacyKey;
    if (restoring) ++fixture::restores;
    const auto result = restoring ? fixture::restore_error : fixture::select_error;
    if (is_ok(result)) fixture::mode = requested;
    return result;
}
CleanupReceiptScope::CleanupReceiptScope() noexcept {}
CleanupReceiptScope::~CleanupReceiptScope() noexcept {}
}
namespace maplesu {
SdkCallScope::SdkCallScope(const char*) { acquired_ = fixture::acquired; context_.process_error = fixture::process_error; }
SdkCallScope::~SdkCallScope() = default;
namespace ultra { void retain_authorization_result_on_process_failure(cJSON*) {} }
namespace sdk {
KModErr run_root_cmd(const char* key, const char* command, std::string& output) {
    ++fixture::calls;
    fixture::null_key = key == nullptr;
    fixture::key = key ? key : "";
    fixture::command = command;
    if (fixture::throw_sdk) throw std::runtime_error("SDK fixture exception");
    output = "root fixture\n";
    fixture::allocation_after = fixture::allocation_offset;
    return fixture::sdk_error;
}
RootCommandResult current_root_command_result() { return fixture::diagnostic; }
}
}

constexpr int kSchemaVersion = 1, kBridgeVersion = 1;
constexpr int kBridgeException = -1001, kBridgeAlloc = -1003, kBridgeProcess = -1006;
#define cJSON_PrintUnformatted fixture::print
#include "root_command_production.inc"
#undef cJSON_PrintUnformatted

using Tree = std::unique_ptr<cJSON, JsonDeleter>;
Tree invoke(jstring key = nullptr) {
    JNIEnv env;
    const auto raw = Java_dev_maplesu_manager_runtime_ultra_bridge_NativeBridge_runRootCmd(&env, nullptr, key, "id -u");
    Tree result(cJSON_Parse(raw));
    assert(result);
    return result;
}
cJSON* field(cJSON* object, const char* key) { return cJSON_GetObjectItemCaseSensitive(object, key); }
int number(cJSON* object, const char* key) { const auto* value = field(object, key); return value ? value->valueint : INT32_MIN; }
bool truth(cJSON* object, const char* key) { return cJSON_IsTrue(field(object, key)); }

int main() {
    cJSON_Hooks hooks{fixture::allocate, std::free};
    cJSON_InitHooks(&hooks);
    using fixture::check;
    fixture::reset();
    auto owner = invoke();
    check(fixture::calls == 1 && fixture::null_key, "genuine null reaches SDK once as nullptr");
    check(fixture::mode_sets == 2 && fixture::restores == 1 && fixture::mode == kernel_module::RequestAuthMode::LegacyKey,
        "Owner selects and restores the actual RequestAuthModeScope once");
    check(truth(owner.get(), "ok") && truth(owner.get(), "operationCompleted"), "SDK success retains completion");
    auto* data = field(owner.get(), "data");
    check(number(data, "resultBytes") == 13 && std::string(field(data, "result")->valuestring) == "root+fixture%0A",
        "output bytes and URL encoding survive");
    auto* root = field(data, "rootCommand");
    check(number(root, "phase") == 5 && number(root, "systemError") == 13 && number(root, "childStatus") == 0 &&
        truth(root, "childStatusValid") && truth(root, "receiptComplete") && !truth(root, "rootAttempted"),
        "original root command failure diagnostics are retained");

    fixture::reset();
    auto legacy = invoke("valid-key-fixture");
    check(fixture::calls == 1 && !fixture::null_key && fixture::key == "valid-key-fixture" && fixture::mode_sets == 0,
        "explicit Key stays explicit and preserves Legacy mode");
    fixture::reset();
    auto empty = invoke("");
    check(fixture::calls == 1 && !fixture::null_key && fixture::key.empty() && fixture::mode_sets == 0,
        "explicit empty Key stays non-null at JNI; SDK owns rejection");

    fixture::reset(); fixture::sdk_error = KModErr::ERR_MODULE_OPEN_FILE; fixture::restore_error = KModErr::ERR_MODULE_TEST_CHANNEL;
    auto denied = invoke();
    check(number(denied.get(), "sdkErrorCode") == to_num(KModErr::ERR_MODULE_OPEN_FILE), "SDK first failure survives restore failure");
    check(number(denied.get(), "authModeRestoreErrorCode") == to_num(KModErr::ERR_MODULE_TEST_CHANNEL) &&
        fixture::calls == 1 && fixture::restores == 1 && !truth(denied.get(), "operationCompleted"),
        "failed SDK call is never retried and restore is reported separately");

    fixture::reset(); fixture::restore_error = KModErr::ERR_MODULE_TEST_CHANNEL;
    auto restored = invoke();
    check(number(restored.get(), "sdkErrorCode") == to_num(KModErr::ERR_MODULE_TEST_CHANNEL) &&
        !truth(restored.get(), "ok") && truth(restored.get(), "operationCompleted"),
        "successful operation with failed restore keeps its completed fact");
    fixture::reset(); fixture::select_error = KModErr::ERR_MODULE_TEST_CHANNEL;
    auto select = invoke();
    check(fixture::calls == 0 && number(select.get(), "sdkErrorCode") == to_num(KModErr::ERR_MODULE_TEST_CHANNEL),
        "auth selection failure prevents submission");
    fixture::reset(); fixture::throw_sdk = true;
    auto exception = invoke();
    check(fixture::calls == 1 && fixture::restores == 1 && number(exception.get(), "sdkErrorCode") == kBridgeException,
        "SDK exception restores identity exactly once without replay");
    fixture::reset(); fixture::process_error = 5; fixture::sdk_error = KModErr::ERR_MODULE_OPEN_FILE;
    auto process = invoke();
    check(number(process.get(), "sdkErrorCode") == to_num(KModErr::ERR_MODULE_OPEN_FILE) &&
        number(process.get(), "bridgeErrorCode") == kBridgeProcess, "SDK first failure survives process failure");

    fixture::reset();
    fixture::diagnostic.root_attempted = fixture::diagnostic.root_returned = fixture::diagnostic.root_report_received = true;
    auto& transition = fixture::diagnostic.root_transition;
    transition.phase = "task_state"; transition.owner_mode = true; transition.credentials_attempted = true;
    transition.credentials.command = 11; transition.credentials.effects = 4; transition.credentials.completed = true;
    transition.task_state_attempted = true; transition.task_state.command = 25; transition.task_state.completed = true;
    transition.threads_total = 8; transition.cpuset_moved = 7; transition.stune_moved = 6; transition.cgroup_error = 13;
    auto detailed = invoke();
    root = field(field(detailed.get(), "data"), "rootCommand");
    check(truth(root, "rootAttempted") && truth(root, "rootReturned") && truth(root, "rootReportReceived") &&
        truth(root, "ownerMode") && number(root, "threadsTotal") == 8 && number(root, "cgroupError") == 13 &&
        number(field(root, "credentials"), "command") == 11 && number(field(root, "taskState"), "command") == 25,
        "full current RootCommandResult JSON retains credential, task and environment details");

    int allocation_failures = 0;
    for (int offset = 0; offset < 160; ++offset) {
        fixture::reset(); fixture::allocation_offset = offset;
        auto result = invoke();
        check(fixture::calls == 1 && fixture::restores == 1, "receipt allocation failure never replays SDK or skips restore");
        check(truth(result.get(), "operationCompleted"), "all post-SDK receipt allocation failures preserve completion");
        if (number(result.get(), "sdkErrorCode") == kBridgeAlloc) ++allocation_failures;
    }
    check(allocation_failures > 15, "allocation sweep actually exercises receipt construction failures");
    fixture::reset(); fixture::sdk_error = KModErr::ERR_MODULE_OPEN_FILE; fixture::allocation_offset = 12;
    auto allocated = invoke();
    check(number(allocated.get(), "sdkErrorCode") == to_num(KModErr::ERR_MODULE_OPEN_FILE) && fixture::calls == 1,
        "SDK first failure survives receipt allocation failure");
    std::cout << "native assertions failures=" << fixture::failures << "; allocation failures=" << allocation_failures << '\n';
    return fixture::failures ? 1 : 0;
}
