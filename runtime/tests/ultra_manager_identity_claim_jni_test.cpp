// SPDX-License-Identifier: GPL-3.0-only
// Production JNI receipt and client bytes run here; kernel replies are explicit fixtures.
#include <cassert>
#include <cerrno>
#include <cstdarg>
#include <iostream>
#include "jni_test_utf8.h"
#include "../ultra/bridge/native_lib_ultra.cpp"

namespace {
std::string output;
const std::string candidate = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKL";
size_t reply_length = 0;
size_t invalid_at = MSU_MANAGER_CLAIM_KEY_BYTES;
unsigned int requests = 0;
unsigned int checks = 0;
bool fixture_response = true;
}

extern "C" long __real_syscall(long, ...);
extern "C" long __wrap_syscall(long number, ...) {
    assert(number == SYS_execve);
    va_list arguments;
    va_start(arguments, number);
    const char* name = va_arg(arguments, const char*);
    const auto argv = va_arg(arguments, const char* const*);
    const auto environment = va_arg(arguments, const char* const*);
    va_end(arguments);
    assert(name && argv && argv[0] == name && !argv[1] && environment && !environment[0]);
    if (!fixture_response) return __real_syscall(number, name, argv, environment);
    ++requests;
    auto* reply = reinterpret_cast<char*>(static_cast<uintptr_t>(
        msu_manager_claim_address(name, std::strlen(name))));
    assert(reply);
    for (size_t i = 0; i < MSU_MANAGER_CLAIM_KEY_BYTES; ++i) assert(reply[i] == 0);
    std::memcpy(reply, candidate.data(), reply_length);
    if (invalid_at < MSU_MANAGER_CLAIM_KEY_BYTES) reply[invalid_at] = '!';
    errno = ENOENT;
    return -1;
}

namespace {
void verify(JNIEnv* env, bool present) {
    Java_dev_maplesu_manager_runtime_ultra_bridge_NativeBridge_claimManagerIdentity(env, nullptr);
    cJSON* receipt = cJSON_Parse(output.c_str());
    assert(receipt && cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(receipt, "ok")));
    assert(std::strcmp(cJSON_GetObjectItemCaseSensitive(receipt, "operation")->valuestring,
                       "claim_manager_identity") == 0);
    cJSON* data = cJSON_GetObjectItemCaseSensitive(receipt, "data");
    assert(data && cJSON_IsFalse(cJSON_GetObjectItemCaseSensitive(data, "liveRootVerified")));
    assert(cJSON_GetArraySize(data) == (present ? 2 : 1));
    cJSON* key = cJSON_GetObjectItemCaseSensitive(data, "candidate");
    if (present) assert(cJSON_IsString(key) && candidate == key->valuestring);
    else assert(!key);
    assert(!cJSON_HasObjectItem(data, "kernelPresent"));
    assert(!cJSON_HasObjectItem(data, "environmentReady"));
    cJSON_Delete(receipt);
    ++checks;
}
}

int main() {
    assert(maplesu::sdk_call_access("claim_manager_identity") == maplesu::SdkCallAccess::Local);
    JNINativeInterface table{};
    table.NewStringUTF = [](JNIEnv*, const char* value) -> jstring { output = value; return nullptr; };
    table.NewString = [](JNIEnv*, const jchar* characters, jsize length) -> jstring {
        output = jni_test_utf16_to_utf8(characters, length);
        return nullptr;
    };
    JNIEnv env{&table};
    fixture_response = false;
    verify(&env, false); // Actual absent-path request on the ordinary host kernel.
    fixture_response = true;
    for (reply_length = 0; reply_length < MSU_MANAGER_CLAIM_KEY_BYTES; ++reply_length) verify(&env, false);
    verify(&env, true);
    for (invalid_at = 0; invalid_at < MSU_MANAGER_CLAIM_KEY_BYTES; ++invalid_at) verify(&env, false);
    {
        maplesu::SdkCallScope held("install_maplesu_environment");
        assert(held.acquired());
        // Local identity requests need neither the exclusive SDK slot nor a root key.
        verify(&env, true);
    }
    assert(requests == checks - 1);
    std::cout << "manager claim JNI checks: " << checks
              << "; all replies remain root-unverified; kernel replies modeled\n";
}
