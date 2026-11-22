// Exercise the production receipt and byte-array handling; no SDK callback grants root here.
#include <cassert>
#include <fstream>
#include <iostream>
#include <iterator>
#include "jni_test_utf8.h"
#include "../ultra/bridge/native_lib_ultra.cpp"

namespace {
std::string output;
bool read_failed = false, exception_pending = false;
using Bytes = std::vector<uint8_t>;

cJSON* extract(JNIEnv* env, Bytes* bytes) {
    Java_dev_maplesu_manager_runtime_ultra_bridge_NativeBridge_recoverImageCredentials(
        env, nullptr, reinterpret_cast<jbyteArray>(bytes));
    cJSON* root = cJSON_Parse(output.c_str()); assert(root);
    assert(std::strcmp(cJSON_GetObjectItemCaseSensitive(root, "operation")->valuestring,
        "recover_image_credentials") == 0);
    return root;
}

void accepted(cJSON* root, size_t count) {
    assert(cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(root, "ok")));
    assert(std::strcmp(cJSON_GetObjectItemCaseSensitive(root, "sdkError")->valuestring, "OK") == 0);
    cJSON* data = cJSON_GetObjectItemCaseSensitive(root, "data"); assert(data);
    assert(size_t(cJSON_GetArraySize(cJSON_GetObjectItemCaseSensitive(data, "credentials"))) == count);
    assert(cJSON_IsFalse(cJSON_GetObjectItemCaseSensitive(data, "liveRootVerified")));
    cJSON_Delete(root);
}

void failed(cJSON* root, const char* error) {
    assert(cJSON_IsFalse(cJSON_GetObjectItemCaseSensitive(root, "ok")));
    assert(std::strcmp(cJSON_GetObjectItemCaseSensitive(root, "sdkError")->valuestring, error) == 0);
    assert(!cJSON_HasObjectItem(root, "data"));
    cJSON_Delete(root);
}
}

int main(int argc, char** argv) {
    assert(maplesu::sdk_call_access("recover_image_credentials") == maplesu::SdkCallAccess::Local);
    JNINativeInterface table{};
    table.NewStringUTF = [](JNIEnv*, const char* text) -> jstring {
        assert(!exception_pending); output = text; return nullptr;
    };
    table.NewString = [](JNIEnv*, const jchar* characters, jsize length) -> jstring {
        assert(!exception_pending);
        output = jni_test_utf16_to_utf8(characters, length);
        return nullptr;
    };
    table.GetArrayLength = [](JNIEnv*, jarray array) -> jsize {
        return jsize(reinterpret_cast<Bytes*>(array)->size());
    };
    table.GetByteArrayRegion = [](JNIEnv*, jbyteArray array, jsize start, jsize size, jbyte* target) {
        if (read_failed) { exception_pending = true; return; }
        const auto& bytes = *reinterpret_cast<Bytes*>(array);
        std::memcpy(target, bytes.data() + start, size_t(size));
    };
    table.ExceptionCheck = [](JNIEnv*) -> jboolean { return exception_pending ? JNI_TRUE : JNI_FALSE; };
    table.ExceptionClear = [](JNIEnv*) { exception_pending = false; };
    JNIEnv env{&table};
    failed(extract(&env, nullptr), "MAPLESU_IMAGE_KERNEL_INVALID");
    Bytes small(63); failed(extract(&env, &small), "MAPLESU_IMAGE_KERNEL_INVALID");
    Bytes raw(4096); accepted(extract(&env, &raw), 0);
    read_failed = true; failed(extract(&env, &raw), "MAPLESU_IMAGE_KERNEL_READ_FAILED");
    assert(!exception_pending); read_failed = false;
    std::cout << "PASS JNI null, truncated, empty, exception receipt and local admission\n";
    assert(argc % 2 == 1);
    for (int i = 1; i < argc; i += 2) {
        std::ifstream input(argv[i + 1], std::ios::binary); assert(input.good());
        Bytes bytes{std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
        accepted(extract(&env, &bytes), size_t(std::stoi(argv[i])));
        std::cout << "PASS production JNI kernel " << i / 2 + 1 << "; root remains unverified\n";
    }
}
