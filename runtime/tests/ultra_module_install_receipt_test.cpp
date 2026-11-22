// Exercise the production JNI receipt with SDK callback and transport fixtures.
#include <cassert>
#include <cstring>
#include <string>
#include "jni_test_utf8.h"
#include "../ultra/bridge/native_lib_ultra.cpp"

namespace {
KModErr install_error = KModErr::OK;
std::string callback_reason, output;
unsigned normal_calls, once_calls;

KModErr install_fixture(const char* key, const char* zip, void (*callback)(const char*)) {
    assert(std::strcmp(key, "fixture-key") == 0);
    assert(std::strcmp(zip, "/fixture/module.zip") == 0);
    callback(callback_reason.c_str());
    return install_error;
}

cJSON* install(JNIEnv* env, bool once) {
    normal_calls = once_calls = 0;
    Java_dev_maplesu_manager_runtime_ultra_bridge_NativeBridge_installModule(
        env, nullptr, reinterpret_cast<jstring>(const_cast<char*>("fixture-key")),
        reinterpret_cast<jstring>(const_cast<char*>("/fixture/module.zip")), once ? JNI_TRUE : JNI_FALSE);
    assert(normal_calls == (once ? 0u : 1u) && once_calls == (once ? 1u : 0u));
    cJSON* root = cJSON_Parse(output.c_str()); assert(root);
    assert(std::strcmp(cJSON_GetObjectItemCaseSensitive(root, "operation")->valuestring,
                       once ? "install_module_dev_run_once" : "install_module") == 0);
    return root;
}

void error_is(cJSON* root, const char* error, int code) {
    assert(cJSON_IsFalse(cJSON_GetObjectItemCaseSensitive(root, "ok")));
    assert(std::strcmp(cJSON_GetObjectItemCaseSensitive(root, "sdkError")->valuestring, error) == 0);
    assert(cJSON_GetObjectItemCaseSensitive(root, "sdkErrorCode")->valueint == code);
}
}

namespace maplesu::sdk {
KModErr install_module_with_cb(const char* key, const char* zip, void (*callback)(const char*)) {
    ++normal_calls;
    return install_fixture(key, zip, callback);
}
KModErr install_module_dev_run_once_with_cb(const char* key, const char* zip, void (*callback)(const char*)) {
    ++once_calls;
    return install_fixture(key, zip, callback);
}
}

int main() {
    JNINativeInterface table{};
    table.NewStringUTF = [](JNIEnv*, const char* text) -> jstring { output = text; return nullptr; };
    table.NewString = [](JNIEnv*, const jchar* characters, jsize length) -> jstring {
        output = jni_test_utf16_to_utf8(characters, length);
        return nullptr;
    };
    table.GetStringUTFChars = [](JNIEnv*, jstring text, jboolean*) -> const char* { return reinterpret_cast<const char*>(text); };
    table.ReleaseStringUTFChars = [](JNIEnv*, jstring, const char*) {};
    JNIEnv env{&table};

    for (bool once : {false, true}) {
        install_error = KModErr::OK; callback_reason.clear();
        cJSON* root = install(&env, once);
        assert(cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(root, "ok")));
        cJSON* data = cJSON_GetObjectItemCaseSensitive(root, "data"); assert(data);
        assert(cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(data, "installCallbackAccepted")));
        assert(std::strcmp(cJSON_GetObjectItemCaseSensitive(data, "mode")->valuestring,
                           once ? "dev_run_once" : "normal") == 0);
        assert(std::strcmp(cJSON_GetObjectItemCaseSensitive(data, "zipPath")->valuestring,
                           "/fixture/module.zip") == 0);
        assert(!cJSON_HasObjectItem(root, "reason")); cJSON_Delete(root);

        callback_reason = "requires another kernel: A+B 50%";
        root = install(&env, once);
        error_is(root, "MAPLESU_MODULE_INSTALL_CALLBACK_DECLINED", -1007);
        assert(std::strcmp(cJSON_GetObjectItemCaseSensitive(root, "reason")->valuestring, callback_reason.c_str()) == 0);
        data = cJSON_GetObjectItemCaseSensitive(root, "data"); assert(data);
        assert(cJSON_IsFalse(cJSON_GetObjectItemCaseSensitive(data, "installCallbackAccepted")));
        assert(std::strcmp(cJSON_GetObjectItemCaseSensitive(data, "refusalReason")->valuestring,
                           url_encode_copy(callback_reason).c_str()) == 0);
        cJSON_Delete(root);

        install_error = KModErr::ERR_MODULE_PARAM;
        root = install(&env, once);
        error_is(root, "ERR_MODULE_PARAM", static_cast<int>(to_num(install_error))); cJSON_Delete(root);

        install_error = KModErr::ERR_READ_CHILD_ERRCODE;
        root = install(&env, once);
        error_is(root, "MAPLESU_MODULE_INSTALL_INTERRUPTED", -1005);
        data = cJSON_GetObjectItemCaseSensitive(root, "data"); assert(data);
        assert(cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(data, "reconciliationRequired")));
        cJSON_Delete(root);
    }
}
