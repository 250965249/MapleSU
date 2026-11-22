// Exercise the production JNI list, JSON receipt and admission scope.
#include <cassert>
#include <cstdio>
#include <cstring>
#include <string>
#include "jni_test_utf8.h"
#include "../ultra/bridge/native_lib_ultra.cpp"

namespace {
std::vector<maplesu::sdk::module_record> fixture;
std::vector<int64_t> replies;
size_t calls = 0;
std::string output;
}

namespace maplesu::sdk {
KModErr get_all_modules_with_cb(const char*, void (*callback)(const module_record*)) {
    for (const auto& row : fixture) callback(&row);
    return KModErr::OK;
}
}

namespace maplesu {
int64_t get_module_control(const char*, const char* id, ModuleControlState& out) {
    ++calls;
    if (strnlen(id, 33) != 32 || strspn(id, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-") != 32)
        return MODULE_CONTROL_INVALID_ID;
    const auto error = replies.empty() ? 0 : replies.at(calls - 1);
    out = {};
    out.toggleSupported = 1;
    out.enabled = calls % 2;
    out.runtimeState = calls % 4;
    out.needsReboot = calls % 2;
    return error;
}
}

void rows(size_t count) {
    fixture.clear(); calls = 0; replies.clear();
    for (size_t i = 0; i < count; ++i) {
        maplesu::sdk::module_record row{};
        snprintf(row.desc.id32, sizeof(row.desc.id32), "%032zu", i);
        row.state = static_cast<maplesu::sdk::ModuleRunState>(i % 4);
        fixture.push_back(row);
    }
}

cJSON* query(JNIEnv* env) {
    Java_dev_maplesu_manager_runtime_ultra_bridge_NativeBridge_getModuleList(
        env, nullptr, reinterpret_cast<jstring>(const_cast<char*>("fixture-key")));
    cJSON* root = cJSON_Parse(output.c_str()); assert(root);
    assert(cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(root, "ok")));
    auto data = cJSON_GetObjectItemCaseSensitive(root, "data"); assert(data);
    assert(cJSON_GetObjectItemCaseSensitive(data, "count")->valueint == int(fixture.size()));
    auto modules = cJSON_DetachItemFromObject(data, "modules");
    assert(cJSON_GetArraySize(modules) == int(fixture.size()));
    cJSON_Delete(root);
    return modules;
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

    rows(0); auto modules = query(&env); assert(calls == 0); cJSON_Delete(modules);
    for (size_t count : {1, 3, 50}) {
        rows(count); replies.assign(count, maplesu::MODULE_CONTROL_UNSUPPORTED);
        modules = query(&env);
        assert(calls == 1 && "unsupported helper was queried once per module");
        for (size_t i = 0; i < count; ++i) {
            auto row = cJSON_GetArrayItem(modules, int(i));
            assert(cJSON_GetObjectItemCaseSensitive(row, "controlErrorCode")->valueint == maplesu::MODULE_CONTROL_UNSUPPORTED);
            assert(!cJSON_HasObjectItem(row, "control"));
            assert(cJSON_GetObjectItemCaseSensitive(row, "state_code")->valueint == int(i % 4));
        }
        cJSON_Delete(modules);
    }
    puts("PASS legacy helper: zero modules / 1, 3, 50 rows / one unsupported query / unchanged errors and runtime states");

    // The next list must observe an upgraded helper, without restarting the process.
    calls = 0; replies.clear(); modules = query(&env); assert(calls == fixture.size());
    for (size_t i = 0; i < fixture.size(); ++i) {
        auto row = cJSON_GetArrayItem(modules, int(i));
        auto control = cJSON_GetObjectItemCaseSensitive(row, "control"); assert(control);
        assert(cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(control, "enabled")) == bool((i + 1) % 2));
        assert(cJSON_GetObjectItemCaseSensitive(control, "state_code")->valueint == int((i + 1) % 4));
        assert(!cJSON_HasObjectItem(row, "controlErrorCode"));
    }
    cJSON_Delete(modules);
    puts("PASS upgraded helper: every row queried / individual control state / no cross-list negative cache");

    rows(3); replies = {maplesu::MODULE_CONTROL_IO, 0, maplesu::MODULE_CONTROL_NOT_FOUND};
    modules = query(&env); assert(calls == 3);
    assert(cJSON_GetObjectItemCaseSensitive(cJSON_GetArrayItem(modules, 0), "controlErrorCode")->valueint == maplesu::MODULE_CONTROL_IO);
    assert(cJSON_HasObjectItem(cJSON_GetArrayItem(modules, 1), "control"));
    assert(cJSON_GetObjectItemCaseSensitive(cJSON_GetArrayItem(modules, 2), "controlErrorCode")->valueint == maplesu::MODULE_CONTROL_NOT_FOUND);
    cJSON_Delete(modules);
    puts("PASS transient errors: preserve each module result / do not suppress later queries");

    rows(4); strcpy(fixture[1].desc.id32, "short"); fixture[2].desc.id32[5] = '/';
    replies.assign(4, maplesu::MODULE_CONTROL_UNSUPPORTED);
    modules = query(&env); assert(calls == 3);
    for (int i : {1, 2})
        assert(cJSON_GetObjectItemCaseSensitive(cJSON_GetArrayItem(modules, i), "controlErrorCode")->valueint == maplesu::MODULE_CONTROL_INVALID_ID);
    cJSON_Delete(modules);
    puts("PASS malformed IDs retain validation errors after unsupported capability");
}
