#include "kernel_module_kit_umbrella.h"
#include <cassert>
#include <cstddef>
#include <cstring>
#include <cstdio>

extern "C" const char* __get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW();

static_assert(sizeof(maplesu::sdk::MapleSUSdkVersion) == 12);
static_assert(offsetof(maplesu::sdk::module_desc, id32) == 7168);
static_assert(offsetof(maplesu::sdk::module_desc, min_sdk_ver) == 9220);
static_assert(sizeof(maplesu::sdk::module_desc) == 9232);
static_assert(sizeof(maplesu::sdk::module_record) == 9236);
static_assert(static_cast<uint32_t>(maplesu::sdk::ModuleRunState::RemovedPendingReboot) == 3);

namespace {
constexpr char module_id[] = "legacy_compat_fixture_0000000000";
static_assert(sizeof(module_id) == 33);
constexpr char private_dir[] = "/fixture/module-private";
constexpr char webroot[] = "/fixture/wwwroot";
std::string reason;
bool reject_install = false, main_called = false, uninstall_called = false, webui_called = false;
int last_port = 0;
KModErr webui_result = KModErr::OK;

void check_context(const char* key, const char* dir) {
    assert(std::strcmp(__get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW(), key) == 0);
    assert(std::strcmp(dir, private_dir) == 0);
}
void install_reason(const char* value) { reason = value; }
class LegacyWebUi : public kernel_module::WebUIHttpHandler {
public:
    void onPrepareCreate(const char* key, const char* dir, uint32_t port) override {
        assert(key && std::strlen(key) == 48);
        assert(std::strcmp(dir, private_dir) == 0);
        last_port = static_cast<int>(port);
        webui_called = true;
    }
    ServerExitAction onBeforeServerExit() override { return ServerExitAction::KeepRunning; }
};
}

int maplesu_module_main(const char* key, const char* dir) {
    check_context(key, dir);
    auto version = maplesu::sdk::get_sdk_version(); // Real, linked SDK implementation.
    assert((version == maplesu::sdk::MapleSUSdkVersion{5, 1, 0}));
    assert((version >= maplesu::sdk::MapleSUSdkVersion{4, 0, 5}));
    assert((version >= maplesu::sdk::MapleSUSdkVersion{5, 0, 5}));
    main_called = true;
    return 42;
}
std::string module_on_install(const char* key, const char* dir) {
    check_context(key, dir);
    return reject_install ? "legacy install rejection" : "";
}
void module_on_uninstall(const char* key, const char* dir) {
    check_context(key, dir);
    uninstall_called = true;
}

MAPLESU_MODULE_NAME("Legacy compatibility fixture")
MAPLESU_MODULE_VERSION("1.0.0")
MAPLESU_MODULE_DESC("SDK ABI and callback fixture; no kernel operations")
MAPLESU_MODULE_AUTHOR("MapleSU")
MAPLESU_MODULE_ID32("legacy_compat_fixture_0000000000")
MAPLESU_MODULE_UPDATE_JSON("https://example.invalid/legacy-update.json")
MAPLESU_MODULE_ON_INSTALL(module_on_install)
MAPLESU_MODULE_ON_UNINSTALL(module_on_uninstall)
MAPLESU_MODULE_WEB_UI(LegacyWebUi)

// Model only the server boundary. No listener, process launch or root/kernel request is made.
KModErr unsafe_module_start_web_ui_server(const char* key, const char* dir, const char* root,
        const char* id, kernel_module::WebUIHttpHandler* handler, int port) {
    assert(std::strcmp(root, webroot) == 0 && std::strcmp(id, module_id) == 0);
    assert(handler != nullptr);
    handler->onPrepareCreate(key, dir, static_cast<uint32_t>(port));
    return webui_result;
}
KModErr unsafe_module_get_last_web_ui_server_port(int& port) {
    port = last_port;
    return webui_result;
}
KModErr unsafe_module_get_before_server_exit_action(kernel_module::WebUIHttpHandler::ServerExitAction& action) {
    action = maplesu_web_ui_handler_6f9d89cc84c2ea1bf7364fc1afda99b5->onBeforeServerExit();
    return webui_result;
}

int main() {
    const std::string key_a(48, 'K'), key_b(48, 'Q');
    assert(MAPLESU_MODULE_ENTRY_NAME(key_a.c_str(), private_dir) == 42 && main_called);
    std::puts("PASS legacy entry, SDK version 5.1.0, minimum-version comparison and root context");
    MAPLESU_MODULE_INSTALL_NAME(key_b.c_str(), private_dir, install_reason);
    assert(reason.empty());
    reject_install = true;
    MAPLESU_MODULE_INSTALL_NAME(key_a.c_str(), private_dir, install_reason);
    assert(reason == "legacy install rejection");
    std::puts("PASS original install callback, updated root context and rejection reason");
    MAPLESU_MODULE_UNINSTALL_NAME(key_b.c_str(), private_dir);
    assert(uninstall_called);
    std::puts("PASS original uninstall callback and root context");
    KModErr err = KModErr::OK;
    MAPLESU_MODULE_WEBUI_NAME(key_a.c_str(), private_dir, webroot, module_id, 48080, err);
    assert(err == KModErr::OK && webui_called && last_port == 48080);
    int port = 0;
    MAPLESU_MODULE_LAST_SERVER_PORT_NAME(port, err);
    assert(err == KModErr::OK && port == 48080);
    auto action = kernel_module::WebUIHttpHandler::ServerExitAction::Exit;
    MAPLESU_MODULE_BEFORE_SERVER_EXIT_NAME(action, err);
    assert(err == KModErr::OK && action == kernel_module::WebUIHttpHandler::ServerExitAction::KeepRunning);
    webui_result = KModErr::ERR_MAPLESU_ENV_NOT_INSTALL;
    MAPLESU_MODULE_LAST_SERVER_PORT_NAME(port, err);
    assert(err == webui_result);
    std::puts("PASS original WebUI exports, handler, port, exit action and error propagation");
    assert(std::strstr(maplesu_module_update_json_7310fa0a06d95799b3f9beaf60e26e85,
                       "https://example.invalid/legacy-update.json") != nullptr);
    std::puts("PASS legacy update JSON descriptor");
    return 0;
}
