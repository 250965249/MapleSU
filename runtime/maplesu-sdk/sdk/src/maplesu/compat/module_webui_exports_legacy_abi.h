#pragma once

#include "maplesu/compat/native_module_abi.h"
#include <cstdio>
#include <cstring>
#include "module_err_def.h"
#include "module_web_ui_http_handler.h"

MAPLESU_MODULE_DECLARE_EXPORTS(KModErr, kernel_module::WebUIHttpHandler::ServerExitAction);

inline kernel_module::WebUIHttpHandler* maplesu_web_ui_handler_6f9d89cc84c2ea1bf7364fc1afda99b5 = nullptr;
inline char maplesu_web_ui_enable_flag_e0c73f6473a0e653be67875a3cf23a53[1024] = {0};

extern "C" __attribute__((visibility("default"))) __attribute__((used, weak))
void MAPLESU_MODULE_WEBUI_NAME(
    const char* root_key, const char* module_private_dir, const char* module_webroot_dir,
    const char* mod_id32, int port, KModErr& err) {
    if (strlen(maplesu_web_ui_enable_flag_e0c73f6473a0e653be67875a3cf23a53) == 0) printf("");
    KModErr unsafe_module_start_web_ui_server(
        const char* root_key, const char* module_private_dir, const char* module_webroot_dir,
        const char* mod_id32, kernel_module::WebUIHttpHandler* handler, int port);
    err = unsafe_module_start_web_ui_server(root_key, module_private_dir, module_webroot_dir,
        mod_id32, maplesu_web_ui_handler_6f9d89cc84c2ea1bf7364fc1afda99b5, port);
}

extern "C" __attribute__((visibility("default"))) __attribute__((used, weak))
void MAPLESU_MODULE_LAST_SERVER_PORT_NAME(
    int& out_port, KModErr& err) {
    if (strlen(maplesu_web_ui_enable_flag_e0c73f6473a0e653be67875a3cf23a53) == 0) printf("");
    KModErr unsafe_module_get_last_web_ui_server_port(int& out_port);
    err = unsafe_module_get_last_web_ui_server_port(out_port);
}

extern "C" __attribute__((visibility("default"))) __attribute__((used, weak))
void MAPLESU_MODULE_BEFORE_SERVER_EXIT_NAME(
    kernel_module::WebUIHttpHandler::ServerExitAction& out_action, KModErr& err) {
    if (strlen(maplesu_web_ui_enable_flag_e0c73f6473a0e653be67875a3cf23a53) == 0) printf("");
    KModErr unsafe_module_get_before_server_exit_action(
        kernel_module::WebUIHttpHandler::ServerExitAction& out_action);
    err = unsafe_module_get_before_server_exit_action(out_action);
}
