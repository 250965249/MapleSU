// MapleSU module webui hooks implementation.
//
#pragma once

#include "maplesu/compat/native_module_abi.h"
#include <cstddef>

extern "C" {
void MAPLESU_MODULE_WEBUI_NAME(void*, void*, void*, void*, int, long long*) MAPLESU_MODULE_WEBUI_ASM;
void MAPLESU_MODULE_LAST_SERVER_PORT_NAME(int*, long long*) MAPLESU_MODULE_LAST_SERVER_PORT_ASM;
void MAPLESU_MODULE_BEFORE_SERVER_EXIT_NAME(int*, long long*) MAPLESU_MODULE_BEFORE_SERVER_EXIT_ASM;

// --- kit-provided entry points (U in every member) -------------------------
long long unsafe_module_start_web_ui_server(void* a, void* b, void* c, void* d,
                                            void* handler, int flag);
long long unsafe_module_get_last_web_ui_server_port(int* out_port);
long long unsafe_module_get_before_server_exit_action(int* out_action);

// --- weak shared state ----------------------------------------------------
__attribute__((weak, visibility("hidden")))
char maplesu_web_ui_enable_flag_e0c73f6473a0e653be67875a3cf23a53[1024] = {};

__attribute__((weak, visibility("hidden")))
void* maplesu_web_ui_handler_6f9d89cc84c2ea1bf7364fc1afda99b5 = nullptr;

// --- weak module entry points --------------------------------------------
__attribute__((weak, visibility("hidden")))
void MAPLESU_MODULE_WEBUI_NAME(
    void* a, void* b, void* c, void* d, int flag, long long* out) {
    const unsigned long enable_flag_len =
        ::strlen(maplesu_web_ui_enable_flag_e0c73f6473a0e653be67875a3cf23a53);
    (void)enable_flag_len;
    *out = unsafe_module_start_web_ui_server(
        a, b, c, d, maplesu_web_ui_handler_6f9d89cc84c2ea1bf7364fc1afda99b5, flag);
}

__attribute__((weak, visibility("hidden")))
void MAPLESU_MODULE_LAST_SERVER_PORT_NAME(
    int* out_port, long long* out) {
    const unsigned long enable_flag_len =
        ::strlen(maplesu_web_ui_enable_flag_e0c73f6473a0e653be67875a3cf23a53);
    (void)enable_flag_len;
    *out = unsafe_module_get_last_web_ui_server_port(out_port);
}

__attribute__((weak, visibility("hidden")))
void MAPLESU_MODULE_BEFORE_SERVER_EXIT_NAME(
    int* out_action, long long* out) {
    const unsigned long enable_flag_len =
        ::strlen(maplesu_web_ui_enable_flag_e0c73f6473a0e653be67875a3cf23a53);
    (void)enable_flag_len;
    *out = unsafe_module_get_before_server_exit_action(out_action);
}

}  // extern "C"
