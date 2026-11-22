#pragma once

// Preserve the frozen binary entry points at the single callback implementation.
namespace maplesu::compat::legacy_callbacks {
extern decltype(sdk::features::callback::invoke_module_on_install) install
    asm("_ZN10skroot_env8features8callback24invoke_module_on_installERKNSt6__ndk112basic_stringIcNS2_11char_traitsIcEENS2_9allocatorIcEEEERS8_")
    __attribute__((alias("_ZN7maplesu3sdk8features8callback24invoke_module_on_installERKNSt6__ndk112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEERS9_")));
extern decltype(sdk::features::callback::invoke_module_on_uninstall) uninstall
    asm("_ZN10skroot_env8features8callback26invoke_module_on_uninstallERKNSt6__ndk112basic_stringIcNS2_11char_traitsIcEENS2_9allocatorIcEEEE")
    __attribute__((alias("maplesu_module_uninstall_callback")));
}
