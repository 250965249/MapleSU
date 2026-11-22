#pragma once

// Frozen binary names share the maintained implementation and descriptor ABI.
namespace maplesu::compat {

extern __typeof__(sdk::serialize_module_descs) legacy_serialize_module_descs
    __asm__("_ZN10skroot_env22serialize_module_descsERKNSt6__ndk16vectorINS_11module_descENS0_9allocatorIS2_EEEE")
    __attribute__((used, visibility("hidden"), alias(
        "_ZN7maplesu3sdk22serialize_module_descsERKNSt6__ndk16vectorINS0_11module_descENS1_9allocatorIS3_EEEE")));

extern __typeof__(sdk::deserialize_module_descs) legacy_deserialize_module_descs
    __asm__("_ZN10skroot_env24deserialize_module_descsERKNSt6__ndk16vectorIhNS0_9allocatorIhEEEE")
    __attribute__((used, visibility("hidden"), alias(
        "_ZN7maplesu3sdk24deserialize_module_descsERKNSt6__ndk16vectorIhNS1_9allocatorIhEEEE")));

extern __typeof__(sdk::module_has_install_callback) legacy_module_has_install_callback
    __asm__("_ZN10skroot_env27module_has_install_callbackERKNSt6__ndk16vectorIhNS0_9allocatorIhEEEE")
    __attribute__((used, visibility("hidden"), alias(
        "_ZN7maplesu3sdk27module_has_install_callbackERKNSt6__ndk16vectorIhNS1_9allocatorIhEEEE")));

extern __typeof__(sdk::module_has_uninstall_callback) legacy_module_has_uninstall_callback
    __asm__("_ZN10skroot_env29module_has_uninstall_callbackERKNSt6__ndk16vectorIhNS0_9allocatorIhEEEE")
    __attribute__((used, visibility("hidden"), alias(
        "_ZN7maplesu3sdk29module_has_uninstall_callbackERKNSt6__ndk16vectorIhNS1_9allocatorIhEEEE")));

extern __typeof__(sdk::parse_module_meta_from_elf_bytes) legacy_parse_module_meta_from_elf_bytes
    __asm__("_ZN10skroot_env32parse_module_meta_from_elf_bytesERKNSt6__ndk16vectorIhNS0_9allocatorIhEEEERNS_11module_descE")
    __attribute__((used, visibility("hidden"), alias(
        "_ZN7maplesu3sdk32parse_module_meta_from_elf_bytesERKNSt6__ndk16vectorIhNS1_9allocatorIhEEEERNS0_11module_descE")));

}  // namespace maplesu::compat
