#pragma once

// Frozen binary names share the maintained implementation and descriptor ABI.
namespace maplesu::compat {

extern __typeof__(sdk::find_module_elf_in_zip) legacy_find_module_elf_in_zip
    __asm__("_ZN10skroot_env22find_module_elf_in_zipEPKcRNS_11module_descERNSt6__ndk112basic_stringIcNS4_11char_traitsIcEENS4_9allocatorIcEEEE")
    __attribute__((used, visibility("hidden"), alias(
        "_ZN7maplesu3sdk22find_module_elf_in_zipEPKcRNS0_11module_descERNSt6__ndk112basic_stringIcNS5_11char_traitsIcEENS5_9allocatorIcEEEE")));

extern __typeof__(sdk::safe_parse_module_desc_from_zip_file) legacy_safe_parse_module_desc_from_zip_file
    __asm__("_ZN10skroot_env36safe_parse_module_desc_from_zip_fileEPKcRNS_11module_descE")
    __attribute__((used, visibility("hidden"), alias(
        "_ZN7maplesu3sdk36safe_parse_module_desc_from_zip_fileEPKcRNS0_11module_descE")));

}  // namespace maplesu::compat
