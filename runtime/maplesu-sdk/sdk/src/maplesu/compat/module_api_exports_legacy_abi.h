#pragma once

// Keep the frozen binary exports at the single MapleSU implementation.
namespace maplesu::compat::legacy_module_api {
extern decltype(sdk::uninstall_module) uninstall_module
    asm("_ZN10skroot_env16uninstall_moduleEPKcS1_")
    __attribute__((alias("_ZN7maplesu3sdk16uninstall_moduleEPKcS2_")));
extern decltype(sdk::install_module_with_cb) install_module_with_cb
    asm("_ZN10skroot_env22install_module_with_cbEPKcS1_PFvS1_E")
    __attribute__((alias("_ZN7maplesu3sdk22install_module_with_cbEPKcS2_PFvS2_E")));
extern decltype(sdk::get_all_modules_with_cb) get_all_modules_with_cb
    asm("_ZN10skroot_env23get_all_modules_with_cbEPKcPFvPKNS_13module_recordEE")
    __attribute__((alias("_ZN7maplesu3sdk23get_all_modules_with_cbEPKcPFvPKNS0_13module_recordEE")));
extern KModErr parse_module_desc_from_zip_file(const char*, const char*, sdk::module_desc&)
    asm("_ZN10skroot_env31parse_module_desc_from_zip_fileEPKcS1_RNS_11module_descE")
    __attribute__((alias("_ZN7maplesu3sdk31parse_module_desc_from_zip_fileEPKcS2_RNS0_11module_descE")));
extern decltype(sdk::install_module_dev_run_once_with_cb) install_module_dev_run_once_with_cb
    asm("_ZN10skroot_env35install_module_dev_run_once_with_cbEPKcS1_PFvS1_E")
    __attribute__((alias("_ZN7maplesu3sdk35install_module_dev_run_once_with_cbEPKcS2_PFvS2_E")));
}
