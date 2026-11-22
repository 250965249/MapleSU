#pragma once

#include <cstdint>
#include <type_traits>
#include "module_err_def.h"
#include "maplesu_sdk/maplesu_test.h"

namespace maplesu::compat {
static_assert(std::is_same_v<std::underlying_type_t<sdk::BasicItem>, uint32_t>);
static_assert(static_cast<uint32_t>(sdk::BasicItem::Channel) == 0 &&
              static_cast<uint32_t>(sdk::BasicItem::KernelBase) == 1 &&
              static_cast<uint32_t>(sdk::BasicItem::WriteTest) == 2 &&
              static_cast<uint32_t>(sdk::BasicItem::ReadTrampoline) == 3 &&
              static_cast<uint32_t>(sdk::BasicItem::WriteTrampoline) == 4 &&
              static_cast<uint32_t>(sdk::BasicItem::PhysAddrCalc) == 5);
static_assert(std::is_same_v<std::underlying_type_t<sdk::DeafultModuleName>, uint32_t>);
static_assert(static_cast<uint32_t>(sdk::DeafultModuleName::RootBridgePrint) == 0 &&
              static_cast<uint32_t>(sdk::DeafultModuleName::RootBridgeExec) == 1 &&
              static_cast<uint32_t>(sdk::DeafultModuleName::SuRedirectPrint) == 2 &&
              static_cast<uint32_t>(sdk::DeafultModuleName::SuRedirectExec) == 3 &&
              static_cast<uint32_t>(sdk::DeafultModuleName::TombstonesPurgePrint) == 4);

KModErr set_boot_fail_protect_enabled_legacy(const char* key, bool enabled)
    asm("_ZN10skroot_env29set_boot_fail_protect_enabledEPKcb");
bool is_boot_fail_protect_enabled_legacy(const char* key)
    asm("_ZN10skroot_env28is_boot_fail_protect_enabledEPKc");
KModErr set_adb_forced_disabled_legacy(const char* key, bool disabled)
    asm("_ZN10skroot_env23set_adb_forced_disabledEPKcb");
bool is_adb_forced_disabled_legacy(const char* key)
    asm("_ZN10skroot_env22is_adb_forced_disabledEPKc");
const char* get_root_status_report_legacy(const char* key)
    asm("_ZN10skroot_env22get_root_status_reportEPKc");
KModErr restart_zygote64_legacy(const char* key)
    asm("_ZN10skroot_env16restart_zygote64EPKc");
KModErr test_basics_with_cb_legacy(const char* key, sdk::BasicItem item,
                                 void (*cb)(const char*))
    asm("_ZN10skroot_env26test_skroot_basics_with_cbEPKcNS_9BasicItemEPFvS1_E");
KModErr test_default_module_with_cb_legacy(const char* key, sdk::DeafultModuleName name,
                                         void (*cb)(const char*))
    asm("_ZN10skroot_env34test_skroot_deafult_module_with_cbEPKcNS_17DeafultModuleNameEPFvS1_E");
} // namespace maplesu::compat
