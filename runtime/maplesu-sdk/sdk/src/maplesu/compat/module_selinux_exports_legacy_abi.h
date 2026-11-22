#pragma once

// Frozen binary name shares the maintained implementation and enum ABI.
namespace maplesu::compat {

extern __typeof__(default_modules::module_selinux::init) legacy_selinux_init
    __asm__("_ZN15default_modules14module_selinux4initEN10skroot_env11InstallModeENS1_13ExploitMethodE")
    __attribute__((used, visibility("hidden"), alias(
        "_ZN15default_modules14module_selinux4initEN7maplesu3sdk11InstallModeENS2_13ExploitMethodE")));

}  // namespace maplesu::compat
