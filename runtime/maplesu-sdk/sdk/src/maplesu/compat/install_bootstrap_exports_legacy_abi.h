#pragma once

namespace maplesu::compat::legacy_install {
extern decltype(sdk::unsafe_install_autorun_bootstrap) install_autorun_bootstrap
    asm("_ZN10skroot_env32unsafe_install_autorun_bootstrapEv")
    __attribute__((alias("_ZN7maplesu3sdk32unsafe_install_autorun_bootstrapEv")));
}
