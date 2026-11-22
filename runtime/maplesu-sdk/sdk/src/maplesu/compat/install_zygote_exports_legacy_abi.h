#pragma once

namespace maplesu::compat::legacy_install {
extern decltype(sdk::safe_restart_zygote64) safe_restart_zygote64
    asm("_ZN10skroot_env21safe_restart_zygote64Ev")
    __attribute__((alias("_ZN7maplesu3sdk21safe_restart_zygote64Ev")));
extern decltype(sdk::unsafe_restart_zygote64) unsafe_restart_zygote64
    asm("_ZN10skroot_env23unsafe_restart_zygote64Ev")
    __attribute__((alias("_ZN7maplesu3sdk23unsafe_restart_zygote64Ev")));
}
