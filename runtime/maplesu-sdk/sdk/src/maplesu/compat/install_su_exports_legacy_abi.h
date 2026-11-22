#pragma once

namespace maplesu::compat::legacy_install {
extern decltype(sdk::unsafe_install_su) install_su
    asm("_ZN10skroot_env17unsafe_install_suEv")
    __attribute__((alias("_ZN7maplesu3sdk17unsafe_install_suEv")));
}
