#pragma once

namespace maplesu::compat::legacy_install {
extern decltype(sdk::unsafe_install_resetprop) install_resetprop
    asm("_ZN10skroot_env24unsafe_install_resetpropEv")
    __attribute__((alias("_ZN7maplesu3sdk24unsafe_install_resetpropEv")));
}
