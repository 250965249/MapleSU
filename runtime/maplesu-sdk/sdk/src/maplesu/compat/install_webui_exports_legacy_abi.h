#pragma once

namespace maplesu::compat::legacy_install {
extern decltype(sdk::unsafe_install_webui_loader) install_webui_loader
    asm("_ZN10skroot_env27unsafe_install_webui_loaderEv")
    __attribute__((alias("_ZN7maplesu3sdk27unsafe_install_webui_loaderEv")));
}
