#pragma once

namespace maplesu::compat::legacy_install {
extern decltype(sdk::unsafe_del_hide_dir) del_hide_dir
    asm("_ZN10skroot_env19unsafe_del_hide_dirEv")
    __attribute__((alias("_ZN7maplesu3sdk19unsafe_del_hide_dirEv")));
extern decltype(sdk::unsafe_create_hide_dir) create_hide_dir
    asm("_ZN10skroot_env22unsafe_create_hide_dirEv")
    __attribute__((alias("_ZN7maplesu3sdk22unsafe_create_hide_dirEv")));
extern decltype(sdk::unsafe_clean_older_hide_dir) clean_older_hide_dir
    asm("_ZN10skroot_env27unsafe_clean_older_hide_dirEv")
    __attribute__((alias("_ZN7maplesu3sdk27unsafe_clean_older_hide_dirEv")));
}
