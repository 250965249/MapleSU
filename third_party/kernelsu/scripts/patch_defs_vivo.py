# SPDX-License-Identifier: GPL-3.0-or-later
"""SakiSU vivo compatibility, pinned at 6f9672837b9359f8853f47e18e00261edbf6d31e."""
import ksu_common as C


def patch_vivo(tree, _source):
    patch = C.KSU_ROOT / "patches/extra/vivo-compatibility-20261109.patch"
    C.git_apply(tree.root, patch, check=True)
    C.git_apply(tree.root, patch)
    return ['kernel/Kbuild', 'kernel/hook/init_module_filter.c', 'kernel/hook/init_module_filter.h', 'kernel/vr_companion.c', 'kernel/hook/syscall_hook_manager.c', 'kernel/policy/feature.c', 'uapi/feature.h', 'userspace/ksud/src/feature_id.rs', 'userspace/ksud/src/vendor_boot.rs', 'userspace/ksud/src/vendor_boot_tests.rs', 'userspace/ksud/src/vr_bootstrap.rs', 'userspace/ksud/src/vr_bootstrap_tests.rs', 'userspace/ksud/src/main.rs', 'userspace/ksud/src/cli.rs', 'userspace/ksud/src/cli_non_android.rs', 'userspace/ksud/src/boot_patch.rs', 'userspace/ksud/src/assets.rs', 'userspace/ksuinit/src/init.rs', 'userspace/ksuinit/src/bin/maplesu_vrinit.rs']


PATCHES_VIVO = [{
    "name": "0018-vivo-vr-compatibility.patch",
    "apply": patch_vivo,
    "status": "implemented",
    "summary": "Normal vr syscall filter, Ultra early companion and lossless vendor_boot v3/v4 rmvr producer",
}]
