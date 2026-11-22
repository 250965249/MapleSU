# SPDX-License-Identifier: GPL-3.0-or-later
"""Historical SELinux backport, superseded by the official CI #5545 baseline."""
import ksu_common as C


def patch_selinux_upstream(tree, _source):
    patch = C.KSU_ROOT / "patches/extra/selinux-upstream-sync-20261107.patch"
    C.git_apply(tree.root, patch, check=True)
    C.git_apply(tree.root, patch)
    return [
        "kernel/feature/selinux_hide.c",
        "kernel/selinux/rules.c",
        "kernel/selinux/sepolicy.c",
        "kernel/selinux/sepolicy.h",
    ]


PATCHES_SELINUX_UPSTREAM = []

SUPERSEDED_PATCHES = [{
    "name": "0017-selinux-upstream-sync.patch",
    "status": "superseded-upstream",
    "upstream": C.UPSTREAM_COMMIT,
    "archive": "patches/extra/selinux-upstream-sync-20261107.patch",
    "summary": "Use upstream #3936/#3964/#3969 and subsequent SELinux fixes; drop the old local newline-condition deviation",
}]
