# SPDX-License-Identifier: GPL-3.0-or-later
"""Scope late-load SELinux defaults to jailbreak sessions."""
import ksu_common as C

def patch_jailbreak_session(tree, _source):
    patch = C.KSU_ROOT / "patches/extra/jailbreak-selinux-session-20261110.patch"
    C.git_apply(tree.root, patch, check=True)
    C.git_apply(tree.root, patch)
    return ["userspace/ksud/src/feature.rs", "userspace/ksud/src/late_load.rs"]

PATCHES_JAILBREAK_SESSION = [{
    "name": "0020-jailbreak-selinux-session.patch",
    "apply": patch_jailbreak_session,
    "status": "implemented",
    "summary": "Initialize jailbreak SELinux hiding before scripts and preserve ordinary boot preferences",
}]
