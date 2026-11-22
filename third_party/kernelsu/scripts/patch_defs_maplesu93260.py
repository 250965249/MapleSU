"""Explicit symbol input for the retained MapleSU_93260 acquisition flow."""
import ksu_common as C


def patch_maplesu93260(tree, _source):
    patch = C.KSU_ROOT / "patches/extra/maplesu-93260-symbol-input.patch"
    C.git_apply(tree.root, patch, check=True)
    C.git_apply(tree.root, patch)
    return ["userspace/ksuinit/src/lib.rs"]


PATCHES_MAPLESU93260 = [{
    "name": "0019-maplesu-93260-symbol-input.patch",
    "apply": patch_maplesu93260,
    "status": "implemented",
    "summary": "MapleSU_93260 explicit source kallsyms input; retain system symbols on other routes",
}]
