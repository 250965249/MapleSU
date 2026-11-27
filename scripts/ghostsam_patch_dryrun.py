#!/usr/bin/env python3
"""GhostSam × MapleSU Normal 兼容补丁的离线 dry-run / 静态登记校验。

背景
----
MapleSU 的基础补丁序列是 ``third_party/kernelsu/patches/7k/series``（26 项，由
``scripts/gen_patches.py`` 生成、``scripts/apply_patches.py`` 消费，并与
``manifest.json.patchSeries.seriesSha256`` 绑定）。本工具**不修改**基础序列，也不
手改生成树 ``applied/``；它校验一个**扩展序列** ``patches/7k/series-ghostsam``
（当前仅 0028-ghostsam-late-load-compat.patch），并在临时目录里按“基础序列 →
扩展序列”的顺序真实 ``git apply`` 一遍，作为可重复的应用检查。

设计边界（fail-closed）
- 只读取/复制 ``third_party/kernelsu/upstream`` 到临时目录，绝不写 ``applied/``；
- 扩展补丁只允许改 ``userspace/ksud/src/{cli.rs,late_load.rs}``；
- 新增行不得出现 boot-patch / boot-restore / InstallerPartitionService / /dev/block /
  modules.rc / metadata / set_active / flash 等系统或启动分区写入路径；
- 校验 ``late_load.rs`` 重启组件走 MapleSU 自己的 build-time 包名（
  ``defs::DEFAULT_PACKAGE_NAME``），不再沿用上游 ``me.weishu`` 硬编码组件；
- 校验 ``cli.rs`` 接受 ``--soft-reboot``（兼容 no-op）。

用法
----
    py -3 scripts/ghostsam_patch_dryrun.py            # 全量 dry-run（真实 apply 到临时树）
    py -3 scripts/ghostsam_patch_dryrun.py --static   # 只做静态登记/内容校验，不 apply
    py -3 scripts/ghostsam_patch_dryrun.py --self-test # 等价默认，供 CI/门禁
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ALLOWED_TARGETS = {
    "userspace/ksud/src/cli.rs",
    "userspace/ksud/src/late_load.rs",
}
FORBIDDEN_ADDED = [
    "/dev/block",
    "boot-patch",
    "boot_patch",
    "boot-restore",
    "boot_restore",
    "InstallerPartitionService",
    "modules.rc",
    "/metadata",
    "set_active",
    "flash ",
    "flash_boot",
]
EXTENSION_PATCH = "0028-ghostsam-late-load-compat.patch"
SAMSUNG_PATCHES = [
    "0029-samsung-kdp.patch",
    "0030-samsung-defex.patch",
    "0031-samsung-selinux-hide.patch",
    "0032-samsung-rkp-no-patch-text.patch",
    "0033-samsung-kbuild-init-order.patch",
    "0034-samsung-exynos-double-name.patch",
]
SAMSUNG_TARGET_PREFIXES = (
    "kernel/compat/",
    "kernel/feature/",
    "kernel/hook/",
    "kernel/core/",
    "kernel/include/",
    "kernel/policy/",
    "kernel/Kbuild",
    "userspace/ksud/src/late_load.rs",
)


class DryRunError(RuntimeError):
    pass


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_series(path: Path) -> list[str]:
    out = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        out.append(line)
    return out


def _git(args: list[str], cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=str(cwd), capture_output=True, text=True)


def _git_ok(args: list[str], cwd: Path) -> subprocess.CompletedProcess:
    proc = _git(args, cwd)
    if proc.returncode != 0:
        raise DryRunError(f"git {' '.join(args)} failed: {proc.stderr.strip() or proc.stdout.strip()}")
    return proc


def patch_added_lines(patch_text: str) -> list[str]:
    return [ln[1:] for ln in patch_text.splitlines() if ln.startswith("+") and not ln.startswith("+++")]


def patch_targets(patch_text: str) -> list[str]:
    targets = []
    for ln in patch_text.splitlines():
        m = re.match(r"^diff --git a/(\S+) b/(\S+)$", ln)
        if m:
            if m.group(1) != m.group(2):
                raise DryRunError(f"patch renames/mismatched path: {ln}")
            targets.append(m.group(1))
    return targets


def static_checks(kroot: Path) -> dict:
    patches_dir = kroot / "patches" / "7k"
    base_series = patches_dir / "series"
    ext_series = patches_dir / "series-ghostsam"
    patch = patches_dir / EXTENSION_PATCH
    for p in (base_series, ext_series, patch):
        if not p.is_file():
            raise DryRunError(f"missing required file: {p}")

    base_entries = read_series(base_series)
    ext_entries = read_series(ext_series)
    if not ext_entries or ext_entries[0] != EXTENSION_PATCH:
        raise DryRunError(f"series-ghostsam must start with {EXTENSION_PATCH}, got {ext_entries}")
    # Samsung delta (0029+) must be registered in order right after 0028.
    if list(ext_entries[1:]) != SAMSUNG_PATCHES:
        raise DryRunError(f"series-ghostsam samsung entries mismatch: {ext_entries[1:]} != {SAMSUNG_PATCHES}")
    if EXTENSION_PATCH in base_entries:
        raise DryRunError("0028 must NOT be in the base series (base must stay byte-identical)")

    text = patch.read_text(encoding="utf-8")
    if "\r" in text:
        raise DryRunError("patch contains CR (line-ending policy is LF-only)")
    targets = patch_targets(text)
    for t in targets:
        if t not in ALLOWED_TARGETS:
            raise DryRunError(f"patch touches a non-allowed file: {t}")
    if "userspace/ksud/src/cli.rs" not in targets or "userspace/ksud/src/late_load.rs" not in targets:
        raise DryRunError(f"patch must touch both cli.rs and late_load.rs, got {targets}")

    added = patch_added_lines(text)
    for ln in added:
        low = ln.lower()
        for bad in FORBIDDEN_ADDED:
            if bad.lower() in low:
                raise DryRunError(f"forbidden token {bad!r} in added line: {ln!r}")
        if "me.weishu" in low:
            raise DryRunError(f"added line still references upstream me.weishu component: {ln!r}")

    added_blob = "\n".join(added)
    if "soft_reboot" not in added_blob or "--soft-reboot" not in added_blob:
        raise DryRunError("patch does not accept --soft-reboot on late-load")
    if "defs::DEFAULT_PACKAGE_NAME" not in added_blob:
        raise DryRunError("patch does not switch manager restart to defs::DEFAULT_PACKAGE_NAME")
    if "MapleSU Manager" not in added_blob:
        raise DryRunError("patch does not log the MapleSU manager restart")

    manifest_path = kroot / "manifest.json"
    manifest_series_sha = None
    if manifest_path.is_file():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest_series_sha = (manifest.get("patchSeries") or {}).get("seriesSha256")

    result = {
        "baseSeries": "series",
        "baseSeriesEntries": base_entries,
        "baseSeriesSha256": _sha256(base_series),
        "manifestSeriesSha256": manifest_series_sha,
        "baseSeriesMatchesManifest": (manifest_series_sha is None or manifest_series_sha == _sha256(base_series)),
        "extensionSeries": "series-ghostsam",
        # Legacy fields keep describing 0028 exactly (existing tests depend on them);
        # the full extension series is exposed separately.
        "extensionSeriesEntries": [EXTENSION_PATCH],
        "fullExtensionEntries": ext_entries,
        "samsungPatches": SAMSUNG_PATCHES,
        "extensionSeriesSha256": _sha256(ext_series),
        "patch": EXTENSION_PATCH,
        "patchSha256": _sha256(patch),
        "patchTargets": targets,
        "patchAddedLines": added,
    }
    if manifest_series_sha is not None and manifest_series_sha != _sha256(base_series):
        raise DryRunError(
            "base series sha256 does not match manifest.json patchSeries.seriesSha256 "
            f"({_sha256(base_series)} != {manifest_series_sha})"
        )
    return result


def samsung_static_checks(kroot: Path) -> dict:
    """Validate the Samsung delta patches (0029+) that live in series-ghostsam."""
    patches_dir = kroot / "patches" / "7k"
    metas = []
    for name in SAMSUNG_PATCHES:
        path = patches_dir / name
        if not path.is_file():
            raise DryRunError(f"missing samsung patch: {path}")
        text = path.read_text(encoding="utf-8")
        if "\r" in text:
            raise DryRunError(f"samsung patch has CR: {name}")
        targets = patch_targets(text)
        if not targets:
            raise DryRunError(f"samsung patch has no targets: {name}")
        for t in targets:
            if t.endswith("apk_sign.c") or "apk_sign" in t:
                raise DryRunError(f"samsung patch must not touch identity code: {t}")
            if not any(t == pre or t.startswith(pre) for pre in SAMSUNG_TARGET_PREFIXES):
                raise DryRunError(f"samsung patch touches disallowed target {t} in {name}")
        added = patch_added_lines(text)
        for ln in added:
            low = ln.lower()
            for bad in FORBIDDEN_ADDED:
                if bad.lower() in low:
                    raise DryRunError(f"forbidden token {bad!r} in {name}: {ln!r}")
        metas.append({"name": name, "targets": targets, "sha256": _sha256(path),
                      "added": added})
    return {"samsungPatches": metas}


def samsung_apply_dry_run(kroot: Path) -> dict:
    """Real apply of base(26) + FULL extension (0028 + six samsung patches) to a temp tree."""
    patches_dir = kroot / "patches" / "7k"
    upstream = kroot / "upstream"
    work = Path(tempfile.mkdtemp(prefix="maplesu-samsung-dryrun-"))
    try:
        dst = work / "u"
        shutil.copytree(upstream, dst)
        _git_ok(["init", "-q"], dst)
        _git_ok(["config", "core.autocrlf", "false"], dst)
        _git_ok(["add", "-A"], dst)
        _git_ok(["-c", "user.email=a@b", "-c", "user.name=a", "commit", "-qm", "base"], dst)
        base = read_series(patches_dir / "series")
        ext = read_series(patches_dir / "series-ghostsam")
        applied = []
        for name in base + ext:
            patch_path = patches_dir / name
            if not patch_path.is_file():
                raise DryRunError(f"series entry missing: {name}")
            check = _git(["apply", "--check", "-p1", "--whitespace=error-all", str(patch_path)], dst)
            if check.returncode != 0:
                raise DryRunError(f"git apply --check failed for {name}: {check.stderr.strip()}")
            _git_ok(["apply", "-p1", "--whitespace=error-all", str(patch_path)], dst)
            applied.append(name)
        late = (dst / "userspace/ksud/src/late_load.rs").read_text(encoding="utf-8")
        for token in ("-exynos_kernelsu.ko", "KSUD_TREE", "exynos"):
            if token not in late:
                raise DryRunError(f"late_load.rs missing exynos token {token!r} after extension apply")
        kdp = (dst / "kernel/compat/samsung_kdp.c").read_text(encoding="utf-8")
        defex = (dst / "kernel/compat/samsung_defex.c").read_text(encoding="utf-8")
        kdph = (dst / "kernel/include/ksu_samsung_kdp.h").read_text(encoding="utf-8")
        # 0031 overwrites the base selinux_hide.c with the reference RKP-kprobe version;
        # the old fake kernel/feature/samsung_selinux_hide.c must NOT exist any more.
        selinux = (dst / "kernel/feature/selinux_hide.c").read_text(encoding="utf-8")
        initc = (dst / "kernel/core/init.c").read_text(encoding="utf-8")
        shm = (dst / "kernel/hook/syscall_hook_manager.c").read_text(encoding="utf-8")
        kbuild = (dst / "kernel/Kbuild").read_text(encoding="utf-8")
        appp = (dst / "kernel/policy/app_profile.c").read_text(encoding="utf-8")
        tpm = (dst / "kernel/hook/tp_marker.c").read_text(encoding="utf-8")
        sup = (dst / "kernel/feature/sucompat.c").read_text(encoding="utf-8")

        # --- KDP: real symbol-resolution + static_key gated cred suite ---
        for tok in ("prepare_ro_creds", "kdp_assign_pgd",
                    "DEFINE_STATIC_KEY_FALSE(ksu_samsung_kdp_key)",
                    "ksu_resolve_symbol_for_functable_hook", "CONFIG_KSU_SAMSUNG_KDP"):
            if tok not in kdp:
                raise DryRunError(f"samsung_kdp.c missing real-implementation token {tok!r}")
        for tok in ("ksu_commit_creds", "ksu_put_cred", "CONFIG_KSU_SAMSUNG_KDP"):
            if tok not in kdph:
                raise DryRunError(f"ksu_samsung_kdp.h missing cred-wrapper token {tok!r}")

        # --- DEFEX: task_defex_enforce kprobe + cred sync ---
        for tok in ("task_defex_enforce", "ksu_samsung_defex_sync_current", "CONFIG_KSU_SAMSUNG_DEFEX"):
            if tok not in defex:
                raise DryRunError(f"samsung_defex.c missing real-implementation token {tok!r}")

        # --- SELinux hide: RKP kprobe trampolines under CONFIG_KSU_RKP_NO_PATCH_TEXT ---
        for tok in ("CONFIG_KSU_RKP_NO_PATCH_TEXT", "sel_hide_context_write_kprobe",
                    "sel_hide_register_probe", "sel_hide_status_open_tramp"):
            if tok not in selinux:
                raise DryRunError(f"selinux_hide.c missing RKP-only token {tok!r}")

        # --- P1 (route b): non-sleeping guard allocation + hide-state aware status probe ---
        guard = re.search(r"static bool sel_hide_guard_enter\(void\)\s*\{(.*?)\n\}", selinux, re.S)
        if not guard:
            raise DryRunError("selinux_hide.c: sel_hide_guard_enter not found")
        gbody = guard.group(1)
        gcode = "\n".join(
            ln for ln in gbody.splitlines()
            if not ln.strip().startswith(("*", "/*", "//"))
        )
        if "GFP_KERNEL" in gcode or "GFP_ATOMIC" not in gcode:
            raise DryRunError("selinux_hide.c: guard_enter uses a sleeping alloc (need GFP_ATOMIC, no GFP_KERNEL)")
        status_pre = re.search(
            r"static int sel_hide_status_open_pre\(struct kprobe \*p, struct pt_regs \*regs\)\s*\{(.*?)\n\}",
            selinux, re.S)
        if not status_pre or "ksu_selinux_hide_enabled" not in status_pre.group(1):
            raise DryRunError("selinux_hide.c: status_open_pre does not gate on the live hide switch")

        # --- syscall hook manager: RKP fallback wired when the dispatcher slot is absent,
        #     while MapleSU's own init_module_filter wiring MUST be preserved ---
        for tok in ("rkp_sucompat_hook_init", "rkp_setresuid_hook_init",
                    "ksu_dispatcher_nr < 0", "syscall_hook_manager_initialized"):
            if tok not in shm:
                raise DryRunError(f"syscall_hook_manager.c missing RKP-fallback token {tok!r}")
        if "ksu_init_module_filter_init" not in shm or "ksu_init_module_filter_exit" not in shm:
            raise DryRunError("syscall_hook_manager.c lost MapleSU init_module_filter wiring")

        # --- init.c order: symbol_resolver -> kdp -> prepare_creds -> defex -> selinux_inode ---
        try:
            i_sym = initc.index("ksu_init_symbol_resolver()")
            i_kdp = initc.index("ksu_samsung_kdp_init()")
            i_cred = initc.index("ksu_cred = prepare_creds()")
            i_def = initc.index("ksu_samsung_defex_init()")
            i_sel = initc.index("ksu_selinux_inode_init()")
        except ValueError as exc:
            raise DryRunError(f"init.c missing Samsung init-sequence anchor: {exc}")
        if not (i_sym < i_kdp < i_cred < i_def < i_sel):
            raise DryRunError(
                "init.c Samsung init order wrong: expected resolver<kdp<prepare_creds<defex<selinux_inode, "
                f"got {i_sym},{i_kdp},{i_cred},{i_def},{i_sel}")
        if "ksu_put_cred" not in initc:
            raise DryRunError("init.c not using ksu_put_cred for the Samsung KDP cred path")

        # --- cred wrapping ports (device-proven: policy/app_profile.c + hook/tp_marker.c) ---
        if "ksu_commit_creds(cred)" not in appp:
            raise DryRunError("app_profile.c not routed through ksu_commit_creds")
        if "ksu_put_cred(cred)" not in tpm:
            raise DryRunError("tp_marker.c not routed through ksu_put_cred")

        # --- Kbuild: unconditional objs + only three ccflags ifeq gates ---
        for tok in ("kernelsu-objs += compat/samsung_kdp.o",
                    "kernelsu-objs += compat/samsung_defex.o",
                    "kernelsu-objs += feature/selinux_hide.o",
                    "ccflags-y += -DCONFIG_KSU_RKP_NO_PATCH_TEXT=1",
                    "ccflags-y += -DCONFIG_KSU_SAMSUNG_KDP=1",
                    "ccflags-y += -DCONFIG_KSU_SAMSUNG_DEFEX=1"):
            if tok not in kbuild:
                raise DryRunError(f"Kbuild missing Samsung build wiring {tok!r}")
        if "samsung_selinux_hide.o" in kbuild or "samsung_rkp_guard.o" in kbuild:
            raise DryRunError("Kbuild still references the removed fake Samsung objects")

        # --- fake files from the old delta must be gone ---
        for fake in ("kernel/feature/samsung_selinux_hide.c", "kernel/hook/samsung_rkp_guard.c"):
            if (dst / fake).exists():
                raise DryRunError(f"obsolete fake file still present after apply: {fake}")

        # --- __exit alignment (modpost section mismatch on 6.1+) ---
        # No .exit.text function may be referenced from .init.text. ksu_syscall_hook_manager_init
        # -> rkp_sucompat_hook_init -> ksu_sucompat_exit() runs in init context, so
        # ksu_sucompat_exit must NOT carry __exit (matches KernelSU@samsung reference tree).
        if "void __exit ksu_sucompat_exit" in sup or "void ksu_sucompat_exit" not in sup:
            raise DryRunError("sucompat.c: ksu_sucompat_exit still __exit (.exit.text) — init.text caller mismatch")
        if "void __exit ksu_samsung_kdp_exit" in kdp or "void ksu_samsung_kdp_exit(void)" not in kdp:
            raise DryRunError("samsung_kdp.c: ksu_samsung_kdp_exit wrongly marked __exit")
        if "void __exit ksu_samsung_defex_exit" in defex or "void ksu_samsung_defex_exit(void)" not in defex:
            raise DryRunError("samsung_defex.c: ksu_samsung_defex_exit wrongly marked __exit")

        return {"appliedEntries": applied, "appliedCount": len(applied)}
    finally:
        shutil.rmtree(work, ignore_errors=True)


def apply_dry_run(kroot: Path, info: dict) -> dict:
    """复制 upstream 到临时树，按 基础序列 -> 扩展序列 顺序真实 git apply。"""
    patches_dir = kroot / "patches" / "7k"
    upstream = kroot / "upstream"
    work = Path(tempfile.mkdtemp(prefix="maplesu-ghostsam-dryrun-"))
    try:
        dst = work / "u"
        shutil.copytree(upstream, dst)
        _git_ok(["init", "-q"], dst)
        _git_ok(["config", "core.autocrlf", "false"], dst)
        _git_ok(["add", "-A"], dst)
        _git_ok(["-c", "user.email=a@b", "-c", "user.name=a", "commit", "-qm", "base"], dst)

        applied = []
        for name in info["baseSeriesEntries"] + info["extensionSeriesEntries"]:
            patch_path = patches_dir / name
            if not patch_path.is_file():
                raise DryRunError(f"series entry missing: {name}")
            check = _git(["apply", "--check", "-p1", "--whitespace=error-all", str(patch_path)], dst)
            if check.returncode != 0:
                raise DryRunError(f"git apply --check failed for {name}: {check.stderr.strip()}")
            _git_ok(["apply", "-p1", "--whitespace=error-all", str(patch_path)], dst)
            applied.append(name)

        cli = (dst / "userspace/ksud/src/cli.rs").read_text(encoding="utf-8")
        late = (dst / "userspace/ksud/src/late_load.rs").read_text(encoding="utf-8")
        if "soft_reboot" not in cli or "--soft-reboot" not in cli:
            raise DryRunError("applied cli.rs lacks --soft-reboot compat flag")
        if "defs::DEFAULT_PACKAGE_NAME" not in late or "MapleSU Manager" not in late:
            raise DryRunError("applied late_load.rs does not restart the MapleSU manager component")
        if "{package_name}/me.weishu.kernelsu.ui.MainActivity" in late:
            raise DryRunError("applied late_load.rs still uses the upstream me.weishu component")
        # 三重身份校验不得被削弱：补丁不得触及 apk_sign.c / Kbuild。
        for t in info["patchTargets"]:
            if "apk_sign" in t or t.endswith("kernel/Kbuild"):
                raise DryRunError(f"patch must not touch identity code: {t}")

        return {"appliedEntries": applied, "appliedCount": len(applied)}
    finally:
        shutil.rmtree(work, ignore_errors=True)


def run(repo_root: Path, apply: bool = True) -> dict:
    kroot = repo_root / "third_party" / "kernelsu"
    info = static_checks(kroot)
    info.update(samsung_static_checks(kroot))
    if apply:
        info.update(apply_dry_run(kroot, info))  # legacy 0028-only (existing tests)
        samsung = samsung_apply_dry_run(kroot)     # full series-ghostsam incl. 0029+
        info["samsungAppliedCount"] = samsung["appliedCount"]
        info["samsungAppliedEntries"] = samsung["appliedEntries"]
    return info


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--static", action="store_true", help="只做静态校验，不真实 apply")
    ap.add_argument("--self-test", action="store_true", help="等价默认 dry-run，供门禁调用")
    ap.add_argument("--json", action="store_true", help="输出 JSON 摘要")
    args = ap.parse_args(argv)
    repo_root = Path(__file__).resolve().parent.parent
    try:
        info = run(repo_root, apply=not args.static)
    except DryRunError as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        return 1
    if args.json:
        summary = {k: v for k, v in info.items() if k != "patchAddedLines"}
        print(json.dumps(summary, ensure_ascii=False, indent=2))
    else:
        print("[OK] base series sha256:", info["baseSeriesSha256"])
        print("[OK] manifest series sha256:", info["manifestSeriesSha256"], "(match:", info["baseSeriesMatchesManifest"], ")")
        print("[OK] extension series:", info["extensionSeriesEntries"], "sha256:", info["extensionSeriesSha256"])
        print("[OK] patch:", info["patch"], "sha256:", info["patchSha256"])
        print("[OK] patch targets:", info["patchTargets"])
        if "appliedCount" in info:
            print("[OK] applied", info["appliedCount"], "patches to temp tree (base+0028 legacy)")
        if "samsungAppliedCount" in info:
            print("[OK] applied", info["samsungAppliedCount"],
                  "patches to temp tree (base + full series-ghostsam incl. 0029+)")
        print("[OK] static + dry-run checks passed; note: nothing was built (no SDK/NDK/artifact).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
