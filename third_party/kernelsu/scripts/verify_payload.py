#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""发布/CI 门禁：校验 manifest.json + ksu-payload.json + patches + applied 三者一致。

对应 03 分册 §7.1（三元组）+ §7.2（CRLF）+ §7.5（UAPI 冻结表）。
任何一条不满足 → 打印失败项并以非 0 退出。**不做任何写操作**（临时目录除外）。

用法：
  python third_party/kernelsu/scripts/verify_payload.py            # 默认全检
  python third_party/kernelsu/scripts/verify_payload.py --quick    # 跳过重放补丁
"""
from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import shutil
import subprocess
import sys
from pathlib import Path

import ksu_common as C

FROZEN_IOCTLS = {
    "APP_LOCK_STATE": 30, "APP_LOCK_AUTH": 31, "APP_LOCK_SET": 32,
    "STEALTH_GET": 33, "STEALTH_SET": 34, "STEALTH_GET_G": 35, "STEALTH_SET_G": 36,
}
UAPI_COPIES = ("kernel/include/uapi", "manager/app/src/main/cpp/uapi")


class Checker:
    def __init__(self) -> None:
        self.fails: list[str] = []
        self.notes: list[str] = []

    def check(self, cond: bool, msg: str) -> bool:
        if not cond:
            self.fails.append(msg)
        return cond

    def note(self, msg: str) -> None:
        self.notes.append(msg)


def replay_series(root: Path) -> tuple[bool, str]:
    """在临时目录里从 upstream 重放 series，证明补丁真的可应用。

    重放目录**必须不在 git 工作树内**：2026-10-31 仓库根被 `git init` 后，原先的
    `third_party/kernelsu/.tmp/` 落进 worktree，`git apply` 把 14 个补丁逐个判成
    "Skipped patch" 且返回 0（G5-a 事故），重放树退化成 upstream 裸树。
    现在用 `C.isolated_apply_root()` 直接开在系统临时目录并断言非仓库，
    `C.git_apply()` 再把 "Skipped patch" 当硬失败，验证强度不变（仍是真应用 + 真哈希）。
    """
    upstream, patch_dir = root / "upstream", root / "patches" / "7k"
    tmp = C.isolated_apply_root("maplesu-verify-replay-")
    try:
        try:
            C.copy_tree(upstream, tmp)
            for name in C.read_series(patch_dir / "series"):
                p = (patch_dir / name).resolve()
                C.git_apply(tmp, p, check=True)
                C.git_apply(tmp, p, check=False)
        except C.KsuError as exc:
            return False, str(exc)
        # 与 apply_patches.py 同一步：Windows 无 symlink，uapi 副本必须同步，
        # 否则重放树的 3 份 supercall.h 与 applied 不一致（差 3 个文件哈希）。
        uapi = tmp / "uapi"
        for rel in UAPI_COPIES:
            dest = tmp.joinpath(*rel.split("/"))
            for header in sorted(p.name for p in uapi.iterdir() if p.is_file()):
                C.write_bytes(dest / header, (uapi / header).read_bytes())
        got = C.tree_sha256(tmp)
        want = C.tree_sha256(root / "applied")
        if got != want:
            return False, f"重放后的树哈希 {got} != applied {want}"
        return True, got
    finally:
        shutil.rmtree(tmp, ignore_errors=True)



def _find_rustfmt() -> str | None:
    """rustup/cargo 常见位置探测（Windows 下 PATH 常没有 rustfmt）。"""
    import os
    home = os.path.expanduser("~")
    for cand in (
        f"{home}/.cargo/bin/rustfmt",
        f"{home}/.cargo/bin/rustfmt.exe",
        "/usr/local/cargo/bin/rustfmt",
        "/usr/bin/rustfmt",
    ):
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return None


def verify(root: Path, quick: bool) -> Checker:
    ck = Checker()
    manifest_path = root / "manifest.json"
    payload_path = root / "ksu-payload.json"
    applied = root / "applied"
    upstream = root / "upstream"
    patch_dir = root / "patches" / "7k"

    for p in (manifest_path, payload_path):
        if not ck.check(p.is_file(), f"缺文件: {p}"):
            return ck
    manifest = C.read_json(manifest_path)
    payload = C.read_json(payload_path)

    # 1) commit 固定（禁止跟随 latest）
    ck.check(manifest["upstream"]["commit"] == C.UPSTREAM_COMMIT,
             f"upstream.commit 漂移: {manifest['upstream']['commit']}")
    ck.check(manifest["source7k"]["commit"] == C.SOURCE7K_COMMIT,
             f"source7k.commit 漂移: {manifest['source7k']['commit']}")
    ck.check(payload["branch"]["upstream"] == manifest["upstream"]["commit"],
             "payload.branch.upstream != manifest.upstream.commit")

    # 2) upstream 树未变、文件数一致
    if ck.check(upstream.is_dir(), "缺 upstream/ 快照"):
        up_tree = C.tree_sha256(upstream)
        ck.check(up_tree == manifest["upstream"]["treeSha256"],
                 f"upstream treeSha256 不符（{up_tree[:16]}… != manifest）")
        ck.check(len(C.iter_tree_files(upstream)) == manifest["upstream"]["fileCount"],
                 "upstream fileCount 不符")

    # 3) patch series：哈希、顺序、文件存在且 LF
    series = C.read_series(patch_dir / "series")
    hashes = C.series_hashes(patch_dir)
    ck.check(hashes["seriesSha256"] == manifest["patchSeries"]["seriesSha256"],
             "series 文件哈希不符")
    ck.check(hashes["aggregateSha256"] == manifest["patchSeries"]["aggregateSha256"],
             "patch 聚合哈希不符（manifest）")
    ck.check(hashes["aggregateSha256"] == payload["branch"]["aggregatePatchSha256"],
             "patch 聚合哈希不符（payload）")
    ck.check(hashes["seriesSha256"] == payload["branch"]["patchSeriesSha256"],
             "series 哈希不符（payload）")
    ck.check(series == manifest["patchSeries"]["order"], "series 顺序与 manifest.order 不符")
    ck.check(series == payload["branch"]["patchOrder"], "series 顺序与 payload.patchOrder 不符")
    for name in series:
        p = patch_dir / name
        ck.check(p.is_file(), f"series 里的补丁不存在: {name}")
        if p.is_file():
            ck.check(b"\r" not in p.read_bytes(), f"补丁含 CR（必须 LF）: {name}")
    ck.check(len(manifest["patchSeries"]["todo"]) >= 1,
             "patchSeries.todo 为空：未完成项必须显式登记，不允许静默")

    # 4) applied 树：存在、哈希一致、文件数一致、与 payload 一致
    if ck.check(applied.is_dir(), "缺 applied/（先跑 apply_patches.py --clean）"):
        applied_tree = C.tree_sha256(applied)
        ck.check(applied_tree == manifest["applied"]["treeSha256"],
                 "applied treeSha256 不符（applied 被手改或未重建）")
        ck.check(applied_tree == payload["branch"]["treeSha256"],
                 "applied treeSha256 != payload.branch.treeSha256")
        applied_inputs = [f for f in C.iter_tree_files(applied)
                          if f not in C.TREE_EXCLUDES]
        ck.check(len(applied_inputs) == payload["branch"]["fileCount"],
                 "applied fileCount != payload.branch.fileCount")

    # 5) UAPI triple：7 + 冻结 ioctl
    if (applied / "uapi" / "supercall.h").is_file():
        uapi_text = C.read_text(applied / "uapi" / "supercall.h")
        ck.check(bool(re.search(r"KERNEL_SU_UAPI_VERSION\s*=\s*7\s*;", uapi_text)),
                 "applied UAPI != 7")
        numbers = {}
        for name, num in re.findall(r"KSU_IOCTL_(\w+)\s*=\s*_IO[RW]*\('K',\s*(\d+)", uapi_text):
            numbers[name] = int(num)
        for name, want in FROZEN_IOCTLS.items():
            ck.check(numbers.get(name) == want,
                     f"冻结 ioctl {name}={numbers.get(name)} != {want}")
        ck.check(numbers.get("LOOKUP_SYMBOLS") == 22,
                 "上游 LOOKUP_SYMBOLS=22 被改动（冻结表要求保留）")
        for reserved in (37, 38, 39):
            ck.check(reserved not in numbers.values(),
                     f"预留 ioctl 号 {reserved} 被普通功能占用")
        values = list(numbers.values())
        ck.check(len(values) == len(set(values)), "ioctl 号重复")
        # 同树：三份 supercall.h 必须逐字节相同（Windows 无 symlink，落成真实副本）
        canon = (applied / "uapi" / "supercall.h").read_bytes()
        for rel in UAPI_COPIES:
            other = applied.joinpath(*rel.split("/")) / "supercall.h"
            ck.check(other.is_file() and other.read_bytes() == canon,
                     f"同树破坏: {rel}/supercall.h 与 uapi/supercall.h 不一致")
        ck.check(payload["branch"]["uapi"] == 7, "payload.branch.uapi != 7")
        ck.check(payload["uapi"]["version"] == 7, "payload.uapi.version != 7")
        ck.check(payload["branch"]["uapiHeaderSha256"] == C.sha256_file(
            applied / "uapi" / "supercall.h"), "payload.uapiHeaderSha256 不符")
        # 结构体稳定性
        for needle in ("struct ksu_app_lock_state_cmd {", "__u8 hash[32];",
                       "__u32 manager_gen;", "__u8 _pad[3];"):
            ck.check(needle in uapi_text, f"UAPI 结构体稳定性断言失败: 缺 {needle!r}")

    # 5b) W18b：补丁自带的静态断言（patches.json.checks）+ 完成度巡检
    patches_json = patch_dir / "patches.json"
    if ck.check(patches_json.is_file(), "缺 patches/7k/patches.json"):
        meta = C.read_json(patches_json)
        for entry in meta.get("entries", []):
            for rel, needles in entry.get("checks", []):
                target = applied / rel
                present = ck.check(target.is_file(),
                                   f"{entry.get('name')}: checks 目标缺失 {rel}")
                if not present:
                    continue
                text = target.read_bytes().decode("utf-8", "replace")
                for needle in needles:
                    ck.check(needle in text,
                             f"{entry.get('name')}: {rel} 缺 {needle!r}")
        statuses = {e.get("name"): e.get("status") for e in meta.get("entries", [])}
        bad = [k for k, v in statuses.items() if v != "implemented"]
        ck.check(not bad, f"仍有非 implemented 补丁: {bad}")

    # 5c) Rust 语法门禁：rustfmt 真解析（不需要依赖，能抓移植块的语法错误）
    rustfmt = shutil.which("rustfmt") or _find_rustfmt()
    if rustfmt and applied.is_dir() and (patch_dir / "patches.json").is_file():
        rs_files: set[str] = set()
        for entry in C.read_json(patch_dir / "patches.json").get("entries", []):
            rs_files.update(t for t in entry.get("touches", []) if t.endswith(".rs"))
        failed = 0
        for rel in sorted(rs_files):
            target = applied / rel
            if not target.is_file():
                continue
            proc = subprocess.run(
                [rustfmt, "--edition", "2024", "--emit", "stdout", str(target)],
                capture_output=True)
            if proc.returncode != 0:
                failed += 1
                ck.check(False, f"rustfmt 语法失败 {rel}: "
                                f"{proc.stderr.decode('utf-8', 'replace')[:300]}")
        ck.note(f"rustfmt syntax gate: {len(rs_files)} files, {failed} failed")
    else:
        ck.note("rustfmt not found: 跳过 Rust 语法门禁（CI 必须装 rustfmt）")

    # 5d) W18b 三重校验：kernel 认主 / ksud 默认包名 / manifest.identity 三处同值
    ident = manifest.get("identity", {})
    pkg = ident.get("managerPackage")
    ck.check(pkg == ident.get("packageName"),
             "identity.managerPackage != identity.packageName")
    if applied.is_dir() and pkg:
        kbuild = C.read_text(applied / "kernel/Kbuild")
        ck.check(f"KSU_MANAGER_PACKAGE ?= {pkg}" in kbuild,
                 "Kbuild 的 KSU_MANAGER_PACKAGE 默认值与 manifest 不一致")
        build_rs = C.read_text(applied / "userspace/ksud/build.rs")
        ck.check(f"cargo:rustc-env=KSU_PACKAGE_NAME={pkg}" in build_rs,
                 "ksud build.rs 的默认包名与 manifest 不一致")
        apk_c = C.read_text(applied / "kernel/manager/apk_sign.c")
        ck.check("#ifdef KSU_MANAGER_PACKAGE" in apk_c and "get_pkg_from_apk_path" in apk_c,
                 "kernel 三重校验（包名判据 get_pkg_from_apk_path）未落地")
    ck.check(payload.get("identity", {}).get("managerPackage") == pkg,
             "payload.identity.managerPackage 与 manifest 不一致")

    # 6) CR 门禁（构建相关范围）
    if applied.is_dir():
        offenders = C.crlf_offenders(applied)
        ck.check(not offenders, f"applied 构建相关范围含 CR: {offenders[:8]}")

    # 7) 产物：present 才校验 sha256；pending 条目**不得**带假 sha256
    present = 0
    for art in payload.get("artifacts", []):
        status = art.get("status")
        if status == "present":
            present += 1
            path = art["path"]
            p = (root / path[len("third_party/kernelsu/"):]) \
                if path.startswith("third_party/kernelsu/") else (C.REPO_ROOT / path)
            if ck.check(p.is_file(), f"artifact 缺失: {path}"):
                ck.check(C.sha256_file(p) == art.get("sha256"),
                         f"artifact sha256 不符: {path}")
                if art.get("name") == "libksud_ksu.so":
                    ck.check(b"MAPLESU_KSUD_BUILD_V1 version=32650 uapi=7" in p.read_bytes(),
                             "ksud compiled identity mismatch: expected version=32650 uapi=7")
        elif "sha256" in art or "size" in art:
            ck.fails.append(f"pending artifact 不得带哈希（防伪造）: {art.get('name')}")
    ck.note(f"artifacts: present={present}, pending="
            f"{[a['name'] for a in payload.get('artifacts', []) if a.get('status') != 'present']}")

    # 7b) 多 KMI 矩阵（Normal/KSU 模式）：每个 KMI 一条 lkm 条目，结构/唯一性/矩阵覆盖。
    #     这是对 §7 的**扩展累加**，不改变上面既有的 present/pending 约定。
    lkm_entries = [a for a in payload.get("artifacts", []) if a.get("kind") == "lkm"]
    seen_kmi: dict[str, str] = {}
    for art in lkm_entries:
        name, kmi = art.get("name", ""), art.get("kmi", "")
        if not ck.check(C.is_kmi(kmi), f"lkm 条目的 kmi 非法: name={name!r} kmi={kmi!r}"):
            continue
        ck.check(name == C.lkm_entry_name(kmi),
                 f"lkm 条目名不符约定: {name!r} != {C.lkm_entry_name(kmi)!r}")
        ck.check(art.get("path") == C.lkm_rel_path(kmi),
                 f"lkm 条目 path 不符约定: {art.get('path')!r} != {C.lkm_rel_path(kmi)!r}")
        if kmi in seen_kmi:
            ck.check(False, f"lkm 条目 KMI 重复: {kmi}（{seen_kmi[kmi]} 与 {name}）")
        else:
            seen_kmi[kmi] = name
        if art.get("status") == "present":
            ck.check(bool(str(art.get("builtBy") or "").strip()),
                     f"present lkm 条目缺 builtBy（无法追溯构建来源）: {name}")
    missing_matrix = [k for k in C.KMI_MATRIX if k not in seen_kmi]
    ck.check(not missing_matrix, f"payload 缺 KMI 矩阵条目: {missing_matrix}")
    unknown_kmi = sorted(k for k in seen_kmi if k not in C.KMI_MATRIX)
    if unknown_kmi:
        ck.note(f"payload 含矩阵外 lkm 条目（未构建，仅登记）: {unknown_kmi}")
    kmi_present = [k for k in C.KMI_MATRIX
                   if next((a for a in lkm_entries if a.get("kmi") == k
                            and a.get("status") == "present"), None)]
    kmi_pending = [k for k in C.KMI_MATRIX if k not in kmi_present]
    ck.note(f"lkm KMI matrix: present={len(kmi_present)}/{len(C.KMI_MATRIX)} "
            f"{kmi_present} pending={kmi_pending}")

    # 8) payload 内 applied 文件清单与磁盘一致（抽查 3 个 + 数量）
    files = payload.get("appliedSource", {}).get("files", [])
    if ck.check(bool(files), "payload.appliedSource.files 为空"):
        applied_inputs = [f for f in C.iter_tree_files(applied)
                          if f not in C.TREE_EXCLUDES]
        ck.check(len(files) == len(applied_inputs),
                 "payload.appliedSource.files 数量 != applied 实际输入文件数")
        for entry in files[:3] + files[-2:]:
            p = applied / entry["path"]
            ck.check(p.is_file() and C.sha256_file(p) == entry["sha256"],
                     f"payload 文件清单哈希不符: {entry['path']}")

    # 9) manifest ↔ payload 身份一致
    for key in ("packageName", "uapiVersion", "managerMinGen"):
        ck.check(manifest["identity"][key] == payload["identity"][key],
                 f"identity.{key} 在 manifest/payload 不一致")

    # 10) 重放补丁（可选，慢）
    if not quick and applied.is_dir():
        ok, detail = replay_series(root)
        ck.check(ok, f"补丁重放失败: {detail}")

    return ck


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="manifest/payload/applied/patches 一致性门禁")
    ap.add_argument("--root", default=str(C.KSU_ROOT))
    ap.add_argument("--quick", action="store_true", help="跳过补丁重放（CI 快检）")
    args = ap.parse_args(argv)
    ck = verify(Path(args.root), args.quick)
    for note in ck.notes:
        print(f"NOTE: {note}")
    if ck.fails:
        print(f"FAILED ({len(ck.fails)}):", file=sys.stderr)
        for f in ck.fails:
            print(f"  - {f}", file=sys.stderr)
        return 2
    print("OK: commit + patch series + UAPI7 + applied tree + artifacts consistent")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
