#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""MapleSU KSU 分支树 · 公共库（纯标准库，主机可跑）。

本模块是 third_party/kernelsu/{upstream,patches/7k,applied,manifest.json,ksu-payload.json}
这条证据链的唯一共享实现：导出 LF 快照、树哈希、文件清单、CR 门禁、JSON 读写。
所有写盘操作一律用二进制 / newline=""，禁止让 Windows 文本模式把 \\n 变成 \\r\\n。

规格来源：docs/dual-mode/impl/03-ksu-contract.md §1.2–§1.3、§7.1–§7.2。
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path, PurePosixPath

# ---------------------------------------------------------------- 固定输入
# Pin the successful official CI selected for this source generation.
UPSTREAM_REPO = "https://github.com/tiann/KernelSU"
UPSTREAM_COMMIT = "f4603d14bd7f3bf21206d6f7c622ddf1c049ade3"
UPSTREAM_UAPI = 6
UPSTREAM_REF_NOTE = "Normal source baseline: official Build Manager #5545, 2026-11-17"
UPSTREAM_CI = {
    "workflow": "Build Manager",
    "runId": 44010950397,
    "runNumber": 5545,
    "url": "https://github.com/tiann/KernelSU/actions/runs/44010950397",
    "headSha": UPSTREAM_COMMIT,
    "conclusion": "success",
    "createdAt": "2026-11-17T03:32:39Z",
}

SOURCE7K_REPO = "https://github.com/hartgerinktarcila-design/7kimisu"
SOURCE7K_COMMIT = "dafd0a96ab1ad37cb4aa692b4081bf68e231d6a7"
SOURCE7K_RELEASE = "v2.30"
SOURCE7K_UAPI = 5

MAPLESU_UAPI = 7
MAPLESU_PACKAGE = "dev.maplesu.manager"
MAPLESU_MANAGER_MIN_GEN = 2
MAPLESU_KSU_VERSION_PIN = 32650

# ---------------------------------------------------------------- 多 KMI 矩阵
# Normal（KSU）模式的 LKM 产物按 KMI 一份：`lkm/<kmi>_kernelsu.ko`。
# Normal follows the selected official CI's eight KMI targets.
#   * 12-5.10 仅用于 android12 设备（无独立 init_boot，直装路径不支持，见 KmiRule）；
# Ultra companions retain their existing six-target matrix below.
KMI_MATRIX = (
    "android12-5.10",
    "android13-5.10",
    "android13-5.15",
    "android14-5.15",
    "android14-6.1",
    "android15-6.6",
    "android16-6.12",
    "android17-6.18",
)
COMPATIBILITY_KMI_MATRIX = (
    "android12-5.10", "android13-5.15", "android14-6.1",
    "android15-6.6", "android16-6.12", "android17-6.18",
)
KMI_DEFAULT = "android15-6.6"
KMI_KO_SUFFIX = "_kernelsu.ko"
KMI_PATTERN = re.compile(r"^android(\d+)-(\d+(?:\.\d+)*)$")


def is_kmi(value: object) -> bool:
    """`android14-6.1` 形状且 Android 大版本/内核序列都是数字。"""
    return isinstance(value, str) and bool(KMI_PATTERN.match(value))


def lkm_entry_name(kmi: str) -> str:
    """payload 条目的名字约定：`<kmi>_kernelsu.ko`。"""
    return f"{kmi}{KMI_KO_SUFFIX}"


def lkm_rel_path(kmi: str) -> str:
    """payload 条目记录的仓库相对路径（ksud 内嵌资产名同此 basename）。"""
    return f"third_party/kernelsu/lkm/{lkm_entry_name(kmi)}"


def kmi_sort_key(kmi: str) -> tuple[int, tuple[int, ...]]:
    """按 (Android 大版本, 内核版本元组) 排序，保证产物顺序稳定。"""
    match = KMI_PATTERN.match(kmi)
    if not match:
        return (1 << 30, ())
    return (int(match.group(1)), tuple(int(p) for p in match.group(2).split(".")))


def ddk_image_for(kmi: str, release: str = "20260828") -> str:
    """该 KMI 对应的 DDK 构建镜像（CI 的 matrix leg 用的同一个 tag）。"""
    return f"ghcr.io/ylarod/ddk-min:{kmi}-{release}"

# 03 分册 §1.2.1：无 `-c core.autocrlf=false` 时 git archive 输出的是 CRLF 工作树字节。
GIT_ARCHIVE_CMD = "git -C <repo> -c core.autocrlf=false archive --format=tar <rev>"

SCRIPT_DIR = Path(__file__).resolve().parent
KSU_ROOT = SCRIPT_DIR.parent
REPO_ROOT = KSU_ROOT.parents[1]
RESEARCH_ROOT = REPO_ROOT / ".research"
UPSTREAM_DIR = KSU_ROOT / "upstream"
PATCH_DIR = KSU_ROOT / "patches" / "7k"
APPLIED_DIR = KSU_ROOT / "applied"
MANIFEST_PATH = KSU_ROOT / "manifest.json"
PAYLOAD_PATH = KSU_ROOT / "ksu-payload.json"
SERIES_PATH = PATCH_DIR / "series"

# 树哈希/门禁排除项（生成物，不进证据链）
# 生成物/声明文件，不属于「构建输入树」，不进树哈希/文件清单（每次重建时写出）。
# 注意：applied/ 必须只含 upstream + patches 的内容，任何本机构建产物（cargo 配置、
# target/、日志、构建证据）都不能进入三元组 —— 否则 treeSha256 不可复现（W12d 实测漂移）。
GENERATED_FILES = (".applied.json", "NOTICE", "BUILD-EVIDENCE.md")
GENERATED_PREFIXES = (".cargo/", ".tmp/", "target/")
GENERATED_SUFFIXES = (".log",)
TREE_EXCLUDES = GENERATED_FILES


def is_generated(rel: str) -> bool:
    """该相对路径是否是构建期生成物（不进 applied 输入树）。"""
    return (
        rel in GENERATED_FILES
        or any(rel.startswith(prefix) for prefix in GENERATED_PREFIXES)
        or any(rel.endswith(suffix) for suffix in GENERATED_SUFFIXES)
    )
# §7.2 的 CR 门禁只针对「会被编译/执行的树内源码」；上游历史里本来就有
# CRLF 的文档（pt_BR）、*.bat、二进制资产不在此列（见 manifest.upstream.crBaseline）。
BUILD_SCOPES = ("kernel/", "userspace/", "uapi/", "manager/app/src/main/cpp/")
BINARY_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".jar", ".so", ".o", ".ko",
    ".a", ".bin", ".class", ".flat", ".zip", ".gz", ".xz", ".zst", ".woff", ".woff2",
    ".ttf", ".otf", ".mp3", ".mp4", ".webp", ".apk", ".dex",
}


class KsuError(RuntimeError):
    """可预期的失败：打印 message 后以退出码 1 结束，不抛裸栈。"""


# ---------------------------------------------------------------- 小工具
def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def read_bytes(path: Path) -> bytes:
    return Path(path).read_bytes()


def read_text(path: Path) -> str:
    return Path(path).read_bytes().decode("utf-8")


def write_text(path: Path, text: str) -> None:
    """原子 + 强制 LF：Windows 上绝不能走文本模式换行转换。"""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "wb") as fh:
        fh.write(text.encode("utf-8"))
    os.replace(tmp, path)


def write_bytes(path: Path, data: bytes) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "wb") as fh:
        fh.write(data)
    os.replace(tmp, path)


def read_json(path: Path) -> dict:
    return json.loads(Path(path).read_bytes().decode("utf-8"))


def write_json(path: Path, obj: dict) -> None:
    """UTF-8 + LF + 2 空格缩进 + 末尾换行；键序沿用插入序。"""
    text = json.dumps(obj, ensure_ascii=False, indent=2) + "\n"
    write_text(path, text)


def git(args: list[str], cwd: Path | None = None,
        env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    cmd = ["git"]
    if cwd is not None:
        cmd += ["-C", str(cwd)]
    cmd += args
    return subprocess.run(cmd, capture_output=True, text=False, env=env)


def require_git() -> None:
    if shutil.which("git") is None:
        raise KsuError("git 不在 PATH：本脚本用 git archive/git apply 实现可复现快照")


# ---------------------------------------------------------------- 补丁应用隔离
# 事故 2026-10-31（G5-a）：仓库根被 `git init` 后，补丁应用目录 `third_party/kernelsu/.tmp/`
# 落进了 git 工作树，`git apply` 把每个文件补丁记为 "Skipped patch"、**返回 0 且不落盘**
# （不加 `-v` 时连提示都没有），重放树于是退化成 upstream 裸树（798 文件 / bb06327c…）。
# 因此应用补丁必须同时满足两条，缺一不可：
#   1) 目标目录里 git **看不到外层仓库**（GIT_CEILING_DIRECTORIES 阻断向上发现，
#      并清掉 GIT_DIR/GIT_WORK_TREE，防止外部环境把仓库指到别处）；
#   2) 输出里一旦出现 "Skipped patch"（或实际应用时没有 "Applied patch"）立即判失败
#      —— 这两种情况下 git 的返回码都是 0，只看 rc 会被静默骗过。
APPLY_ENV_UNSET = ("GIT_DIR", "GIT_WORK_TREE")
SKIPPED_PATCH_MARK = "Skipped patch"
APPLIED_PATCH_MARK = "Applied patch"


def apply_env(cwd: Path) -> dict[str, str]:
    """返回在 `cwd` 里应用补丁用的环境变量（阻断外层仓库发现）。

    `GIT_CEILING_DIRECTORIES` 的语义是「不向上**穿过**这些目录」，所以必须设成
    `cwd` 的**父目录**；设成 `cwd` 本身无效（本机实测 git 仍发现仓库根）。
    """
    env = {k: v for k, v in os.environ.items() if k not in APPLY_ENV_UNSET}
    env["GIT_CEILING_DIRECTORIES"] = str(Path(cwd).resolve().parent)
    return env


def repo_root_of(cwd: Path) -> Path | None:
    """在 `apply_env()` 隔离下 git 仍能发现的仓库根；隔离生效时返回 None。

    用途是**自检隔离本身**（`isolated_apply_root` 用它断言应用环境里看不到仓库），
    不是「这个目录真实属于哪个仓库」——那要看没隔离时的 `git rev-parse`。
    """
    proc = git(["rev-parse", "--show-toplevel"], cwd=cwd, env=apply_env(cwd))
    if proc.returncode != 0:
        return None
    found = proc.stdout.decode("utf-8", "replace").strip()
    return Path(found) if found else None


def isolated_apply_root(prefix: str = "maplesu-apply-") -> Path:
    """系统临时目录里的补丁应用根，**不在**任何 git 工作树内（调用方负责删除）。

    放系统临时目录而不是仓库 `.tmp/`：仓库根被 `git init` 后 `.tmp/` 就在 worktree 内，
    正是 G5-a 的触发条件。建好后立刻用**应用时同一套环境**断言 git 看不到仓库；
    若临时目录本身就是个仓库（有 .git），直接报明确错误而不是让它静默 skip。
    """
    root = Path(tempfile.mkdtemp(prefix=prefix))
    found = repo_root_of(root)
    if found is not None:
        shutil.rmtree(root, ignore_errors=True)
        raise KsuError(
            f"临时目录 {root} 在补丁应用环境里仍被识别为 git 仓库 {found}："
            f"git apply 会静默 skip 全部补丁（G5-a）。请把 TEMP/TMPDIR 指向非仓库目录后重试。")
    return root


def git_apply(cwd: Path, patch: Path, *, check: bool = False) -> None:
    """在 `cwd` 里 `git apply -p1 --whitespace=error-all` 一个补丁；失败抛 KsuError。

    失败判据包含返回码**和**输出（见文件头 G5-a 注释）：返回码为 0 但出现
    "Skipped patch"，或实际应用时没有 "Applied patch"，都算失败。
    """
    args = ["-c", "core.autocrlf=false", "apply", "-p1", "--whitespace=error-all", "-v"]
    if check:
        args.append("--check")
    args.append(str(Path(patch).resolve()))
    proc = git(args, cwd=cwd, env=apply_env(cwd))
    out = (proc.stdout + proc.stderr).decode("utf-8", "replace")
    tag = "git apply(check)" if check else "git apply"
    if proc.returncode != 0:
        raise KsuError(f"{Path(patch).name}: {tag} 失败:\n{out}")
    if SKIPPED_PATCH_MARK in out:
        raise KsuError(
            f"{Path(patch).name}: {tag} 静默跳过补丁（返回 0 但未落盘）:\n{out}"
            f"—— 应用目录 {cwd} 仍在 git 工作树内（G5-a 同类问题）")
    if not check and APPLIED_PATCH_MARK not in out:
        raise KsuError(f"{Path(patch).name}: {tag} 未输出 Applied patch（疑似静默无效）:\n{out}")


def utc_now_iso() -> str:
    # 只写进 manifest/payload 的易变字段；树哈希与 --check 会忽略它。
    import datetime

    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------- 树导出
def iter_tree_files(root: Path, exclude_rel: tuple[str, ...] = (),
                    exclude_prefixes: tuple[str, ...] = ()) -> list[str]:
    """返回排序后的相对 POSIX 路径（只含普通文件）。"""
    root = Path(root)
    out: list[str] = []
    if not root.is_dir():
        raise KsuError(f"directory missing: {root}")
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for name in sorted(filenames):
            full = Path(dirpath) / name
            rel = full.relative_to(root).as_posix()
            if rel in exclude_rel or is_generated(rel):
                continue
            if any(rel.startswith(prefix) for prefix in exclude_prefixes):
                continue
            out.append(rel)
    out.sort()
    return out


def tree_file_entries(root: Path, exclude_rel: tuple[str, ...] = (),
                      exclude_prefixes: tuple[str, ...] = ()) -> list[dict]:
    root = Path(root)
    entries = []
    for rel in iter_tree_files(root, exclude_rel, exclude_prefixes):
        p = root / rel
        entries.append({"path": rel, "sha256": sha256_file(p), "size": p.stat().st_size})
    return entries


def tree_sha256(root: Path, exclude_rel: tuple[str, ...] = TREE_EXCLUDES,
                exclude_prefixes: tuple[str, ...] = ()) -> str:
    """03 分册 §1.2.2：对 `path\\0sha256\\n` 按 path 排序后拼接再取 sha256。"""
    root = Path(root)
    rows = []
    for rel, entry in zip(iter_tree_files(root, exclude_rel, exclude_prefixes),
                          tree_file_entries(root, exclude_rel, exclude_prefixes)):
        rows.append(f"{rel}\0{entry['sha256']}\n")
    return sha256_bytes("".join(rows).encode("utf-8"))


def _is_binary(data: bytes) -> bool:
    if b"\x00" in data:
        return True
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        return True
    return False


def crlf_offenders(root: Path, scopes: tuple[str, ...] = BUILD_SCOPES) -> list[str]:
    """返回 build-relevant 范围内含 CR 的文本文件（§7.2 G1 门禁）。"""
    root = Path(root)
    bad = []
    for rel in iter_tree_files(root):
        if not any(rel.startswith(scope) for scope in scopes):
            continue
        if PurePosixPath(rel).suffix.lower() in BINARY_EXTS:
            continue
        data = (root / rel).read_bytes()
        if b"\r" not in data or _is_binary(data):
            continue
        bad.append(rel)
    return bad


def all_cr_files(root: Path) -> list[str]:
    """全树含 CR 的文本文件（只作基线记录，不作门禁）。"""
    root = Path(root)
    bad = []
    for rel in iter_tree_files(root):
        data = (root / rel).read_bytes()
        if b"\r" in data and not _is_binary(data):
            bad.append(rel)
    return bad


# ---------------------------------------------------------------- git archive → LF 快照
def export_git_tree(repo: Path, rev: str, dest: Path, *, clean: bool = False) -> dict:
    """把 git 对象字节导出为 LF 快照，并把 symlink 条目落成真实文件/目录。

    为什么不用 `tar -x`：Windows 的 tar 会把 symlink 解成目录副本或 19 字节文本文件，
    两者在不同机器上不一致；本函数自己写字节，跨平台可复现。
    """
    require_git()
    repo = Path(repo)
    dest = Path(dest)
    if not (repo / ".git").exists():
        raise KsuError(f"不是 git 仓库: {repo}")
    if dest.exists() and any(dest.iterdir()):
        if not clean:
            raise KsuError(f"{dest} 非空；加 --clean 才会重建（防误删/防叠补丁）")
        shutil.rmtree(dest)
    dest.mkdir(parents=True, exist_ok=True)

    proc = git(["-c", "core.autocrlf=false", "archive", "--format=tar", rev], cwd=repo)
    if proc.returncode != 0:
        raise KsuError(f"git archive 失败: {proc.stderr.decode('utf-8', 'replace')}")

    symlinks: list[tuple[str, str]] = []
    member_count = 0
    with tarfile.open(fileobj=io.BytesIO(proc.stdout), mode="r:") as tar:
        for member in tar.getmembers():
            if member.isdir():
                continue
            member_count += 1
            rel = PurePosixPath(member.name)
            if rel.is_absolute() or ".." in rel.parts:
                raise KsuError(f"git archive 含不安全路径: {member.name}")
            target = dest.joinpath(*rel.parts)
            if member.issym():
                symlinks.append((rel.as_posix(), member.linkname))
                continue
            if not member.isreg():
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            fh = tar.extractfile(member)
            if fh is None:
                raise KsuError(f"无法读取归档条目: {member.name}")
            write_bytes(target, fh.read())

    materialized = []
    for rel, linkname in symlinks:
        src = Path(os.path.normpath(str((dest / rel).parent / linkname)))
        try:
            src.relative_to(dest.resolve())
        except ValueError as exc:  # 越界 symlink
            raise KsuError(f"symlink 越界: {rel} -> {linkname}") from exc
        if not src.exists():
            raise KsuError(f"symlink 目标不存在: {rel} -> {linkname}")
        target = dest / rel
        if src.is_dir():
            if target.exists():
                shutil.rmtree(target)
            shutil.copytree(src, target)
            kind = "directory"
        else:
            write_bytes(target, src.read_bytes())
            kind = "file"
        materialized.append({
            "path": rel,
            "target": linkname,
            "gitMode": "120000",
            "materializedAs": kind,
            "reason": "Windows 无 core.symlinks；03 分册 §1.2.4 推荐落成真实目录",
        })

    return {
        "repo": str(repo),
        "rev": rev,
        "exportCommand": GIT_ARCHIVE_CMD.replace("<repo>", str(repo)).replace("<rev>", rev),
        "gitMembers": member_count,
        "fileCount": len(iter_tree_files(dest)),
        "materializedSymlinks": materialized,
    }


def copy_tree(src: Path, dest: Path) -> None:
    """逐字节复制目录树（不做任何 eol 转换）。"""
    src, dest = Path(src), Path(dest)
    if dest.exists():
        shutil.rmtree(dest)
    for rel in iter_tree_files(src):
        write_bytes(dest / rel, (src / rel).read_bytes())


# ---------------------------------------------------------------- series
def read_series(series_path: Path = SERIES_PATH) -> list[str]:
    if not Path(series_path).is_file():
        raise KsuError(f"缺少 series: {series_path}")
    names = []
    for raw in Path(series_path).read_bytes().decode("utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        names.append(line)
    if not names:
        raise KsuError("series 为空")
    return names


def series_hashes(patch_dir: Path = PATCH_DIR) -> dict:
    names = read_series(Path(patch_dir) / "series")
    entries = []
    for name in names:
        p = Path(patch_dir) / name
        if not p.is_file():
            raise KsuError(f"series 里的补丁不存在: {p}")
        entries.append({"name": name, "sha256": sha256_file(p), "size": p.stat().st_size})
    aggregate = sha256_bytes("".join(e["sha256"] for e in entries).encode("utf-8"))
    series_sha = sha256_file(Path(patch_dir) / "series")
    return {
        "order": names,
        "seriesSha256": series_sha,
        "aggregateSha256": aggregate,
        "entries": entries,
    }


def fail(msg: str, code: int = 1) -> "NoReturn":  # type: ignore[name-defined]
    print(f"ERROR: {msg}", file=sys.stderr)
    raise SystemExit(code)


def main_stub(name: str) -> None:
    print(f"{name}: this module is a library; run the individual script", file=sys.stderr)


if __name__ == "__main__":
    main_stub(Path(__file__).name)
