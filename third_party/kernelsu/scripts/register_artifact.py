#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""把 CI/外部构建产物**如实**登记进 ksu-payload.json，并立刻跑门禁。

用途（W12d 闭环）：本机唯一不产的 `kernelsu.ko` 由 CI/DDK 产出后，
不允许手工改 JSON —— 必须由本脚本计算 sha256/size 后写回，再跑 verify_payload.py。

    python3 third_party/kernelsu/scripts/register_artifact.py \
        --name android15-6.6_kernelsu.ko \
        --path third_party/kernelsu/lkm/android15-6.6_kernelsu.ko \
        --kmi android15-6.6 \
        --built-by "ghcr.io/ylarod/ddk-min:android15-6.6-20260828"

非 lkm 产物（ksuinit / libksud_ksu.so / jni / asset）用同一入口，但走「条目自身 path 契约」：
不校验 KMI 名字约定、不接受改路径、也不会给条目加 kmi 字段（W13 扩展）：

    python3 third_party/kernelsu/scripts/register_artifact.py \
        --name libksud_ksu.so \
        --path manager/src/main/jniLibs/arm64-v8a/libksud_ksu.so \
        --built-by "build_userland.sh --kmi all (5 KMI embedded)"

行为：
  1) 校验文件存在、非空、路径文件名与 `--name` 一致；lkm 条目还要求名字符合
     `${kmi}_kernelsu.ko` 约定；
  2) 计算真实 sha256/size；
  3) 在 payload.artifacts 里按 name 找到条目（不存在则拒绝，防止拼错名字绕过门禁），
     置 status=present 并写入 sha256/size/path/kmi/builtBy/registeredAt；
  4) 原子写回 ksu-payload.json（UTF-8/LF），然后**自动运行 verify_payload.py**（`--no-verify` 可关）。

自检（不碰仓库 payload）：
  python3 .../register_artifact.py --self-test
  在 `.tmp/` 里造一个临时 fixture + payload 副本，走完整登记/回读/失败分支断言；
  绝不把假文件写进 third_party/kernelsu/ 或真实 payload。

退出码：0 成功；2 参数/文件/条目错误；3 登记后 verify 失败。
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import ksu_common as C


def _sha256(path: Path) -> str:
    import hashlib

    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def register(payload_path: Path, name: str, path: Path, kmi: str, built_by: str | None,
             dry_run: bool) -> dict:
    if not path.is_file():
        raise C.KsuError(f"artifact 文件不存在: {path}")
    size = path.stat().st_size
    if size <= 0:
        raise C.KsuError(f"artifact 为空文件（拒绝登记）: {path}")
    if path.name != name:
        raise C.KsuError(f"路径文件名与 --name 不一致: {path.name} != {name}")

    payload = C.read_json(payload_path)
    artifacts = payload.get("artifacts", [])
    entry = next((a for a in artifacts if a.get("name") == name), None)
    if entry is None:
        raise C.KsuError(
            f"payload.artifacts 里没有名为 {name} 的条目（不允许新建条目绕过门禁）")
    is_lkm = entry.get("kind") == "lkm"
    if is_lkm:
        if name != f"{kmi}_kernelsu.ko":
            raise C.KsuError(f"名字不符合 KMI 约定: {name} != {kmi}_kernelsu.ko")
        # 多 KMI 扩展的防串行闸：条目自述的 kmi 必须与 --kmi 一致，禁止把
        # android14-6.1 的字节登记到 android15-6.6 的条目上。
        recorded_kmi = entry.get("kmi")
        if recorded_kmi not in (None, kmi):
            raise C.KsuError(f"{name} 的条目 kmi={recorded_kmi!r} 与 --kmi={kmi!r} 不一致")
    # 非 lkm（ksuinit / ksud-executable / jni / asset）走「条目自身 path 契约」：
    # 不允许改名/改路径，只能用真实字节刷新该条目（ksud 重建后回填 sha256/size）。

    # 相对仓库根的路径更稳定（CI 与本地一致）
    try:
        rel = path.resolve().relative_to(C.REPO_ROOT.resolve()).as_posix()
    except ValueError as exc:
        raise C.KsuError(f"artifact 必须位于仓库内（payload 记录相对路径）: {path}") from exc
    if not is_lkm:
        # 非 lkm 条目只允许按**条目自己声明的 path** 回填：换路径必须改 gen_payload.py，
        # 不能靠命令行参数把字节搬到另一条契约上。
        expected_rel = entry.get("path")
        if expected_rel and rel != expected_rel:
            raise C.KsuError(f"{name} 的路径与条目契约不一致: {rel} != {expected_rel}")

    sha = _sha256(path)
    if dry_run:
        print(f"DRY-RUN: {name} path={rel} size={size} sha256={sha}")
        return entry

    entry.update({
        "status": "present",
        "path": rel,
        "sha256": sha,
        "size": size,
        "builtBy": built_by or entry.get("builtBy", ""),
        "registeredAt": C.utc_now_iso(),
        "registeredBy": "third_party/kernelsu/scripts/register_artifact.py@2",
    })
    if is_lkm:
        # lkm 条目必须有 kmi；非 lkm 条目不能凭空多出 kmi 字段（gen_payload --check 会判漂移）。
        entry["kmi"] = kmi
    payload["generatedAt"] = C.utc_now_iso()
    C.write_json(payload_path, payload)
    print(f"OK registered: {name} size={size} sha256={sha} path={rel}")
    return entry


def check(payload_path: Path, name: str, path: Path) -> int:
    payload = C.read_json(payload_path)
    entry = next((a for a in payload.get("artifacts", []) if a.get("name") == name), None)
    if entry is None:
        print(f"FAIL: payload 无条目 {name}", file=sys.stderr)
        return 2
    problems = []
    if entry.get("status") != "present":
        problems.append(f"status={entry.get('status')}")
    if not path.is_file():
        problems.append(f"文件缺失 {path}")
    else:
        if entry.get("sha256") != _sha256(path):
            problems.append("sha256 不匹配")
        if entry.get("size") != path.stat().st_size:
            problems.append("size 不匹配")
    if problems:
        print(f"FAIL: {name}: {', '.join(problems)}", file=sys.stderr)
        return 2
    print(f"OK check: {name} present 且 sha256/size 与实际文件一致")
    return 0


def lkm_entries(payload_path: Path) -> list[dict]:
    payload = C.read_json(payload_path)
    return [a for a in payload.get("artifacts", []) if a.get("kind") == "lkm"]


def register_all(payload_path: Path, lkm_dir: Path, built_by: str | None,
                 ci_run: str | None = None, force: bool = False) -> int:
    """逐条登记 `lkm/<kmi>_kernelsu.ko`（缺失的 KMI 保持 pending，不伪造）。

    红线与单条登记完全一致：条目必须**已存在**于 payload、kmi/name/path 必须符合
    `lkm/<kmi>_kernelsu.ko` 约定、哈希必须来自真实字节。返回 0 = 至少登记成功一条
    或全部已 present；2 = payload 无 lkm 条目 / 一个文件都没找到。

    `built_by` 留空时保留条目自己的 `builtBy`（gen_payload 写的该 KMI 的 DDK 镜像）；
    `ci_run` 非空时把 GitHub Actions run id 写进 `builtBy`（真实来源，仍不伪造哈希）。
    """
    entries = lkm_entries(payload_path)
    if not entries:
        print("ERROR: payload 没有 kind=lkm 的条目（先跑 gen_payload.py）", file=sys.stderr)
        return 2
    registered, already, missing = [], [], []
    for entry in entries:
        kmi = entry.get("kmi") or ""
        name = entry.get("name") or ""
        if not C.is_kmi(kmi):
            print(f"ERROR: payload lkm 条目 kmi 非法: name={name!r} kmi={kmi!r}", file=sys.stderr)
            return 2
        expected = C.lkm_entry_name(kmi)
        if name != expected or entry.get("path") != C.lkm_rel_path(kmi):
            print(f"ERROR: lkm 条目不符合约定: name={name!r} path={entry.get('path')!r} "
                  f"(期望 {expected!r} / {C.lkm_rel_path(kmi)!r})", file=sys.stderr)
            return 2
        path = lkm_dir / expected
        if not path.is_file():
            missing.append(kmi)
            continue
        if entry.get("status") == "present" and entry.get("sha256") == _sha256(path) \
                and entry.get("size") == path.stat().st_size and not force:
            already.append(kmi)
            continue
        resolved = built_by
        if resolved is None and ci_run:
            resolved = f"{C.ddk_image_for(kmi)} (GitHub Actions run {ci_run})"
        register(payload_path, name, path, kmi, resolved, dry_run=False)
        registered.append(kmi)
    print(f"OK lkm batch: registered={registered} unchanged={already} "
          f"missing(仍 pending)={missing}")
    if not registered and not already:
        print("ERROR: lkm/ 下没有任何 <kmi>_kernelsu.ko 可登记", file=sys.stderr)
        return 2
    return 0


def check_all(payload_path: Path, lkm_dir: Path) -> int:
    """逐条校验 lkm 条目与真实文件一致；缺失/不一致返回 2（不写任何东西）。"""
    entries = lkm_entries(payload_path)
    if not entries:
        print("ERROR: payload 没有 kind=lkm 的条目", file=sys.stderr)
        return 2
    rc = 0
    for entry in entries:
        kmi = entry.get("kmi") or ""
        name = entry.get("name") or ""
        if not C.is_kmi(kmi) or name != C.lkm_entry_name(kmi):
            print(f"FAIL: lkm 条目不符合约定: name={name!r} kmi={kmi!r}", file=sys.stderr)
            rc = 2
            continue
        status = entry.get("status")
        path = lkm_dir / name
        if status != "present":
            print(f"PENDING: {kmi} status={status} (file={'yes' if path.is_file() else 'no'})")
            continue
        problems = []
        if not path.is_file():
            problems.append("文件缺失")
        else:
            if entry.get("sha256") != _sha256(path):
                problems.append("sha256 不匹配")
            if entry.get("size") != path.stat().st_size:
                problems.append("size 不匹配")
        if problems:
            print(f"FAIL: {kmi}: {', '.join(problems)}", file=sys.stderr)
            rc = 2
        else:
            print(f"OK: {kmi} present size={entry.get('size')} sha256={entry.get('sha256')}")
    return rc



def self_test() -> int:
    """用临时 fixture 验证登记/回读/失败分支；绝不触碰真实 payload/artifacts。"""
    tmp = Path(tempfile.mkdtemp(prefix="register-selftest-", dir=str(C.KSU_ROOT / ".tmp")
                                if (C.KSU_ROOT / ".tmp").is_dir() else None))
    try:
        payload_src = C.KSU_ROOT / "ksu-payload.json"
        if not payload_src.is_file():
            print("SKIP self-test: ksu-payload.json 不存在（先重建分支树）")
            return 0
        payload = C.read_json(payload_src)
        payload_copy = tmp / "ksu-payload.json"
        C.write_json(payload_copy, payload)

        # 自检覆盖**整个 lkm 矩阵**（现在每 KMI 一条）：每个条目都用独立 fixture，
        # 名字/路径/kmi 全部按约定，登记后逐条回读。真实 payload 全程不被修改。
        entries = [a for a in payload["artifacts"] if a.get("kind") == "lkm"]
        if not entries:
            print("FAIL self-test: payload 没有 lkm 条目", file=sys.stderr)
            return 2
        selftest_dir = C.KSU_ROOT / ".tmp" / "selftest"
        selftest_dir.mkdir(parents=True, exist_ok=True)
        tmp_payload = selftest_dir / "ksu-payload.json"
        C.write_json(tmp_payload, payload)

        for entry in entries:
            kmi = entry["kmi"]
            name = C.lkm_entry_name(kmi)
            if entry.get("name") != name:
                print(f"FAIL self-test: 条目名不符约定 {entry.get('name')!r} != {name!r}",
                      file=sys.stderr)
                return 2
            # fixture：ELF 魔数 + 每 KMI 不同字节（仅自检用，不进仓库 artifacts 路径）
            real_fixture = selftest_dir / name
            real_fixture.write_bytes(b"\x7fELF" + b"\x00" * 60 + f"selftest:{kmi}".encode())
            got = register(tmp_payload, name, real_fixture, kmi, "self-test", dry_run=False)
            assert got["status"] == "present", got
            assert got["sha256"] == _sha256(real_fixture), got
            assert got["size"] == real_fixture.stat().st_size, got
            assert got["path"] == "third_party/kernelsu/.tmp/selftest/" + name, got["path"]
            rc = check(tmp_payload, name, real_fixture)
            if rc != 0:
                return rc

        # 批量路径用**另一份未改动的 payload 副本**：上面的单条登记会把条目 path 改写到
        # `.tmp/selftest/`，而 register_all 的第一道闸是"条目 path 必须仍是 canonical lkm 路径"。
        batch_payload = selftest_dir / "ksu-payload-batch.json"
        C.write_json(batch_payload, payload)
        rc = register_all(batch_payload, selftest_dir, "self-test")
        if rc != 0:
            print("FAIL self-test: register_all 批量路径失败", file=sys.stderr)
            return 2
        rc = check_all(batch_payload, selftest_dir)
        if rc != 0:
            print("FAIL self-test: check_all 失败", file=sys.stderr)
            return 2

        first = entries[0]
        first_name, first_kmi = first["name"], first["kmi"]
        first_fixture = selftest_dir / first_name

        # 失败分支 1：文件缺失必须拒绝
        try:
            register(tmp_payload, first_name, selftest_dir / "missing.ko", first_kmi,
                     "self-test", dry_run=True)
            print("FAIL self-test: 缺文件未被拒绝", file=sys.stderr)
            return 2
        except C.KsuError:
            pass
        # 失败分支 2：名字拼错必须拒绝
        try:
            register(tmp_payload, "wrong_" + first_name, first_fixture, first_kmi,
                     "self-test", dry_run=True)
            print("FAIL self-test: 错名字未被拒绝", file=sys.stderr)
            return 2
        except C.KsuError:
            pass
        # 失败分支 3（多 KMI 新增）：kmi 与条目不一致必须拒绝（防串行登记）
        other = next((e["kmi"] for e in entries if e["kmi"] != first_kmi), None)
        if other is not None:
            try:
                register(tmp_payload, first_name, first_fixture, other,
                         "self-test", dry_run=True)
                print("FAIL self-test: kmi 串行未被拒绝", file=sys.stderr)
                return 2
            except C.KsuError:
                pass
        print(f"OK self-test: {len(entries)} 个 lkm 条目 register/check/batch/失败分支 全部通过"
              f"（真实 payload 未被修改）")
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
        # 清理仓库内自检临时目录
        shutil.rmtree(C.KSU_ROOT / ".tmp" / "selftest", ignore_errors=True)


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="把真实构建产物登记进 ksu-payload.json")
    ap.add_argument("--payload", default=str(C.PAYLOAD_PATH))
    ap.add_argument("--name", default=None, help="artifact 名（如 android15-6.6_kernelsu.ko）")
    ap.add_argument("--path", default=None, help="产物文件路径（仓库内）")
    ap.add_argument("--kmi", default=C.KMI_DEFAULT)
    ap.add_argument("--built-by", default=None)
    ap.add_argument("--lkm-dir", default=str(C.KSU_ROOT / "lkm"),
                    help="批量模式下的产物目录（默认 third_party/kernelsu/lkm）")
    ap.add_argument("--all", action="store_true",
                    help="逐条登记 lkm/ 下所有 <kmi>_kernelsu.ko（缺失的保持 pending）")
    ap.add_argument("--ci-run", default=None,
                    help="GitHub Actions run id（写进 builtBy 作为可追溯来源）")
    ap.add_argument("--force", action="store_true",
                    help="批量模式下即使 sha256/size 未变也重写条目（用于补齐 builtBy/registeredAt）")
    ap.add_argument("--check-all", action="store_true", help="逐条校验所有 lkm 条目，不写")
    ap.add_argument("--dry-run", action="store_true", help="只计算/打印，不写 payload")
    ap.add_argument("--check", action="store_true", help="只校验 payload 与文件一致，不写")
    ap.add_argument("--self-test", action="store_true", help="用临时 fixture 自检（不碰真实 payload）")
    ap.add_argument("--no-verify", action="store_true", help="登记后不自动跑 verify_payload.py")
    args = ap.parse_args(argv)

    if args.self_test:
        return self_test()

    payload = Path(args.payload)
    lkm_dir = Path(args.lkm_dir)
    try:
        if args.check_all:
            return check_all(payload, lkm_dir)
        if args.all:
            rc = register_all(payload, lkm_dir, args.built_by, args.ci_run, args.force)
            if rc != 0 or args.no_verify:
                return rc
            return run_verifier()
        if not args.name or not args.path:
            print("ERROR: 需要 --name 与 --path（或 --all / --check-all / --self-test）",
                  file=sys.stderr)
            return 2
        path = Path(args.path)
        if args.check:
            return check(payload, args.name, path)
        register(payload, args.name, path, args.kmi, args.built_by, args.dry_run)
    except C.KsuError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    if args.dry_run or args.no_verify:
        return 0
    return run_verifier()


def run_verifier() -> int:
    """登记之后立刻跑门禁：payload 与真实文件必须一致（失败即视为登记失败）。"""
    verifier = Path(__file__).with_name("verify_payload.py")
    proc = subprocess.run([sys.executable, str(verifier), "--quick"])
    if proc.returncode != 0:
        print("ERROR: 登记后 verify_payload.py 失败（payload 与文件不一致）", file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
