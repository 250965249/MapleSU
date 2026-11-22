#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""生成 third_party/kernelsu/ksu-payload.json（03 分册 §1.7 的构建产物清单）。

本机不可能产出的产物（LKM / ksud / ksuinit / JNI .so）在 payload 里是
`status: pending-ci` 的条目：**没有 sha256 就不写 sha256**，绝不用假哈希占位。
verify_payload.py 只对 status=present 的条目做哈希比对。

用法：python third_party/kernelsu/scripts/gen_payload.py [--root ...] [--check]
跨源码代次的 present 产物仅由 build_all.sh 全构建成功出口以
--built-source-tree <起始源码树SHA> 绑定；该声明不证明原子构建或功能验收。
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import ksu_common as C

PAYLOAD_GENERATOR = "third_party/kernelsu/scripts/gen_payload.py@2"
KMI_DEFAULT = C.KMI_DEFAULT
LKM_REQUIRED_ENV = [
    "KSU_PACKAGE_NAME", "KSU_EXPECTED_SIZE", "KSU_EXPECTED_HASH",
    "KSU_VERSION_PIN", "KSU_MANAGER_MIN_GEN", "KSU_IS_PR_BUILD",
]


def lkm_artifacts(root: Path) -> list[dict]:
    """每个 KMI 一条 lkm 条目（矩阵顺序 = `ksu_common.KMI_MATRIX`）。

    `status` 只看 `lkm/<kmi>_kernelsu.ko` 是否真的存在：存在也**不**在这里编造
    哈希以外的字段（sha256/size 由下方统一按真实字节回填）；不存在就是
    `pending-ci` 且**不带** sha256/size（门禁禁止 pending 带哈希）。
    """
    entries = []
    for kmi in C.KMI_MATRIX:
        ko = root / "lkm" / C.lkm_entry_name(kmi)
        entries.append({
            "name": C.lkm_entry_name(kmi),
            "kind": "lkm",
            "kmi": kmi,
            "path": C.lkm_rel_path(kmi),
            "producedBy": "DDK container (CI only; local host has no KDIR/clang)",
            "builtBy": C.ddk_image_for(kmi),
            "status": "present" if ko.is_file() else "pending-ci",
            "requiredEnv": list(LKM_REQUIRED_ENV),
        })
    return entries


def artifacts(root: Path) -> list[dict]:
    jni = C.REPO_ROOT / "manager/src/main/jniLibs/arm64-v8a"
    companions = [{
        "name": f"{kmi}_maplesu_vr.ko", "kind": "compatibility-lkm", "kmi": kmi,
        "path": f"third_party/kernelsu/lkm/{kmi}_maplesu_vr.ko",
        "producedBy": "scripts/build_lkm.sh --vr-only", "builtBy": C.ddk_image_for(kmi),
        "status": "present" if (root / f"lkm/{kmi}_maplesu_vr.ko").is_file() else "pending-ci",
    } for kmi in C.COMPATIBILITY_KMI_MATRIX]
    entries = lkm_artifacts(root) + companions + [
        {
            "name": "maplesu_vrinit", "kind": "compatibility-init", "abi": "arm64-v8a",
            "path": "third_party/kernelsu/artifacts/maplesu_vrinit",
            "producedBy": "scripts/build_userland.sh (static executable, 16K page)",
            "status": "present" if (root / "artifacts/maplesu_vrinit").is_file() else "pending-ci",
        },
        {
            "name": "ksuinit",
            "kind": "ksuinit",
            "abi": "arm64-v8a",
            # 注意：ksuinit 不能放 applied/（applied 只含 upstream+patches），
            # 由 scripts/build_userland.sh 产出到 artifacts/。
            "path": "third_party/kernelsu/artifacts/ksuinit",
            "producedBy": "scripts/build_userland.sh (cargo + NDK clang, crt-static, 16K page)",
            "status": "present"
            if (root / "artifacts/ksuinit").is_file() else "pending-ci",
            "requiredEnv": ["ANDROID_NDK_HOME", "RUSTFLAGS"],
        },
        {
            "name": "libksud_ksu.so",
            "kind": "ksud-executable",
            "abi": "arm64-v8a",
            "path": "manager/src/main/jniLibs/arm64-v8a/libksud_ksu.so",
            "producedBy": "cargo --target aarch64-linux-android (PIE, embeds ksuinit + *.ko)",
            "status": "present" if (jni / "libksud_ksu.so").is_file() else "pending-ci",
            "requiredEnv": ["KSU_PACKAGE_NAME", "ANDROID_NDK_HOME"],
            "note": "文件名不是 libksud.so（主文档:530-531）；AGP strip 会改字节 → keepDebugSymbols",
        },
        {
            "name": "libmaplesu_ksu.so",
            "kind": "jni",
            "abi": "arm64-v8a",
            "path": "manager/src/main/jniLibs/arm64-v8a/libmaplesu_ksu.so",
            "producedBy": "CMake + NDK (manager/src/main/cpp, 同树 -I applied/)",
            "status": "present" if (jni / "libmaplesu_ksu.so").is_file() else "pending-ci",
            "note": "导出 25 个 Java_dev_maplesu_manager_ksu_KsuNatives_* 符号（03 §3.6）",
        },
        {
            "name": "libadbroot.so",
            "kind": "jni",
            "abi": "arm64-v8a",
            "path": "manager/src/main/jniLibs/arm64-v8a/libadbroot.so",
            "producedBy": "CMake + NDK (applied/manager/app/src/main/cpp/adbroot.cc)",
            "status": "present" if (jni / "libadbroot.so").is_file() else "pending-ci",
        },
        {
            # L3 NativeSu JNI（2026-10-31 新增）：jniLibs 里的文件必须被 payload 登记，
            # 否则 verify_dual_mode 的 jni-declared 检查会判「未声明的已构建产物」。
            "name": "libmaplesu_l3_su.so",
            "kind": "jni",
            "abi": "arm64-v8a",
            "path": "manager/src/main/jniLibs/arm64-v8a/libmaplesu_l3_su.so",
            "producedBy": "NDK r28c 手工编译 manager/src/main/cpp/maplesu_su.c"
                          "（Gradle externalNativeBuild 尚未接线）",
            "status": "present" if (jni / "libmaplesu_l3_su.so").is_file() else "pending-ci",
            "note": "L3 NativeSu JNI：导出 Java_dev_maplesu_manager_runtime_NativeSu_run"
                    "（NativeSu.LIBRARY=\"maplesu_l3_su\"）",
        },
        {
            "name": "assets/ksu_manager_gen2",
            "kind": "asset",
            "path": "manager/src/main/assets/ksu_manager_gen2",
            "producedBy": "W18/集成轮手写（判据是 ZIP 条目名，内容无关）",
            "status": "present"
            if (C.REPO_ROOT / "manager/src/main/assets/ksu_manager_gen2").is_file() else "pending-w18",
        },
    ]
    for entry in entries:
        if entry["status"] == "present":
            p = (C.REPO_ROOT / entry["path"]) if not entry["path"].startswith("third_party/") else (
                root / entry["path"][len("third_party/kernelsu/"):])
            entry["sha256"] = C.sha256_file(p)
            entry["size"] = p.stat().st_size
    return entries


def build_payload(root: Path) -> dict:
    manifest = C.read_json(root / "manifest.json")
    applied = root / "applied"
    if not applied.is_dir():
        raise C.KsuError("缺 applied/：先跑 apply_patches.py --clean")
    series = C.series_hashes(root / "patches" / "7k")
    applied_tree = C.tree_sha256(applied)
    if applied_tree != manifest["applied"]["treeSha256"]:
        raise C.KsuError("applied 树哈希与 manifest 不一致（重跑 gen_manifest.py）")
    files = [e for e in C.tree_file_entries(applied) if e["path"] not in C.TREE_EXCLUDES]
    uapi_header = C.sha256_file(applied / "uapi" / "supercall.h")
    return {
        "schema": 1,
        "product": "MapleSU",
        "generator": PAYLOAD_GENERATOR,
        "generatedAt": C.utc_now_iso(),
        "branch": {
            "upstream": C.UPSTREAM_COMMIT,
            "upstreamRepo": C.UPSTREAM_REPO,
            "source7k": C.SOURCE7K_COMMIT,
            "source7kRelease": C.SOURCE7K_RELEASE,
            "patchSeriesSha256": series["seriesSha256"],
            "aggregatePatchSha256": series["aggregateSha256"],
            "patchOrder": series["order"],
            "uapi": C.MAPLESU_UAPI,
            "treeSha256": applied_tree,
            "fileCount": len(files),
            "uapiHeaderSha256": uapi_header,
        },
        "identity": manifest["identity"],
        "uapi": manifest["uapi"],
        "appliedSource": {
            "manifest": "third_party/kernelsu/manifest.json",
            "generatedBy": "third_party/kernelsu/scripts/apply_patches.py --clean",
            "treeSha256": applied_tree,
            "fileCount": len(files),
            "files": files,
        },
        "artifacts": artifacts(root),
        "buildEnvironment": {
            "localCapable": ["applied tree", "manifest", "payload", "JNI C++ sources",
                             "ksud/ksuinit sources"],
            "localImpossible": {
                "kernelsu.ko": "无 KDIR/内核树/vmlinux、无 clang/make、DDK 需容器（Docker 未启动）",
                "libksud_ksu.so": "ksud 的 git 依赖（prop-rs-android/android-bootimg）需网络；"
                                  "且 ksuinit 需先产出（crt-static + 16K page + builtins）",
                "libmaplesu_ksu.so": "需要 NDK r29 + prefab libcxx + applied 树（本机 NDK 26.1，"
                                     "gradle 尚未接 externalNativeBuild）",
            },
            "ciEntrypoint": "bash third_party/kernelsu/scripts/build_all.sh",
            "payloadCommand": "python third_party/kernelsu/scripts/gen_payload.py",
        },
        "todos": manifest["patchSeries"]["todo"],
    }


# `--check` 时忽略的字段：生成时间 + **登记元数据**（由 register_artifact.py 写入）。
# 这些字段不是 payload 合同的一部分（合同 = kmi/name/path/status/sha256/size），
# 不忽略的话「登记过一次」就会被判成 payload 漂移。
REGISTRATION_KEYS = ("registeredAt", "registeredBy", "builtBy")


def _normalized(payload: dict) -> dict:
    import copy

    value = copy.deepcopy(payload)
    value.pop("generatedAt", None)
    for art in value.get("artifacts", []):
        for key in REGISTRATION_KEYS:
            art.pop(key, None)
    return value


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="生成 ksu-payload.json")
    ap.add_argument("--root", default=str(C.KSU_ROOT))
    ap.add_argument("--out", default=None)
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--built-source-tree", help="full build_all success declaration: starting source tree SHA, not atomic-build or functional proof")
    args = ap.parse_args(argv)
    root = Path(args.root)
    out = Path(args.out) if args.out else root / "ksu-payload.json"
    payload = build_payload(root)
    if args.built_source_tree is not None and args.built_source_tree != payload["branch"]["treeSha256"]:
        raise C.KsuError("built source tree differs from current manifest/applied tree")
    if args.check:
        if not out.is_file():
            print(f"ERROR: {out} 不存在", file=sys.stderr)
            return 2
        if _normalized(payload) != _normalized(C.read_json(out)):
            print("ERROR: payload 漂移（重跑 gen_payload.py）", file=sys.stderr)
            return 2
        print(f"OK payload --check: {out}（忽略生成时间与登记元数据）")
        return 0
    previous_path = out if out.is_file() else root / "ksu-payload.json"
    previous = C.read_json(previous_path) if previous_path.is_file() else {}
    old_branch = previous.get("branch", {})
    changed = any(old_branch.get(key) != payload["branch"][key] for key in ("upstream", "treeSha256"))
    present = any(entry.get("status") == "present"
                  for entry in previous.get("artifacts", []) + payload["artifacts"])
    if changed and present and args.built_source_tree is None:
        raise C.KsuError("source generation changed or unrecorded with present artifacts; complete build_all.sh --kmi all before registering the new generation")
    C.write_json(out, payload)
    present = [a for a in payload["artifacts"] if a["status"] == "present"]
    pending = [a["name"] for a in payload["artifacts"] if a["status"] != "present"]
    print(f"OK payload: {out} tree={payload['branch']['treeSha256']} "
          f"files={payload['branch']['fileCount']} presentArtifacts={len(present)} "
          f"pending={pending}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except C.KsuError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
