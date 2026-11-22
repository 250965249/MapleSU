#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""W18b：7K 剩余移植补丁定义（0006b / 0007b / 0008b / KSU_MANAGER_PACKAGE 三重校验）。

本文件由 `gen_patches.py` 导入，与 0001–0010 共用同一套「LF 快照 → 声明式编辑 → git diff
→ 干净目录重放」流水线。所有 7K 源内容都从 `.research/7kimisu` 的 **git 对象导出树**里
按锚点切片（不手抄），因此补丁与 7K 源逐字一致、可审计。

设计纪律（与 task-21 一致）：
* 每个补丁只做一件事，锚点必须唯一（重复/缺失立即失败，绝不生成「差不多」的补丁）；
* 补丁必须 LF、可顺序 `git apply --check`；
* 无法在本机验证编译的，在 metadata 里标 `compile_verified: false` + 证据化 blocker。
"""
from __future__ import annotations

import ksu_common as C

S7K_KS = "userspace/ksud/src"
S7K_KERNEL = "kernel"


# ---------------------------------------------------------------- 工具
def slice_from(text: str, start_marker: str) -> str:
    """从 start_marker 到文件末尾（用于「追加式」移植）。"""
    idx = text.index(start_marker)
    return text[idx:].rstrip("\n") + "\n"


def slice_between(text: str, start_marker: str, stop_marker: str) -> str:
    """从 start_marker 到 stop_marker 之前（不含 stop_marker）。"""
    start = text.index(start_marker)
    stop = text.index(stop_marker, start)
    return text[start:stop].rstrip("\n") + "\n"


def append_block(tree, rel: str, block: str, note: str) -> None:
    text = tree.read(rel)
    if note in text:
        raise C.KsuError(f"{rel}: 已包含移植块（{note}），拒绝重复追加")
    tree.write(rel, text + block)


# ================================================================ 0014
def patch_0014(tree, s7k) -> list[str]:
    """KSU_MANAGER_PACKAGE 三重校验：kernel 认主 + ksud 默认值 + manifest 断言。

    7K 源：`kernel/manager/apk_sign.c:465-475`（ksu_manager_apk_gen 里的包名判据）
    与 `:509-550`（get_pkg_from_apk_path，从 base.apk 路径取包名）。
    本补丁把它接到我们 0005 的 ksu_manager_apk_gen() 上，并让 Kbuild 默认开启。
    """
    apk_c = "kernel/manager/apk_sign.c"
    apk_h = "kernel/manager/apk_sign.h"
    kbuild = "kernel/Kbuild"

    s7k_apk = s7k.read(apk_c)
    pkg_fn = slice_between(
        s7k_apk,
        "// /data/app/XXXXX/<PACKAGE_NAME>-YYY/base.apk，从倒数第二段取包名（7kimisu 认主用）",
        "// /data/app/XXXXX/<PACKAGE_NAME>-YYY, which contains base.apk",
    )
    # 路径注释改成 MapleSU 口径（函数体逐字保留）
    pkg_fn = pkg_fn.replace(
        "// /data/app/XXXXX/<PACKAGE_NAME>-YYY/base.apk，从倒数第二段取包名（7kimisu 认主用）",
        "/*\n"
        " * MapleSU（W18b，移植自 7K kernel/manager/apk_sign.c:509-550）：\n"
        " * 从 `/data/app/<hash>/<PKG>-<suffix>/base.apk` 的**倒数第二段**取包名，\n"
        " * 供 ksu_manager_apk_gen() 做「证书 + 世代 + 包名」三重校验。\n"
        " */",
    )
    tree.insert_before(
        apk_c,
        "// /data/app/XXXXX/<PACKAGE_NAME>-YYY, which contains base.apk\n"
        "int get_pkg_from_apk_dir_path",
        pkg_fn,
    )
    tree.insert_after(
        apk_h,
        "int get_pkg_from_apk_dir_path(char *pkg, const char *path);\n",
        "/* MapleSU W18b：从 base.apk 路径取包名（三重校验用，见 apk_sign.c） */\n"
        "int get_pkg_from_apk_path(char *pkg, const char *path);\n",
    )
    # ksu_manager_apk_gen：插入包名判据（0005 的版本没有这段）
    tree.replace_once(
        apk_c,
        "int ksu_manager_apk_gen(char *path)\n{\n"
        "    if (!check_v2_signature(path, EXPECTED_SIZE, EXPECTED_HASH)) {\n",
        "int ksu_manager_apk_gen(char *path)\n{\n"
        "#ifdef KSU_MANAGER_PACKAGE\n"
        "    /*\n"
        "     * 第三重校验：包名。KSU_MANAGER_PACKAGE 由 Kbuild 编译期注入（默认\n"
        "     * dev.maplesu.manager），必须与 ksud build.rs 的默认包名、manifest.identity\n"
        "     * 三处同值 —— verify_payload.py 会断言这一点。\n"
        "     */\n"
        "    char pkg[KSU_MAX_PACKAGE_NAME];\n"
        "    if (get_pkg_from_apk_path(pkg, path) < 0) {\n"
        '        pr_err("Failed to get package name from apk path: %s\\n", path);\n'
        "        return -1;\n"
        "    }\n"
        "    if (strncmp(pkg, KSU_MANAGER_PACKAGE, sizeof(KSU_MANAGER_PACKAGE))) {\n"
        "        return -1;\n"
        "    }\n"
        "#endif\n"
        "    if (!check_v2_signature(path, EXPECTED_SIZE, EXPECTED_HASH)) {\n",
    )
    # Kbuild：把可选透传改成默认开启（三重校验的编译期真相源）
    tree.replace_once(
        kbuild,
        "# 可选的双重校验（包名 + 证书 + gen），发布流水线传 -e KSU_MANAGER_PACKAGE=...\n"
        "# 注：0005 只落地「证书 + gen」两重；包名校验需要额外路径解析，见 manifest.todos。\n"
        "ifdef KSU_MANAGER_PACKAGE\n"
        'ccflags-y += -DKSU_MANAGER_PACKAGE=\\"$(KSU_MANAGER_PACKAGE)\\"\n'
        "endif\n",
        "# 三重校验（证书 + 世代 + 包名）的编译期默认值。\n"
        "# 必须与 ksud build.rs 的 default 包名、manifest.identity.managerPackage 同值；\n"
        "# verify_payload.py 会断言三处一致（改这里必须同步另两处）。\n"
        "KSU_MANAGER_PACKAGE ?= dev.maplesu.manager\n"
        "$(info -- KernelSU manager package (triple check): $(KSU_MANAGER_PACKAGE))\n"
        'ccflags-y += -DKSU_MANAGER_PACKAGE=\\"$(KSU_MANAGER_PACKAGE)\\"\n',
    )
    return [apk_c, apk_h, kbuild]


# ================================================================ 0011 (0006b)
KS_APPEND_NOTE = "MapleSU W18b（0006b）· webadmin ksud API surface"
KS_IMPORTS = """\
// ══════════════════════════════════════════════════════════════════════════
// MapleSU W18b（0006b）· webadmin ksud API surface
//
// 7K 的 `webadmin_ksud.rs`（2540+1645 行，已在 0006 入库）依赖下面这批 ksucalls
// 辅助函数：7K `userspace/ksud/src/ksucalls.rs:678-1055` 逐字移植（含注释）。
// 说明：本文件是该区间在 pinned 7K 源上的原样切片，未做语义改写；
//      UAPI 常量来自同树 `applied/uapi/`（0002 已把 STEALTH_* 重编号到 33-36）。
// ══════════════════════════════════════════════════════════════════════════

"""

MODULE_APPEND_NOTE = "MapleSU W18b（0006b）· 模块网页执行 API"
MODULE_IMPORTS = """\
// ══════════════════════════════════════════════════════════════════════════
// MapleSU W18b（0006b）· 模块网页（module webui / webadmin）执行 API
//
// 7K `userspace/ksud/src/module.rs` 的模块网页支持（ExecOptions / 进程捕获 /
// 包名与包信息 / action 捕获 / 模块内执行），逐字切片移植。
// ══════════════════════════════════════════════════════════════════════════

"""


def patch_0011(tree, s7k) -> list[str]:
    """webadmin ksud API surface：补齐 webadmin_ksud 依赖的 ksucalls/module 函数并接线。"""
    ks = s7k.read(f"{S7K_KS}/ksucalls.rs")
    block = slice_from(ks, "pub fn allow_list_uids() -> Vec<u32> {")
    append_block(tree, f"{S7K_KS}/ksucalls.rs", KS_IMPORTS + block, KS_APPEND_NOTE)

    mod_rs = s7k.read(f"{S7K_KS}/module.rs")
    exec_block = slice_between(
        mod_rs,
        "/// 模块网页传过来的执行选项（对齐 KernelSU 的 `options`：`cwd` 与 `env`）。",
        "pub fn run_action(id: &str) -> Result<()> {",
    )
    list_block = slice_between(
        mod_rs,
        "/// 模块列表的 JSON 文本（网页管理器直接拿去当 /api/modules 的响应）",
        "/// Get all managed features from active modules",
    )
    append_block(tree, f"{S7K_KS}/module.rs", MODULE_IMPORTS + exec_block + "\n" + list_block,
                 MODULE_APPEND_NOTE)

    # main.rs：接线 webadmin_ksud（android-only，与 7K main.rs:73-74 一致）
    tree.replace_once(
        f"{S7K_KS}/main.rs",
        "// MapleSU 0006：rs 后端 webadmin_ksud.rs 依赖 7K ksucalls/module API-surface，\n"
        "// 待 0006b 接线；文件已在 applied 树内，未 mod 因此不参与本次编译。\n",
        "#[cfg(target_os = \"android\")]\n"
        "mod webadmin_ksud;\n",
    )
    # main.rs：接线 res_label（module::packages_info 用；7K main.rs 不限定 cfg，宿主可编）
    tree.replace_once(
        f"{S7K_KS}/main.rs",
        "// MapleSU 0007：res_label.rs（APK 资源读应用名）依赖 7K 的 apk 资源解析\n"
        "// API-surface，待 0007b 接线；文件已入库，未 mod。\n",
        "// MapleSU W18b：资源标签解析（module::packages_info 用；flate2 rust_backend，\n"
        "// 7K 注明宿主也能编，因此不限定 android）—— 文件由 0007 入库，本补丁接线\n"
        "mod res_label;\n",
    )
    # cli.rs：Webadmin 子命令 + 分发 arm
    cli = s7k.read(f"{S7K_KS}/cli.rs")
    webadmin_enum = slice_between(cli, "/// 网页管理器的子命令\n#[derive(clap::Subcommand, Debug)]\nenum Webadmin {",
                                  "#[derive(clap::Subcommand, Debug)]\nenum Commands {")
    tree.insert_before(
        f"{S7K_KS}/cli.rs",
        "#[derive(clap::Subcommand, Debug)]\nenum Commands {",
        webadmin_enum + "\n",
    )
    tree.insert_after(
        f"{S7K_KS}/cli.rs",
        "    /// Manage KernelSU modules\n    Module {\n        #[command(subcommand)]\n"
        "        command: Module,\n    },\n",
        "\n    /// 内置网页管理器（跑在 ksud 里，不依赖 App）\n"
        "    Webadmin {\n        #[command(subcommand)]\n        command: Webadmin,\n    },\n",
    )
    webadmin_arm = slice_between(
        cli,
        "        Commands::Webadmin { command } => match command {",
        "        Commands::PostFsData => init_event::on_post_fs_data(),",
    )
    tree.insert_after(
        f"{S7K_KS}/cli.rs",
        "    let result = match cli.command {\n",
        webadmin_arm,
    )
    return [f"{S7K_KS}/ksucalls.rs", f"{S7K_KS}/module.rs", f"{S7K_KS}/main.rs",
            f"{S7K_KS}/cli.rs"]


PATCHES_W18B = [
    {
        "name": "0011-webadmin-api-surface.patch",
        "summary": "0006b：webadmin_ksud 的 ksud API surface（ksucalls 9 个函数 + module 网页 API "
                   "逐字移植）并接线 mod/cli；7K 源 userspace/ksud/src/{ksucalls,module}.rs",
        "apply": patch_0011,
        "status": "implemented",
        "compile_verified": False,
        "compile_note": "本机无 Rust 依赖（android-bootimg/prop-rs-android 为 git 源，离线不可得）；"
                        "已用 rustfmt 做语法校验，语义/类型校验留给 CI aarch64 构建",
        "checks": [
            ["userspace/ksud/src/ksucalls.rs", ["pub fn allow_list_uids", "pub fn manager_appid",
                                                "pub fn stealth_get_authed", "pub fn get_app_profile",
                                                "pub fn read_cstr"]],
            ["userspace/ksud/src/module.rs", ["pub struct ExecOptions", "pub fn list_modules_json",
                                              "pub fn packages_info", "pub fn exec_in_module"]],
            ["userspace/ksud/src/main.rs", ["mod webadmin_ksud;"]],
            ["userspace/ksud/src/cli.rs", ["enum Webadmin {", "Commands::Webadmin { command }"]],
        ],
    },
    {
        "name": "0014-manager-package-triple-check.patch",
        "summary": "KSU_MANAGER_PACKAGE 三重校验：kernel 认主（证书+世代+包名，移植 7K "
                   "apk_sign.c get_pkg_from_apk_path/包名判据）+ Kbuild 默认值；manifest 断言三处同值",
        "apply": patch_0014,
        "status": "implemented",
        "compile_verified": False,
        "compile_note": "本机无内核 clang/KDIR，无法编译 kernel C；已做静态一致性断言"
                        "（Kbuild 默认值 / apk_sign.c 判据 / build.rs 默认包名 / manifest 同值）",
        "checks": [
            ["kernel/Kbuild", ["KSU_MANAGER_PACKAGE ?= dev.maplesu.manager"]],
            ["kernel/manager/apk_sign.c", ["int get_pkg_from_apk_path(char *pkg, const char *path)",
                                            "#ifdef KSU_MANAGER_PACKAGE",
                                            "strncmp(pkg, KSU_MANAGER_PACKAGE"]],
            ["kernel/manager/apk_sign.h", ["int get_pkg_from_apk_path"]],
            ["userspace/ksud/build.rs", ["cargo:rustc-env=KSU_PACKAGE_NAME=dev.maplesu.manager"]],
        ],
    },
]


# 0012（boot-patch 安全接线）/0013（restore-user-data 接线）定义在 boot 模块里；
# 这里按补丁序号重排，保证 series 顺序 = 依赖顺序（0007b 必须先于 0008b：后者用到
# BootRestoreArgs.force_foreign 语义收紧后的 restore()）。
from patch_defs_w18b_boot import PATCHES_W18B_BOOT  # noqa: E402

PATCHES_W18B = [
    PATCHES_W18B[0],       # 0011 webadmin API surface
    PATCHES_W18B_BOOT[0],  # 0012 boot-patch safety wiring
    PATCHES_W18B_BOOT[1],  # 0013 restore-user-data wiring
    PATCHES_W18B[1],       # 0014 manager package triple check
]
