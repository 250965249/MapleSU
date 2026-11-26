#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# MapleSU · KSU 用户态（ksuinit + libksud_ksu.so）构建入口。
#
# 本机可做的部分：Rust 1.94.0 + aarch64-linux-android target 已装；
# 但**本仓任务书禁止在本机尝试**（且离线缺 git 依赖：prop-rs-android / android-bootimg /
# adb_client / rustix fork，见 03 分册 §4.3 与 §9-R7）→ 这一步设计为 CI 入口。
#
# 用法：
#   bash third_party/kernelsu/scripts/build_ksud.sh --dry-run
#   ANDROID_NDK_HOME=/opt/android-ndk-r29 bash third_party/kernelsu/scripts/build_ksud.sh
#
# 顺序（照上游 .github/workflows/ksud.yml:26-80）：
#   1) ksuinit（crt-static + 16K page + builtins）→ applied/userspace/ksud/bin/aarch64/ksuinit
#   2) LKM（build_lkm.sh 产物）→ applied/userspace/ksud/bin/aarch64/*_kernelsu.ko
#   3) ksud（内嵌 ksuinit + .ko）→ manager/src/main/jniLibs/arm64-v8a/libksud_ksu.so
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KSU_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$KSU_ROOT/../.." && pwd)"
APPLIED="$KSU_ROOT/applied"
KS="$APPLIED/userspace/ksud"
JNI_DIR="$REPO_ROOT/manager/src/main/jniLibs/arm64-v8a"
KSIUNIT_OUT="$KS/bin/aarch64/ksuinit"

DRY_RUN=0
KMI="android15-6.6"
# MapleSU Samsung delta: product/asset naming for the fork build matrix.
# ksud-maplesu[-exynos]/<kmi>_kernelsu.ko ; KSUD_TREE=exynos prefers {kmi}-exynos_kernelsu.ko
KSUD_PRODUCT_NAME="${KSUD_PRODUCT_NAME:-ksud-maplesu}"
KSUD_TREE="${KSUD_TREE:-}"
EXYNOS_SUFFIX=""
[ "$KSUD_TREE" = "exynos" ] && EXYNOS_SUFFIX="-exynos"
KSUD_ARTIFACT_DIR="${KSUD_PRODUCT_NAME}${EXYNOS_SUFFIX}"
while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY_RUN=1; shift ;;
    --kmi) KMI="$2"; shift 2 ;;
    -h|--help) sed -n '2,20p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 64 ;;
  esac
done

die() { echo "ERROR: $*" >&2; exit 1; }
[ -d "$KS" ] || die "applied/userspace/ksud 缺失：先跑 rebuild.sh"
[ -f "$APPLIED/uapi/supercall.h" ] || die "applied/uapi/supercall.h 缺失"
grep -q 'KERNEL_SU_UAPI_VERSION = 7' "$APPLIED/uapi/supercall.h" || die "applied UAPI != 7"

export PATH="$HOME/.cargo/bin:$PATH"
: "${ANDROID_NDK_HOME:=${ANDROID_NDK_HOME:-/opt/android-ndk-r29}}"
PKG="$(grep -o '"packageName": *"[^"]*"' "$KSU_ROOT/manifest.json" | head -n1 | cut -d'"' -f4)"
: "${KSU_PACKAGE_NAME:=$PKG}"
export KSU_PACKAGE_NAME

HOST_TAG="linux-x86_64"
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*) HOST_TAG="windows-x86_64" ;;
  Darwin) HOST_TAG="darwin-x86_64" ;;
esac

echo "== KSU userspace build"
echo "   applied: $APPLIED"
echo "   ksuinit: $KSIUNIT_OUT"
echo "   ksud:    $JNI_DIR/libksud_ksu.so"
echo "   package: $KSU_PACKAGE_NAME"
echo "   ndk:     $ANDROID_NDK_HOME ($HOST_TAG)"
echo "   rustc:   $( "$HOME/.cargo/bin/rustc" --version 2>/dev/null || echo 'MISSING' )"

# 离线/可复现构建：ksud 的 git 依赖可以改走 third_party/ksu_props（同提交全量源码）
if [ "${KSU_OFFLINE:-0}" = "1" ]; then
  echo "   offline: KSU_OFFLINE=1（需要 applied/userspace/ksud/Cargo.toml 已有 path patch，"
  echo "            见 patches/extra/ksu_props-path-patch.toml；缺失时构建会失败）"
fi

if [ "$DRY_RUN" = "1" ]; then
  echo "== dry-run: checking toolchain inputs"
  for f in "$KS/Cargo.toml" "$APPLIED/userspace/ksuinit/Cargo.toml" \
           "$APPLIED/.github/scripts/setup-rust-build.sh"; do
    [ -f "$f" ] || die "缺构建输入: $f"
  done
  grep -q 'aarch64-linux-android' "$KS/Cargo.toml" || true
  echo "OK dry-run: inputs complete（真实构建需要网络拉 git 依赖 + NDK r29）"
  exit 0
fi

command -v cargo >/dev/null 2>&1 || die "cargo 不在 PATH（export PATH=\"\$HOME/.cargo/bin:\$PATH\"）"
rustup target list --installed 2>/dev/null | grep -q aarch64-linux-android || \
  die "缺 rust target：rustup target add aarch64-linux-android"
[ -d "$ANDROID_NDK_HOME" ] || die "ANDROID_NDK_HOME 不存在: $ANDROID_NDK_HOME"

# 真实构建才需要 toolchain 探测（dry-run 时 NDK 可以不存在）
# 目录前缀单独放进 CLANG_BIN（工具链 bin 目录）；CLANG_PATH 必须是**可执行文件全路径**，
# 因为 clang-sys/bindgen 会把它当 clang 可执行文件校验，设成目录会报
# "CLANG_PATH env var set but is not a full path to an executable"（run 45777330482）。
CLANG_BIN="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$HOST_TAG/bin"
export CLANG_PATH="$CLANG_BIN/clang"
export AR="$CLANG_BIN/llvm-ar"
export CC_aarch64_linux_android="$CLANG_BIN/aarch64-linux-android31-clang"
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="${CC_aarch64_linux_android}"
# bindgen 需要 NDK sysroot + android target + arch 专属 include，否则回落宿主 /usr/include，
# 找不到 asm/ioctl.h → ../../applied/userspace/ksud/build.rs:57 configure_bindgen().expect() panic。
export BINDGEN_EXTRA_CLANG_ARGS_aarch64_linux_android="--sysroot=$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$HOST_TAG/sysroot -I$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$HOST_TAG/sysroot/usr/include/aarch64-linux-android -target aarch64-linux-android"
BUILTINS="$("$CLANG_PATH" --print-resource-dir)/lib/linux/libclang_rt.builtins-aarch64-android.a"
KSUINIT_RUSTFLAGS="-C target-feature=+crt-static -C link-arg=-Wl,-z,max-page-size=16384 \
-C link-arg=-Wno-unused-command-line-argument -C link-arg=$BUILTINS"

mkdir -p "$KS/bin/aarch64" "$JNI_DIR"

echo "== 1/3 ksuinit"
( cd "$APPLIED" && \
  RUSTFLAGS="$KSUINIT_RUSTFLAGS" cargo build --package ksuinit \
    --target=aarch64-linux-android --release )
cp -f "$APPLIED/target/aarch64-linux-android/release/ksuinit" "$KSIUNIT_OUT"
chmod +x "$KSIUNIT_OUT"

echo "== 2/3 lkm -> bin/aarch64"
KO="$KSU_ROOT/lkm/${KMI}_kernelsu.ko"
[ -f "$KO" ] || die "缺 $KO（先跑 build_lkm.sh --kmi $KMI）"
cp -f "$KO" "$KS/bin/aarch64/"

echo "== 3/3 ksud"
( cd "$KS" && cargo build --target aarch64-linux-android --release )
# 产物定位：Cargo 对 workspace 成员使用 **workspace 根** 的 target/，不能按成员目录硬编码。
# applied/Cargo.toml 是 [workspace]（members: userspace/ksud、userspace/ksuinit），
# 因此 ksud 产物落在 $APPLIED/target，而不是 $KS/target。用 cargo metadata 的
# target_directory 优先解析，找不到再回退旧路径，两者都缺才报错（报告 §2「产物定位假设」）。
PYBIN="${MAPLESU_PYTHON:-python3}"
TARGET_DIR="$( cd "$KS" && cargo metadata --no-deps --format-version 1 2>/dev/null \
  | "$PYBIN" -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])' 2>/dev/null || true )"
BIN=""
if [ -n "${TARGET_DIR:-}" ] && [ -f "$TARGET_DIR/aarch64-linux-android/release/ksud" ]; then
  BIN="$TARGET_DIR/aarch64-linux-android/release/ksud"
elif [ -f "$KS/target/aarch64-linux-android/release/ksud" ]; then
  BIN="$KS/target/aarch64-linux-android/release/ksud"
else
  die "ksud 构建产物缺失: target_directory=${TARGET_DIR:-<unset>} fallback=$KS/target/aarch64-linux-android/release/ksud"
fi
echo "   target_directory: ${TARGET_DIR:-<unset>}"
echo "   ksud bin:         $BIN"
mkdir -p "$JNI_DIR"
cp -f "$BIN" "$JNI_DIR/libksud_ksu.so"

python_bin="${MAPLESU_PYTHON:-python3}"
"$python_bin" - "$JNI_DIR/libksud_ksu.so" "$KSU_PACKAGE_NAME" <<'PY'
import hashlib, sys
path, pkg = sys.argv[1], sys.argv[2]
data = open(path, "rb").read()
print(f"size={len(data)} sha256={hashlib.sha256(data).hexdigest()}")
print("OK package name embedded" if pkg.encode() in data else f"FAIL: {pkg} not embedded")
PY
echo "OK: $JNI_DIR/libksud_ksu.so"
echo "下一步：python3 $SCRIPT_DIR/gen_payload.py"
