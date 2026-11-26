#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# MapleSU · KSU 用户态（ksuinit + ksud）构建入口 —— W12d 实测可用的真实配方。
#
# 产物（都在 applied 之外，applied 永远只含 upstream+patches）：
#   third_party/kernelsu/artifacts/ksuinit           (静态可执行文件, 16K page)
#   third_party/kernelsu/artifacts/maplesu_vrinit    (Ultra 静态 PID 1, 16K page)
#   manager/src/main/jniLibs/arm64-v8a/libksud_ksu.so (PIE 可执行伪装 .so)
#
# 构建目录 = `.tmp/userland-build/`（applied 的副本，用于放入 ksuinit/.ko 与合成版本 git 历史），
# `.tmp/userland-build` 与 `target/` 都不进 applied 树哈希（verify 会断言）。
#
# 平台：
#   * Linux/CI：标准上游流程（cargo + NDK；`setup-rust-build.sh`），本脚本自动走简单路径。
#   * Windows（本机实测）：宿主缺 MSVC linker/Windows SDK，用 **rustup 的
#     stable-x86_64-pc-windows-gnu** 作为宿主工具链 + 其自带 rust-lld 作为宿主 linker；
#     还需：
#       - DLLTOOL: 一个可用的 GNU dlltool（W12d 实测用 llvm-mingw 的 x86_64-w64-mingw32-dlltool.exe，
#                  放到 PATH 里命名为 dlltool.exe；rustup self-contained 的 dlltool 因缺 as 失败）
#       - LIBCLANG_PATH: 含 libclang.dll 的目录（NDK 的 clang.exe 是静态的，无 libclang.dll；
#                  可从 LLVM/llvm-mingw 或 `pip install libclang` 的 clang/native 目录拿）
#     这两个用 `--dlltool`/`--libclang` 参数或同名环境变量传入。
#
# 用法：
#   bash third_party/kernelsu/scripts/build_userland.sh --dry-run
#   LIBCLANG_PATH=/path/to/clang/native KSU_DLLTOOL_DIR=/path/to/dlltool \
#     bash third_party/kernelsu/scripts/build_userland.sh
#   bash ... --kmi all            # 默认：嵌入 lkm/ 下**所有** <kmi>_kernelsu.ko（多 KMI 矩阵）
#   bash ... --kmi android14-6.1  # 只嵌一份（调试；产物只能直装该 KMI）
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KSU_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$KSU_ROOT/../.." && pwd)"
APPLIED="$KSU_ROOT/applied"
BUILD="$KSU_ROOT/.tmp/userland-build"
TARGET_DIR="${MAPLESU_CARGO_TARGET_DIR:-$KSU_ROOT/.tmp/cargo-target}"
ARTIFACTS="$KSU_ROOT/artifacts"
JNI_DIR="$REPO_ROOT/manager/src/main/jniLibs/arm64-v8a"
CARGO_CONFIG="$KSU_ROOT/.cargo-build/config.toml"
KMI="all"
# MapleSU Samsung delta: ksud-maplesu product line and exynos asset alias.
KSUD_PRODUCT_NAME="${KSUD_PRODUCT_NAME:-ksud-maplesu}"
KSUD_TREE="${KSUD_TREE:-}"
EXYNOS_SUFFIX=""
[ "$KSUD_TREE" = "exynos" ] && EXYNOS_SUFFIX="-exynos"
# Every KMI is packaged as "<kmi>_kernelsu.ko"; exynos builds additionally publish
# "<kmi>-exynos_kernelsu.ko" for late_load's KSUD_TREE=exynos preference.
SAMSUNG_EXYNOS_ASSET_FORMAT="{kmi}-exynos_kernelsu.ko"
VERSION_PIN=32650
DRY_RUN=0
SKIP_KSUINIT=0

while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY_RUN=1; shift ;;
    --kmi) KMI="$2"; shift 2 ;;
    --version-pin) VERSION_PIN="$2"; shift 2 ;;
    --skip-ksuinit) SKIP_KSUINIT=1; shift ;;
    -h|--help) sed -n '2,32p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 64 ;;
  esac
done

die() { echo "ERROR: $*" >&2; exit 1; }
[ -d "$APPLIED/userspace/ksud" ] || die "applied/ 缺失：先跑 scripts/rebuild.sh"
[ -f "$APPLIED/uapi/supercall.h" ] || die "applied/uapi missing"
grep -q 'KERNEL_SU_UAPI_VERSION = 7' "$APPLIED/uapi/supercall.h" || die "applied UAPI != 7"

export PATH="$HOME/.cargo/bin:$PATH"
: "${ANDROID_NDK_HOME:=${ANDROID_NDK_HOME:-/opt/android-ndk-r29}}"
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*) HOST_TAG="windows-x86_64"; OS=windows ;;
  Darwin) HOST_TAG="darwin-x86_64"; OS=mac ;;
  *) HOST_TAG="linux-x86_64"; OS=linux ;;
esac
BIN="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$HOST_TAG/bin"
SYSROOT="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$HOST_TAG/sysroot"
KSU_PACKAGE_NAME="${KSU_PACKAGE_NAME:-dev.maplesu.manager}"

# rustup 的 gnu 宿主工具链（Windows 无 MSVC/Windows SDK 时的实测可用路径）
CARGO="cargo"
HOST_LINKER=""
if [ "$OS" = "windows" ]; then
  CARGO="cargo +stable-x86_64-pc-windows-gnu"
  GNU_BIN="$HOME/.rustup/toolchains/stable-x86_64-pc-windows-gnu/lib/rustlib/x86_64-pc-windows-gnu/bin"
  HOST_LINKER="$GNU_BIN/rust-lld.exe"
  [ -x "$HOST_LINKER" ] || die "缺 rust-lld: $HOST_LINKER（rustup toolchain 未装？）"
  [ -n "${LIBCLANG_PATH:-}" ] || die "Windows 构建需 LIBCLANG_PATH（含 libclang.dll）"
  [ -f "$LIBCLANG_PATH/libclang.dll" ] || die "LIBCLANG_PATH 下没有 libclang.dll: $LIBCLANG_PATH"
  # llvm-mingw 的 dlltool.exe 是 wrapper，需要它自己的 bin（clang-23/llvm-dlltool）在 PATH 里；
  # KSU_DLLTOOL_DIR 指「含 dlltool.exe 的目录」，KSU_HOST_BIN_DIR 指 llvm-mingw 的 bin/。
  if [ -n "${KSU_DLLTOOL_DIR:-}" ]; then PATH="$KSU_DLLTOOL_DIR:$PATH"; fi
  if [ -n "${KSU_HOST_BIN_DIR:-}" ]; then PATH="$KSU_HOST_BIN_DIR:$PATH"; fi
  command -v dlltool >/dev/null 2>&1 || die "缺 dlltool（用 KSU_DLLTOOL_DIR 指定；见脚本头注释）"
fi

mkdir -p "$KSU_ROOT/.cargo-build" "$ARTIFACTS" "$JNI_DIR" "$KSU_ROOT/.tmp"
cat > "$CARGO_CONFIG" <<EOF
# 本文件由 scripts/build_userland.sh 生成，位于 applied/ **之外**：
# applied 必须只含 upstream+patches，构建配置不得进入三元组（否则 treeSha256 漂移）。
[target.aarch64-linux-android]
linker = "$BIN/aarch64-linux-android26-clang$([ "$OS" = windows ] && echo .cmd)"

[env]
BINDGEN_EXTRA_CLANG_ARGS_aarch64_linux_android = "--sysroot=$SYSROOT -I$SYSROOT/usr/include/aarch64-linux-android"
CC_aarch64_linux_android = "$BIN/aarch64-linux-android26-clang$([ "$OS" = windows ] && echo .cmd)"
CXX_aarch64_linux_android = "$BIN/aarch64-linux-android26-clang++$([ "$OS" = windows ] && echo .cmd)"
AR_aarch64_linux_android = "$BIN/llvm-ar$([ "$OS" = windows ] && echo .exe)"
EOF

BUILTINS="$("$BIN/clang$([ "$OS" = windows ] && echo .exe)" --print-resource-dir)/lib/linux/libclang_rt.builtins-aarch64-android.a"
KSUINIT_RUSTFLAGS="-C target-feature=+crt-static -C link-arg=-Wl,-z,max-page-size=16384 -C link-arg=-Wno-unused-command-line-argument -C link-arg=$BUILTINS"
KSKD_RUSTFLAGS="-C link-arg=-Wl,-z,max-page-size=16384 -C link-arg=-Wno-unused-command-line-argument -C link-arg=$BUILTINS"

echo "== KSU userland build"
echo "   applied: $APPLIED"
echo "   build:   $BUILD"
echo "   ndk:     $ANDROID_NDK_HOME ($HOST_TAG)"
echo "   cargo:   $CARGO"
echo "   version: pin=$VERSION_PIN (git count $((VERSION_PIN - 30000)))"
[ -n "$HOST_LINKER" ] && echo "   host ld: $HOST_LINKER"

if [ "$DRY_RUN" = "1" ]; then
  for f in "$APPLIED/userspace/ksud/Cargo.toml" "$APPLIED/userspace/ksuinit/Cargo.toml"; do
    [ -f "$f" ] || die "缺构建输入: $f"
  done
  echo "OK dry-run: inputs complete（真实构建见脚本正文；本机已验证可产 ksuinit+ksud）"
  exit 0
fi

# 0) 构建副本（applied 副本，放入 ksuinit/.ko 与合成版本历史；applied 本体不动）
rm -rf "$BUILD"
mkdir -p "$BUILD"
cp -a "$APPLIED/." "$BUILD/"
rm -rf "$BUILD/.cargo" "$BUILD/target" "$BUILD/NOTICE" "$BUILD/BUILD-EVIDENCE.md"

# 合成 git 历史：build.rs 用 `git rev-list --count HEAD` 计算 VERSION_CODE
# （KSU_VERSION_PIN=32650 ⇔ 2650 个提交）。用 fast-import 秒级生成，不伪造产物。
if [ ! -d "$BUILD/.git" ]; then
  ( cd "$BUILD" && git init -q )
  COUNT=$((VERSION_PIN - 30000))
  python_bin="${MAPLESU_PYTHON:-python3}"
  "$python_bin" - "$COUNT" "$VERSION_PIN" <<'PY' | (cd "$BUILD" && git -c init.defaultBranch=main fast-import --quiet)
import sys
count, pin = int(sys.argv[1]), sys.argv[2]
out = []
mark = 0
for i in range(count):
    mark += 1
    # 消息固定 1 字节：`data 4` + "m000" 在 i>=1000 时会变 5 字节，导致 fast-import
    # 报 "unsupported command: 0"（W12d 实测）。
    out.append(f"commit refs/heads/main\nmark :{mark}\ncommitter MapleSU <ci@maplesu.invalid> {1600000000+i} +0000\ndata 1\nm\n")
    if i > 0:
        out.append(f"from :{mark-1}\n")
    out.append("\n")
out.append(f"reset refs/tags/v{pin}\nfrom :{mark}\n\n")
# 必须写二进制：Windows 文本模式会把 LF 变 CRLF，导致 fast-import 的 ref 名非法。
sys.stdout.buffer.write("".join(out).encode())
PY
  ( cd "$BUILD" && git -c user.name=MapleSU -c user.email=ci@maplesu.invalid \
      -c core.autocrlf=false checkout -q main 2>/dev/null || true )
  ( cd "$BUILD" && git describe --tags --always >/dev/null 2>&1 || true )
fi
VERIFY_VERSION="$(cd "$BUILD" && git rev-list --count HEAD)"
echo "   synthetic git history: $VERIFY_VERSION commits (VERSION_CODE=$((30000+VERIFY_VERSION)))"

CARGO_ENV=(env CARGO_TARGET_DIR="$TARGET_DIR" KSU_PACKAGE_NAME="$KSU_PACKAGE_NAME")
if [ -n "$HOST_LINKER" ]; then
  CARGO_ENV+=(CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER="$HOST_LINKER")
fi

# 1) ksuinit + maplesu_vrinit（静态可执行文件，16K page）
if [ "$SKIP_KSUINIT" = "0" ]; then
  echo "== 1/3 ksuinit"
  ( cd "$BUILD" && "${CARGO_ENV[@]}" RUSTFLAGS="$KSUINIT_RUSTFLAGS" \
      $CARGO --config "$CARGO_CONFIG" build --package ksuinit \
      --target aarch64-linux-android --release )
  mkdir -p "$BUILD/userspace/ksud/bin/aarch64"
  cp -f "$TARGET_DIR/aarch64-linux-android/release/ksuinit" "$BUILD/userspace/ksud/bin/aarch64/ksuinit"
  cp -f "$TARGET_DIR/aarch64-linux-android/release/ksuinit" "$ARTIFACTS/ksuinit"
  cp -f "$TARGET_DIR/aarch64-linux-android/release/maplesu_vrinit" "$BUILD/userspace/ksud/bin/aarch64/maplesu_vrinit"
  cp -f "$TARGET_DIR/aarch64-linux-android/release/maplesu_vrinit" "$ARTIFACTS/maplesu_vrinit"
  # ⚠️ W12d 实测坑：rust-embed 的 #[folder = "bin/aarch64"] 在编译期展开，Cargo 看不到
  # 「文件夹里新增了文件」→ ksud 会复用旧产物、**不嵌入 ksuinit**（新旧 libksud 同 hash）。
  # touch assets.rs 强制重编该 crate，确保 ksuinit 被嵌入（release 下 deflate 压缩：
  # include-flate/libflate；见 applied/BUILD-EVIDENCE.md §2 的校验方法）。
  touch "$BUILD/userspace/ksud/src/assets.rs"
else
  mkdir -p "$BUILD/userspace/ksud/bin/aarch64"
  for INIT in ksuinit maplesu_vrinit; do
    [ -s "$ARTIFACTS/$INIT" ] || die "--skip-ksuinit requires artifacts/$INIT"
    cp -f "$ARTIFACTS/$INIT" "$BUILD/userspace/ksud/bin/aarch64/$INIT"
  done
fi

# 2) LKM（多 KMI：默认把所有 lkm/<kmi>_kernelsu.ko 都嵌入；未产出则跳过并说明）
#    ksud 侧按 `--kmi` 查内嵌资产 `<kmi>_kernelsu.ko`（assets::get_asset），
#    所以「嵌入哪几个 KMI」= 管理器能直装哪些 KMI。`--kmi <one>` 可只嵌一份（调试用）。
if [ "$KMI" = "all" ]; then
  KO_LIST=("$KSU_ROOT"/lkm/*_kernelsu.ko)
else
  KO_LIST=("$KSU_ROOT/lkm/${KMI}_kernelsu.ko")
fi
EMBEDDED=0
for KO in "${KO_LIST[@]}"; do
  [ -f "$KO" ] || continue
  cp -f "$KO" "$BUILD/userspace/ksud/bin/aarch64/"
  VR_KO="${KO%_kernelsu.ko}_maplesu_vr.ko"
  KO_KMI="$(basename "$KO" _kernelsu.ko)"
  if "${MAPLESU_PYTHON:-python3}" -c 'import sys; sys.path.insert(0,sys.argv[1]); import ksu_common as C; sys.exit(0 if sys.argv[2] in C.COMPATIBILITY_KMI_MATRIX else 1)' "$SCRIPT_DIR" "$KO_KMI"; then
    [ -f "$VR_KO" ] || die "missing Ultra companion: $VR_KO"
    cp -f "$VR_KO" "$BUILD/userspace/ksud/bin/aarch64/"
  fi
  echo "   embedded LKM: $(basename "$KO") ($(stat -c %s "$KO" 2>/dev/null || echo ?) bytes)"
  EMBEDDED=$((EMBEDDED + 1))
done
if [ "$EMBEDDED" = "0" ]; then
  echo "   note: lkm/ 下没有 *_kernelsu.ko → ksud 内不含 .ko（需 CI/DDK，见 README）"
elif [ "$KMI" = "all" ]; then
  echo "   embedded KMI count: $EMBEDDED（ksud boot-info supported-kmis 应列出同样数量）"
fi

# Force bindgen and rust-embed to refresh after copy/asset changes, even with a warm Cargo cache.
touch "$BUILD/userspace/ksud/build.rs" "$BUILD/userspace/ksud/src/assets.rs"

# 3) ksud（PIE；内嵌 ksuinit 与可选 LKM）
echo "== 3/3 ksud"
( cd "$BUILD" && "${CARGO_ENV[@]}" RUSTFLAGS="$KSKD_RUSTFLAGS" \
    $CARGO --config "$CARGO_CONFIG" build --target aarch64-linux-android --release \
    --manifest-path userspace/ksud/Cargo.toml )
"${MAPLESU_PYTHON:-python3}" - "$TARGET_DIR/aarch64-linux-android/release/ksud" "$VERSION_PIN" <<'PY'
from pathlib import Path
import sys
identity = f"MAPLESU_KSUD_BUILD_V1 version={sys.argv[2]} uapi=7".encode()
if identity not in Path(sys.argv[1]).read_bytes():
    raise SystemExit("ERROR: stale ksud compile identity; deployment aborted")
PY
cp -f "$TARGET_DIR/aarch64-linux-android/release/ksud" "$JNI_DIR/libksud_ksu.so"

echo "== artifacts"
for f in "$ARTIFACTS/ksuinit" "$ARTIFACTS/maplesu_vrinit" "$JNI_DIR/libksud_ksu.so"; do
  [ -f "$f" ] || die "产物缺失: $f"
  echo "   $f size=$(stat -c %s "$f" 2>/dev/null || echo ?) sha256=$(sha256sum "$f" | cut -d' ' -f1)"
done
echo "OK: ksuinit + libksud_ksu.so built（下一步：python3 $SCRIPT_DIR/gen_payload.py）"
