#!/usr/bin/env bash
#
# Build the L3 su JNI shim (manager/src/main/cpp/maplesu_su.c) for arm64-v8a.
#
# The output name is libmaplesu_l3_su.so on purpose. manager/build.gradle.kts
# publishes the runtime's `maplesu-su` *executable* as lib/arm64-v8a/libmaplesu_su.so
# (build.gradle.kts:241), so a second entry with that exact name would either fail
# the jniLibs merge or shadow the executable. `System.loadLibrary` can only ever load
# a shared object, so the shim carries its own name; NativeSu.LIBRARY must match it.
#
# Usage: tools/build_su_client.sh [output.so]
#   MAPLESU_NDK       NDK root (default: MAPLESU_PROVIDER_NDK, else $ANDROID_HOME/ndk/28.2.13676358)
#   MAPLESU_SU_API    Android API level for the target triple (default 21)
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
sdk="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
ndk="${MAPLESU_NDK:-${MAPLESU_PROVIDER_NDK:-${sdk:+$sdk/ndk/28.2.13676358}}}"
[ -n "$ndk" ] || { echo "build_su_client: set MAPLESU_NDK, MAPLESU_PROVIDER_NDK or ANDROID_HOME" >&2; exit 2; }
api="${MAPLESU_SU_API:-21}"

case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*) host="windows-x86_64" ;;
    Linux*) host="linux-x86_64" ;;
    Darwin*) host="darwin-x86_64" ;;
    *) echo "build_su_client: unsupported host $(uname -s)" >&2; exit 2 ;;
esac

prebuilt="$ndk/toolchains/llvm/prebuilt/$host"
clang="$prebuilt/bin/clang"
sysroot="$prebuilt/sysroot"
source_file="$here/manager/src/main/cpp/maplesu_su.c"
out="${1:-$here/manager/src/main/jniLibs/arm64-v8a/libmaplesu_l3_su.so}"

[ -x "$clang" ] || { echo "build_su_client: no clang at $clang" >&2; exit 2; }
[ -f "$source_file" ] || { echo "build_su_client: no $source_file" >&2; exit 2; }
mkdir -p "$(dirname "$out")"

# -fPIC and -shared are the whole build: the file is one JNI translation unit with
# no C++ runtime and no Android logging dependency, so nothing else has to be linked.
#
# 16 KB page alignment is stated, not inherited: NDK r28 already defaults to
# max-page-size=16384 for arm64, but a package built for a 16 KB-page device must
# not depend on that default surviving a toolchain or flag edit. The assertion in
# manager/src/test/.../L3AbiSourceTest.kt reads the LOAD alignment back from the
# shipped .so, so a build that loses it fails the unit tests instead of the device.
"$clang" \
    --target="aarch64-linux-android$api" \
    --sysroot="$sysroot" \
    -shared -fPIC -O2 \
    -Wl,-z,max-page-size=16384 \
    -Wall -Wextra -Werror \
    -o "$out" "$source_file"

echo "build_su_client: built $out"
