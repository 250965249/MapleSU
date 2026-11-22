#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# MapleSU · KSU 全产物 CI 入口（LKM + ksuinit + ksud + JNI）。
#
# 本机不可完成的部分与原因（03 分册 §5.1 实测）：
#   * kernelsu.ko : 无 KDIR/内核树/vmlinux/clang/make；DDK 需容器（本机 docker daemon 未启动）
#   * ksuinit/ksud: Rust git 依赖需网络（prop-rs-android / android-bootimg / adb_client）
#   * JNI .so     : 需要 NDK r29 + prefab libcxx（本机 NDK 26.1，Gradle 尚未接 externalNativeBuild）
# → 本脚本只做「CI 编排 + 输入/哈希/门禁」，本机跑 `--dry-run` 验证可执行性。
#
# 用法：
#   bash third_party/kernelsu/scripts/build_all.sh --dry-run
#   KSU_EXPECTED_SIZE=0x... KSU_EXPECTED_HASH=<sha256(cert.der)> \
#     ANDROID_NDK_HOME=/opt/android-ndk-r29 bash third_party/kernelsu/scripts/build_all.sh --kmi android15-6.6
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KSU_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$KSU_ROOT/../.." && pwd)"

DRY_RUN=0
KMI="all"
PASSTHRU=()
while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY_RUN=1; shift ;;
    --kmi) KMI="$2"; shift 2 ;;
    -h|--help) sed -n '2,18p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) PASSTHRU+=("$1"); shift ;;
  esac
done

die() { echo "ERROR: $*" >&2; exit 1; }

echo "== MapleSU KSU CI build plan"
echo "   repo:    $REPO_ROOT"
echo "   kmi:     $KMI"
echo "   dry-run: $DRY_RUN"

# 0) 分支树门禁：任何产物都必须建立在「补丁序列 + UAPI=7 + 树哈希一致」之上
echo "== 0) branch tree gate"
bash "$SCRIPT_DIR/rebuild.sh" --verify-only --source-only
python_bin="${MAPLESU_PYTHON:-python3}"
SOURCE_TREE="$("$python_bin" - "$SCRIPT_DIR" <<'PY'
import sys
sys.path.insert(0, sys.argv[1])
import ksu_common as C
manifest_tree = C.read_json(C.KSU_ROOT / "manifest.json")["applied"]["treeSha256"]
actual_tree = C.tree_sha256(C.KSU_ROOT / "applied")
if actual_tree != manifest_tree:
    raise C.KsuError("build start source tree differs from manifest")
print(actual_tree)
PY
)"

# 1) 输入完整性
echo "== 1) inputs"
for f in \
  "$KSU_ROOT/applied/kernel/Kbuild" \
  "$KSU_ROOT/applied/uapi/supercall.h" \
  "$KSU_ROOT/applied/userspace/ksud/Cargo.toml" \
  "$KSU_ROOT/applied/userspace/ksuinit/Cargo.toml" \
  "$KSU_ROOT/applied/manager/app/src/main/cpp/jni.cc" \
  "$KSU_ROOT/manifest.json" \
  "$KSU_ROOT/ksu-payload.json"; do
  [ -f "$f" ] || die "缺输入: $f"
done
echo "   manifest tree: $(grep -o '"treeSha256": *"[^"]*"' "$KSU_ROOT/manifest.json" | head -n1)"
echo "   patch series:  $(grep -o '"seriesSha256": *"[^"]*"' "$KSU_ROOT/manifest.json" | head -n1)"

EXTRA=()
[ "$DRY_RUN" = 0 ] || EXTRA+=(--dry-run)

# 2) LKM
echo "== 2) LKM ($KMI)"
if [ "$KMI" = all ]; then
  read -r -a KMIS <<< "$("$python_bin" -c 'import sys; sys.path.insert(0,sys.argv[1]); import ksu_common as C; print(" ".join(C.KMI_MATRIX))' "$SCRIPT_DIR")"
else
  KMIS=("$KMI")
fi
for selected_kmi in "${KMIS[@]}"; do
  bash "$SCRIPT_DIR/build_lkm.sh" --kmi "$selected_kmi" "${EXTRA[@]}"
  if "$python_bin" -c 'import sys; sys.path.insert(0,sys.argv[1]); import ksu_common as C; sys.exit(0 if sys.argv[2] in C.COMPATIBILITY_KMI_MATRIX else 1)' "$SCRIPT_DIR" "$selected_kmi"; then
    bash "$SCRIPT_DIR/build_lkm.sh" --kmi "$selected_kmi" --vr-only "${EXTRA[@]}"
  fi
done

# 3) ksuinit + ksud
echo "== 3) ksuinit + ksud"
bash "$SCRIPT_DIR/build_userland.sh" --kmi "$KMI" "${EXTRA[@]}"

# 4) JNI
echo "== 4) JNI"
bash "$SCRIPT_DIR/build_jni.sh" "${EXTRA[@]}"

# 5) 产物清单 + 哈希
if [ "$DRY_RUN" = "1" ]; then
  echo "== 5) artifact inventory (dry-run: all pending)"
  echo "   third_party/kernelsu/lkm/${KMI}_kernelsu.ko      [pending]"
  echo "   manager/src/main/jniLibs/arm64-v8a/libksud_ksu.so [pending]"
  echo "   manager/src/main/jniLibs/arm64-v8a/libmaplesu_ksu.so [pending]"
  echo "   manager/src/main/jniLibs/arm64-v8a/libadbroot.so  [pending]"
elif [ "$KMI" = all ]; then
  echo "== 5) regenerate payload with present artifact hashes"
  # This declares successful full orchestration and binds before/after source;
  # it is not proof of atomic compilation or complete functional acceptance.
  "$python_bin" "$SCRIPT_DIR/gen_payload.py" --built-source-tree "$SOURCE_TREE"
  "$python_bin" "$SCRIPT_DIR/verify_payload.py"
  echo "== release checklist (03 分册 §1.7)"
  echo "   [ ] strings lkm/${KMI}_kernelsu.ko | grep -c dev.maplesu.manager >= 1"
  echo "   [ ] strings libksud_ksu.so | grep -c dev.maplesu.manager >= 1"
  echo "   [ ] unzip -p <apk> assets/ksu_manager_gen2 >/dev/null   (W18 资产)"
  echo "   [ ] aapt dump badging <apk> | grep \"package: name='dev.maplesu.manager'\""
  echo "   [ ] 设备：KsuNatives.version>0 && isManager && kernelUAPIVersion==7"
else
  echo "== partial KMI build: payload generation deferred until the complete source generation is built"
fi

echo "OK: CI build plan complete (dry-run=$DRY_RUN)"
