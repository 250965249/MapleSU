#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# MapleSU · KSU LKM（kernelsu.ko）构建入口 —— **只能在 CI / DDK 容器里跑**。
#
# 本机为什么不可构建（03 分册 §5.1 实测）：
#   * 无内核源码树 / KDIR / vmlinux；PATH 上无 clang/make；
#   * DDK 需要容器，本机 docker daemon 未启动；
#   * 因此 `ddk build` 是唯一路径（ghcr.io/ylarod/ddk-min:<kmi>）。
#
# 用法：
#   bash third_party/kernelsu/scripts/build_lkm.sh --kmi android15-6.6 [--dry-run]
#   bash third_party/kernelsu/scripts/build_lkm.sh --kmi android15-6.6 --ddk-image <image>
#
# 产物：third_party/kernelsu/lkm/<kmi>_kernelsu.ko（+ .sha256）
# 发布前必须满足 §1.7 门禁：`strings ... | grep -c dev.maplesu.manager >= 1`
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KSU_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$KSU_ROOT/../.." && pwd)"
APPLIED="$KSU_ROOT/applied"
OUT_DIR="$KSU_ROOT/lkm"

KMI="android15-6.6"
DDK_IMAGE=""
DRY_RUN=0
VR_ONLY=0
while [ $# -gt 0 ]; do
  case "$1" in
    --kmi) KMI="$2"; shift 2 ;;
    --ddk-image) DDK_IMAGE="$2"; shift 2 ;;
    --vr-only) VR_ONLY=1; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help) sed -n '2,20p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 64 ;;
  esac
done
[ -n "$DDK_IMAGE" ] || DDK_IMAGE="ghcr.io/ylarod/ddk-min:${KMI}-20260828"

die() { echo "ERROR: $*" >&2; exit 1; }

PYTHON_BIN="${MAPLESU_PYTHON:-}"
if [ -z "$PYTHON_BIN" ]; then
  if [ -x "/c/Python314/python.exe" ]; then PYTHON_BIN="/c/Python314/python.exe"
  elif command -v python3 >/dev/null 2>&1; then PYTHON_BIN="python3"
  else PYTHON_BIN="python"; fi
fi
"$PYTHON_BIN" - "$SCRIPT_DIR" "$VR_ONLY" "$KMI" <<'PY'
import sys
sys.path.insert(0, sys.argv[1])
import ksu_common as C
matrix = C.COMPATIBILITY_KMI_MATRIX if sys.argv[2] == "1" else C.KMI_MATRIX
if sys.argv[3] not in matrix:
    print(f"ERROR: unsupported KMI {sys.argv[3]} for vr-only={sys.argv[2]}; allowed: {', '.join(matrix)}", file=sys.stderr)
    sys.exit(64)
PY

[ -f "$APPLIED/uapi/supercall.h" ] || \
  die "applied/ 缺失：先跑 bash $SCRIPT_DIR/rebuild.sh"
[ -f "$APPLIED/kernel/Kbuild" ] || die "applied/kernel/Kbuild 缺失"

# 身份参数默认来自 manifest.identity 的发行证书，允许发布流水线显式覆盖（缺失时拒绝构建）
MANIFEST="$KSU_ROOT/manifest.json"
read_identity() { # read_identity <key>
  "$PYTHON_BIN" - "$MANIFEST" "$1" <<'PY'
import json, sys
m = json.load(open(sys.argv[1], encoding="utf-8"))
v = m["identity"].get(sys.argv[2], "")
print("" if v is None else v)
PY
}
KSU_PACKAGE_NAME="${KSU_PACKAGE_NAME:-$(read_identity packageName)}"
KSU_MANAGER_MIN_GEN="${KSU_MANAGER_MIN_GEN:-$(read_identity managerMinGen)}"
KSU_VERSION_PIN="${KSU_VERSION_PIN:-$(read_identity ksuVersionPin)}"
KSU_IS_PR_BUILD="${KSU_IS_PR_BUILD:-0}"
KSU_EXPECTED_SIZE="${KSU_EXPECTED_SIZE:-$(read_identity expectedSize)}"
KSU_EXPECTED_HASH="${KSU_EXPECTED_HASH:-$(read_identity expectedHash)}"

if [ "$KSU_EXPECTED_SIZE" = "TODO-RELEASE" ] || [ -z "$KSU_EXPECTED_SIZE" ]; then
  if [ "$DRY_RUN" = "1" ]; then
    echo "WARN: KSU_EXPECTED_SIZE/HASH 仍是 TODO-RELEASE —— 真实构建必须显式传"
    echo "      -e KSU_EXPECTED_SIZE=<DER 长度> -e KSU_EXPECTED_HASH=<sha256(cert.der)>"
  else
    die "KSU_EXPECTED_SIZE/HASH 未提供（发布构建禁止用上游占位指纹）"
  fi
fi

mkdir -p "$OUT_DIR"
DDK_CMD=(ddk build "$KMI" "ODIR=$OUT_DIR/out-$KMI" -e CONFIG_KSU=m
  -e "KSU_PACKAGE_NAME=$KSU_PACKAGE_NAME"
  -e "KSU_EXPECTED_SIZE=$KSU_EXPECTED_SIZE"
  -e "KSU_EXPECTED_HASH=$KSU_EXPECTED_HASH"
  -e "KSU_VERSION_PIN=$KSU_VERSION_PIN"
  -e "KSU_MANAGER_MIN_GEN=$KSU_MANAGER_MIN_GEN"
  -e "KSU_IS_PR_BUILD=$KSU_IS_PR_BUILD")

echo "== KSU LKM build"
echo "   applied:  $APPLIED"
echo "   kmi:      $KMI"
echo "   ddk:      $DDK_IMAGE"
echo "   package:  $KSU_PACKAGE_NAME (min_gen=$KSU_MANAGER_MIN_GEN, version_pin=$KSU_VERSION_PIN)"
echo "   cmd:      ${DDK_CMD[*]}"

if [ "$DRY_RUN" = "1" ]; then
  echo "== dry-run: skipping execution"
  # 校验输入闭包（补丁后的树里必须有 stealth/app_lock/gen 的关键文件）
  for f in kernel/manager/stealth.c kernel/manager/app_lock.c kernel/Kbuild uapi/supercall.h; do
    [ -f "$APPLIED/$f" ] || die "applied 缺 $f"
  done
  grep -q 'KSU_MANAGER_MIN_GEN' "$APPLIED/kernel/Kbuild" || die "Kbuild 未带 manager gen"
  echo "OK dry-run: inputs complete"
  exit 0
fi

command -v docker >/dev/null 2>&1 || die "docker 不可用：LKM 只能由 DDK 容器产出"
docker image inspect "$DDK_IMAGE" >/dev/null 2>&1 || \
  die "DDK 镜像不在本地：docker pull $DDK_IMAGE（或 --ddk-image 指定）"

# Keep source read-only and object files outside applied/. Both identities use
# separate output trees, including when the caller supplies a larger build disk.
SUFFIX=kernelsu
[ "$VR_ONLY" = 0 ] || SUFFIX=maplesu_vr
WORK="${MAPLESU_LKM_WORK_ROOT:-$KSU_ROOT/.tmp/lkm}/$KMI-$SUFFIX"
mkdir -p "$WORK"
case "$(uname -s)" in
  MINGW*|MSYS*) SOURCE_HOST="$(cygpath -w "$APPLIED")"; OUTPUT_HOST="$(cygpath -w "$WORK")" ;;
  *) SOURCE_HOST="$APPLIED"; OUTPUT_HOST="$WORK" ;;
esac
MSYS_NO_PATHCONV=1 docker run --rm \
  --mount "type=bind,source=$SOURCE_HOST,target=/source,readonly" \
  --mount "type=bind,source=$OUTPUT_HOST,target=/out" \
  --entrypoint sh "$DDK_IMAGE" -c \
  'set -eu
   cp -a /source/kernel/. /out/
   case "${KDIR##*/}" in
     android17-6.18) set -- MO=/out "$@" ;;
     *) set -- src=/out "$@" ;;
   esac
   make -C "$KDIR" M=/out CONFIG_KSU=m "$@" modules -j2
   cc /out/tools/check_symbol.c -o /out/check_symbol
   for ko in /out/*.ko; do /out/check_symbol "$ko" "$KDIR/vmlinux"; done' sh \
  "MAPLESU_VR_ONLY=$VR_ONLY" "KSU_PACKAGE_NAME=$KSU_PACKAGE_NAME" \
  "KSU_EXPECTED_SIZE=$KSU_EXPECTED_SIZE" "KSU_EXPECTED_HASH=$KSU_EXPECTED_HASH" \
  "KSU_VERSION_PIN=$KSU_VERSION_PIN" "KSU_MANAGER_MIN_GEN=$KSU_MANAGER_MIN_GEN" "KSU_IS_PR_BUILD=$KSU_IS_PR_BUILD"
KO="$WORK/$SUFFIX.ko"
[ -s "$KO" ] || die "missing build output: $KO"
TARGET="$OUT_DIR/${KMI}_${SUFFIX}.ko"
cp -f "$KO" "$TARGET"
"$PYTHON_BIN" - "$TARGET" "$KSU_PACKAGE_NAME" "$VR_ONLY" <<'PY'
import hashlib, sys
path, pkg = sys.argv[1], sys.argv[2]
data = open(path, "rb").read()
print(f"size={len(data)} sha256={hashlib.sha256(data).hexdigest()}")
needle = b"vr_filter_active" if sys.argv[3] == "1" else pkg.encode()
print("OK package name embedded" if needle in data else f"FAIL: {pkg} not embedded")
sys.exit(0 if needle in data else 1)
PY
(cd "$(dirname "$TARGET")" && sha256sum "$(basename "$TARGET")" > "$(basename "$TARGET").sha256") 2>/dev/null || \
  "$PYTHON_BIN" -c "import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest())" "$TARGET" > "$TARGET.sha256"
echo "OK: $TARGET"
echo "下一步：完整 build_all.sh --kmi all 成功后统一登记 payload；单 KMI 构建不提升源码代次"
