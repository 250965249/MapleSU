#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# MapleSU · KSU 分支树一键重建/校验（Windows Git-Bash 与 Linux 均可跑）
#
#   bash third_party/kernelsu/scripts/rebuild.sh              # 源码重建 + 完整门禁，不重标产物
#   bash third_party/kernelsu/scripts/rebuild.sh --verify-only # 只跑门禁（CI 快检）
#   bash third_party/kernelsu/scripts/rebuild.sh --quick       # 门禁跳过补丁重放
#   bash third_party/kernelsu/scripts/rebuild.sh --source-only # source generation, preserve artifact provenance
#
# 本机（Windows）可完成：快照 / 补丁 / applied / manifest / 门禁。
# 本机不可完成：kernelsu.ko（无 DDK/内核树/clang）、ksud/ksuinit（Rust git 依赖需网络）、
# JNI .so（需 NDK r29 + gradle externalNativeBuild）→ 见 build_all.sh 与 README.md。
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KSU_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$KSU_ROOT/../.." && pwd)"

# Python 选择顺序：MAPLESU_PYTHON → py -3 → python3 → python
PY=""
if [ -n "${MAPLESU_PYTHON:-}" ]; then
  PY="$MAPLESU_PYTHON"
elif command -v py >/dev/null 2>&1; then
  PY="py -3"
elif command -v python3 >/dev/null 2>&1; then
  PY="python3"
else
  PY="python"
fi

run_py() { # run_py <script> [args...]
  local script="$1"; shift
  echo "==> $PY $(basename "$script") $*"
  ( cd "$SCRIPT_DIR" && $PY "$script" "$@" )
}

MODE="rebuild"
QUICK=""
SOURCE_ONLY=0
for arg in "$@"; do
  case "$arg" in
    --verify-only) MODE="verify" ;;
    --quick) QUICK="--quick" ;;
    --source-only) SOURCE_ONLY=1 ;;
    -h|--help) sed -n '2,20p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "unknown arg: $arg" >&2; exit 64 ;;
  esac
done

if [ "$MODE" = "rebuild" ]; then
  echo "== MapleSU KSU branch tree rebuild (repo: $REPO_ROOT)"
  run_py export_snapshot.py --which upstream --clean
  run_py gen_patches.py
  run_py apply_patches.py --clean
  run_py gen_manifest.py
fi

if [ "$SOURCE_ONLY" = 1 ]; then
  echo "== source gate (payload/artifacts retain their recorded generation)"
  run_py apply_patches.py --check-only
  run_py gen_manifest.py --check
else
  echo "== verify only"
  echo "   payload retains its recorded generation; changed sources require a successful full build_all.sh --kmi all"
  run_py verify_payload.py $QUICK
  run_py gen_manifest.py --check
  run_py gen_payload.py --check
fi

echo
echo "OK: third_party/kernelsu tree consistent (source-only=$SOURCE_ONLY)"
echo "   applied/  $(find "$KSU_ROOT/applied" -type f | wc -l) files, tree=$(du -sh "$KSU_ROOT/applied" | cut -f1)"
echo "   LKM/ksud/ksuinit/JNI 见 scripts/build_all.sh（本机不可产，CI 执行）"
