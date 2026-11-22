#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""校验 libksud_ksu.so 里**确实内嵌**了给定资产（ksuinit 等），并给出证据。

为什么需要专门校验（W12d 结论）：
  `userspace/ksud/Cargo.toml` 的 rust-embed 开启了 `features = ["debug-embed", "compression"]`，
  `src/assets.rs` 用 `#[derive(RustEmbed)] #[folder = "bin/aarch64"]`。release 构建时
  每个资产被 **raw DEFLATE（libflate）压缩后**放进 ELF rodata —— 所以：
    * 二进制里**不存在**逐字节相同的原始副本（这是预期，不是漏嵌）；
    * 校验方式是「找到一个 raw-deflate 流，解压后与资产逐字节相同」。

用法：
  python3 third_party/kernelsu/scripts/verify_embedded_asset.py \
      --lib manager/src/main/jniLibs/arm64-v8a/libksud_ksu.so \
      --asset third_party/kernelsu/artifacts/ksuinit --offset 275550   # 快检（记录于 BUILD-EVIDENCE）
  python3 ... --asset ... --deep        # 未知偏移时全量扫描（慢，CI 可选）

退出码：0 找到且字节一致；2 未找到/不一致/参数错误。
"""
from __future__ import annotations

import argparse
import sys
import zlib
from pathlib import Path

import ksu_common as C

ELF_MAGIC = b"\x7fELF"
HEAD_WINDOW = 512  # 见 find_offset 的说明：64B 窗口会假阴性


def try_decompress(lib: bytes, offset: int, want: bytes) -> bool:
    """从 offset 起按 raw-deflate 解压，判断是否逐字节等于 want。"""
    d = zlib.decompressobj(-15)  # raw DEFLATE
    try:
        out = d.decompress(lib[offset:], len(want) + 1)
    except zlib.error:
        return False
    return out == want


def find_offset(lib: bytes, want: bytes) -> int | None:
    """全量扫描：先用 512B 输入窗口试解压 4 字节，命中 ELF 魔数再做完整比对。

    W13 实测（2026-10-30，5 KMI 重建后 libksud 6,641,192 B）：
      * **64B 输入窗口会假阴性**：在已知偏移（旧库 275550）上 64B 只解出 0 字节，
        旧实现因此恒返回 None（`--deep` 报 "no raw-deflate stream"）。原因：
        libflate 把整个资产压成**单个 dynamic Huffman block**，产出前 4 字节需要
        >64B 输入（实测 128B 才出首字节）；这里取 512B 留余量。
      * 按 BTYPE=11（非法块）预剪枝 + 512B 窗口：6.6MB 全量扫描约 8 秒。
    """
    n = len(lib)
    for off in range(n - 2):
        if (lib[off] & 0x06) == 0x06:  # BFINAL/BTYPE 中 BTYPE=11 一定不是流起点
            continue
        d = zlib.decompressobj(-15)
        try:
            head = d.decompress(lib[off:off + HEAD_WINDOW], 4)
        except zlib.error:
            continue
        if len(head) < 4 or head != ELF_MAGIC:
            continue
        if try_decompress(lib, off, want):
            return off
    return None


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="校验 rust-embed 压缩内嵌的资产")
    ap.add_argument("--lib", default="manager/src/main/jniLibs/arm64-v8a/libksud_ksu.so")
    ap.add_argument("--asset", default="third_party/kernelsu/artifacts/ksuinit")
    ap.add_argument("--offset", type=int, default=None,
                    help="已知压缩流偏移（BUILD-EVIDENCE 记录）；提供则只做快检")
    ap.add_argument("--deep", action="store_true", help="全量扫描（无已知偏移时）")
    args = ap.parse_args(argv)

    lib_path, asset_path = Path(args.lib), Path(args.asset)
    if not lib_path.is_file():
        print(f"ERROR: lib not found: {lib_path}", file=sys.stderr)
        return 2
    if not asset_path.is_file():
        print(f"ERROR: asset not found: {asset_path}", file=sys.stderr)
        return 2
    lib = lib_path.read_bytes()
    want = asset_path.read_bytes()

    offset = args.offset
    if offset is None:
        if not args.deep:
            print("ERROR: --offset (recorded in BUILD-EVIDENCE) or --deep is required",
                  file=sys.stderr)
            return 2
        print(f"deep scan {lib_path} ({len(lib)} bytes) for {asset_path.name} "
              f"({len(want)} bytes) ...")
        offset = find_offset(lib, want)
        if offset is None:
            print("FAIL: no raw-deflate stream inflating to the asset found", file=sys.stderr)
            return 2
    if not (0 <= offset < len(lib)):
        print(f"FAIL: offset out of range: {offset}", file=sys.stderr)
        return 2
    if not try_decompress(lib, offset, want):
        print(f"FAIL: raw-deflate stream at {offset} does not inflate to {asset_path}",
              file=sys.stderr)
        return 2

    print("OK: asset is embedded as a raw-DEFLATE stream (rust-embed compression)")
    print(f"  lib   : {lib_path} ({len(lib)} bytes, sha256 {C.sha256_file(lib_path)})")
    print(f"  asset : {asset_path} ({len(want)} bytes, sha256 {C.sha256_file(asset_path)})")
    print(f"  offset: {offset} (raw-deflate stream -> {len(want)} bytes, byte-identical when inflated)")
    print("  note: rust-embed features=[debug-embed,compression] means there is NO raw copy"
          " in the ELF; this command is the verification method.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
