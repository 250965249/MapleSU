#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Replay only the new empty-origin source patch; no compiler or device calls.

Rust behavioral tests are emitted into boot_patch.rs by the production definition.
This script proves deterministic source replay and immutable historical definitions,
not image correctness or Android packaging.
"""
from __future__ import annotations

import argparse
import ast
import difflib
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

BOOT = "userspace/ksud/src/boot_patch.rs"


class MemoryTree:
    def __init__(self, text: str):
        self.text = text

    def read(self, path: str) -> str:
        if path != BOOT:
            raise AssertionError(path)
        return self.text

    def write(self, path: str, text: str) -> None:
        if path != BOOT:
            raise AssertionError(path)
        self.text = text

    def replace_once(self, path: str, before: str, after: str) -> None:
        text = self.read(path)
        if text.count(before) != 1:
            raise ValueError("unique source anchor missing")
        self.write(path, text.replace(before, after, 1))

    def insert_before(self, path: str, anchor: str, value: str) -> None:
        self.replace_once(path, anchor, value + anchor)


def preserved_nodes(source: str) -> dict[str, str]:
    wanted = {"patch_0022", "BOOT_COPY_HELPER", "BOOT_COPY_TESTS", "MODULE_PARAMS_FILTER", "PATCHES_BOOT_COPY"}
    result = {}
    for node in ast.parse(source).body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in wanted:
            result[node.name] = ast.dump(node, include_attributes=False)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id in wanted:
                    result[target.id] = ast.dump(node, include_attributes=False)
    if "patch_0022" not in result or "BOOT_COPY_HELPER" not in result or "BOOT_COPY_TESTS" not in result:
        raise AssertionError("historical 0022 definitions not found")
    return result


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--definitions", type=Path, required=True)
    parser.add_argument("--baseline-definitions", type=Path, required=True)
    parser.add_argument("--base-source", type=Path, required=True,
                        help="boot_patch.rs after immutable 0001-0023")
    parser.add_argument("--common-scripts", type=Path, required=True)
    parser.add_argument("--patch", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(args.common_scripts.resolve()))
    old = args.baseline_definitions.read_text(encoding="utf-8")
    current = args.definitions.read_text(encoding="utf-8")
    assert preserved_nodes(old) == preserved_nodes(current), "0022 definitions changed"
    spec = importlib.util.spec_from_file_location("empty_origin_definitions", args.definitions)
    if spec is None or spec.loader is None:
        raise AssertionError("definition loader missing")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    definitions = module.PATCHES_EMPTY_RAMDISK_RESTORE
    assert len(definitions) == 1 and definitions[0]["name"] == "0024-boot-empty-origin-restore.patch"
    source = args.base_source.read_text(encoding="utf-8")
    first = MemoryTree(source)
    assert definitions[0]["apply"](first, None) == [BOOT]
    again = MemoryTree(source)
    definitions[0]["apply"](again, None)
    assert first.text == again.text, "source transform not deterministic"
    try:
        definitions[0]["apply"](first, None)
    except ValueError:
        pass
    else:
        raise AssertionError("applying the same patch twice succeeded")
    # Failed reapplication can change the in-memory stage, so use fresh replay.
    generated = again.text
    expected = "diff --git a/" + BOOT + " b/" + BOOT + "\n" + "".join(difflib.unified_diff(
        source.splitlines(keepends=True), generated.splitlines(keepends=True),
        fromfile="a/" + BOOT, tofile="b/" + BOOT))
    assert expected.encode() == args.patch.read_bytes(), "generated patch bytes differ"
    for name in ["own_empty_origin_copy_restores_zero_ramdisk_and_preserves_kernel",
                 "empty_origin_unknown_entries_and_invalid_identity_never_clear_ramdisk",
                 "empty_origin_does_not_override_original_init_or_vr",
                 "actual_empty_install_repatch_and_file_restore_share_one_origin"]:
        assert generated.count("fn " + name + "(") == 1
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "boot_patch.rs").write_text(generated, encoding="utf-8", newline="\n")
    receipt = {"schema": "maplesu-empty-origin-source-replay/1", "scope": "source replay only",
               "baseSourceSha256": digest(args.base_source.read_bytes()),
               "definitionsSha256": digest(args.definitions.read_bytes()),
               "generatedSourceSha256": digest(generated.encode()), "patchSha256": digest(expected.encode()),
               "rustTestsExecuted": False, "deviceAccess": False}
    (args.out / "RECEIPT.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print("PASS deterministic empty-origin source replay; Rust behavior not executed")


if __name__ == "__main__":
    main()
