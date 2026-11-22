"""Prepare the m024 permission-return fix without publishing native artifacts."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys

sys.dont_write_bytecode = True
from ar_archive import parse_ar, sha256_bytes, sha256_file

ROOT = Path(__file__).resolve().parents[1]
OUT_ROOT = ROOT / "work/panic-kernel-read-20261114/memory-protection"
ARCHIVE = ROOT / "runtime/maplesu-sdk/lib/arm64-v8a/libkernel_module_kit_static.a"
FROZEN = ROOT / "evidence/pro-sdk-505/inputs/experimental/patch-write/m024.checked.ll"
ARCHIVE_SHA = "8dee1c71700ae5d97a744d46b08ada688d1c375ef43b79820ed716017450649d"
MEMBER_SHA = "56e28f80c20549e170c8000088bbac2ba7438fdb9d47bec64215dd48b4fda591"
FROZEN_SHA = "f52cd84fe37b9d26f1f592eaefdef30a4b3f38d428dd6ae124c5e2d8ad36a2dd"
OLD = "_ZL31exec_kernel_shellcode_no_resultNSt6__ndk18functionIF7KModErrPN6asmjit5v1_163a649AssemblerEEEE"
CHECKED = "maplesu_exec_kernel_patch_checked"
CALLERS = {
    "_ZN13kernel_module25set_kernel_mem_protectionEmmNS_11KernMemProtE": 2,
    "_ZN13kernel_moduleL24set_memory_ro_protectionEmm": 1,
}


def permission_ir(original):
    candidate = original
    for name, count in CALLERS.items():
        matches = list(re.finditer(r"^define[^\n]*@" + re.escape(name) +
                                   r"\([^\n]*\{\r?\n.*?^}", candidate, re.M | re.S))
        assert len(matches) == 1, "Permission function changed: " + name
        match = matches[0]
        body = match[0]
        assert body.count("@" + OLD + "(") == count, "Permission call count changed: " + name
        changed = body.replace("@" + OLD + "(", "@" + CHECKED + "(")
        candidate = candidate[:match.start()] + changed + candidate[match.end():]
    assert candidate.count("@" + OLD + "(") == original.count("@" + OLD + "(") - 3
    assert candidate.count("@" + CHECKED + "(") == original.count("@" + CHECKED + "(") + 3
    # The checked helper and every other function stay byte-identical.
    before = original.splitlines(keepends=True)
    after = candidate.splitlines(keepends=True)
    assert len(before) == len(after)
    differences = [(a, b) for a, b in zip(before, after) if a != b]
    assert len(differences) == 3
    assert all(a.replace("@" + OLD + "(", "@" + CHECKED + "(") == b for a, b in differences)
    return candidate


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ndk", required=True, type=Path)
    parser.add_argument("--out", type=Path, default=OUT_ROOT)
    args = parser.parse_args()
    out = args.out.resolve()
    assert out == OUT_ROOT or out.is_relative_to(OUT_ROOT), "Output must stay in memory-protection/"
    assert sha256_file(ARCHIVE) == ARCHIVE_SHA, "Product archive changed"
    assert sha256_file(FROZEN) == FROZEN_SHA, "Frozen m024 IR changed"
    parsed = parse_ar(str(ARCHIVE))
    member = parsed["members"][24]
    assert member["ord"] == 24 and member["name"] == "module_base_kernel_mem.o"
    assert member["sha256"] == MEMBER_SHA and member["size"] == 183720
    with ARCHIVE.open("rb") as handle:
        handle.seek(member["body_offset"])
        baseline = handle.read(member["size"])
    assert sha256_bytes(baseline) == MEMBER_SHA
    spec = importlib.util.spec_from_file_location("sdk_upgrade_contract", ROOT / "scripts/repair-ultra-environment-upgrade.py")
    contracts = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(contracts)
    source = FROZEN.read_bytes()
    candidate = permission_ir(source.decode("utf-8"))
    out.mkdir(parents=True, exist_ok=True)
    paths = [out / name for name in ("m024.permissions.ll", "m024.baseline.o", "module_base_kernel_mem.o", "build.json")]
    assert not any(path.exists() for path in paths), "Use a fresh output directory"
    patched, reproduced, object_path, report_path = paths
    patched.write_bytes(candidate.encode("utf-8"))
    clang = args.ndk.resolve() / "toolchains/llvm/prebuilt/windows-x86_64/bin/clang.exe"
    commands = []

    def run(*arguments):
        command = [str(clang), *map(str, arguments)]
        result = subprocess.run(command, capture_output=True, text=True, timeout=60)
        commands.append(dict(argv=command, exitCode=result.returncode, stderr=result.stderr))
        assert result.returncode == 0, result.stderr
        return result.stdout

    version = run("--version")
    assert "clang version 17.0.2" in version, "Pinned NDK LLVM generation required"
    flags = ("--target=aarch64-linux-android21", "-Oz", "-fPIC", "-c")
    run(*flags, FROZEN, "-o", reproduced)
    assert reproduced.read_bytes() == baseline, "Frozen m024 does not reproduce the product member"
    run(*flags, patched, "-o", object_path)
    before_contract = contracts.object_contract(baseline)[1]
    after_contract = contracts.object_contract(object_path.read_bytes())[1]
    assert before_contract == after_contract, "Global symbol ABI changed"
    assert sha256_file(ARCHIVE) == ARCHIVE_SHA and sha256_file(FROZEN) == FROZEN_SHA
    report = dict(passed=True, scope="m024 permission result propagation only", changedCallSites=3,
                  archiveSha256=ARCHIVE_SHA, memberOrdinal=24, baselineMemberSha256=MEMBER_SHA,
                  frozenIrSha256=FROZEN_SHA, candidateIrSha256=sha256_file(patched),
                  candidateObjectSha256=sha256_file(object_path), baselineReproducedExactly=True,
                  globalSymbolContractUnchanged=True, globalSymbols=len(before_contract),
                  compilerVersion=version.strip(), scriptSha256=sha256_file(Path(__file__)),
                  commands=commands, productionModified=False, deviceVerification=False,
                  embeddedHelperUpdated=False)
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
