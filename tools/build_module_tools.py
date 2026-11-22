#!/usr/bin/env python3
"""Build the MapleSU module tool host from the pinned ksu_props attribute library.

Shape follows the pinned KSU userspace contract, not a new design:

* `defs.rs:15` puts module tools in `BINARY_DIR` = `<working>/bin/`.
* `assets.rs:26-28` publishes `resetprop` as a **symlink** to the host binary
  rather than as a second executable.
* `cli.rs:521-524` dispatches on `arg0.ends_with("resetprop")`; `cli.rs:814-819`
  also accepts `resetprop` as a subcommand.

The resetprop CLI itself is reused from `ksu_props` by source path, so flags and
exit codes are upstream, not a MapleSU reimplementation. This build only produces
the host executable; the symlink is created at deployment time by Root, because a
symlink cannot be represented as an APK native-library entry.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

from native_toolchain import ndk_bin, ndk_home, tool

ROOT = Path(__file__).resolve().parents[1]
PROJECT = ROOT / "module-tools"
KSU_PROPS = ROOT / "third_party" / "ksu_props"
KSU_PROPS_SRC = KSU_PROPS / "src"

COMMIT = "ddb6ee7294467f7f25bad2118e9e24eee104144b"
HOST = "maplesu-tools"
# Deployed tool name -> how it resolves. `link` mirrors KSU assets.rs:26-28.
TOOLS = {"resetprop": "link"}


def sha256(path):
    digest = hashlib.sha256()
    digest.update(path.read_bytes())
    return digest.hexdigest()


def run(args, env=None, cwd=PROJECT):
    result = subprocess.run([str(x) for x in args], cwd=cwd, env=env)
    if result.returncode != 0:
        raise SystemExit("command failed (%d): %s" % (result.returncode, " ".join(str(x) for x in args)))


def verify_pinned_checkout(report):
    manifest = json.loads((KSU_PROPS / "SOURCE.json").read_text(encoding="utf-8"))
    if manifest["commit"] != COMMIT or manifest["hash_normalization"] != "CRLF to LF":
        raise SystemExit("ksu_props source manifest does not match the pinned contract")
    for name, expected in manifest["files"].items():
        path = KSU_PROPS_SRC / name
        if not path.resolve().is_relative_to(KSU_PROPS_SRC.resolve()) or not path.is_file():
            raise SystemExit("Pinned ksu_props source is missing: " + name)
        if hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest() != expected:
            raise SystemExit("Pinned ksu_props source changed: " + name)
    report["pinnedCheckout"] = {
        "path": str(KSU_PROPS_SRC.relative_to(ROOT)),
        "commit": COMMIT,
        "filesVerified": len(manifest["files"]),
        "sourceManifest": sha256(KSU_PROPS / "SOURCE.json"),
        "cargoLock": sha256(KSU_PROPS_SRC / "Cargo.lock"),
    }


def verify_contract(report):
    """The reused CLI must still be the upstream one; record and cross-check it."""
    reused = KSU_PROPS_SRC / "tools" / "resetprop" / "src" / "resetprop_main.rs"
    entry = PROJECT / "src" / "main.rs"
    report["reuse"] = {
        "includedFrom": str(reused.relative_to(ROOT)),
        "includedSha256": sha256(reused),
        "hostEntry": "module-tools/src/main.rs",
        "hostEntrySha256": sha256(entry),
        "hostModule": "module-tools/src/module_sync.rs",
        "hostModuleSha256": sha256(PROJECT / "src" / "module_sync.rs"),
    }
    # The host must dispatch the way KSU does, or the symlinked tool name would
    # not actually select the resetprop CLI.
    host = entry.read_text(encoding="utf-8")
    for expected in ['arg0.ends_with("resetprop")', '"resetprop"']:
        if expected not in host:
            raise SystemExit("host dispatch no longer mirrors KSU argv[0] contract: " + expected)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ndk")
    parser.add_argument("--toolchain-home", default=os.environ.get(
        "RUSTUP_HOME", str(Path.home() / ".rustup")))
    parser.add_argument("--cargo-home", default=os.environ.get(
        "CARGO_HOME", str(Path.home() / ".cargo")))
    parser.add_argument("--abi", default="arm64-v8a", choices=["arm64-v8a"])
    parser.add_argument("--host-toolchain")
    parser.add_argument("--mingw")
    parser.add_argument("--output-dir", default=str(PROJECT / "build" / "native"))
    args = parser.parse_args()

    report = {"host": HOST, "abi": args.abi, "tools": TOOLS}
    verify_pinned_checkout(report)
    verify_contract(report)

    native_bin = ndk_bin(ndk_home(args.ndk))
    suffix = ".exe" if os.name == "nt" else ""
    clang = tool(native_bin, "aarch64-linux-android31-clang" + (".cmd" if os.name == "nt" else ""))
    llvm_ar = tool(native_bin, "llvm-ar" + suffix)
    llvm_strip = tool(native_bin, "llvm-strip" + suffix)
    llvm_readelf = tool(native_bin, "llvm-readelf" + suffix)

    env = dict(os.environ)
    paths = [str(Path(args.cargo_home) / "bin"), str(native_bin)]
    env["RUSTUP_HOME"] = str(args.toolchain_home)
    env["CARGO_HOME"] = str(args.cargo_home)
    if args.host_toolchain and args.host_toolchain.endswith("windows-gnu"):
        gnu_bin = Path(args.toolchain_home) / "toolchains" / args.host_toolchain / "lib/rustlib/x86_64-pc-windows-gnu/bin"
        if not gnu_bin.is_dir():
            raise SystemExit("Host toolchain is missing: " + args.host_toolchain)
        paths.append(str(gnu_bin))
        env["CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER"] = "rust-lld"
        env["CARGO_TARGET_X86_64_PC_WINDOWS_GNU_RUSTFLAGS"] = "-Clinker-flavor=ld"
    if args.mingw:
        if not Path(args.mingw).is_dir():
            raise SystemExit("MinGW tool directory is missing: " + args.mingw)
        paths.append(args.mingw)
    env["PATH"] = os.pathsep.join(paths + [env.get("PATH", "")])
    env["CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER"] = str(clang)
    env["CARGO_TARGET_AARCH64_LINUX_ANDROID_AR"] = str(llvm_ar)
    # Link the final Android executable for both 4 KB and 16 KB page kernels.
    target_flags = env.get("CARGO_TARGET_AARCH64_LINUX_ANDROID_RUSTFLAGS", "")
    env["CARGO_TARGET_AARCH64_LINUX_ANDROID_RUSTFLAGS"] = (
        target_flags + " -C link-arg=-Wl,-z,max-page-size=16384,-z,common-page-size=16384").strip()

    cargo = shutil.which("cargo", path=env["PATH"])
    if not cargo:
        raise SystemExit("Install Rust and the aarch64-linux-android target before building")
    command = [cargo] + (["+" + args.host_toolchain] if args.host_toolchain else [])
    run(command + ["build", "--release", "--locked", "--target", "aarch64-linux-android",
                   "--target-dir", PROJECT / "target"], env=env)
    report["cargoLock"] = sha256(PROJECT / "Cargo.lock")

    produced = PROJECT / "target" / "aarch64-linux-android" / "release" / HOST
    if not produced.is_file():
        raise SystemExit("build produced no binary at " + str(produced))

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    stripped = out_dir / HOST
    run([llvm_strip, "--strip-unneeded", "-o", stripped, produced])

    header = subprocess.run([str(llvm_readelf), "-h", str(stripped)], stdout=subprocess.PIPE,
                            text=True, check=True).stdout
    dynamic = subprocess.run([str(llvm_readelf), "-d", str(stripped)], stdout=subprocess.PIPE,
                             text=True, check=True).stdout
    interpreter = subprocess.run([str(llvm_readelf), "-l", str(stripped)], stdout=subprocess.PIPE,
                                 text=True, check=True).stdout
    facts = {
        "unstrippedSha256": sha256(produced),
        "sha256": sha256(stripped),
        "size": stripped.stat().st_size,
        "elfClass": "ELF64" in header,
        "machine": "AArch64" in header,
        "type": "DYN (Shared object file)" in header,
        "interpreter": next((line.split("[Requesting program interpreter: ")[1].split("]")[0]
                             for line in interpreter.splitlines()
                             if "Requesting program interpreter" in line), None),
        "needed": sorted({line.split("[")[1].split("]")[0]
                          for line in dynamic.splitlines()
                          if "(NEEDED)" in line and "[" in line}),
    }
    if not (facts["elfClass"] and facts["machine"] and facts["type"]):
        raise SystemExit("artifact is not an AArch64 PIE: " + json.dumps(facts))
    forbidden = {"libstdc++.so.6", "libgcc_s.so.1"}
    if forbidden & set(facts["needed"]):
        raise SystemExit("artifact links unsupported libraries: " + json.dumps(facts["needed"]))
    report["artifact"] = facts
    try:
        report["strippedPath"] = str(stripped.relative_to(ROOT))
    except ValueError:
        report["strippedPath"] = str(stripped.resolve())

    (out_dir.parent / "build.json").write_text(json.dumps(report, indent=2) + "\n",
                                               encoding="utf-8", newline="\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
