"""Build the step-2 canary helper (aarch64, freestanding, no libc) and prove it.

The helper is the only userspace program the canary module execs
(`jailbreak-providers/root-loader/module/maplesu_root.c` ->
`/data/user_de/0/dev.maplesu.manager/maplesu-bootstrap`). It is deliberately
tiny: raw syscalls, no libc, no crt, static non-PIE, so there is no dynamic
linker, no ART and no bionic dependency in the kernel-domain handover path.

What this script proves before it reports success (host-side only):

  * the artifact is an ELF64 aarch64 **ET_EXEC** with an entry point;
  * it has **no** PT_INTERP, no PT_DYNAMIC and no DT_NEEDED -- i.e. nothing that
    could pull in a loader at exec time on the device;
  * `llvm-nm -u` reports **no undefined symbols** -- a compiler-emitted memset /
    memcpy / __stack_chk_fail would fail the build instead of shipping;
  * the GNU_STACK segment is non-executable;
  * the only absolute path strings in the image are the four this helper is
    allowed to touch (selinuxfs, kmsg, /proc/self/attr/current, and the
    evidence log, which `--kmsg-only` removes);
  * (v2, DEV-164) the image really carries the kernel-line capture: the
    `maplesu-umh-canary: kernel | ` prefix, the `maplesu_root:` tag it filters on
    and its summary line, plus a `.bss` big enough for the 64 KiB ring-buffer
    copy. A capture that was optimised out, or a buffer that shrank, fails here
    instead of silently producing a helper that cannot report the module lines.

Usage:
    python jailbreak-providers/root-loader/canary/build_canary_helper.py
    ... --kmsg-only          # strict variant: /dev/kmsg is the only sink
    ... --verify-only        # re-run the gates on the existing artifact
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROJECT_ROOT = HERE.parents[2]
SOURCE = HERE / "maplesu-umh-canary.c"
DEFAULT_OUT = HERE / "build"
TARGET = "aarch64-linux-android21"
HELPER_NAME = "maplesu-umh-canary"

# One flag per property this artifact must have; see the module on why each one
# matters. -nostdlib + -ffreestanding keep libc out, -fno-builtin keeps
# compiler-inlined memset/memcpy from turning into imports, and -no-pie makes the
# result ET_EXEC so the kernel's binfmt_elf can exec it with no loader.
CLANG_FLAGS = [
    "--target=" + TARGET,
    "-O2",
    "-static",
    "-nostdlib",
    "-ffreestanding",
    "-fno-builtin",
    "-fno-stack-protector",
    "-fno-asynchronous-unwind-tables",
    "-fno-unwind-tables",
    "-fno-pic",
    "-fno-ident",              # no ".comment" clang version path in the image
    "-Wall",
    "-Wextra",
    "-Werror",
]
LINK_FLAGS = [
    "-Wl,-e,_start",
    "-Wl,--build-id=none",
    "-Wl,-z,noexecstack",
    "-Wl,-z,noseparate-code",
]

# The kernel-domain helper may name exactly these paths. Anything else in the
# image is either a bug or a smuggled-in capability, so the gate is a whitelist.
ALLOWED_PATH_PREFIXES = (
    "/sys/fs/selinux/enforce",
    "/dev/kmsg",
    "/proc/self/attr/current",
    "/data/user_de/0/dev.maplesu.manager/maplesu-provider.log",
)
FORBIDDEN_STRINGS = (
    b"app_process",
    b"BOOTCLASSPATH",
    b"/system/bin/sh",
    b"mount",
    b"reboot",
    b"powerctl",
    b"rmmod",
    b"delete_module",
    b"init_module",
    b"/dev/block",
    b"mknod",
)
# The kernel-line capture (DEV-164) is evidence, not an optional extra: each of
# these strings must be in the image, and .bss must still hold the ring-buffer
# copy. `maplesu_root:` is the module's tag; the prefix is what the acceptance
# grep keys on; the summary makes "captured nothing" visible.
KERNEL_CAPTURE_STRINGS = (
    b"maplesu-umh-canary: kernel | ",
    b"maplesu-umh-canary: kernel summary lines=",
    b"maplesu_root:",
)
KERNEL_CAPTURE_MIN_BSS = 64 * 1024


class BuildError(RuntimeError):
    pass


def sha256(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def rel(path: Path) -> str:
    try:
        return Path(path).resolve().relative_to(PROJECT_ROOT).as_posix()
    except (ValueError, OSError):
        return Path(path).as_posix()


def find_ndk(explicit: str | None) -> Path:
    candidates = []
    if explicit:
        candidates.append(Path(explicit))
    for name in ("MAPLESU_PROVIDER_NDK", "ANDROID_NDK_HOME", "ANDROID_NDK_ROOT",
                 "ANDROID_NDK"):
        if os.environ.get(name):
            candidates.append(Path(os.environ[name]))
    sdk = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
    if sdk:
        for version in ("28.2.13676358", "28.1.13356709", "27.2.12479018",
                        "26.3.11579264", "26.1.10909125"):
            candidates.append(Path(sdk) / "ndk" / version)
    for candidate in candidates:
        if (candidate / "toolchains/llvm/prebuilt").is_dir():
            return candidate.resolve()
    raise BuildError("no Android NDK found; pass --ndk-dir")


def host_tag() -> str:
    system = platform.system()
    return "windows-x86_64" if system == "Windows" else (
        "darwin-x86_64" if system == "Darwin" else "linux-x86_64")


def tool(ndk: Path, name: str) -> Path:
    suffix = ".exe" if platform.system() == "Windows" else ""
    path = ndk / "toolchains/llvm/prebuilt" / host_tag() / "bin" / (name + suffix)
    if not path.is_file():
        raise BuildError("missing NDK tool: " + str(path))
    return path


def run(command: list[str], what: str) -> str:
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode != 0:
        raise BuildError("%s failed (rc=%d)\n%s\n%s"
                         % (what, result.returncode, result.stdout, result.stderr))
    return result.stdout


def tool_version(path: Path) -> str:
    for command in ([str(path), "--version"],):
        try:
            return run(command, path.name).splitlines()[0]
        except BuildError:
            return "unknown"


def compile_helper(ndk: Path, out_dir: Path, kmsg_only: bool, extra: list[str]) -> tuple[Path, list[str]]:
    clang = tool(ndk, "clang")
    out_dir.mkdir(parents=True, exist_ok=True)
    module = out_dir / HELPER_NAME
    flags = list(CLANG_FLAGS) + list(extra) + (["-DMAPLESU_CANARY_KMSG_ONLY"] if kmsg_only else [])
    command = [str(clang)] + flags + [str(SOURCE), "-o", str(module)] + LINK_FLAGS
    run(command, "clang")
    return module, command


def readelf_text(ndk: Path, module: Path, args: list[str]) -> str:
    return run([str(tool(ndk, "llvm-readelf")), *args, str(module)], "llvm-readelf")


def nm_undefined(ndk: Path, module: Path) -> list[str]:
    output = run([str(tool(ndk, "llvm-nm")), "-u", str(module)], "llvm-nm")
    return [line.strip() for line in output.splitlines() if line.strip()]


def disassembly(ndk: Path, module: Path) -> str:
    return run([str(tool(ndk, "llvm-objdump")), "-d", str(module)], "llvm-objdump")


def capture_order(source: str) -> dict:
    """The capture must be emitted before the enforcement write (DEV-164).

    The property is about order in the one function that owns both, so it is
    asserted on the source; the artifact gates below then prove the capture code
    (strings, syscall number, buffer) actually survived compilation.
    """
    capture = source.find("capture_kernel_window(log_fd")
    restore = source.find("wrote = (write_fd >= 0")
    if capture < 0:
        raise BuildError("source has no capture_kernel_window(log_fd ...) call")
    if restore < 0:
        raise BuildError("source has no enforcement write to order against")
    if capture > restore:
        raise BuildError("kernel-line capture is emitted after the enforcement write; "
                         "it must run inside the permissive window")
    return {"captureBeforeRestore": True,
            "captureOffset": capture, "restoreOffset": restore}


def capture_summary(facts: dict) -> str:
    """One line for build.txt/stdout; the kmsg-only variant has no capture."""
    capture = facts.get("kernelCapture", {})
    if capture.get("variant") == "kmsg-only":
        return "kmsg-only variant: no provider-log capture (not packaged)"
    return ("%s (bss=%d, syslog READ_ALL calls=%d, before restore=%s)"
            % (capture["strings"][0], capture["bssBytes"],
               capture["syslogReadAllCalls"], capture["captureBeforeRestore"]))


def gates(ndk: Path, module: Path, kmsg_only: bool = False) -> dict:
    header = readelf_text(ndk, module, ["-h"])
    programs = readelf_text(ndk, module, ["-l"])
    dynamic = readelf_text(ndk, module, ["-d"])
    sections = readelf_text(ndk, module, ["-S"])
    notes: list[str] = []

    if re.search(r"Type:\s+EXEC", header) is None:
        raise BuildError("artifact is not ET_EXEC:\n" + header)
    if re.search(r"Machine:\s+AArch64", header) is None:
        raise BuildError("artifact is not AArch64:\n" + header)
    entry = re.search(r"Entry point address:\s+(0x[0-9a-f]+)", header)
    if entry is None or int(entry.group(1), 16) == 0:
        raise BuildError("artifact has no entry point:\n" + header)
    if "Requesting program interpreter" in programs:
        raise BuildError("artifact has a PT_INTERP; it must be static")
    if re.search(r"^\s+INTERP\s", programs, re.MULTILINE):
        raise BuildError("artifact has an INTERP segment; it must be static")
    if "NEEDED" in dynamic or "(NEEDED)" in dynamic:
        raise BuildError("artifact has DT_NEEDED; it must be static")
    if re.search(r"^\s+\(?DYNAMIC\)?\s", programs, re.MULTILINE):
        raise BuildError("artifact has a DYNAMIC segment; it must be static")
    stack = re.search(r"GNU_STACK\s+.*?\s+(RWE|RW)\s", programs)
    if stack is None:
        raise BuildError("artifact has no GNU_STACK segment")
    if "E" in stack.group(1):
        raise BuildError("artifact requests an executable stack")

    undefined = nm_undefined(ndk, module)
    if undefined:
        raise BuildError("artifact has undefined symbols (libc crept in): %s"
                         % ", ".join(undefined))

    raw = module.read_bytes()
    found = sorted({match.decode("ascii", "replace")
                    for match in re.findall(rb"/(?:[A-Za-z0-9_.\-]+/)*[A-Za-z0-9_.\-]+", raw)})
    suspicious = [path for path in found
                  if not path.startswith(ALLOWED_PATH_PREFIXES)]
    if suspicious:
        raise BuildError("artifact names paths outside the whitelist: %s"
                         % ", ".join(suspicious))
    for needle in FORBIDDEN_STRINGS:
        if needle in raw:
            raise BuildError("artifact contains forbidden string %r" % needle)

    # v2 (DEV-164): the kernel-line capture must be in the shipped bytes, not just
    # in the source. These three strings are what the acceptance grep and the
    # module tag depend on, and .bss is where the ring-buffer copy lives. The
    # kmsg-only variant deliberately drops the provider log, so it has no capture
    # and is recorded as such (it is not the packaged helper; build.py rejects it).
    capture: dict = {"variant": "provider-log", "strings": list(KERNEL_CAPTURE_STRINGS)}
    if kmsg_only:
        capture = {"variant": "kmsg-only", "captureStrings": False,
                   "strings": []}
    else:
        missing_capture = [needle.decode("ascii") for needle in KERNEL_CAPTURE_STRINGS
                           if needle not in raw]
        if missing_capture:
            raise BuildError("artifact lost the kernel-line capture (DEV-164): missing %s"
                             % ", ".join(missing_capture))
        bss = re.search(r"\.bss\s+NOBITS\s+[0-9a-f]+\s+[0-9a-f]+\s+([0-9a-f]+)", sections)
        bss_bytes = int(bss.group(1), 16) if bss else 0
        if bss_bytes < KERNEL_CAPTURE_MIN_BSS:
            raise BuildError(".bss is %d bytes; the ring-buffer copy needs at least %d"
                             % (bss_bytes, KERNEL_CAPTURE_MIN_BSS))

        # The syslog(READ_ALL) call is one raw svc: w0 = 3 (READ_ALL), w8 = 116
        # (syslog). The bootstrap uses the same pair; no symbol is imported for it.
        code = disassembly(ndk, module)
        read_all_calls = len(re.findall(r"mov\s+w0, #0x3\b", code))
        syslog_calls = len(re.findall(r"mov\s+w8, #0x74\b", code))
        if read_all_calls < 1 or syslog_calls != 1:
            raise BuildError("artifact does not carry exactly one syslog(READ_ALL) raw "
                             "call (w0=0x3 seen %d, w8=0x74 seen %d)"
                             % (read_all_calls, syslog_calls))
        capture.update({
            "strings": [needle.decode("ascii") for needle in KERNEL_CAPTURE_STRINGS],
            "bssBytes": bss_bytes,
            "syslogReadAllCalls": syslog_calls,
            "captureBeforeRestore": True,
        })

    text_section = re.search(r"\.text\s+PROGBITS\s+[0-9a-f]+\s+([0-9a-f]+)", sections)
    notes.append("entry=%s" % entry.group(1))
    if text_section:
        notes.append(".text=0x%s" % text_section.group(1))
    return {
        "elfType": "EXEC",
        "machine": "AArch64",
        "entry": entry.group(1),
        "interp": None,
        "needed": [],
        "undefinedSymbols": [],
        "executableStack": False,
        "pathStrings": found,
        "kernelCapture": capture,
        "notes": notes,
        "readelf": {"header": header.strip(), "programHeaders": programs.strip(),
                    "dynamic": dynamic.strip(), "sections": sections.strip()},
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="build the MapleSU canary helper")
    parser.add_argument("--ndk-dir", default=None)
    parser.add_argument("--out-dir", default=str(DEFAULT_OUT))
    parser.add_argument("--kmsg-only", action="store_true",
                        help="strict variant: /dev/kmsg is the only marker sink; the "
                             "App-owned provider log is not touched")
    parser.add_argument("--verify-only", action="store_true")
    parser.add_argument("--extra-flag", action="append", default=[])
    args = parser.parse_args(argv)

    ndk = find_ndk(args.ndk_dir)
    out_dir = Path(args.out_dir).resolve()
    module = out_dir / HELPER_NAME
    try:
        if args.verify_only:
            if not module.is_file():
                raise BuildError("%s does not exist; run without --verify-only" % rel(module))
            command = []
        else:
            module, command = compile_helper(ndk, out_dir, args.kmsg_only, args.extra_flag)
        facts = gates(ndk, module, args.kmsg_only)
        if not args.kmsg_only:
            facts["kernelCapture"].update(capture_order(SOURCE.read_text(encoding="utf-8")))
        readelf = facts.pop("readelf")
        (out_dir / "readelf.txt").write_text(
            "== -h ==\n%s\n\n== -l ==\n%s\n\n== -d ==\n%s\n\n== -S ==\n%s\n"
            % (readelf["header"], readelf["programHeaders"], readelf["dynamic"],
               readelf["sections"]), encoding="utf-8")
        record = {
            "schemaVersion": 1,
            "generatedAtUtc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "helper": HELPER_NAME,
            "path": rel(module),
            "sha256": sha256(module),
            "bytes": module.stat().st_size,
            "source": {"path": rel(SOURCE), "sha256": sha256(SOURCE),
                       "bytes": SOURCE.stat().st_size},
            "variants": {"kmsgOnly": bool(args.kmsg_only)},
            "flags": {"clang": CLANG_FLAGS, "link": LINK_FLAGS,
                      "define": ["MAPLESU_CANARY_KMSG_ONLY"] if args.kmsg_only else []},
            "tools": {"clang": tool_version(tool(ndk, "clang")), "ndk": rel(ndk),
                      "python": platform.python_version(),
                      "platform": platform.platform()},
            "devicePath": "/data/user_de/0/dev.maplesu.manager/maplesu-bootstrap",
            "deviceMode": "0700",
            "facts": facts,
            "commands": [" ".join(command)] if command else [],
            "deviceExecuted": False,
        }
        (out_dir / "build.json").write_text(json.dumps(record, indent=2) + "\n",
                                            encoding="utf-8")
        (out_dir / "build.txt").write_text(
            "helper     %s (%d bytes, sha256 %s)\n"
            "source     %s (sha256 %s)\n"
            "elf        ET_EXEC AArch64 entry=%s interp=none needed=none "
            "undefined=none stack=rw\n"
            "capture    %s\n"
            "device     %s mode %s\n"
            % (rel(module), record["bytes"], record["sha256"], rel(SOURCE),
               record["source"]["sha256"], facts["entry"], capture_summary(facts),
               record["devicePath"], record["deviceMode"]), encoding="utf-8")
        print("helper     %s (%d bytes)" % (rel(module), record["bytes"]))
        print("sha256     %s" % record["sha256"])
        print("source     %s (sha256 %s)" % (rel(SOURCE), record["source"]["sha256"]))
        print("gates      ET_EXEC AArch64, no PT_INTERP, no DT_NEEDED, no undefined "
              "symbols, no executable stack")
        print("capture    %s" % capture_summary(facts))
        print("paths      %s" % ", ".join(facts["pathStrings"]))
        print("readelf    %s" % rel(out_dir / "readelf.txt"))
        print("wrote      %s" % rel(out_dir / "build.json"))
        return 0
    except BuildError as error:
        print("build_canary_helper: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
