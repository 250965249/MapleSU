"""Toolchain discovery and bounded command execution for the P0 gates.

Host-only helpers. They locate a host C compiler (needed for the portable unit
tests), an Android NDK clang (needed for the design's exact source/symbol
checks), and run commands with captured text output. Nothing here touches a
device, a kernel or a build system.
"""

from __future__ import annotations

import os
import pathlib
import shutil
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]  # .../maplesu-ghostlock
REPO = ROOT.parents[1]  # .../MapleSU
INCLUDE = ROOT / "include"
SOURCES = tuple(sorted((ROOT / "src").glob("*.c")))
HARNESS = ROOT / "tests" / "msk_tests.c"
GATES_OUT = ROOT / "gates" / "out"

ALLOWED_EXTERNAL_SYMBOLS = {"memcpy", "memset", "strlen"}
PUBLIC_API_SYMBOLS = {
    "msk_spec_parse",
    "msk_spec_parse_ex",
    "msk_spec_validate",
    "msk_spec_accept_release",
    "msk_spec_digest",
    "msk_spec_schema_digest",
    "msk_plan_build",
    "msk_plan_validate",
    "msk_machine_arm",
    "msk_machine_step",
    "msk_machine_reset",
    "msk_machine_effect",
    "msk_handoff_render",
    "msk_ready_parse",
    "msk_ops_ready",
    "msk_failure_from_status",
}


class ToolchainError(RuntimeError):
    """Raised when a required tool or build step is unavailable."""


def _run_bytes(command, cwd=None, env=None, timeout=300):
    try:
        return subprocess.run(
            [str(part) for part in command],
            cwd=str(cwd or REPO),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
    except OSError as error:
        raise ToolchainError("cannot execute %s: %s" % (command[0], error)) from error


def run(command, cwd=None, env=None, timeout=300):
    """Run a command and return (returncode, stdout, stderr) as text."""
    completed = _run_bytes(command, cwd=cwd, env=env, timeout=timeout)
    return (
        completed.returncode,
        completed.stdout.decode("utf-8", "replace"),
        completed.stderr.decode("utf-8", "replace"),
    )


def run_bytes(command, cwd=None, env=None, timeout=300):
    completed = _run_bytes(command, cwd=cwd, env=env, timeout=timeout)
    return completed.returncode, completed.stdout, completed.stderr


def host_environment(compiler: pathlib.Path) -> dict:
    """Environment that lets the compiler find its own cc1/as/ld helpers."""
    environment = os.environ.copy()
    environment["PATH"] = str(compiler.parent) + os.pathsep + environment.get("PATH", "")
    environment["PYTHONIOENCODING"] = "utf-8"
    return environment


def _version_ok(compiler: pathlib.Path) -> bool:
    try:
        code, stdout, stderr = run(
            [compiler, "--version"], env=host_environment(compiler), timeout=60
        )
    except ToolchainError:
        return False
    text = (stdout + stderr).lower()
    return code == 0 and ("gcc" in text or "clang" in text)


def find_host_cc() -> pathlib.Path:
    """First usable host C compiler: env override, PATH, then known installs."""
    candidates = []
    override = os.environ.get("MAPLESU_HOST_CC")
    if override:
        candidates.append(pathlib.Path(override))
    for name in ("gcc", "clang", "cc"):
        found = shutil.which(name)
        if found:
            candidates.append(pathlib.Path(found))
    candidates.extend(
        [
            pathlib.Path(r"C:\msys64\ucrt64\bin\gcc.exe"),
            pathlib.Path(r"C:\msys64\mingw64\bin\gcc.exe"),
            pathlib.Path(r"C:\msys64\clang64\bin\clang.exe"),
            pathlib.Path(r"C:\Program Files\LLVM\bin\clang.exe"),
        ]
    )
    seen = set()
    for candidate in candidates:
        key = str(candidate).lower()
        if key in seen or not candidate.is_file():
            continue
        seen.add(key)
        if _version_ok(candidate):
            return candidate
    raise ToolchainError(
        "no host C compiler found (tried MAPLESU_HOST_CC, gcc/clang/cc on PATH, "
        "and the MSYS2/LLVM default locations)"
    )


def find_ndk() -> pathlib.Path | None:
    """Return the NDK bin directory when clang/llvm-nm/llvm-ar are all present."""
    candidates = []
    override = os.environ.get("MAPLESU_NDK_BIN")
    if override:
        candidates.append(pathlib.Path(override))
    sdk = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
    provider = os.environ.get("MAPLESU_PROVIDER_NDK")
    if provider:
        candidates.append(pathlib.Path(provider) / "toolchains" / "llvm" / "prebuilt" / "windows-x86_64" / "bin")
    bases = [pathlib.Path(sdk) / "ndk"] if sdk else []
    for base in (*bases, pathlib.Path(r"C:\Android\ndk")):
        if base.is_dir():
            for ndk in sorted(base.iterdir()):
                candidates.append(
                    ndk / "toolchains" / "llvm" / "prebuilt" / "windows-x86_64" / "bin"
                )
    for candidate in candidates:
        if not candidate.is_dir():
            continue
        names = ("clang.exe", "llvm-nm.exe", "llvm-ar.exe", "ld.lld.exe")
        if all((candidate / name).is_file() for name in names):
            return candidate
        if all((candidate / name).is_file() for name in ("clang", "llvm-nm", "llvm-ar", "ld.lld")):
            return candidate
    return None


def ndk_tool(ndk: pathlib.Path, name: str) -> pathlib.Path:
    for suffix in (".exe", ""):
        candidate = ndk / (name + suffix)
        if candidate.is_file():
            return candidate
    raise ToolchainError("NDK tool missing: %s in %s" % (name, ndk))


def build_host_harness(output_directory, compiler: pathlib.Path | None = None) -> pathlib.Path:
    """Compile the unit-test harness with the host compiler; returns the exe path."""
    compiler = compiler or find_host_cc()
    output = pathlib.Path(output_directory)
    output.mkdir(parents=True, exist_ok=True)
    executable = output / "msk_tests.exe"
    command = [
        compiler,
        "-std=c11",
        "-O2",
        "-g",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-pedantic",
        "-I",
        INCLUDE,
    ]
    command.extend(SOURCES)
    command.extend([HARNESS, "-o", executable])
    code, stdout, stderr = run(command, env=host_environment(compiler), timeout=300)
    if code != 0:
        raise ToolchainError(
            "host harness build failed (%s):\n%s\n%s" % (" ".join(map(str, command)), stdout, stderr)
        )
    return executable


def harness(output_directory, *arguments, compiler: pathlib.Path | None = None):
    """Build (cached per output dir) and run the harness; returns (code, out, err)."""
    executable = build_host_harness(output_directory, compiler)
    return run([executable, *arguments], cwd=ROOT, timeout=300)


def parse_nm(text: str):
    """Split `nm` output into (undefined names, defined names)."""
    undefined = set()
    defined = set()
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.endswith(":"):
            continue
        fields = stripped.split()
        if len(fields) == 2 and fields[0] == "U":
            undefined.add(fields[1])
            continue
        if len(fields) >= 3 and len(fields[0]) > 1:
            symbol_type = fields[1]
            if symbol_type in {"T", "t", "D", "d", "B", "b", "R", "r", "W", "w"}:
                defined.add(fields[2])
    return undefined, defined


def write_log(path: pathlib.Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")
