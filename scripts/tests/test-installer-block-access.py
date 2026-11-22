"""Exercise real partition preparation and write/readback/rollback with isolated OS transports."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools/specgen"))
from specgen.product import cached_jar


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    java = shutil.which("java")
    if not java:
        raise RuntimeError("JAVA_REQUIRED")
    javac = str(Path(java).with_name("javac.exe" if os.name == "nt" else "javac"))
    dependencies = [cached_jar(*coordinates) for coordinates in [
        ("org.jetbrains.kotlin", "kotlin-stdlib", "2.4.20"),
        ("org.jetbrains", "annotations", "13.0"),
        ("org.jetbrains.kotlinx", "kotlinx-coroutines-core-jvm", "1.11.0")]]
    compiler = cached_jar("org.jetbrains.kotlin", "kotlin-compiler-embeddable", "2.4.20")
    java_sources = [ROOT / "installer-core/src/main/java/dev/maplesu/installer" / name
                    for name in ["BlockDeviceTransaction.java", "WritablePartition.java"]]
    installer = ROOT / "manager/src/main/java/dev/maplesu/manager/installer"
    access = installer / "BlockPartitionAccess.kt"
    # Leave the complete production access class unchanged; the JNI object alone has a test transport.
    marker = "internal object BlockPartitionControl {"
    content = access.read_text(encoding="utf-8")
    assert content.count(marker) == 1
    transport_copy = out / "BlockPartitionAccess.kt"
    transport_copy.write_text(content.split(marker)[0], encoding="utf-8")
    sources = [transport_copy, installer / "AndroidWritablePartition.kt", installer / "InstallerSnapshot.kt"]
    fixtures = sorted((ROOT / "runtime/tests/installer_block_access").glob("*.kt"))
    commands = [
        [javac, "--release", "17", "-d", str(out), *map(str, java_sources)],
        [java, "-Xmx512m", "-cp", os.pathsep.join(map(str, [compiler] + dependencies)),
         "org.jetbrains.kotlin.cli.jvm.K2JVMCompiler", "-no-stdlib", "-no-reflect", "-jvm-target", "17",
         "-classpath", os.pathsep.join(map(str, [out] + dependencies)), "-d", str(out / "tests.jar"),
         *map(str, sources + fixtures)],
        [java, "-cp", os.pathsep.join(map(str, [out / "tests.jar", out] + dependencies)),
         "dev.maplesu.manager.installer.BlockAccessTestKt"],
    ]
    records = {}
    for index, command in enumerate(commands):
        result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True,
                                encoding="utf-8", errors="replace", timeout=60)
        log = result.stdout + result.stderr
        (out / f"jvm-{index}.log").write_text(log, encoding="utf-8")
        print(log, end="", flush=True)
        records[f"jvm-{index}"] = result.returncode
        if result.returncode:
            break
    native_script = """set -eu
C=/opt/ddk/clang/clang-r510928
$C/bin/clang++ -std=c++20 -Wall -Wextra -Werror /repo/runtime/tests/block_partition_ioctl_test.cpp -o /tmp/block-test
/tmp/block-test
"""
    native = subprocess.run(["docker", "run", "--rm", "--network", "none", "--mount",
        f"type=bind,source={ROOT},target=/repo,readonly", "--entrypoint", "sh",
        "ghcr.io/ylarod/ddk-min:android15-6.6-20260828", "-c", native_script],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60)
    native_log = native.stdout + native.stderr
    (out / "native.log").write_text(native_log, encoding="utf-8")
    print(native_log, end="", flush=True)
    records["native"] = native.returncode
    fingerprinted = [access, *sources[1:], *fixtures, *java_sources, Path(__file__),
        ROOT / "runtime/src/block_partition_ioctl.h", ROOT / "runtime/tests/block_partition_ioctl_test.cpp"]
    record = dict(recordedAt=datetime.now(timezone.utc).isoformat(), passed=not any(records.values()),
        exitCodes=records, actualAccessClass=True, actualWritableAdapter=True, actualBlockTransaction=True,
        actualNativeControl=True, androidTransport="fixture", nativeIoctl="fixture", deviceAcceptance=False,
        sources={str(p.relative_to(ROOT).as_posix()): hashlib.sha256(p.read_bytes()).hexdigest()
                 for p in fingerprinted})
    (out / "verification.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    raise SystemExit(0 if record["passed"] else 1)


if __name__ == "__main__":
    main()
