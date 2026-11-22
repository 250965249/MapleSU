"""Run the production parasite recovery/uninstall code and JVM regression tests."""
import argparse
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
import native_toolchain
sys.path.insert(0, str(ROOT / "tools/specgen"))
from specgen.product import cached_jar


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--product-classes", type=Path, required=True)
    parser.add_argument("--baseline", action="store_true", help="Test the already-built product before the fix")
    parser.add_argument("--apk", type=Path, help="Also verify extraction from a delivered manager APK")
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    (out / "classes").mkdir(exist_ok=True)
    product = args.product_classes.resolve()
    deps = [cached_jar(*entry) for entry in [
        ("org.jetbrains.kotlin", "kotlin-stdlib", "2.4.20"),
        ("org.jetbrains", "annotations", "13.0"),
        ("org.jetbrains.kotlinx", "kotlinx-coroutines-core-jvm", "1.11.0"),
        ("org.jetbrains.kotlinx", "kotlinx-serialization-core-jvm", "1.11.0"),
        ("org.jetbrains.kotlinx", "kotlinx-serialization-json-jvm", "1.11.0"),
        ("junit", "junit", "4.13.2"), ("org.hamcrest", "hamcrest-core", "1.3"),
        ("org.json", "json", "20240303"),
    ]]
    deps.append(native_toolchain.android_jar())
    compiler = cached_jar("org.jetbrains.kotlin", "kotlin-compiler-embeddable", "2.4.20")
    base = ROOT / "manager/src/main/java/dev/maplesu/manager"
    sources = [base / name for name in [
        "liteweb/daemon/UltraSdkSuAuthRevoke.kt",
        "liteweb/daemon/DaemonManagerUninstall.kt",
        "litehidden/ProductionHiddenModeBackend.kt",
        "litehidden/HttpHiddenManagerRemoval.kt",
    ]]
    tests = ["liteweb.daemon.DaemonSdkLibraryTest", "liteweb.daemon.DaemonManagerUninstallTest",
             "liteweb.daemon.DaemonManagerRecoveryReadinessTest", "litehidden.ParasiteBackendTest"]
    sources += [ROOT / "manager/src/test/java/dev/maplesu/manager" /
                (name.replace(".", "/") + ".kt") for name in tests]
    if args.baseline:
        sources = [path for path in sources if "src/test" in path.as_posix()]
    cp = os.pathsep.join(map(str, [out / "classes", product, *deps]))
    commands = [
        [str(native_toolchain.jdk_tool("javac")), "--release", "17", "-d", str(out / "classes"),
         str(ROOT / "manager/src/test/java/android/util/Log.java")],
        [str(native_toolchain.jdk_tool("java")), "-Xmx1g", "-cp",
         os.pathsep.join(map(str, [compiler, *deps])), "org.jetbrains.kotlin.cli.jvm.K2JVMCompiler",
         "-no-stdlib", "-no-reflect", "-jvm-target", "21", f"-Xfriend-paths={product}",
         "-classpath", cp, "-d", str(out / "classes"), *map(str, sources)],
        [str(native_toolchain.jdk_tool("java")), "-Xmx1g",
         *([f"-Dmaplesu.test.parasite.apk={args.apk.resolve()}"] if args.apk else []),
         "-cp", cp, "org.junit.runner.JUnitCore",
         *["dev.maplesu.manager." + name for name in tests]],
    ]
    for index, command in enumerate(commands):
        result = subprocess.run(command, cwd=ROOT / "manager", capture_output=True, text=True,
                                encoding="utf-8", errors="replace", timeout=300)
        output = result.stdout + result.stderr
        (out / f"step-{index}.log").write_text(output, encoding="utf-8")
        print(output, end="")
        if result.returncode:
            return result.returncode
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
