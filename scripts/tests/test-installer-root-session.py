"""Run the production partition discovery chain with a host-only libsu transport substitute."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
import native_toolchain
sys.path.insert(0, str(ROOT / "tools/specgen"))
from specgen.product import cached_jar


def identity(path):
    return {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--manager-classes", type=Path,
        default=ROOT / ".tmp/p1-delivery-r7/gradle-build/manager/intermediates/built_in_kotlinc/debug/compileDebugKotlin/classes")
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    fixture = ROOT / "scripts/fixtures/installer-root-session"
    shell = fixture / "Shell.java"
    sources = [ROOT / "manager/src/main/java/dev/maplesu/manager/installer" / (name + ".kt")
        for name in ["InstallerRootSession", "InstallerSnapshot", "InstallTargetPartition"]]
    sources += [fixture / "InstallerRootSessionHostTest.kt",
        ROOT / "manager/src/test/java/dev/maplesu/manager/installer/InstallerBootTargetTest.kt"]
    dependencies = [cached_jar(*item) for item in [
        ("org.jetbrains.kotlin", "kotlin-stdlib", "2.4.20"), ("org.jetbrains", "annotations", "13.0"),
        ("org.jetbrains.kotlinx", "kotlinx-coroutines-core-jvm", "1.11.0"),
        ("junit", "junit", "4.13.2"), ("org.hamcrest", "hamcrest-core", "1.3")]]
    compiler = cached_jar("org.jetbrains.kotlin", "kotlin-compiler-embeddable", "2.4.20")
    java = str(native_toolchain.jdk_tool("java"))
    javac = str(native_toolchain.jdk_tool("javac"))
    classes = out / "transport-classes"
    classes.mkdir(exist_ok=True)
    classpath = os.pathsep.join(map(str, [classes, *dependencies, args.manager_classes, native_toolchain.android_jar()]))
    jar = out / "tests.jar"
    commands = [
        [javac, "-encoding", "UTF-8", "-d", str(classes), str(shell)],
        [java, "-Xmx512m", "-cp", os.pathsep.join(map(str, [compiler, *dependencies])),
            "org.jetbrains.kotlin.cli.jvm.K2JVMCompiler", "-no-stdlib", "-no-reflect", "-jvm-target", "21",
            "-Xfriend-paths=" + str(args.manager_classes), "-classpath", classpath, "-d", str(jar), *map(str, sources)],
        [java, "-Xmx256m", "-cp", str(jar) + os.pathsep + classpath, "org.junit.runner.JUnitCore",
            "dev.maplesu.manager.installer.InstallerRootSessionHostTest",
            "dev.maplesu.manager.installer.InstallerBootTargetTest"],
    ]
    inputs = [identity(path) for path in [*sources, shell, Path(__file__)]]
    record = dict(recordedAt=datetime.now(timezone.utc).isoformat(), inputs=inputs, commands=commands,
        java=java, javac=javac, managerClasses=str(args.manager_classes), dependencies=[identity(p) for p in dependencies + [compiler]],
        scope="Actual InstallerRootSession discoverBootTarget/read with host substitute Shell; real parser and partition policy",
        deviceAccess=False, realRoot=False, partitionWrites=False, APKProduced=False, nativeSdkRebuilt=False)
    stages = []
    for name, command in zip(["transport", "compile", "tests"], commands):
        result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=90)
        log = result.stdout + result.stderr
        (out / (name + ".log")).write_text(log, encoding="utf-8")
        stages.append(dict(stage=name, exitCode=result.returncode))
        if name == "tests" or result.returncode:
            print(log)
        if result.returncode:
            break
    record.update(stages=stages, passed=len(stages) == 3 and stages[-1]["exitCode"] == 0,
        inputsUnchanged=inputs == [identity(path) for path in [*sources, shell, Path(__file__)]])
    (out / "verification.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    raise SystemExit(stages[-1]["exitCode"])


if __name__ == "__main__":
    main()
