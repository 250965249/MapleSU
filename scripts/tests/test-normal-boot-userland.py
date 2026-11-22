"""Compile current Normal boot/userland and transaction code, then run host regressions.

An existing Manager compilation supplies only unrelated Android dependencies.
The selected production Kotlin sources are rebuilt. Filesystem rollback tests run
their production shell scripts against isolated host fixtures using Bash.
No Android device access, root commands, APK build or partition writes occur.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools/specgen"))
from specgen.product import cached_jar


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--compile-inputs", type=Path,
                        default=ROOT / ".tmp/p0-mode-a-tests/compile-inputs.json")
    parser.add_argument("--manager-build", type=Path,
                        default=ROOT / ".tmp/normal-ksu-gradle/manager")
    parser.add_argument("--fallback-manager-build", type=Path,
                        default=ROOT / ".tmp/p1-delivery-r7/gradle-build/manager")
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    java = shutil.which("java")
    if not java:
        parser.error("Java 21 is required on PATH")
    inputs = json.loads(args.compile_inputs.read_text("utf-8"))
    kotlin_classes = "intermediates/built_in_kotlinc/debug/compileDebugKotlin/classes"
    current = args.manager_build / kotlin_classes
    previous = args.fallback_manager_build / kotlin_classes
    cached = next((path for path in (current, previous) if path.is_dir()), None)
    if cached is None:
        parser.error("An existing Manager compilation is required")
    deps = [path for path in [
        current, previous,
        args.manager_build / "intermediates/javac/debug/compileDebugJavaWithJavac/classes",
        args.fallback_manager_build / "intermediates/javac/debug/compileDebugJavaWithJavac/classes",
        ROOT / ".tmp/p0-mode-a-tests/b2-wiring.jar", ROOT / ".tmp/p0-mode-a-tests/c-installer-classes",
    ] if path.exists()]
    deps += list(map(Path, inputs["libraries"]))
    deps = [cached_jar(*item) for item in [
        ("junit", "junit", "4.13.2"), ("org.hamcrest", "hamcrest-core", "1.3"),
        ("org.json", "json", "20240303"), ("org.jetbrains.kotlin", "kotlin-stdlib", "2.4.20"),
        ("org.jetbrains.kotlinx", "kotlinx-coroutines-core-jvm", "1.11.0")]] + deps
    production = [ROOT / "manager/src/main/java/dev/maplesu/manager" / name for name in [
        "ksu/KsuBootstrap.kt", "installer/InstallCommit.kt", "workmode/service/ModeSwitchFacade.kt",
        "workmode/service/ModeSwitchProgress.kt", "workmode/service/ModeSwitchClient.kt",
        "workmode/switch/ModeSwitchPreflight.kt", "workmode/switch/ModeSwitchTypes.kt",
        "installer/RootScriptInstallConfigMover.kt", "installer/InstallTargetPartition.kt",
        "workmode/service/ServiceResumeModeSwitchClient.kt"]]
    production += [ROOT / "manager/src/ksu/java/dev/maplesu/manager/ksu/KsuVersionInfo.kt"]
    sources = production + [ROOT / "manager/src/test/java/dev/maplesu/manager" / name for name in [
        "ksu/NormalBootUserlandTest.kt", "installer/InstallCommitCoordinatorTest.kt",
        "workmode/service/ModeSwitchFacadeTest.kt", "workmode/TestFixtures.kt",
        "installer/RootScriptInstallConfigMoverTest.kt"]]
    tests = ["dev.maplesu.manager.ksu.NormalBootUserlandTest",
             "dev.maplesu.manager.installer.InstallCommitCoordinatorTest",
             "dev.maplesu.manager.workmode.service.ModeSwitchFacadeTest",
             "dev.maplesu.manager.installer.RootScriptInstallConfigMoverTest"]
    compiler_deps = [cached_jar(*item) for item in [
        ("org.jetbrains.kotlin", "kotlin-compiler-embeddable", "2.4.20"),
        ("org.jetbrains.kotlin", "kotlin-stdlib", "2.4.20"), ("org.jetbrains", "annotations", "13.0"),
        ("org.jetbrains.kotlinx", "kotlinx-coroutines-core-jvm", "1.11.0")]]
    before = {path.relative_to(ROOT).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest() for path in sources}
    jar = out / "tests.jar"
    commands = [[java, "-Xmx768m", "-cp", os.pathsep.join(map(str, compiler_deps)),
                 "org.jetbrains.kotlin.cli.jvm.K2JVMCompiler", "-no-stdlib", "-no-reflect", "-jvm-target", "21",
                 "-Xfriend-paths=" + ",".join(str(p) for p in (current, previous) if p.is_dir()),
                 "-classpath", os.pathsep.join(map(str, deps)), "-d", str(jar), *map(str, sources)],
                [java, "-cp", os.pathsep.join(map(str, [jar] + deps)), "org.junit.runner.JUnitCore", *tests]]
    result = None
    count = None
    try:
        for index, command in enumerate(commands):
            result = subprocess.run(command, cwd=ROOT / "manager", capture_output=True,
                                    text=True, encoding="utf-8", errors="replace", timeout=120)
            log = result.stdout + result.stderr
            (out / ("compile.log" if index == 0 else "tests.log")).write_text(log, "utf-8")
            print(log)
            if index == 1:
                matched = re.search(r"OK \((\d+) tests?\)", log)
                count = int(matched.group(1)) if matched else None
            if result.returncode:
                break
    finally:
        after = {path.relative_to(ROOT).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest() for path in sources}
        unchanged = before == after
        passed = result is not None and result.returncode == 0 and unchanged and count is not None
        (out / "verification.json").write_text(json.dumps(dict(
            passed=passed,
            exitCode=None if result is None else result.returncode, testCount=count,
            sourcesUnchanged=unchanged, sourceSha256=before,
            sourceSha256Before=before, sourceSha256After=after,
            productionSources=[p.relative_to(ROOT).as_posix() for p in production], tests=tests,
            dependencyClasses=str(cached), compileInputs=str(args.compile_inputs),
            javaExecutable=java, hostBashFixtures=True,
            deviceTestsPerformed=False, partitionWrites=False, apkProduced=False,
        ), indent=2) + "\n", "utf-8")
    raise SystemExit(0 if passed else result.returncode if result is not None and result.returncode else 1)


if __name__ == "__main__":
    main()
