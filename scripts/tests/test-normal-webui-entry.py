"""Compile Normal WebUI entry gates and run cold-start and explicit-open regressions."""
import argparse
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
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--compile-dispatcher", action="store_true",
                        help="also compile the Compose dispatcher against cached Manager dependencies")
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    java = shutil.which("java")
    if not java:
        parser.error("Java 21 is required")
    dependencies = [cached_jar(*item) for item in [
        ("org.jetbrains.kotlin", "kotlin-stdlib", "2.4.20"),
        ("org.jetbrains", "annotations", "13.0"),
        ("org.jetbrains.kotlinx", "kotlinx-coroutines-core-jvm", "1.11.0"),
        ("junit", "junit", "4.13.2"), ("org.hamcrest", "hamcrest-core", "1.3")]]
    compiler = cached_jar("org.jetbrains.kotlin", "kotlin-compiler-embeddable", "2.4.20")
    package = "com/maplesu/core/ui/navigation3"
    sources = [ROOT / "manager/src/main/java" / package / (name + ".kt")
               for name in ["IntentManagerReadiness", "WebUiOpenPolicy"]]
    tests = ["IntentManagerReadinessTest", "WebUiOpenPolicyTest"]
    sources += [ROOT / "manager/src/test/java" / package / (name + ".kt") for name in tests]
    jar = out / "tests.jar"
    classpath = os.pathsep.join(map(str, dependencies))
    commands = [
        [java, "-Xmx768m", "-cp", os.pathsep.join(map(str, [compiler] + dependencies)),
         "org.jetbrains.kotlin.cli.jvm.K2JVMCompiler", "-no-stdlib", "-no-reflect", "-jvm-target", "21",
         "-classpath", classpath, "-d", str(jar), *map(str, sources)],
        [java, "-cp", str(jar) + os.pathsep + classpath, "org.junit.runner.JUnitCore",
         *[package.replace("/", ".") + "." + name for name in tests]],
    ]
    logs = ["compile.log", "tests.log"]
    if args.compile_dispatcher:
        inputs = json.loads((ROOT / ".tmp/p0-mode-a-tests/compile-inputs.json").read_text(encoding="utf-8"))
        build = ROOT / ".tmp/p1-delivery-r7/gradle-build/manager"
        cached = build / "intermediates/built_in_kotlinc/debug/compileDebugKotlin/classes"
        dispatcher = ROOT / "manager/src/main/java" / package / "IntentDispatcher.kt"
        deps = [ROOT / ".tmp/normal-ksu-gradle/manager/intermediates/compile_and_runtime_r_class_jar/debug/processDebugResources/R.jar",
                cached, build / "intermediates/javac/debug/compileDebugJavaWithJavac/classes",
                ROOT / ".tmp/p0-mode-a-tests/b2-wiring.jar",
                ROOT / ".tmp/p0-mode-a-tests/c-installer-classes", *map(Path, inputs["libraries"])]
        commands.insert(0, [java, "-Xmx768m", "-cp", os.pathsep.join(map(str, [compiler] + dependencies)),
            "org.jetbrains.kotlin.cli.jvm.K2JVMCompiler", "-no-stdlib", "-no-reflect", "-jvm-target", "21",
            "-Xfriend-paths=" + str(cached), "-classpath", os.pathsep.join(map(str, deps)),
            "-d", str(out / "dispatcher.jar"),
            *("-Xplugin=" + p for p in inputs["pluginClasspath"][:3]), str(sources[0]), str(dispatcher)])
        logs.insert(0, "dispatcher-compile.log")
        sources.append(dispatcher)
    digests = {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in sources}
    for name, command in zip(logs, commands):
        result = subprocess.run(command, cwd=ROOT / "manager", capture_output=True,
                                text=True, encoding="utf-8", errors="replace", timeout=120)
        log = result.stdout + result.stderr
        (out / name).write_text(log, encoding="utf-8")
        print(log)
        if result.returncode:
            break
    unchanged = digests == {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                            for p in sources}
    (out / "verification.json").write_text(json.dumps(dict(
        passed=result.returncode == 0 and unchanged, exitCode=result.returncode,
        sourcesUnchanged=unchanged, sourceSha256=digests, tests=tests,
        deviceTestsPerformed=False, moduleScriptsExecuted=False, partitionWrites=False,
    ), indent=2) + "\n", encoding="utf-8")
    raise SystemExit(result.returncode if unchanged else 1)


if __name__ == "__main__":
    main()
