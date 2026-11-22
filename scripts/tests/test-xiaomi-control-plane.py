"""Compile the changed manager sources and replay the SDK stdout/exit contract."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
import native_toolchain  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools/specgen"))
from specgen.product import cached_jar


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    classes = ROOT / "manager/build/intermediates/built_in_kotlinc/debug/compileDebugKotlin/classes"
    javac = ROOT / "manager/build/intermediates/javac/debug/compileDebugJavaWithJavac/classes"
    assert classes.is_dir() and javac.is_dir()
    java = native_toolchain.jdk_tool("java")
    deps = [cached_jar(*item) for item in [
        ("org.jetbrains.kotlin", "kotlin-stdlib", "2.4.20"), ("org.jetbrains", "annotations", "13.0"),
        ("org.jetbrains.kotlinx", "kotlinx-coroutines-core-jvm", "1.11.0"),
        ("org.jetbrains.kotlinx", "kotlinx-serialization-core-jvm", "1.11.0"),
        ("org.jetbrains.kotlinx", "kotlinx-serialization-json-jvm", "1.11.0"),
        ("junit", "junit", "4.13.2"), ("org.hamcrest", "hamcrest-core", "1.3"),
        ("org.json", "json", "20240303")]]
    deps.append(native_toolchain.android_jar())
    deps.append(ROOT / "manager/build/intermediates/compile_and_runtime_r_class_jar/debug/processDebugResources/R.jar")
    compiler = cached_jar("org.jetbrains.kotlin", "kotlin-compiler-embeddable", "2.4.20")
    serialization = cached_jar("org.jetbrains.kotlin", "kotlin-serialization-compiler-plugin-embeddable", "2.4.20")
    main_base = ROOT / "manager/src/main/java/dev/maplesu/manager"
    production = [main_base / name for name in [
        "runtime/UltraRootCommandReceipt.kt", "runtime/RootExecutionRouter.kt", "runtime/RootServiceBootstrap.kt",
        "runtime/ultra/UltraPolicyBackendDeployment.kt", "runtime/ultra/UltraPolicyBackendArtifact.kt",
        "runtime/ultra/UltraSuChannel.kt", "runtime/ultra/UltraReceipt.kt",
        "runtime/ultra/UltraEnvironmentInstaller.kt", "runtime/ultra/UltraSdkSession.kt", "runtime/ultra/UltraBootSdkSession.kt", "runtime/ultra/UltraBootSdkGateway.kt",
        "runtime/ultra/UltraEnvironmentAutoSetup.kt", "runtime/ultra/UltraAutoSetupAttempt.kt",
        "workmode/service/ModeSwitchClient.kt", "workmode/service/UltraRootModeSwitchClient.kt",
        "workmode/service/SelectingModeSwitchClient.kt", "workmode/service/ModeSwitchRootProtocol.kt",
        "modules/ModuleToolDeployment.kt", "modules/UltraModulePolicyState.kt"]]
    production.append(ROOT / "manager/src/main/java/com/maplesu/core/ui/screen/settings/UltraModulePolicyStatus.kt")
    tests = ["runtime.UltraRootCommandReceiptTest", "runtime.ultra.UltraPolicyBackendDeploymentTest",
        "modules.UltraModulePolicyStateTest", "modules.ModuleToolDeploymentPublicationTest",
        "runtime.RootServiceBootstrapTest", "workmode.service.UltraRootModeSwitchClientTest",
        "workmode.service.ModeSwitchRootSessionTest", "runtime.ultra.UltraPolicyBackendInstallTest"]
    sources = production + [ROOT / "manager/src/test/java/dev/maplesu/manager" /
        (name.replace(".", "/") + ".kt") for name in tests]
    inputs = sources + [ROOT / name for name in [
        "runtime/ultra/policy/backend_publish.cpp", "runtime/ultra/policy/backend_publish.h",
        "runtime/ultra/upgrade/executable_publish.cpp", "runtime/ultra/upgrade/executable_publish.h",
        "runtime/tests/policy_backend_preparation_test.cpp"]]
    digests = {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs}
    cp = os.pathsep.join(map(str, [out, classes, javac] + deps))
    commands = [[str(java), "-Xmx512m", "-cp", os.pathsep.join(map(str, [compiler] + deps)),
        "org.jetbrains.kotlin.cli.jvm.K2JVMCompiler", "-no-stdlib", "-no-reflect", "-jvm-target", "21",
        "-Xplugin=" + str(serialization),
        "-Xfriend-paths=" + str(classes), "-classpath", cp, "-d", str(out), *map(str, sources)],
        [str(java), "-Dfile.encoding=UTF-8", "-cp", cp, "org.junit.runner.JUnitCore",
         *["dev.maplesu.manager." + name for name in tests]]]
    logs = []
    for command in commands:
        result = subprocess.run(command, cwd=ROOT / "manager", capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=55)
        logs.append(result.stdout + result.stderr)
        if result.returncode:
            break
    output = "\n".join(logs)
    (out / "regression.log").write_text(output, encoding="utf-8")
    unchanged = digests == {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs}
    record = dict(passed=result.returncode == 0 and unchanged, recordedAt=datetime.now(timezone.utc).isoformat(),
        exitCode=result.returncode,
        sourceSha256=digests, inputsUnchanged=unchanged,
        deviceAccess=False, scope="Fresh production sources; Android runtime and native SDK transport are boundaries")
    (out / "verification.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(output)
    raise SystemExit(result.returncode if unchanged else 1)


if __name__ == "__main__":
    main()
