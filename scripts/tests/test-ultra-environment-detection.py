"""Compile the real detector/startup sources and verify the persisted home verdict."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import zipfile
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
    java = native_toolchain.jdk_tool("java")
    classes = ROOT / "manager/build/intermediates/built_in_kotlinc/debug/compileDebugKotlin/classes"
    javac = ROOT / "manager/build/intermediates/javac/debug/compileDebugJavaWithJavac/classes"
    deps = [cached_jar(*item) for item in [
        ("org.jetbrains.kotlin", "kotlin-stdlib", "2.4.20"), ("org.jetbrains", "annotations", "13.0"),
        ("org.jetbrains.kotlinx", "kotlinx-coroutines-core-jvm", "1.11.0"),
        ("org.jetbrains.kotlinx", "kotlinx-serialization-core-jvm", "1.11.0"),
        ("org.jetbrains.kotlinx", "kotlinx-serialization-json-jvm", "1.11.0"),
        ("junit", "junit", "4.13.2"), ("org.hamcrest", "hamcrest-core", "1.3"),
        ("org.json", "json", "20240303")]]
    deps.append(native_toolchain.android_jar())
    cache = Path(os.environ.get("GRADLE_USER_HOME", Path.home() / ".gradle"))
    core = next((cache / "caches/modules-2/files-2.1/com.github.topjohnwu.libsu/core/6.0.0").glob("*/*.aar"))
    libsu = out / "libsu-core.jar"
    with zipfile.ZipFile(core) as archive:
        libsu.write_bytes(archive.read("classes.jar"))
    deps.append(libsu)
    annotation = next((cache / "caches/modules-2/files-2.1/androidx.compose.runtime/runtime-annotation-android").glob("*/*/*.aar"))
    compose = out / "compose-runtime-annotation.jar"
    with zipfile.ZipFile(annotation) as archive:
        compose.write_bytes(archive.read("classes.jar"))
    deps.append(compose)
    serialization = cached_jar("org.jetbrains.kotlin", "kotlin-serialization-compiler-plugin-embeddable", "2.4.20")
    compiler = cached_jar("org.jetbrains.kotlin", "kotlin-compiler-embeddable", "2.4.20")
    main = ROOT / "manager/src/main/java/dev/maplesu/manager/workmode"
    tests = ["boot.UltraStartupRegressionTest", "boot.ModeBootstrapDeadlineTest", "boot.ModeBootstrapPipelineTest", "boot.ModeBootstrapCoordinatorTest",
             "detect.KsuProbeTraceTest", "detect.SuReadinessCacheTest", "detect.SuReadinessTest",
             "detect.ModeRecognitionMatrixTest", "detect.NormalRebootRecognitionTest", "detect.EnvironmentInheritanceTest", "detect.EnvironmentDetectionProjectionTest",
             "detect.UltraColdStartDetectorTest", "detect.ModeDetectionRulesTest"]
    sources = [*sorted((main / "detect").glob("*.kt")),
               main / "boot/ModeBootstrapPipeline.kt", main / "boot/ModeBootstrapCoordinator.kt",
               ROOT / "manager/src/test/java/dev/maplesu/manager/workmode/TestFixtures.kt",
               *[ROOT / "manager/src/test/java/dev/maplesu/manager/workmode" /
                 (name.replace(".", "/") + ".kt") for name in tests]]
    base = ROOT / "manager/src/main/java/dev/maplesu/manager"
    sources += [base / name for name in [
        "runtime/ultra/UltraEnvironmentProbe.kt", "runtime/ultra/UltraSdkSession.kt", "runtime/ultra/UltraBootSdkSession.kt", "runtime/ultra/UltraBootSdkGateway.kt", "runtime/ultra/UltraEnvironmentAutoSetup.kt", "runtime/ultra/UltraReadinessRules.kt", "runtime/HookRootExecutor.kt",
        "workmode/detect/probes/KsuKernelProbeAdapter.kt",
        "workmode/superuser/AndroidSuperuserPorts.kt", "workmode/superuser/KsuSuperuserBackend.kt",
        "runtime/RootExecutionRouter.kt", "runtime/UltraRootCommandReceipt.kt",
        "runtime/ultra/UltraAuthorization.kt", "runtime/ultra/UltraAuthorizationState.kt",
        "workmode/switch/UltraEnvSwitchPolicy.kt", "workmode/service/ProductionUltraEnvironmentPort.kt", "runtime/ultra/UltraAutoPair.kt", "runtime/ultra/UltraIdentityResolution.kt", "runtime/ultra/UltraAutoSetupAttempt.kt",
        "workmode/control/schema/ModesFile.kt",
        "workmode/detect/probes/UltraEnvironmentAdapter.kt", "workmode/detect/probes/EnvironmentProbesAdapter.kt",
        "workmode/detect/probes/RootEvidenceReaderAdapter.kt", "workmode/detect/probes/UltraRootShellSession.kt"]]
    sources += [ROOT / "manager/src/main/java/com/maplesu/core" / name for name in [
        "ui/util/SELinuxChecker.kt", "ui/screen/home/HomeUiState.kt"]]
    sources += [ROOT / "manager/src/test/java/dev/maplesu/manager/workmode/superuser/SuperuserTestFixtures.kt"]
    extra_tests = ["workmode.switch.UltraEnvSwitchPolicyTest", "workmode.superuser.ModeSuperuserBackendsTest",
        "workmode.superuser.SuperuserBackendsTest", "runtime.HookRootExecutorTest",
        "workmode.detect.probes.KsuProbeMappingTest", "runtime.ultra.UltraRuntimeClientReadinessTest",
        "runtime.RootExecutionRouterTest", "runtime.UltraRootCommandReceiptTest",
        "runtime.ultra.UltraAuthorizationStateTest", "runtime.ultra.UltraStartupWarmupTest","runtime.ultra.UltraKernelPairingRegressionTest", "runtime.ultra.UltraIdentityMatrixTest", "runtime.ultra.UltraIdentityResolutionTest", "runtime.ultra.UltraRecoveryFingerprintTest", "runtime.ultra.UltraProbeAdmissionTest",
        "runtime.ultra.UltraProbeRecoveryTest", "runtime.ultra.UltraAutoSetupAttemptTest",
        "runtime.ultra.UltraFaultRecoveryTest", "runtime.ultra.UltraEnvironmentInstallReadinessTest",
        "runtime.ultra.UltraEnvironmentInstallWiringTest", "installer.UltraDirectInstallPolicyTest",
        "workmode.detect.probes.UltraRootEvidenceWiringTest", "workmode.detect.probes.UltraRootShellSessionTest",
        "workmode.detect.probes.UltraRootSnapshotTest"]
    sources += [ROOT / "manager/src/test/java/dev/maplesu/manager" /
                (name.replace(".", "/") + ".kt") for name in extra_tests]
    digests = {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in sources}
    cp = os.pathsep.join(map(str, [out, classes, javac] + deps))
    commands = [[str(java), "-Xmx768m", "-cp", os.pathsep.join(map(str, [compiler] + deps)),
                 "org.jetbrains.kotlin.cli.jvm.K2JVMCompiler", "-no-stdlib", "-no-reflect", "-jvm-target", "21",
                 "-Xplugin=" + str(serialization), "-Xfriend-paths=" + str(classes), "-classpath", cp, "-d", str(out), *map(str, sources)],
                [str(java), "-Dfile.encoding=UTF-8", "-cp", cp, "org.junit.runner.JUnitCore",
                 *["dev.maplesu.manager.workmode." + name for name in tests],
                 *["dev.maplesu.manager." + name for name in extra_tests]]]
    logs = []
    for command in commands:
        result = subprocess.run(command, cwd=ROOT / "manager", capture_output=True,
                                text=True, encoding="utf-8", errors="replace", timeout=90)
        logs.append(result.stdout + result.stderr)
        if result.returncode:
            break
    output = "\n".join(logs)
    (out / "regression.log").write_text(output, encoding="utf-8")
    unchanged = digests == {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in sources}
    (out / "verification.json").write_text(json.dumps(dict(
        passed=result.returncode == 0 and unchanged, exitCode=result.returncode, deviceAccess=False,
        inputsUnchanged=unchanged, sources=digests,
    ), indent=2) + "\n", encoding="utf-8")
    print(output)
    raise SystemExit(result.returncode if unchanged else 1)


if __name__ == "__main__":
    main()
