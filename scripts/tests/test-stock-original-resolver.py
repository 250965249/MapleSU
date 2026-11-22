"""Compile production stock-source/recovery code and run focused JVM regressions."""
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
    parser.add_argument("--typecheck-service", action="store_true")
    parser.add_argument("--manager-classes", type=Path)
    parser.add_argument("--manager-java-classes", type=Path)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    java = str(native_toolchain.jdk_tool("java"))
    java_source = ROOT / "image-core/src/main/java/dev/maplesu/image/LenovoAvbSigner.java"
    transaction_source = ROOT / "installer-core/src/main/java/dev/maplesu/installer/BlockDeviceTransaction.java"
    image_classes = out / "image-classes"
    image_classes.mkdir(exist_ok=True)
    javac = str(native_toolchain.jdk_tool("javac"))
    java_build = subprocess.run([javac, "-encoding", "UTF-8", "-cp", str(ROOT / "image-core/build/libs/image-core.jar"),
        "-d", str(image_classes), str(java_source), str(transaction_source)], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30)
    (out / "image-compile.log").write_text(java_build.stdout + java_build.stderr, encoding="utf-8")
    if java_build.returncode:
        print(java_build.stdout + java_build.stderr)
        raise SystemExit(java_build.returncode)
    dependencies = [cached_jar(*item) for item in [
        ("org.jetbrains.kotlin", "kotlin-stdlib", "2.4.20"),
        ("org.jetbrains", "annotations", "13.0"),
        ("org.jetbrains.kotlinx", "kotlinx-coroutines-core-jvm", "1.11.0"),
        ("org.jetbrains.kotlinx", "kotlinx-serialization-core-jvm", "1.11.0"),
        ("org.jetbrains.kotlinx", "kotlinx-serialization-json-jvm", "1.11.0"),
        ("junit", "junit", "4.13.2"), ("org.hamcrest", "hamcrest-core", "1.3"),
        ("org.json", "json", "20240303")]]
    classes = args.manager_classes or ROOT / "manager/build/intermediates/built_in_kotlinc/debug/compileDebugKotlin/classes"
    java_classes = args.manager_java_classes or (classes.parents[3] / "javac/debug/compileDebugJavaWithJavac/classes")
    dependencies += [image_classes, ROOT / "image-core/build/libs/image-core.jar", classes,
        native_toolchain.android_jar()]
    if args.typecheck_service:
        import zipfile
        cache = Path.home() / ".gradle/caches/modules-2/files-2.1/com.github.topjohnwu.libsu"
        for name in ["core", "service", "io", "nio"]:
            aar = next((cache / name / "6.0.0").glob("*/*.aar"))
            destination = out / ("libsu-" + name + ".jar")
            with zipfile.ZipFile(aar) as archive:
                destination.write_bytes(archive.read("classes.jar"))
            dependencies.append(destination)
        dependencies += [ROOT / "installer-core/build/libs/installer-core.jar",
            java_classes]
    compiler = cached_jar("org.jetbrains.kotlin", "kotlin-compiler-embeddable", "2.4.20")
    sources = sorted((ROOT / "manager/src/main/java/dev/maplesu/manager/ultrakernel").glob("*.kt"))
    installer = ROOT / "manager/src/main/java/dev/maplesu/manager/installer"
    sources += [installer / (name + ".kt") for name in [
        "InstallerSnapshot", "StockBackupResolver", "StockOriginalResolver", "StockRestoreTargets", "NativeInstallSequence"]]
    bootstrap_type_inputs = []
    if args.typecheck_service:
        sources += [installer / (name + ".kt") for name in [
            "InstallerPartitionReader", "NativeInstallTransaction", "InstallerPartitionService", "BaselineProvisioner", "NativeStockBaseline"]]
        # The native service retains the bootstrap's typed failure. Compile its
        # actual pure result/exception declarations without selecting root setup.
        bootstrap_source = ROOT / "manager/src/main/java/dev/maplesu/manager/ksu/KsuBootstrap.kt"
        bootstrap_text = bootstrap_source.read_text(encoding="utf-8-sig")
        types = bootstrap_text[bootstrap_text.index("\nclass KsuBootstrapFailure(") + 1:]
        bootstrap_fixture = out / "KsuBootstrapResultFixture.kt"
        bootstrap_fixture.write_text("package dev.maplesu.manager.ksu\n\n" + types, encoding="utf-8")
        sources.append(bootstrap_fixture)
        bootstrap_type_inputs.append(bootstrap_source)
    tests = ["StockOriginalResolverTest", "StockBackupResolverTest", "StockOriginalAvbTest",
        "StockRestoreTargetsTest", "NativeInstallSequenceTest"]
    if args.typecheck_service:
        tests += ["BaselineCaptureFirstTest", "NativeStockBaselineTest", "NativeInstallSourceExportContractTest"]
    sources += [ROOT / "manager/src/test/java/dev/maplesu/manager/installer" / (name + ".kt") for name in tests]
    jar = out / "tests.jar"
    classpath = os.pathsep.join(map(str, dependencies))
    build = subprocess.run([java, "-Xmx768m", "-cp", os.pathsep.join(map(str, [compiler] + dependencies)),
        "org.jetbrains.kotlin.cli.jvm.K2JVMCompiler", "-no-stdlib", "-no-reflect", "-jvm-target", "21",
        "-Xfriend-paths=" + str(classes), "-classpath", classpath, "-d", str(jar), *map(str, sources)],
        cwd=ROOT / "manager", capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120)
    (out / "compile.log").write_text(build.stdout + build.stderr, encoding="utf-8")
    if build.returncode:
        print(build.stdout + build.stderr)
        raise SystemExit(build.returncode)
    result = subprocess.run([java, "-Xmx768m", "-Dfile.encoding=UTF-8", "-cp", str(jar) + os.pathsep + classpath,
        "org.junit.runner.JUnitCore", *["dev.maplesu.manager.installer." + name for name in tests]],
        cwd=ROOT / "manager", capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=90)
    log = result.stdout + result.stderr
    (out / "regression.log").write_text(log, encoding="utf-8")
    record = dict(recordedAt=datetime.now(timezone.utc).isoformat(), passed=result.returncode == 0,
        exitCode=result.returncode, scope="Real product container, receipt/spec recovery and stock-source selection on host JVM",
        deviceAccess=False, partitionWrites=False,
        dependencyClasses=[str(classes.resolve()), str(java_classes.resolve())],
        sourceSha256={(p.relative_to(ROOT).as_posix() if p.is_relative_to(ROOT) else str(p)):
            hashlib.sha256(p.read_bytes()).hexdigest() for p in sources + [java_source, transaction_source, *bootstrap_type_inputs]})
    (out / "verification.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(log)
    raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
