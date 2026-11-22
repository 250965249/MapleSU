"""Compile real image-patch logic and run focused JVM caller/process tests without a device."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools/specgen"))
from specgen.product import cached_jar


def identity(path):
    data = path.read_bytes()
    return {"path": str(path), "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


PREVIEW_PORTS = '''package com.maplesu.core.ui.util
import java.io.File
import com.maplesu.core.ui.screen.install.UltraKernelGenerationPort
internal data class UltraKernelVariantInfo(val id:String,val label:String,val summary:String,val patches:Int,val experimental:Boolean,val isDefault:Boolean)
internal data class UltraKernelFacts(val release:String,val variants:List<UltraKernelVariantInfo> = emptyList(),val rejected:List<String> = emptyList(),val defaultId:String?=null,val stableCode:String="",val detail:String="",val knownReleases:List<String> = emptyList(),val series:String="",val assetRelease:String="")
internal object UltraKernelGeneration { val port = object: UltraKernelGenerationPort { override fun plan(boot:File?, release:String):UltraKernelGenerationPort.GenerationPlan = error("unused platform port") } }
internal fun ultraKernelFacts(release:String) = UltraKernelFacts(release)
internal fun ultraKernelReleaseOf(image:File):String = error("unused platform IO")
internal fun ultraKernelStableCode(error:Throwable):String = error.message.orEmpty()
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--java", type=Path, required=True)
    parser.add_argument("--image-core", type=Path, required=True)
    parser.add_argument("--installer-core", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    java, image, installer, output = (p.resolve() for p in (args.java, args.image_core, args.installer_core, args.output))
    output.mkdir(parents=True, exist_ok=False)
    std = cached_jar("org.jetbrains.kotlin", "kotlin-stdlib", "2.4.20")
    annotations = cached_jar("org.jetbrains", "annotations", "13.0")
    compiler = cached_jar("org.jetbrains.kotlin", "kotlin-compiler-embeddable", "2.4.20")
    coroutines = cached_jar("org.jetbrains.kotlinx", "kotlinx-coroutines-core-jvm", "1.11.0")
    junit = cached_jar("junit", "junit", "4.13.2")
    hamcrest = cached_jar("org.hamcrest", "hamcrest-core", "1.3")
    android = Path(os.environ["ANDROID_HOME"]) / "platforms/android-37.0/android.jar"
    json_jar = cached_jar("org.jetbrains.kotlinx", "kotlinx-serialization-json-jvm", "1.11.0")
    serialization = cached_jar("org.jetbrains.kotlinx", "kotlinx-serialization-core-jvm", "1.11.0")
    dependencies = [std, annotations, junit, hamcrest, image, installer, android, json_jar, serialization]
    compiler_cp = os.pathsep.join(map(str, [compiler, std, annotations, coroutines]))
    main = ROOT / "manager/src/main/java"
    ksu = ROOT / "manager/src/ksu/java/dev/maplesu/manager/ksu"
    tests = ROOT / "manager/src/test/java"
    ports = output / "PreviewPorts.kt"
    ports.write_text(PREVIEW_PORTS, encoding="utf-8")
    sources = [ports, main / "com/maplesu/core/ui/screen/install/InstallBootFlow.kt",
        main / "dev/maplesu/manager/installer/KsuKernelPreservation.kt",
        main / "dev/maplesu/manager/installer/KsuKmiMatrix.kt",
        main / "dev/maplesu/manager/installer/KsuModeInstallContract.kt",
        main / "dev/maplesu/manager/ksu/KsuInstallProducer.kt",
        main / "dev/maplesu/manager/ksu/KsuFileCommandRunner.kt"]
    sources += sorted((main / "dev/maplesu/manager/ultrakernel").glob("*.kt"))
    sources += [ksu / name for name in ("KsuCommandBackend.kt", "KsuSupport.kt", "KsuRootShell.kt", "KsuBootInfo.kt", "KsuSettingsFeature.kt")]
    sources += [tests / "com/maplesu/core/ui/screen/install" / name for name in
        ("InstallBootFlowSourceTargetTest.kt", "InstallBootFlowTest.kt")]
    sources += [tests / "dev/maplesu/manager/ksu" / name for name in
        ("KsuImageFixtures.kt", "KsuInstallProducerTest.kt", "KsuPatchProcessReceiptTest.kt", "KsuCommandConstructionTest.kt")]
    sources += [tests / "com/maplesu/core/ui/util/UltraKernelVariantChoiceTest.kt"]
    receipt = {"inputs": [identity(p) for p in sources + dependencies + [compiler, coroutines, java]],
        "platformBoundaryStubs": [str(ports)], "deviceBootTestPerformed": False, "partitionWrites": False, "steps": []}
    def run(command, name):
        result = subprocess.run(list(map(str, command)), cwd=ROOT, capture_output=True,
            text=True, encoding="utf-8", errors="replace")
        log = output / (name + ".log")
        log.write_text(result.stdout + result.stderr, encoding="utf-8")
        receipt["steps"].append({"command": list(map(str, command)), "exitCode": result.returncode, "log": identity(log)})
        print(name + " code=" + str(result.returncode), flush=True)
        if result.returncode:
            raise RuntimeError(log.read_text(encoding="utf-8"))
    try:
        classpath = os.pathsep.join(map(str, dependencies))
        jar = output / "caller-tests.jar"
        run([java, "-Xmx768m", "-cp", compiler_cp, "org.jetbrains.kotlin.cli.jvm.K2JVMCompiler",
            "-no-stdlib", "-no-reflect", "-jvm-target", "21", "-classpath", classpath,
            "-d", jar, *sources], "compile")
        run([java, "-Xmx768m", "-cp", str(jar) + os.pathsep + classpath, "org.junit.runner.JUnitCore",
            "com.maplesu.core.ui.screen.install.InstallBootFlowSourceTargetTest",
            "com.maplesu.core.ui.screen.install.InstallBootFlowTest",
            "dev.maplesu.manager.ksu.KsuInstallProducerTest",
            "dev.maplesu.manager.ksu.KsuPatchProcessReceiptTest",
            "dev.maplesu.manager.ksu.KsuCommandConstructionTest",
            "com.maplesu.core.ui.util.UltraKernelVariantChoiceTest"], "tests")
        receipt["compiledTests"] = identity(jar)
        receipt["inputsUnchanged"] = receipt["inputs"] == [identity(p) for p in sources + dependencies + [compiler, coroutines, java]]
        assert receipt["inputsUnchanged"]
        receipt["passed"] = True
    finally:
        (output / "execution.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
