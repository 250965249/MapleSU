"""Run the production host's portable symbol, metadata and hook regressions."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools/specgen"))
from specgen.product import cached_jar


def identity(path):
    path = Path(path).resolve()
    raw = path.read_bytes()
    return dict(path=str(path), bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-receipt", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--ngki-fixture", type=Path)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    scratch = out / "tmp"
    scratch.mkdir()
    host = json.loads(args.runtime_receipt.read_bytes())
    runtime = host["runtime"]
    inputs = [runtime["java"], runtime["jar"], *runtime["dependencies"],
              *runtime["buildDependencies"], *host["sources"], identity(__file__)]
    assert all(identity(row["path"]) == row for row in inputs), "HOST_INPUT_DRIFT"
    classes = ["UltraKernelCaveAllocatorTest", "UltraKernelRecipeTest", "UltraKernelStaticScsEntryTest",
               "UltraKernelHookSiteTest", "UltraKernelBootSafetyTest", "UltraKernelKallsymsLayoutTest",
               "UltraKernelExecveEntryTest", "UltraKernelShellcodeTest", "UltraKernelArchivedRecoveryTest",
               "UltraKernelOriginalRecoveryTest", "UltraKernelEmbeddedRecoveryTest", "UltraKernelRecoveryRecordTest",
               "UltraKernelGeneratedRecoveryTest", "UltraKernelSignedRecoveryTest", "UltraKernelRecoveryInvalidAvbTest",
               "UltraKernelLegacyMetadataFlowTest", "UltraKernelMetadataRebaseTest", "UltraKernelMetadataCredentialTest",
               "UltraKernelMetadataLocatorBoundsTest"]
    inputs.append(identity(ROOT / "Boot_Research/NGKI/boot.img"))
    inputs += [identity(ROOT / "Boot_Research" / path) for path in (
        "._boot/k70uboot.img", "._boot/maplesu-ultra-k70u-patched.img", "Jeannette/boot.img",
        "Jeannette/maplesu-ultra-patched-fixed.img", "Jeannette/maplesu-ultra-patched.img",
        "\u7c0c/boot.img", "\u7c0c/XiaoMi_15_Ultra_Patch2.img")]
    inputs += [identity(path) for path in sorted((ROOT / "manager/src/main/assets/ultra-kernels").rglob("*"))
               if path.is_file()]
    if args.ngki_fixture:
        classes.append("UltraKernelKallsymsNgkiTest")
        inputs += [identity(args.ngki_fixture / name) for name in (
            "target-5.4-kallsyms.zlib", "target-5.4-header.bin", "target-5.4-oracle.tsv.zlib")]
    paths = [ROOT / "manager/src/test/java/dev/maplesu/manager/ultrakernel" / (name + ".kt")
             for name in ["UltraKernelPlanFixtures", *classes]]
    sources = [identity(path) for path in paths]
    snapshots = []
    for path in paths:
        target = out / "source" / path.name
        target.parent.mkdir(exist_ok=True)
        target.write_bytes(path.read_bytes())
        snapshots.append(target)
    runner = out / "source/PortableKernelTestMain.kt"
    runner.write_text('''package dev.maplesu.manager.ultrakernel
import org.junit.runner.JUnitCore
import org.junit.runner.notification.Failure
import org.junit.runner.notification.RunListener
fun main(args: Array<String>) {
    var assumptions = 0
    val core = JUnitCore()
    core.addListener(object : RunListener() {
        override fun testAssumptionFailure(failure: Failure) {
            assumptions++
            println("ASSUMPTION_SKIPPED ${failure.description}")
        }
    })
    val result = core.run(*args.map { Class.forName(it) }.toTypedArray())
    result.failures.forEach { println(it.trace) }
    println("JUNIT_SUMMARY run=${result.runCount} ignored=${result.ignoreCount} assumptions=$assumptions failures=${result.failureCount}")
    println(if (result.wasSuccessful()) "OK (${result.runCount} tests)" else "FAILURES!!!")
    kotlin.system.exitProcess(if (result.wasSuccessful()) 0 else 1)
}
''', encoding="utf-8")
    snapshots.append(runner)
    junit = cached_jar("junit", "junit", "4.13.2")
    hamcrest = cached_jar("org.hamcrest", "hamcrest-core", "1.3")
    inputs += [identity(junit), identity(hamcrest)]
    compiler = cached_jar("org.jetbrains.kotlin", "kotlin-compiler-embeddable", "2.4.20")
    coroutines = cached_jar("org.jetbrains.kotlinx", "kotlinx-coroutines-core-jvm", "1.11.0")
    boot = os.pathsep.join(map(str, [compiler, *runtime["classpath"].split(os.pathsep)[:2], coroutines]))
    cp = os.pathsep.join([runtime["jar"]["path"], runtime["classpath"], str(junit), str(hamcrest)])
    java, jar = runtime["java"]["path"], out / "tests.jar"
    commands = [("compile", [java, "-Dfile.encoding=UTF-8", "-Djava.io.tmpdir=" + str(scratch), "-Xmx768m", "-cp", boot,
        "org.jetbrains.kotlin.cli.jvm.K2JVMCompiler", "-no-stdlib", "-no-reflect", "-jvm-target", "17",
        "-Xfriend-paths=" + runtime["jar"]["path"], "-classpath", cp, "-d", str(jar), *map(str, snapshots)]),
        ("tests", [java, "-Dfile.encoding=UTF-8", "-Djava.io.tmpdir=" + str(scratch), "-Xmx768m", "-Dmaplesu.repo=" + str(ROOT),
        "-Dmaplesu.ngki.fixture=" + str(args.ngki_fixture.resolve() if args.ngki_fixture else ""),
        "-cp", str(jar) + os.pathsep + cp, "dev.maplesu.manager.ultrakernel.PortableKernelTestMainKt",
        *["dev.maplesu.manager.ultrakernel." + name for name in classes]])]
    receipt = dict(runtimeReceipt=identity(args.runtime_receipt), runtime=runtime, inputs=inputs,
                   sources=sources, classes=classes, commands=[], deviceTest=False, partitionWrites=False)
    for label, command in commands:
        result = subprocess.run(command, cwd=ROOT / "manager", stdin=subprocess.DEVNULL, capture_output=True)
        (out / (label + ".log")).write_bytes(result.stdout + result.stderr)
        receipt["commands"].append(dict(label=label, argv=command, exitCode=result.returncode))
        print((result.stdout + result.stderr).decode("utf-8", "replace"), flush=True)
        if result.returncode:
            break
    summary = re.search(rb"JUNIT_SUMMARY run=(\d+) ignored=(\d+) assumptions=(\d+) failures=(\d+)", result.stdout)
    if summary:
        receipt["junitSummary"] = dict(zip(("run", "ignored", "assumptions", "failures"), map(int, summary.groups())))
    receipt["inputsUnchanged"] = all(identity(row["path"]) == row for row in inputs + sources)
    receipt["exitCode"] = result.returncode or (0 if receipt["inputsUnchanged"] else 2)
    (out / "receipt.json").write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return receipt["exitCode"]


if __name__ == "__main__":
    raise SystemExit(main())
