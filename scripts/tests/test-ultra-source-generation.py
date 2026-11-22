"""Exercise source generation, default flow and retained-image recovery on a real boot image."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools/specgen"))
from specgen import bootimg
from specgen.product import cached_jar


def identity(path):
    return {"path": str(path.relative_to(ROOT)) if path.is_relative_to(ROOT) else str(path),
            "bytes": path.stat().st_size, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


def run(command, output, env):
    started = time.monotonic()
    result = subprocess.run(list(map(str, command)), cwd=ROOT, env=env,
                            capture_output=True, text=True, encoding="utf-8", errors="replace")
    output.write_text(result.stdout + result.stderr, encoding="utf-8")
    return {"command": list(map(str, command)), "exitCode": result.returncode,
            "elapsedSeconds": time.monotonic() - started, "log": str(output)}


HARNESS = r'''package dev.maplesu.manager.ultrakernel
import java.io.File
import kotlinx.serialization.json.*

private class CountedAssets(private val files: Map<String, ByteArray>) : UltraKernelAssetSource {
    private val delegate = UltraKernelMemoryAssets(files)
    var lists = 0
    var reads = 0
    override fun list(directory: String): List<String> { lists++; return delegate.list(directory) }
    override fun read(path: String): ByteArray { reads++; return delegate.read(path) }
}

fun main(args: Array<String>) {
    val boot = File(args[0])
    val output = File(args[1])
    val host = Json.parseToJsonElement(File(output, "receipt.json").readText()).jsonObject
    val bootHash = UltraKernelSpec.sha256(boot)
    val raw = UltraKernelPlan.readKernel(boot)
    val credential = UltraKernelCredential.of("Aa1".repeat(16))
    val plan = UltraKernelSpecGenerator().generate(raw, credential)
    val applied = plan.apply(raw)
    check(plan.layout.fields.size == 6)
    check(plan.withDerived(applied.derived).layout === plan.layout)
    check(plan.withSlots(plan.slots).layout === plan.layout)
    check(plan.rebind(UltraKernelCredential.of("Bb2".repeat(16))).layout === plan.layout)
    check(UltraKernelPlan.planFor(raw, credential, plan).layout === plan.layout)
    check(UltraKernelPlan.fromSpec(UltraKernelSpec.parse(plan.specText(plan.credential)),
        credential = plan.credential).layout.fields.isEmpty())
    check(plan.specText(plan.credential) == File(output, "patch.spec").readText())
    plan.layout.fields.forEach { (name, field) ->
        val emitted = host.getValue("layout").jsonObject.getValue("fields").jsonObject.getValue(name).jsonObject
        check(emitted.getValue("offsetBytes").jsonPrimitive.int == field.offsetBytes)
        check(emitted.getValue("widthBytes").jsonPrimitive.int == field.widthBytes)
        check(emitted.getValue("ownerSizeBytes").jsonPrimitive.intOrNull == field.ownerSizeBytes)
        check(emitted.getValue("source").jsonPrimitive.content == field.source)
        check(emitted.getValue("parserVersion").jsonPrimitive.int == field.parserVersion)
    }
    val manifest = File("manager/src/main/assets/ultra-kernels/manifest.json").readText()
    val release = plan.kernelRelease
    val variants = linkedMapOf(
        "empty-catalog" to emptyMap<String, ByteArray>(),
        "missing-default" to mapOf("ultra-kernels/manifest.json" to
            manifest.replace("\"default\": true", "\"default\": false").toByteArray()),
        "broken-declared-recommendation" to mapOf(
            "ultra-kernels/manifest.json" to manifest.toByteArray(),
            "ultra-kernels/releases/$release/meta.json" to "{".toByteArray(),
            "ultra-kernels/k22-ultra-6.6.89.spec" to "invalid".toByteArray()),
    )
    val cases = buildJsonArray {
        variants.entries.forEachIndexed { index, (name, files) ->
            val selector = listOf<String?>(null, "generated", UltraKernelSpecGenerator().recipeId)[index]
            val work = File(output, "flow-$name")
            check(!work.exists())
            val source = CountedAssets(files)
            val flow = UltraKernelFlow(work, source)
            val notices = mutableListOf<String>()
            try {
                val prepared = flow.prepareTarget(boot, credential, selector, notices::add)
                val candidate = requireNotNull(prepared.candidate)
                check(!prepared.alreadyInstalled)
                check(prepared.planOrigin == "GENERATED")
                check(UltraKernelPlan.readKernel(candidate.image).contentEquals(applied.kernel))
                check(candidate.bootSha256 == host.getValue("patchedBootSha256").jsonPrimitive.content)
                repeat(2) {
                    val repeated = flow.prepareTarget(candidate.image, requireNotNull(prepared.credential), selector, notices::add)
                    check(repeated.alreadyInstalled && repeated.candidate == null)
                }
                check(source.lists == 0 && source.reads == 0)
                check(UltraKernelSpec.sha256(boot) == bootHash)
                add(buildJsonObject {
                    put("case", name); put("passed", true)
                    put("variantId", selector?.let(::JsonPrimitive) ?: JsonNull)
                    put("assetLists", source.lists); put("assetReads", source.reads)
                    put("candidateBootSha256", candidate.bootSha256)
                    put("candidateKernelSha256", candidate.kernelSha256)
                    put("retainedRepairs", 2); put("sourceUnchanged", true)
                    put("notices", buildJsonArray { notices.forEach { add(it) } })
                })
            } finally { check(work.deleteRecursively()) }
        }
    }
    val legacy = CountedAssets(emptyMap())
    check(runCatching { UltraKernelFlow(File(output, "legacy"), legacy).prepare(boot, null) }.isFailure)
    check(legacy.lists + legacy.reads > 0)
    File(output, "flow-receipt.json").writeText(buildJsonObject {
        put("cases", cases); put("layoutPreservedAcrossPlanCopies", true)
        put("legacySpecHasNoInferredLayout", true); put("nullCredentialRetainsAssetPath", true)
        put("deviceBootTestPerformed", false); put("partitionWrites", false)
    }.toString() + "\n")
    println("SOURCE_FLOW_E2E_OK cases=${variants.size} retainedRepairs=6 layoutFields=${plan.layout.fields.size}")
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--boot", type=Path, required=True)
    parser.add_argument("--image-core", type=Path, required=True)
    parser.add_argument("--java", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    boot, image, java, output = (p.resolve() for p in
        (args.boot, args.image_core, args.java, args.output))
    if output.exists():
        raise RuntimeError("TEST_OUTPUT_EXISTS")
    output.mkdir(parents=True)
    env = dict(os.environ)
    sources = sorted((ROOT / "manager/src/main/java/dev/maplesu/manager/ultrakernel").glob("*.kt"))
    sources += [ROOT / "tools/specgen/HostMain.kt"]
    dependencies = [cached_jar("org.jetbrains.kotlin", "kotlin-stdlib", "2.4.20"),
        cached_jar("org.jetbrains", "annotations", "13.0"),
        cached_jar("org.jetbrains.kotlinx", "kotlinx-serialization-json-jvm", "1.11.0"),
        cached_jar("org.jetbrains.kotlinx", "kotlinx-serialization-core-jvm", "1.11.0"),
        image, Path(env["ANDROID_HOME"]) / "platforms/android-37.0/android.jar"]
    compiler = cached_jar("org.jetbrains.kotlin", "kotlin-compiler-embeddable", "2.4.20")
    coroutines = cached_jar("org.jetbrains.kotlinx", "kotlinx-coroutines-core-jvm", "1.11.0")
    inputs = [identity(p) for p in [boot, java] + sources + dependencies + [compiler, coroutines]]
    execution = {"inputs": inputs, "deviceBootTestPerformed": False, "partitionWrites": False, "steps": []}
    try:
        credential = output / "synthetic-credential.txt"
        credential.write_text("Aa1" * 16 + "\n", encoding="ascii")
        command = [sys.executable, ROOT / "tools/specgen/make_spec.py", "--boot", boot,
            "--credential-file", credential, "--image-core", image, "--java", java,
            "--out", output / "patch.spec", "--receipt", output / "receipt.json",
            "--patched-boot", output / "patched-boot.img"]
        step = run(command, output / "product.log", env)
        execution["steps"].append(step)
        assert step["exitCode"] == 0, (output / "product.log").read_text()
        raw = bootimg.kernel(boot)
        patched = bootimg.kernel(output / "patched-boot.img")
        expected, covered = bytearray(raw), bytearray(len(raw))
        records = 0
        for line in (output / "patch.spec").read_text().splitlines():
            if not line or line.startswith("#"):
                continue
            offset, original, replacement = line.split("|")
            offset, original, replacement = int(offset), bytes.fromhex(original), bytes.fromhex(replacement)
            assert len(original) == len(replacement) and raw[offset:offset + len(original)] == original
            assert offset >= 0 and offset + len(replacement) <= len(raw)
            expected[offset:offset + len(replacement)] = replacement
            covered[offset:offset + len(replacement)] = b"\1" * len(replacement)
            records += 1
        assert patched == expected
        outside = sum(a != b and not c for a, b, c in zip(raw, patched, covered))
        assert outside == 0
        execution["independentReadback"] = {"records": records, "outsideSites": outside,
            "patchedBoot": identity(output / "patched-boot.img"),
            "patchedKernelSha256": hashlib.sha256(patched).hexdigest()}
        (output / "patched-boot.img").unlink()
        del raw, patched, expected, covered
        fingerprint = hashlib.sha256()
        for path in sources + dependencies + [compiler, coroutines]:
            fingerprint.update(str(path).encode()); fingerprint.update(path.read_bytes())
        product = ROOT / ".tmp/specgen-product" / (fingerprint.hexdigest() + ".jar")
        assert product.is_file()
        harness = output / "SourceFlowMain.kt"
        harness.write_text(HARNESS, encoding="utf-8")
        junit = cached_jar("junit", "junit", "4.13.2")
        hamcrest = cached_jar("org.hamcrest", "hamcrest-core", "1.3")
        classpath = os.pathsep.join(map(str, [product] + dependencies + [junit, hamcrest]))
        compiler_cp = os.pathsep.join(map(str, [compiler, dependencies[0], dependencies[1], coroutines]))
        tests = ROOT / "manager/src/test/java/dev/maplesu/manager/ultrakernel/UltraKernelGeneratedRecoveryTest.kt"
        step = run([java, "-Xmx768m", "-cp", compiler_cp,
            "org.jetbrains.kotlin.cli.jvm.K2JVMCompiler", "-no-stdlib", "-no-reflect", "-jvm-target", "21",
            "-classpath", classpath, "-Xfriend-paths=" + str(product), "-d", output / "flow-tests.jar",
            harness, tests], output / "compile-tests.log", env)
        execution["steps"].append(step)
        assert step["exitCode"] == 0, (output / "compile-tests.log").read_text()
        runtime = str(output / "flow-tests.jar") + os.pathsep + classpath
        for name, main_class, extra in [
            ("flow", "dev.maplesu.manager.ultrakernel.SourceFlowMainKt", [boot, output]),
            ("recovery-tests", "org.junit.runner.JUnitCore", ["dev.maplesu.manager.ultrakernel.UltraKernelGeneratedRecoveryTest"]),
        ]:
            step = run([java, "-Xmx768m", "-cp", runtime, main_class, *extra], output / (name + ".log"), env)
            execution["steps"].append(step)
            assert step["exitCode"] == 0, (output / (name + ".log")).read_text()
        execution["compiledProduct"] = identity(product)
        execution["sourceInputsUnchanged"] = inputs == [identity(p) for p in
            [boot, java] + sources + dependencies + [compiler, coroutines]]
        assert execution["sourceInputsUnchanged"]
        execution["passed"] = True
        print("SOURCE_GENERATION_E2E_OK " + str(output))
    finally:
        (output / "execution.json").write_text(json.dumps(execution, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
