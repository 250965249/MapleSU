"""Observe the real prepareTarget entry on historical images without changing production."""
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
from specgen.product import cached_jar


HARNESS = r'''package dev.maplesu.manager.ultrakernel
import java.io.File
import kotlinx.serialization.json.*

private fun facts(file: File) = buildJsonObject {
    put("path", file.absolutePath); put("bytes", file.length())
    put("sha256", UltraKernelSpec.sha256(file))
}

fun main(args: Array<String>) {
    val input = File(args[0]); val stock = File(args[1]); val output = File(args[2])
    val assets = UltraKernelFileAssets(File(args[3]))
    val credential = UltraKernelCredential.of("Aa1".repeat(16))
    val steps = mutableListOf<JsonObject>()
    val inputHash = UltraKernelSpec.sha256(input); val stockHash = UltraKernelSpec.sha256(stock)

    fun prepare(label: String, image: File, work: File): UltraKernelFlow.Preparation? {
        val notices = mutableListOf<String>()
        var result: UltraKernelFlow.Preparation? = null
        steps += buildJsonObject {
            put("stage", label); put("input", facts(image))
            try {
                result = UltraKernelFlow(work, assets).prepareTarget(image, credential, null, notices::add)
                val prepared = requireNotNull(result)
                put("outcome", "SUCCESS"); put("alreadyInstalled", prepared.alreadyInstalled)
                put("planOrigin", prepared.planOrigin)
                prepared.candidate?.let { candidate ->
                    put("candidate", facts(candidate.image)); put("kernelSha256", candidate.kernelSha256)
                    check(UltraKernelSpec.sha256(UltraKernelPlan.readKernel(candidate.image)) == candidate.kernelSha256)
                    put("candidateReadbackHashMatches", true)
                }
            } catch (error: Exception) {
                put("outcome", "ERROR"); put("errorClass", error.javaClass.name)
                put("error", error.message.orEmpty())
                if (error is UltraKernelGenerateException) {
                    put("generateCode", error.code); put("generateDetail", error.detail)
                }
            }
            put("notices", buildJsonArray { notices.forEach { add(it) } })
        }
        return result
    }

    val work = File(output, "historical-work")
    prepare("historical-default-prepareTarget", input, work)
    var recovered: UltraKernelOriginalRecovery.Recovered? = null
    for ((label, originals) in listOf("exact-recovery-without-backup" to emptyList<File>(),
            "exact-recovery-with-known-original" to listOf(stock))) {
        steps += buildJsonObject {
            put("stage", label)
            try {
                val value = UltraKernelOriginalRecovery(assets).recover(input, work, originals,
                    File(output, label))
                if (value == null) put("outcome", "NO_MATCHING_PREIMAGE")
                else {
                    recovered = value
                    put("outcome", "SUCCESS"); put("source", value.source.name)
                    put("image", facts(value.image)); put("release", value.kernelRelease)
                    put("matchesKnownOriginal", UltraKernelSpec.sha256(value.image) == stockHash)
                }
            } catch (error: Exception) {
                put("outcome", "ERROR"); put("errorClass", error.javaClass.name)
                put("error", error.message.orEmpty())
            }
        }
        if (recovered != null) break
    }
    recovered?.let { prepare("recovered-default-prepareTarget", it.image, File(output, "recovered-work")) }
    val currentWork = File(output, "current-control")
    val control = prepare("known-original-default-prepareTarget-control", stock, currentWork)
    control?.candidate?.let {
        val before = UltraKernelSpec.sha256(it.image)
        val repeated = prepare("current-generated-retained-prepareTarget-control", it.image, currentWork)
        check(UltraKernelSpec.sha256(it.image) == before)
        if (repeated != null) check(repeated.alreadyInstalled && repeated.candidate == null)
    }
    check(UltraKernelSpec.sha256(input) == inputHash && UltraKernelSpec.sha256(stock) == stockHash)
    File(output, "result.json").writeText(Json { prettyPrint = true }.encodeToString(JsonObject.serializer(),
        buildJsonObject {
            put("schema", "maplesu-real-repatch-entry/1"); put("input", facts(input))
            put("knownOriginal", facts(stock)); put("kernelRelease", UltraKernelSpec.releaseOf(UltraKernelPlan.readKernel(input)))
            put("steps", JsonArray(steps)); put("inputsUnchanged", true)
            put("deviceTestPerformed", false); put("partitionWrites", false)
        }) + "\n")
    println("REPATCH_ENTRY_OBSERVED steps=${steps.size}")
}
'''


def identity(path):
    with path.open("rb") as stream:
        sha = hashlib.file_digest(stream, "sha256").hexdigest()
    return {"path": str(path), "bytes": path.stat().st_size, "sha256": sha}


def execute(command, output, label, timeout=180):
    started = time.monotonic()
    result = subprocess.run(list(map(str, command)), cwd=ROOT, capture_output=True, timeout=timeout)
    (output / (label + ".stdout.log")).write_bytes(result.stdout)
    (output / (label + ".stderr.log")).write_bytes(result.stderr)
    return {"argv": list(map(str, command)), "exitCode": result.returncode,
            "seconds": round(time.monotonic() - started, 3),
            "stdout": identity(output / (label + ".stdout.log")),
            "stderr": identity(output / (label + ".stderr.log"))}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--product", type=Path, required=True)
    parser.add_argument("--image-core", type=Path, required=True)
    parser.add_argument("--java", type=Path, required=True)
    args = parser.parse_args()
    output, product, image, java = (p.resolve() for p in
        (args.output, args.product, args.image_core, args.java))
    if output.exists():
        raise RuntimeError("TEST_OUTPUT_EXISTS")
    output.mkdir(parents=True)
    if output.drive.lower() != "c:":
        raise RuntimeError("TEST_OUTPUT_MUST_USE_C_DRIVE")
    sources = sorted((ROOT / "manager/src/main/java/dev/maplesu/manager/ultrakernel").glob("*.kt"))
    sources.append(ROOT / "tools/specgen/HostMain.kt")
    source_inputs = [identity(path) for path in sources]
    assets = sorted((ROOT / "manager/src/main/assets/ultra-kernels").rglob("*"))
    assets = [path for path in assets if path.is_file()]
    asset_inputs = [identity(path) for path in assets]
    deps = [cached_jar("org.jetbrains.kotlin", "kotlin-stdlib", "2.4.20"),
            cached_jar("org.jetbrains", "annotations", "13.0"),
            cached_jar("org.jetbrains.kotlinx", "kotlinx-serialization-json-jvm", "1.11.0"),
            cached_jar("org.jetbrains.kotlinx", "kotlinx-serialization-core-jvm", "1.11.0"),
            image, Path(os.environ["ANDROID_HOME"]) / "platforms/android-37.0/android.jar"]
    compiler = cached_jar("org.jetbrains.kotlin", "kotlin-compiler-embeddable", "2.4.20")
    coroutines = cached_jar("org.jetbrains.kotlinx", "kotlinx-coroutines-core-jvm", "1.11.0")
    receipt = {"schema": "maplesu-real-repatch-execution/1", "product": identity(product),
               "imageCore": identity(image), "java": identity(java),
               "sourceInputs": source_inputs, "assetInputs": asset_inputs,
               "dependencies": [identity(path) for path in deps + [compiler, coroutines]],
               "steps": [], "cases": [], "deviceTestPerformed": False, "partitionWrites": False}
    try:
        harness = output / "RepatchEntryMain.kt"
        harness.write_text(HARNESS, encoding="utf-8")
        classpath = os.pathsep.join(map(str, [product] + deps))
        compiler_cp = os.pathsep.join(map(str, [compiler, deps[0], deps[1], coroutines]))
        step = execute([java, "-Xmx768m", "-cp", compiler_cp,
            "org.jetbrains.kotlin.cli.jvm.K2JVMCompiler", "-no-stdlib", "-no-reflect", "-jvm-target", "21",
            "-classpath", classpath, "-Xfriend-paths=" + str(product), "-d", output / "repatch-tests.jar",
            harness], output, "compile")
        receipt["steps"].append(step)
        if step["exitCode"]:
            raise RuntimeError("HARNESS_COMPILE_FAILED")
        cases = [
            ("pad3pro", "一加pad3promaplesu-patched-02bdc5f38009.img", "一加pad3pro原boot.img"),
            ("ace5", "ace5至尊修补好的.img", "一加ace5至尊原boot.img"),
        ]
        for label, historical_name, stock_name in cases:
            folder = output / label
            folder.mkdir()
            historical = ROOT / "Log_Reference/11.13/Boot" / historical_name
            stock = ROOT / "Log_Reference/11.13/Boot" / stock_name
            inputs = [identity(historical), identity(stock)]
            case = {"label": label, "inputs": inputs, "folder": str(folder)}
            try:
                case["command"] = execute([java, "-Xmx1024m", "-Djava.io.tmpdir=" + str(folder),
                    "-cp", str(output / "repatch-tests.jar") + os.pathsep + classpath,
                    "dev.maplesu.manager.ultrakernel.RepatchEntryMainKt", historical, stock, folder,
                    ROOT / "manager/src/main/assets"], folder, "run")
                if (folder / "result.json").is_file():
                    case["result"] = json.loads((folder / "result.json").read_text(encoding="utf-8"))
                if case["command"]["exitCode"]:
                    raise RuntimeError("HARNESS_EXECUTION_FAILED")
            finally:
                case["inputsUnchanged"] = inputs == [identity(historical), identity(stock)]
                generated = [path for path in folder.rglob("*") if path.is_file() and
                             (path.suffix in (".img", ".raw", ".encoded") or path.stat().st_size > 2 * 1024 * 1024)]
                case["removedGeneratedFiles"] = [identity(path) for path in generated]
                for path in generated:
                    if not path.resolve().is_relative_to(folder.resolve()):
                        raise RuntimeError("GENERATED_PATH_ESCAPED_CASE")
                    path.unlink()
                receipt["cases"].append(case)
                print(label + " " + json.dumps(case.get("result", {}).get("steps", []), ensure_ascii=True), flush=True)
            if not case["inputsUnchanged"]:
                raise RuntimeError("INPUT_DRIFT")
        receipt["sourceInputsUnchanged"] = source_inputs == [identity(path) for path in sources]
        receipt["assetInputsUnchanged"] = asset_inputs == [identity(path) for path in assets]
        if not receipt["sourceInputsUnchanged"] or not receipt["assetInputsUnchanged"]:
            raise RuntimeError("PRODUCTION_INPUT_DRIFT")
        receipt["observationsCompleted"] = True
    finally:
        (output / "EXECUTION.json").write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
