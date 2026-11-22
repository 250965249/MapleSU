"""Run real Ultra prepare/recovery contracts on read-only Boot_Research images."""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]

HARNESS = r'''
package dev.maplesu.manager.ultrakernel

import dev.maplesu.image.BootImageInspector
import dev.maplesu.image.BootImageRebuilder
import java.io.File
import java.io.RandomAccessFile
import kotlinx.serialization.json.*

private fun identity(file: File): JsonObject = buildJsonObject {
    put("path", file.canonicalPath); put("bytes", file.length())
    put("sha256", UltraKernelSpec.sha256(file))
}

private fun failure(error: Exception): JsonObject = buildJsonObject {
    put("passed", false); put("errorType", error.javaClass.simpleName)
    if (error is UltraKernelGenerateException) {
        put("code", error.code); put("detail", error.detail)
    } else {
        val message = error.message.orEmpty()
        put("code", message.substringBefore(':').takeIf { it.matches(Regex("[A-Z][A-Z0-9_]+")) }
            ?: "PRODUCT_EXCEPTION")
        put("detail", message)
    }
}

private fun candidate(prepared: UltraKernelFlow.Preparation): JsonObject = buildJsonObject {
    put("alreadyInstalled", prepared.alreadyInstalled); put("planOrigin", prepared.planOrigin)
    put("supportLevel", prepared.supportLevel)
    prepared.candidate?.let { value ->
        put("image", identity(value.image)); put("kernelSha256", value.kernelSha256)
        put("kernelRelease", value.kernelRelease); put("records", value.patches)
        put("changedBytes", value.differingBytes)
    }
    (prepared.variant as? UltraKernelGeneratedAsset)?.let { asset ->
        put("layout", buildJsonObject {
            asset.plan.layout.fields.toSortedMap().forEach { (name, field) ->
                put(name, buildJsonObject {
                    put("offsetBytes", field.offsetBytes); put("widthBytes", field.widthBytes)
                    put("ownerSizeBytes", field.ownerSizeBytes?.let(::JsonPrimitive) ?: JsonNull)
                    put("source", field.source); put("parserVersion", field.parserVersion)
                })
            }
        })
    }
}

private fun independentReplay(base: File, patched: File, spec: File): JsonObject {
    val raw = UltraKernelPlan.readKernel(base)
    val actual = UltraKernelPlan.readKernel(patched)
    val expected = raw.copyOf()
    var records = 0
    fun hex(value: String) = value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    spec.forEachLine { line ->
        if (line.isNotBlank() && !line.startsWith('#')) {
            val fields = line.split('|'); check(fields.size == 3)
            val offset = fields[0].toLong(); val before = hex(fields[1]); val after = hex(fields[2])
            check(before.size == after.size && offset >= 0 && offset <= raw.size.toLong() - before.size)
            check(raw.copyOfRange(offset.toInt(), offset.toInt() + before.size).contentEquals(before))
            after.copyInto(expected, offset.toInt()); records++
        }
    }
    check(actual.contentEquals(expected)) { "INDEPENDENT_SPEC_REPLAY_MISMATCH" }
    return buildJsonObject {
        put("passed", true); put("records", records); put("allOriginalBytesMatched", true)
        put("completeKernelEqual", true); put("outsideRecordsChanged", 0)
        put("baseKernelSha256", UltraKernelSpec.sha256(raw))
        put("patchedKernelSha256", UltraKernelSpec.sha256(actual))
    }
}

fun main(args: Array<String>) {
    val source = File(args[0]); val work = File(args[1]); val evidence = File(args[2])
    val assets = UltraKernelFileAssets(File(args[3])); work.mkdirs(); evidence.mkdirs()
    val stages = linkedMapOf<String, JsonElement>()
    fun publish() = File(evidence, "result.json").writeText(Json { prettyPrint = true }.encodeToString(
        JsonObject.serializer(), buildJsonObject {
            put("input", identity(source)); put("stages", JsonObject(stages))
            put("deviceTest", false); put("partitionWrites", false)
            put("versionUpgradePerformed", false)
            put("versionScope", "same r3 generator; credential change is not version upgrade")
        }) + "\n")
    fun stage(name: String, action: () -> JsonObject): Boolean {
        val started = System.nanoTime()
        var passed = false
        val value = try { action().also { passed = it["passed"]?.jsonPrimitive?.booleanOrNull == true } }
            catch (error: Exception) { failure(error) }
        stages[name] = JsonObject(value + ("elapsedSeconds" to JsonPrimitive((System.nanoTime() - started) / 1e9)))
        publish(); println("$name passed=$passed"); System.out.flush()
        return passed
    }
    val before = UltraKernelSpec.sha256(source)
    val report = BootImageInspector.inspect(source)
    stages["inspect"] = Json.parseToJsonElement(report.toJson())
    val a = UltraKernelCredential.of("Aa1".repeat(16))
    val b = UltraKernelCredential.of("Bb2".repeat(16))
    val notices = mutableListOf<String>()
    val recovery = UltraKernelOriginalRecovery(assets)
    if (args.getOrNull(4) == "backup-only") {
        var prepared: UltraKernelFlow.Preparation? = null
        stage("prepareTarget") {
            prepared = UltraKernelFlow(File(work, "flow"), assets).prepareTarget(source, a)
            check(prepared!!.candidate != null) { "BACKUP_TEST_CANDIDATE_MISSING" }
            buildJsonObject { put("passed", true); put("preparation", candidate(prepared!!)) }
        }
        prepared?.candidate?.let { initial ->
            stage("exactOriginalBootRecoveryWithBackup") {
                val found = recovery.recover(initial.image, File(work, "flow"), listOf(source),
                    File(work, "backup-recovery"))
                check(found != null) { "PRODUCT_BACKUP_RECOVERY_MISSING" }
                check(found.source == UltraKernelOriginalRecovery.Source.LOCAL_PREIMAGE)
                check(UltraKernelSpec.sha256(found.image) == before) { "BACKUP_RECOVERED_DIGEST_MISMATCH" }
                check(source.length() == found.image.length()) { "BACKUP_RECOVERED_SIZE_MISMATCH" }
                RandomAccessFile(source, "r").use { left ->
                    RandomAccessFile(found.image, "r").use { right ->
                        val a = ByteArray(65536); val b = ByteArray(a.size)
                        var remaining = left.length()
                        while (remaining > 0) {
                            val count = minOf(remaining, a.size.toLong()).toInt()
                            left.readFully(a, 0, count); right.readFully(b, 0, count)
                            check((0 until count).all { a[it] == b[it] }) { "BACKUP_RECOVERED_BYTES_MISMATCH" }
                            remaining -= count
                        }
                    }
                }
                buildJsonObject { put("passed", true); put("source", found.source.name)
                    put("image", identity(found.image)); put("fullBootDigestEqual", true)
                    put("fullBootBytesEqual", true); put("backup", identity(source)) }
            }
        }
        stages["sourcePreservation"] = buildJsonObject {
            put("passed", UltraKernelSpec.sha256(source) == before); put("sha256Before", before)
            put("sha256After", UltraKernelSpec.sha256(source))
        }
        publish(); return
    }
    var recoveredInput: File? = null
    var recoverAtTarget = false
    stage("existingImageRecoveryWithoutLocalReceipt") {
        val stock = recovery.recover(source, File(work, "empty-receipts"), emptyList(),
            File(work, "historical-recovery"))
        val found = stock ?: recovery.recover(source, File(work, "empty-receipts"), emptyList(),
            File(work, "historical-kernel-recovery"), generatedOnly = true)
        recoveredInput = found?.image
        recoverAtTarget = stock == null && found != null
        buildJsonObject {
            put("passed", found != null); put("matchedRealRecoveryEvidence", found != null)
            put("originalContainerProven", stock != null)
            put("receiptSupplied", false); put("metadataFabricated", false)
            found?.let {
                put("source", it.source.name); put("image", identity(it.image))
                put("kernelRelease", it.kernelRelease)
            }
            if (found == null) put("code", "NO_MATCHING_PRODUCT_RECOVERY_EVIDENCE")
        }
    }
    if (report.kernelSize == 0L) {
        stage("ultraPrepareTarget") {
            val prepared = UltraKernelFlow(File(work, "flow"), assets).prepareTarget(source, a, onNotice = notices::add)
            buildJsonObject { put("passed", true); put("preparation", candidate(prepared)) }
        }
        stage("ramdiskContainerRoundtrip") {
            val ramdisk = File(work, "ramdisk.bin")
            RandomAccessFile(source, "r").use { input ->
                input.seek(report.ramdiskOffset)
                val bytes = ByteArray(report.ramdiskSize.toInt()); input.readFully(bytes); ramdisk.writeBytes(bytes)
            }
            val output = File(work, "ramdisk-roundtrip.img")
            val rebuilt = BootImageRebuilder.rebuildRamdisk(source, ramdisk, output)
            check(rebuilt.equivalence.ok())
            buildJsonObject {
                put("passed", true); put("ultraBootSupportProven", false)
                put("report", Json.parseToJsonElement(rebuilt.toJson()))
                put("output", identity(output))
            }
        }
    } else {
        val base = recoveredInput ?: source
        val flowWork = File(work, "flow")
        val flow = UltraKernelFlow(flowWork, assets)
        var first: UltraKernelFlow.Preparation? = null
        val generated = stage("prepareTarget") {
            first = flow.prepareTarget(if (recoverAtTarget) source else base, a, onNotice = notices::add)
            buildJsonObject { put("passed", first!!.candidate != null || first!!.alreadyInstalled)
                put("sourceTargetEntryExercised", recoverAtTarget || recoveredInput == null)
                put("usedProductRecoveredInput", recoveredInput != null); put("preparation", candidate(first!!)) }
        }
        val initial = first?.candidate
        if (generated && initial != null) {
            val retained = flowWork.listFiles().orEmpty().single { it.name.endsWith(".spec") }
            stage("independentCompleteKernelReadback") { independentReplay(base, initial.image, retained) }
            stage("sameGeneratorRepatchWithReceipt") {
                val again = flow.prepareTarget(initial.image, requireNotNull(first!!.credential), onNotice = notices::add)
                check(again.alreadyInstalled && again.candidate == null) { "SAME_GENERATOR_REPATCH_NOT_NOOP" }
                buildJsonObject { put("passed", true); put("preparation", candidate(again))
                    put("sameGeneratorNoop", true); put("versionUpgrade", false) }
            }
            stage("generatedKernelRecovery") {
                val found = recovery.recover(initial.image, flowWork, emptyList(),
                    File(work, "kernel-recovery"), generatedOnly = true)
                check(found != null) { "PRODUCT_GENERATED_KERNEL_RECOVERY_MISSING" }
                check(UltraKernelPlan.readKernel(found.image).contentEquals(UltraKernelPlan.readKernel(base))) {
                    "RECOVERED_KERNEL_DIFFERS_FROM_BASE"
                }
                val result = buildJsonObject {
                    put("passed", true); put("source", found.source.name); put("image", identity(found.image))
                    put("originalKernelEqual", true)
                    put("originalBootEqual", UltraKernelSpec.sha256(found.image) == UltraKernelSpec.sha256(base))
                }
                found.image.delete(); result
            }
            stage("exactOriginalBootRecovery") {
                val found = recovery.recover(initial.image, flowWork, emptyList(), File(work, "exact-recovery"))
                buildJsonObject {
                    put("passed", found != null && UltraKernelSpec.sha256(found.image) == UltraKernelSpec.sha256(base))
                    put("recoveryReturned", found != null)
                    found?.let { put("source", it.source.name); put("image", identity(it.image)); it.image.delete() }
                    if (found == null) put("code", "EXACT_ORIGINAL_CONTAINER_RECOVERY_UNAVAILABLE")
                }
            }
            stage("repatchWithoutLocalReceipt") {
                val again = UltraKernelFlow(File(work, "missing-receipt"), assets).prepareTarget(
                    initial.image, requireNotNull(first!!.credential), onNotice = notices::add)
                buildJsonObject { put("passed", true); put("preparation", candidate(again))
                    put("receiptSupplied", false); put("metadataFabricated", false) }
            }
            stage("credentialChangeRepatch") {
                val changedWork = File(work, "credential-change").also { it.mkdirs() }
                flowWork.listFiles().orEmpty().filter { it.isFile && (it.extension == "json" || it.extension == "spec") }
                    .forEach { it.copyTo(File(changedWork, it.name)) }
                val changed = UltraKernelFlow(changedWork, assets).prepareTarget(initial.image, b, onNotice = notices::add)
                val output = requireNotNull(changed.candidate) { "CREDENTIAL_CHANGE_CANDIDATE_MISSING" }
                check(output.kernelSha256 != initial.kernelSha256) { "CREDENTIAL_CHANGE_NOT_APPLIED" }
                val changedSpec = changedWork.listFiles().orEmpty().filter { it.extension == "spec" }
                    .single { it.name.contains(requireNotNull(changed.variant).specSha256) }
                val proof = independentReplay(base, output.image, changedSpec)
                buildJsonObject { put("passed", true); put("preparation", candidate(changed))
                    put("independentReplay", proof); put("versionUpgrade", false) }
            }
            // Only synthetic-credential specs produced by this run are retained.
            flowWork.listFiles().orEmpty().filter { it.isFile && (it.extension == "json" || it.extension == "spec") }
                .forEach { it.copyTo(File(evidence, it.name), overwrite = true) }
        }
    }
    stages["sourcePreservation"] = buildJsonObject {
        put("passed", UltraKernelSpec.sha256(source) == before); put("sha256Before", before)
        put("sha256After", UltraKernelSpec.sha256(source))
    }
    // Notices are generated only with this harness's synthetic test credentials.
    File(evidence, "notices.json").writeText(buildJsonArray { notices.forEach { add(it) } }.toString() + "\n")
    publish()
}
'''


def identity(path):
    path = Path(path).resolve()
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return {"path": str(path), "bytes": path.stat().st_size, "sha256": digest.hexdigest()}


def assess_stages(stages, backup_recovery_only=False):
    kernel_size = stages.get("inspect", {}).get("kernelSize")
    if not isinstance(kernel_size, int) or kernel_size < 0:
        return {"passed": False, "scope": "unclassified", "failedRequiredStages": ["inspect"]}
    if backup_recovery_only:
        scope = "exact-backup-recovery"
        required = ("prepareTarget", "exactOriginalBootRecoveryWithBackup", "sourcePreservation")
    elif kernel_size == 0:
        scope = "ramdisk-container-only"
        required = ("ramdiskContainerRoundtrip", "sourcePreservation")
    else:
        scope = "kernel-generation-and-recovery"
        required = ("prepareTarget", "independentCompleteKernelReadback", "sameGeneratorRepatchWithReceipt",
                    "generatedKernelRecovery", "repatchWithoutLocalReceipt", "credentialChangeRepatch",
                    "sourcePreservation")
    failed = [name for name in required if stages.get(name, {}).get("passed") is not True]
    return {"passed": not failed, "scope": scope, "failedRequiredStages": failed}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-receipt", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--scratch", type=Path, required=True)
    parser.add_argument("--backup-recovery-only", action="store_true")
    parser.add_argument("--image", type=Path, action="append", help="Limit a focused replay to these Boot_Research images")
    args = parser.parse_args()
    out, scratch = args.out.resolve(), args.scratch.resolve()
    out.mkdir(parents=True, exist_ok=args.backup_recovery_only)
    scratch.mkdir(parents=True, exist_ok=False)
    runtime_receipt = json.loads(args.runtime_receipt.read_bytes())
    runtime = runtime_receipt["runtime"]
    java, jar, classpath = Path(runtime["java"]["path"]), Path(runtime["jar"]["path"]), runtime["classpath"]
    assert identity(jar)["sha256"] == runtime["jar"]["sha256"]
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(ROOT / "tools/specgen"))
    from specgen import product
    compiler = product.cached_jar("org.jetbrains.kotlin", "kotlin-compiler-embeddable", "2.4.20")
    stdlib = product.cached_jar("org.jetbrains.kotlin", "kotlin-stdlib", "2.4.20")
    annotations = product.cached_jar("org.jetbrains", "annotations", "13.0")
    coroutines = product.cached_jar("org.jetbrains.kotlinx", "kotlinx-coroutines-core-jvm", "1.11.0")
    source = out / ("BootResearchBackupMain.kt" if args.backup_recovery_only else "BootResearchLifecycleMain.kt")
    source.write_text(HARNESS, encoding="utf-8")
    harness = out / ("backup-harness.jar" if args.backup_recovery_only else "lifecycle-harness.jar")
    command = [str(java), "-Xmx512m", "-cp", os.pathsep.join(map(str,
        (compiler, stdlib, annotations, coroutines))), "org.jetbrains.kotlin.cli.jvm.K2JVMCompiler",
        *product.JVM_FLAGS, "-Xfriend-paths=" + str(jar), "-classpath", str(jar) + os.pathsep + classpath,
        "-d", str(harness), str(source)]
    build = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                           encoding="utf-8", errors="replace")
    prefix = "backup-compile" if args.backup_recovery_only else "compile"
    (out / (prefix + ".stdout.log")).write_text(build.stdout, encoding="utf-8")
    (out / (prefix + ".stderr.log")).write_text(build.stderr, encoding="utf-8")
    record = {"schemaVersion": 1, "startedAtUtc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "scope": "all Boot_Research images; offline product lifecycle only",
        "runtimeReceipt": identity(args.runtime_receipt), "runtime": runtime,
        "compile": {"argv": command, "exitCode": build.returncode}, "cases": [],
        "deviceTest": False, "partitionWrites": False, "productionModified": False,
        "oldReceiptFabricated": False, "versionUpgradePerformed": False}
    record_name = "BACKUP-RECOVERY.json" if args.backup_recovery_only else "LIFECYCLE.json"
    def save():
        (out / record_name).write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    save()
    if build.returncode:
        return build.returncode
    record["harness"] = identity(harness)
    sources = [Path(value["path"]) for value in runtime_receipt["sources"]
               if "/ultrakernel/" in value["path"].replace("\\", "/")
               or "/image-core/" in value["path"].replace("\\", "/")]
    record["sources"] = [identity(path) for path in sources]
    asset_root = ROOT / "manager/src/main/assets/ultra-kernels"
    def asset_inputs():
        return [identity(path) for path in sorted(asset_root.rglob("*")) if path.is_file()]
    record["assets"] = asset_inputs()
    previous = {value["path"]: value for value in runtime_receipt["sources"]}
    assert all(item["sha256"] == previous[item["path"]]["sha256"] for item in record["sources"])
    images = sorted(path.resolve() for path in args.image) if args.image else sorted((ROOT / "Boot_Research").rglob("*.img"))
    if args.image:
        assert all(path.is_file() and path.is_relative_to(ROOT / "Boot_Research") for path in images)
        record["scope"] = "explicit Boot_Research images; offline product lifecycle only"
    initial_cases = {}
    if args.backup_recovery_only:
        previous_run = json.loads((out / "LIFECYCLE.json").read_bytes())
        initial_cases = {case["input"]["path"]: case for case in previous_run["cases"]
            if case.get("result", {}).get("stages", {}).get("prepareTarget", {}).get("passed")}
        images = [path for path in images if str(path.resolve()) in initial_cases]
        record["scope"] = "successful lifecycle cases only; real original-backup full-boot recovery"
        record["initialLifecycle"] = identity(out / "LIFECYCLE.json")
    unique = {}
    for path in images:
        item = identity(path)
        unique.setdefault(item["sha256"], []).append(item)
    record["inventory"] = list(unique.values())
    save()
    try:
        for index, entries in enumerate(unique.values(), 1):
            path = Path(entries[0]["path"])
            work = scratch / f"case-{index:02}"
            evidence = out / (("backup-case-" if args.backup_recovery_only else "case-") + f"{index:02}")
            evidence.mkdir()
            before = identity(path)
            command = [str(java), "-Xmx768m", "-cp", os.pathsep.join((str(harness), str(jar), classpath)),
                "dev.maplesu.manager.ultrakernel." + ("BootResearchBackupMainKt" if args.backup_recovery_only
                    else "BootResearchLifecycleMainKt"), str(path), str(work),
                str(evidence), str(ROOT / "manager/src/main/assets")]
            if args.backup_recovery_only:
                command.append("backup-only")
            started = time.monotonic()
            result = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                                    encoding="utf-8", errors="replace")
            (evidence / "stdout.log").write_text(result.stdout, encoding="utf-8")
            (evidence / "stderr.log").write_text(result.stderr, encoding="utf-8")
            case = {"input": before, "aliases": entries, "argv": command, "exitCode": result.returncode,
                "elapsedSeconds": time.monotonic() - started, "inputAfter": identity(path)}
            case["inputUnchanged"] = case["input"] == case["inputAfter"]
            if (evidence / "result.json").is_file():
                case["result"] = json.loads((evidence / "result.json").read_bytes())
                if args.backup_recovery_only:
                    original = initial_cases[str(path.resolve())]["result"]["stages"]["prepareTarget"]
                    repeated = case["result"]["stages"].get("prepareTarget", {})
                    original_hash = original["preparation"]["image"]["sha256"]
                    repeated_hash = repeated.get("preparation", {}).get("image", {}).get("sha256")
                    case["regeneratedCandidateMatchesInitialRun"] = original_hash == repeated_hash
            case["assessment"] = assess_stages(case.get("result", {}).get("stages", {}),
                                                args.backup_recovery_only)
            record["cases"].append(case)
            shutil.rmtree(work, ignore_errors=False) if work.exists() else None
            case["scratchRemoved"] = not work.exists()
            save()
            print(f"{index}/{len(unique)} {path.relative_to(ROOT)} exit={result.returncode} "
                  f"contractPassed={case['assessment']['passed']}", flush=True)
        record["sourceUnchanged"] = record["sources"] == [identity(path) for path in sources]
        record["assetsUnchanged"] = record["assets"] == asset_inputs()
        record["runtimeJarUnchanged"] = identity(jar)["sha256"] == runtime["jar"]["sha256"]
        record["executionComplete"] = len(record["cases"]) == len(unique)
        record["allRequiredStagesPassed"] = bool(record["cases"]) and all(
            case["assessment"]["passed"] for case in record["cases"])
        record["finishedAtUtc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        save()
    finally:
        if scratch.exists():
            assert scratch.resolve() == args.scratch.resolve() and scratch != ROOT
            shutil.rmtree(scratch)
        save()
    return 0 if (record.get("executionComplete") and record.get("sourceUnchanged") and record.get("assetsUnchanged") and
                 record.get("runtimeJarUnchanged") and record.get("allRequiredStagesPassed") and
                 all(case["exitCode"] == 0 and case["inputUnchanged"] and
                     case.get("regeneratedCandidateMatchesInitialRun", True)
                     for case in record["cases"])) else 2


if __name__ == "__main__":
    raise SystemExit(main())
