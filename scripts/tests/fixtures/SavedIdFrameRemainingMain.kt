package dev.maplesu.manager.ultrakernel

import dev.maplesu.image.BootImageRebuilder
import java.io.File
import java.io.RandomAccessFile
import kotlinx.serialization.json.*

private fun identity(file: File): JsonObject = buildJsonObject {
    put("path", file.canonicalPath); put("bytes", file.length()); put("sha256", UltraKernelSpec.sha256(file))
}

private fun sameBytes(first: File, second: File): Boolean {
    if (first.length() != second.length()) return false
    RandomAccessFile(first, "r").use { left -> RandomAccessFile(second, "r").use { right ->
        val a = ByteArray(65536); val b = ByteArray(a.size)
        var remaining = left.length()
        while (remaining > 0) {
            val count = minOf(remaining, a.size.toLong()).toInt()
            left.readFully(a, 0, count); right.readFully(b, 0, count)
            if ((0 until count).any { a[it] != b[it] }) return false
            remaining -= count
        }
    } }
    return true
}

private fun independentReplay(base: File, candidate: File, text: String): JsonObject {
    val raw = UltraKernelPlan.readKernel(base)
    val actual = UltraKernelPlan.readKernel(candidate)
    val expected = raw.copyOf()
    var count = 0
    fun hex(value: String) = value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    text.lineSequence().filter { it.isNotBlank() && !it.startsWith('#') }.forEach { line ->
        val fields = line.split('|'); check(fields.size == 3)
        val at = fields[0].toLong(); val before = hex(fields[1]); val after = hex(fields[2])
        check(before.size == after.size && at >= 0 && at <= raw.size.toLong() - before.size)
        check(raw.copyOfRange(at.toInt(), at.toInt() + before.size).contentEquals(before))
        after.copyInto(expected, at.toInt()); count++
    }
    check(expected.contentEquals(actual)) { "INDEPENDENT_SPEC_REPLAY_MISMATCH" }
    return buildJsonObject { put("records", count); put("allOriginalBytesMatched", true)
        put("completeKernelEqual", true); put("outsideRecordsChanged", 0)
        put("baseKernelSha256", UltraKernelSpec.sha256(raw)); put("patchedKernelSha256", UltraKernelSpec.sha256(actual)) }
}

fun main(args: Array<String>) {
    val base = File(args[0]); val installed = File(args[1]); val receipts = File(args[2])
    val keySpec = File(args[3]); val work = File(args[4]); val assets = UltraKernelFileAssets(File(args[5]))
    check(!work.exists() && work.mkdirs()) { "PHASE_OUTPUT_MUST_BE_FRESH" }
    check(work.usableSpace >= 850_000_000L) { "PHASE_DISK_BUDGET_INSUFFICIENT" }
    val beforeBase = identity(base); val beforeInstalled = identity(installed)
    val stages = linkedMapOf<String, JsonElement>()
    fun publish() = File(work, "result.json").writeText(Json { prettyPrint = true }.encodeToString(
        JsonObject.serializer(), buildJsonObject {
            put("base", beforeBase); put("installed", beforeInstalled); put("stages", JsonObject(stages))
            put("scope", "remaining phases reusing an already generated candidate")
            put("deviceTest", false); put("partitionWrites", false); put("versionUpgradePerformed", false)
        }) + "\n")
    fun stage(name: String, action: () -> JsonObject): Boolean {
        val started = System.nanoTime(); val free = work.usableSpace
        val value = try {
            val result = action()
            check(identity(base) == beforeBase && identity(installed) == beforeInstalled) { "READ_ONLY_INPUT_CHANGED" }
            JsonObject(result + ("passed" to JsonPrimitive(true)))
        } catch (error: Exception) {
            buildJsonObject { put("passed", false); put("errorType", error.javaClass.simpleName)
                put("code", (error as? UltraKernelGenerateException)?.code ?: "PRODUCT_EXCEPTION")
                put("detail", (error as? UltraKernelGenerateException)?.detail ?: error.message.orEmpty()) }
        }
        stages[name] = JsonObject(value + mapOf("freeBefore" to JsonPrimitive(free),
            "freeAfter" to JsonPrimitive(work.usableSpace), "baseAfter" to identity(base),
            "installedAfter" to identity(installed), "elapsedSeconds" to JsonPrimitive((System.nanoTime() - started) / 1e9)))
        publish(); println("$name passed=${value["passed"]}"); System.out.flush()
        return value["passed"]?.jsonPrimitive?.booleanOrNull == true
    }
    val recovery = UltraKernelOriginalRecovery(assets)
    // This new D: output is deliberately reused; the installed candidate remains read-only on C:.
    val recoveredOutput = File(work, "recovered")
    if (!stage("rawKernelRecoveryWithoutReceipt") {
        val found = requireNotNull(recovery.recover(installed, File(work, "empty-receipts"), emptyList(),
            recoveredOutput, generatedOnly = true))
        check(found.source == UltraKernelOriginalRecovery.Source.IMAGE_BOUND_KERNEL_REVERSE)
        check(UltraKernelPlan.readKernel(found.image).contentEquals(UltraKernelPlan.readKernel(base)))
        check(BootImageRebuilder.readRecoveryRecord(found.image) == null)
        buildJsonObject { put("source", found.source.name); put("image", identity(found.image))
            put("originalKernelEqual", true); put("recordRemoved", true)
            put("originalBootEqual", UltraKernelSpec.sha256(found.image) == UltraKernelSpec.sha256(base)) }
    }) return
    if (!stage("exactOriginalBootRecoveryWithBackup") {
        val found = requireNotNull(recovery.recover(installed, receipts, listOf(base), recoveredOutput))
        check(found.source == UltraKernelOriginalRecovery.Source.LOCAL_PREIMAGE)
        check(sameBytes(base, found.image))
        buildJsonObject { put("source", found.source.name); put("image", identity(found.image))
            put("fullBootDigestEqual", UltraKernelSpec.sha256(base) == UltraKernelSpec.sha256(found.image))
            put("fullBootBytesEqual", true) }
    }) return
    val freshFlow = File(work, "flow")
    val flow = UltraKernelFlow(freshFlow, assets)
    val originalKey = UltraKernelCredential.of(UltraKernelSpec.parse(keySpec.readText()).key)
    if (!stage("repatchWithoutLocalReceipt") {
        check(!freshFlow.exists())
        val prepared = flow.prepareTarget(installed, originalKey)
        check(prepared.alreadyInstalled && prepared.candidate == null)
        buildJsonObject { put("alreadyInstalled", true); put("sameGeneratorNoop", true)
            put("receiptSupplied", false); put("metadataFabricated", false) }
    }) return
    stage("credentialChangeRepatch") {
        val prepared = flow.prepareTarget(installed, UltraKernelCredential.of("Bb2".repeat(16)))
        val candidate = requireNotNull(prepared.candidate)
        check(candidate.kernelSha256 != UltraKernelSpec.sha256(UltraKernelPlan.readKernel(installed)))
        val plan = (prepared.variant as UltraKernelGeneratedAsset).plan
        buildJsonObject { put("image", identity(candidate.image)); put("kernelSha256", candidate.kernelSha256)
            put("independentReplay", independentReplay(base, candidate.image,
                plan.specText(requireNotNull(prepared.credential)))) }
    }
}
