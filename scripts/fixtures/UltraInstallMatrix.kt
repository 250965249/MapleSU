package dev.maplesu.manager.ultrakernel

import dev.maplesu.image.BootImageInspector
import dev.maplesu.installer.BlockDeviceTransaction
import java.io.File
import java.io.IOException
import java.io.RandomAccessFile
import kotlinx.serialization.json.*

/** Product patch/build and partition transaction code; only the block device is a host file. */
private class ImageDevice(file: File, private val scenario: String) : BlockDeviceTransaction.Device {
    private val handle = RandomAccessFile(file, "rw")
    private val partitionSize = handle.length()
    var writes = 0
    private var corrupted = false
    override fun size() = partitionSize
    override fun revalidate() { check(handle.length() == partitionSize) }
    override fun read(offset: Long, buffer: ByteArray, length: Int): Int {
        handle.seek(offset)
        return handle.read(buffer, 0, minOf(length, if (scenario == "short-io") 8191 else length))
    }
    override fun write(offset: Long, buffer: ByteArray, start: Int, length: Int): Int {
        writes++
        if (scenario == "partial-write" && writes == 2) throw IOException("INSTALLER_DEVICE_WRITE_FAILED")
        val count = minOf(length, if (scenario == "short-io") 4093 else length)
        handle.seek(offset)
        handle.write(buffer, start, count)
        return count
    }
    override fun sync() {
        if (scenario == "readback-corruption" && !corrupted) {
            handle.seek(0)
            val first = handle.read()
            handle.seek(0)
            handle.write(first xor 1)
            corrupted = true
        }
        handle.fd.sync()
    }
    override fun close() = handle.close()
}

fun main(args: Array<String>) {
    val root = File(args[0]).canonicalFile
    val output = File(args[1]).canonicalFile.also { it.mkdirs() }
    val sources = File(args[2]).readLines().filter { it.isNotBlank() }
    val results = mutableListOf<JsonObject>()
    val assets = UltraKernelFileAssets(File(root, "manager/src/main/assets"))
    for ((index, path) in sources.withIndex()) {
        val source = File(root, path)
        val checks = linkedMapOf<String, Boolean>()
        var release = ""
        var error = ""
        var sourceHash = ""
        var candidateHash = ""
        var header = -1
        var compression = ""
        val workspace = File(output, "image-$index").also { it.mkdirs() }
        try {
            check(source.isFile) { "MATRIX_INPUT_ABSENT" }
            sourceHash = UltraKernelSpec.sha256(source)
            val before = BootImageInspector.inspect(source)
            header = before.headerVersion
            compression = before.compression
            val flow = UltraKernelFlow(workspace, assets, managerClaimAssets = assets)
            val prepared = flow.prepare(source, UltraKernelCredential.of("Aa1".repeat(16)))
            val candidate = requireNotNull(prepared.candidate)
            release = candidate.kernelRelease
            candidateHash = candidate.bootSha256
            val raw = UltraKernelPlan.readKernel(source)
            val expectedPlan = UltraKernelSpecGenerator(managerClaimAssets = assets)
                .generate(raw, requireNotNull(prepared.credential))
            val expected = expectedPlan.apply(raw)
            checks["manager-claim-carrier-present"] = expectedPlan.records.any {
                it.role == "manager_claim:bootstrap"
            } && expectedPlan.records.any { it.role == "manager_claim:anchor" }
            checks["independent-plan-readback"] = expected.kernel.contentEquals(UltraKernelPlan.readKernel(candidate.image)) &&
                expected.derived.outsideSites == 0 && candidate.kernelSha256 == UltraKernelSpec.sha256(expected.kernel)
            checks["container-preserved"] = BootImageInspector.inspect(candidate.image).let {
                it.headerVersion == before.headerVersion && it.ramdiskSize == before.ramdiskSize &&
                    it.pageSize == before.pageSize && it.compression == before.compression
            }
            check(checks.values.all { it }) { "MATRIX_PATCH_READBACK" }
            for (scenario in listOf("direct", "short-io", "partial-write", "readback-corruption", "journal-failure", "cancel")) {
                val partition = File(workspace, "partition-$scenario.img")
                source.copyTo(partition, overwrite = true)
                val events = mutableListOf<String>()
                ImageDevice(partition, scenario).use { device ->
                    try {
                        val result = BlockDeviceTransaction.commit(device, candidate.image.toPath(), candidateHash,
                            source.toPath(), sourceHash) { state, _ ->
                            events += state
                            if (scenario == "journal-failure") throw IOException("INSTALLER_JOURNAL_WRITE_FAILED")
                            if (scenario == "cancel" && state == "WRITING") Thread.currentThread().interrupt()
                        }
                        checks[scenario] = if (scenario in listOf("direct", "short-io")) {
                            result.state == "REBOOT_REQUIRED" && result.rebootRequired &&
                                UltraKernelSpec.sha256(partition) == BlockDeviceTransaction.paddedDigest(candidate.image.toPath(), source.length()) &&
                                events == listOf("WRITING", "REBOOT_REQUIRED")
                        } else {
                            result.state == "RESTORED" && !result.rebootRequired &&
                                UltraKernelSpec.sha256(partition) == sourceHash && events.last() == "RESTORED"
                        }
                    } catch (failure: IOException) {
                        checks[scenario] = scenario == "journal-failure" && device.writes == 0 &&
                            UltraKernelSpec.sha256(partition) == sourceHash
                    } finally {
                        if (scenario == "cancel") checks["cancellation-preserved"] = Thread.interrupted()
                    }
                }
                check(partition.delete()) { "MATRIX_PARTITION_CLEANUP" }
            }
            val repeated = flow.prepare(candidate.image, requireNotNull(prepared.credential))
            checks["repeat-same-patched-boot"] = repeated.alreadyInstalled && repeated.candidate == null &&
                repeated.credential == prepared.credential
            checks["source-unchanged"] = sourceHash == UltraKernelSpec.sha256(source)
            check(checks.values.all { it }) { "MATRIX_ASSERTION" }
            check(File(workspace, "generated-recovery").deleteRecursively()) { "MATRIX_RECOVERY_CLEANUP" }
        } catch (failure: Throwable) {
            error = failure.message.orEmpty().substringBefore('\n').take(180)
        }
        val passed = error.isEmpty() && checks.isNotEmpty() && checks.values.all { it }
        results += buildJsonObject {
            put("path", path)
            put("passed", passed)
            put("release", release)
            put("headerVersion", header)
            put("compression", compression)
            put("sourceSha256", sourceHash)
            put("candidateSha256", candidateHash)
            put("checks", buildJsonObject { checks.forEach { (name, value) -> put(name, value) } })
            put("error", error)
        }
        println("${if (passed) "PASS" else "FAIL"} image=$index release=$release checks=${checks.size} $error")
        File(output, "matrix.json").writeText(Json { prettyPrint = true }.encodeToString(JsonObject.serializer(),
            buildJsonObject {
                put("passed", results.size == sources.size && results.all { it["passed"]!!.jsonPrimitive.boolean })
                put("deviceAccess", false)
                put("partitionTarget", "host-regular-file")
                put("deviceBootTestPerformed", false)
                put("results", JsonArray(results))
            }) + "\n")
    }
    check(results.all { it["passed"]!!.jsonPrimitive.boolean }) { "MATRIX_FAILED" }
}
