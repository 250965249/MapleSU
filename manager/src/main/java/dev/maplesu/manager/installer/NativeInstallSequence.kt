package dev.maplesu.manager.installer

import dev.maplesu.installer.BlockDeviceTransaction
import java.io.File
import java.io.IOException
import java.nio.file.Files
import java.nio.file.LinkOption

/** Pure multi-partition ordering around the existing full-write/readback/PRE primitive. */
internal object NativeInstallSequence {
    data class Image(val partition: String, val file: File, val sha256: String)
    data class Outcome(val state: String, val error: String = "")
    fun interface Journal { fun record(state: String, error: String, attempted: List<String>) }

    fun commit(
        devices: Map<String, BlockDeviceTransaction.Device>,
        pre: Map<String, Image>,
        writes: List<Image>,
        journal: Journal,
        beforeReboot: () -> Unit = {},
    ): Outcome {
        require(devices.keys.isNotEmpty() && devices.keys.all { it in setOf("boot", "init_boot", "vendor_boot", "recovery", "vbmeta_system", "vbmeta") })
        require(pre.keys == devices.keys && writes.isNotEmpty() &&
            writes.all { it.partition in devices } && writes.map { it.partition }.distinct().size == writes.size)
        val attempted = mutableListOf<String>()
        try {
            pre.forEach { (name, image) -> verify(image, devices.getValue(name), full = true) }
            writes.forEach { verify(it, devices.getValue(it.partition), full = false) }
            devices.forEach { (name, device) ->
                device.revalidate()
                check(BlockDeviceTransaction.digest(device) == pre.getValue(name).sha256) { "INSTALLER_PARTITION_CHANGED" }
            }
            // Compare the bytes the writer would persist, including a compact image's zero tail.
            // Keep all candidates in the validation/readback set; only changed partitions are written.
            val changed = writes.filter { image ->
                BlockDeviceTransaction.paddedDigest(image.file.toPath(), devices.getValue(image.partition).size()) !=
                    pre.getValue(image.partition).sha256
            }
            changed.forEach { image ->
                val device = devices.getValue(image.partition)
                journal.record("WRITING", "", attempted + image.partition)
                attempted += image.partition
                val original = pre.getValue(image.partition)
                val result = BlockDeviceTransaction.commit(device, image.file.toPath(), image.sha256,
                    original.file.toPath(), original.sha256) { state, error ->
                    if (state in setOf("WRITING", "RESTORING", "RECOVERY_REQUIRED")) journal.record(state, error, attempted)
                }
                if (result.state != "REBOOT_REQUIRED") throw IOException(result.error.ifEmpty { "INSTALLER_WRITE_FAILED" })
            }
            devices.forEach { (name, device) ->
                device.revalidate()
                val image = writes.firstOrNull { it.partition == name } ?: pre.getValue(name)
                check(BlockDeviceTransaction.digest(device) == BlockDeviceTransaction.paddedDigest(image.file.toPath(), device.size())) {
                    "INSTALLER_READBACK_MISMATCH"
                }
            }
            beforeReboot()
            journal.record("REBOOT_REQUIRED", "", attempted)
            return Outcome("REBOOT_REQUIRED")
        } catch (error: Exception) {
            val reason = code(error)
            if (attempted.isEmpty()) {
                // No partition has been touched even if persisting this terminal state fails.
                runCatching { journal.record("FAILED_BEFORE_WRITE", reason, emptyList()) }
                return Outcome("FAILED_BEFORE_WRITE", reason)
            }
            return restore(devices, pre, attempted, journal, reason)
        }
    }

    fun restore(
        devices: Map<String, BlockDeviceTransaction.Device>,
        pre: Map<String, Image>,
        writeOrder: List<String>,
        journal: Journal,
        reason: String = "INSTALLER_RECOVERED",
    ): Outcome {
        val interrupted = Thread.interrupted()
        var failed = false
        fun record(state: String) {
            try { journal.record(state, reason, writeOrder) } catch (_: Exception) { failed = true }
        }
        try {
            // Validate every recovery file before the first recovery write.
            check(pre.keys == devices.keys && writeOrder.all { it in devices }) { "INSTALLER_IMAGE_CHANGED" }
            pre.forEach { (name, image) -> verify(image, devices.getValue(name), full = true) }
            record("RESTORING")
            writeOrder.distinct().asReversed().forEach { name ->
                try {
                    val original = pre.getValue(name)
                    BlockDeviceTransaction.restore(devices.getValue(name), original.file.toPath(), original.sha256) { _, _ ->
                        // A journal failure must never strand an already-written partition.
                        record("RESTORING")
                    }
                } catch (_: Exception) { failed = true }
            }
            devices.forEach { (name, device) ->
                try {
                    device.revalidate()
                    if (BlockDeviceTransaction.digest(device) != pre.getValue(name).sha256) failed = true
                } catch (_: Exception) { failed = true }
            }
        } catch (_: Exception) { failed = true }
        finally { if (interrupted) Thread.currentThread().interrupt() }
        val finalState = if (failed) "RECOVERY_REQUIRED" else "RESTORED"
        record(finalState)
        if (failed && finalState == "RESTORED") record("RECOVERY_REQUIRED")
        return Outcome(if (failed) "RECOVERY_REQUIRED" else "RESTORED", reason)
    }

    private fun verify(image: Image, device: BlockDeviceTransaction.Device, full: Boolean) {
        check(Files.isRegularFile(image.file.toPath(), LinkOption.NOFOLLOW_LINKS) &&
            image.file.length() in 1..device.size() && (!full || image.file.length() == device.size()) &&
            image.sha256.matches(Regex("[0-9a-f]{64}")) &&
            BlockDeviceTransaction.paddedDigest(image.file.toPath(), image.file.length()) == image.sha256) {
            "INSTALLER_IMAGE_CHANGED"
        }
    }

    private fun code(error: Exception) = error.message?.takeIf { it.matches(Regex("INSTALLER_[A-Z_]+")) }
        ?: "INSTALLER_WRITE_FAILED"
}
