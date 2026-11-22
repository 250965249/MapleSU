package dev.maplesu.manager.installer

import android.os.Bundle
import android.os.ParcelFileDescriptor
import android.system.Os
import android.system.OsConstants
import dev.maplesu.image.BootImageRoundTrip
import dev.maplesu.installer.BlockDeviceTransaction
import org.json.JSONObject
import java.io.File
import java.io.FileDescriptor
import java.io.FileOutputStream
import java.io.IOException
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.util.UUID

/** Root-owned persistent tasks; only the current boot partition is a writable target. */
internal object InstallerBootTransaction {
    private val root = File("/data/adb/maplesu/installer")
    private val activeStates = setOf("WRITING", "RESTORING", "RECOVERY_REQUIRED")

    fun prepare(candidate: ParcelFileDescriptor, recovery: ParcelFileDescriptor,
                expected: Bundle, candidateSha256: String, taskId: String): Bundle = withLock {
        InstallerPending.assertNoPendingSwitch(File("/data/adb/maplesu-workmode"))
        require(UUID.fromString(taskId).toString() == taskId) { "INSTALLER_TASK_INVALID" }
        val existing = File(root, taskId)
        if (existing.exists()) {
            val record = readRecord(existing)
            check(record.getString("candidateSha256") == candidateSha256) { "INSTALLER_TASK_CONFLICT" }
            checkSnapshot(snapshot(record), expected, true, true)
            return@withLock response(record)
        }
        require(candidateSha256.matches(Regex("[0-9a-f]{64}"))) { "INSTALLER_HASH_INVALID" }
        val snapshot = InstallerServiceClient.decodeSnapshot(expected)
        require(snapshot.partitions.values.all { it.identity != null }) { "INSTALLER_DEVICE_IDENTITY_REQUIRED" }
        checkSnapshot(snapshot, InstallerPartitionReader.observe(), true, true)
        val boot = snapshot.partitions.getValue("boot")
        check(candidateSha256 != boot.sha256) { "INSTALLER_CANDIDATE_UNCHANGED" }
        val directory = File(root, taskId)
        check(directory.mkdir()) { "INSTALLER_TASK_CREATE_FAILED" }
        Os.chmod(directory.path, 0x1c0) // 0700
        syncDirectory(root)
        val record = JSONObject().apply {
            put("schema", 1)
            put("taskId", directory.name)
            put("state", "PREPARING")
            put("error", "")
            put("candidateSha256", candidateSha256)
            put("bootId", File("/proc/sys/kernel/random/boot_id").readText().trim())
            put("kernelRelease", snapshot.kernelRelease)
            put("firmware", snapshot.firmware)
            put("slotSuffix", snapshot.slotSuffix)
            // Recorded as evidence (2026-11-01). It is never compared before a write and never a
            // reason to refuse one; the value is only surfaced in status/records.
            put("selinux", snapshot.selinux)
            put("partitions", JSONObject().apply {
                snapshot.partitions.forEach { (name, partition) ->
                    val identity = requireNotNull(partition.identity)
                    put(name, JSONObject().apply {
                        put("resolvedPath", partition.resolvedPath)
                        put("size", partition.size)
                        put("sha256", partition.sha256)
                        put("deviceNumber", identity.deviceNumber)
                        put("inode", identity.inode)
                        put("filesystem", identity.filesystem)
                    })
                }
            })
        }
        try {
            save(directory, record)
            InstallerImageInput.copy(candidate, File(directory, "candidate.img"), boot.size)
            InstallerImageInput.copy(recovery, File(directory, "recovery.img"), boot.size)
            check(File(directory, "recovery.img").length() == boot.size &&
                BlockDeviceTransaction.paddedDigest(File(directory, "recovery.img").toPath(), boot.size) == boot.sha256) {
                "INSTALLER_RECOVERY_MISMATCH"
            }
            val image = File(directory, "candidate.img")
            check(BlockDeviceTransaction.paddedDigest(image.toPath(), image.length()) == candidateSha256) {
                "INSTALLER_CANDIDATE_CHANGED"
            }
            val verified = BootImageRoundTrip.verify(image, directory)
            check(verified.kernelRelease == snapshot.kernelRelease && verified.image.sha256 == candidateSha256) {
                "INSTALLER_CANDIDATE_KERNEL_MISMATCH"
            }
            record.put("expectedSha256", BlockDeviceTransaction.paddedDigest(image.toPath(), boot.size))
            checkSnapshot(snapshot, InstallerPartitionReader.observe(), true, true)
            record.put("state", "PREPARED")
            save(directory, record)
            response(record)
        } catch (error: Exception) {
            record.put("state", "FAILED_BEFORE_WRITE").put("error", errorCode(error))
            save(directory, record)
            throw error
        }
    }

    fun commit(taskId: String): Bundle = withLock {
        InstallerPending.assertNoPendingSwitch(File("/data/adb/maplesu-workmode"))
        val directory = taskDirectory(taskId)
        val record = readRecord(directory)
        if (record.getString("state") in setOf("REBOOT_REQUIRED", "REBOOT_REQUESTED", "BOOT_IMAGE_VERIFIED")) {
            val observed = InstallerPartitionReader.observe()
            rebindAfterBoot(record, observed, false, true)
            check(observed.getBundle("boot")?.getString("sha256") == record.getString("expectedSha256")) {
                "INSTALLER_PARTITION_CHANGED"
            }
            return@withLock response(record)
        }
        check(record.getString("state") == "PREPARED") { "INSTALLER_TRANSACTION_NOT_PREPARED" }
        val expected = snapshot(record)
        try {
            checkSnapshot(expected, InstallerPartitionReader.observe(), true, true)
            WritableBoot(expected).use { device ->
                BlockDeviceTransaction.commit(device, File(directory, "candidate.img").toPath(),
                    record.getString("candidateSha256"), File(directory, "recovery.img").toPath(),
                    expected.partitions.getValue("boot").sha256) { state, error ->
                    record.put("state", state).put("error", error)
                    save(directory, record)
                }
            }
        } catch (error: Exception) {
            finishFailure(directory, record, error)
        }
        response(record)
    }

    /** The exclusive operation/transaction locks exclude a live prepare or commit. No device is opened. */
    fun cancel(taskId: String): Bundle = withLock {
        val directory = taskDirectory(taskId)
        val record = readRecord(directory)
        if (record.getString("state") == "CANCELLED") return@withLock response(record)
        check(record.getString("state") in setOf("PREPARED", "PREPARING")) {
            "INSTALLER_CANCELLATION_NOT_ALLOWED"
        }
        record.put("state", "CANCELLED").put("error", "")
        save(directory, record)
        response(record)
    }

    // record.json is atomically replaced. Observation never waits for the writer lock.
    fun status(taskId: String): Bundle {
        if (!root.exists()) return emptyStatus(taskId)
        requirePrivateDirectory(root)
        val record = if (taskId.isNotEmpty()) {
            require(UUID.fromString(taskId).toString() == taskId) { "INSTALLER_TASK_INVALID" }
            val directory = File(root, taskId)
            if (!File(directory, "record.json").exists()) return emptyStatus(taskId)
            readRecord(directory)
        } else {
            root.listFiles().orEmpty().filter { it.isDirectory && File(it, "record.json").isFile }
                .sortedByDescending { File(it, "record.json").lastModified() }
                .map { readRecord(it) }.filter { it.optString("kind") != "NATIVE" }.firstOrNull { it.getString("state") in
                    activeStates + setOf("PREPARING", "PREPARED", "REBOOT_REQUIRED", "REBOOT_REQUESTED", "BOOT_IMAGE_VERIFIED") }
                ?: return emptyStatus(taskId)
        }
        return response(record)
    }

    private fun emptyStatus(taskId: String) = Bundle().apply {
        putString("taskId", taskId)
        putString("state", "NONE")
        putBoolean("rebootRequired", false)
    }

    fun verifyBoot(taskId: String): Bundle = withLock {
        val directory = taskDirectory(taskId)
        val record = readRecord(directory)
        check(record.getString("state") in setOf("REBOOT_REQUIRED", "REBOOT_REQUESTED", "BOOT_IMAGE_VERIFIED")) {
            "INSTALLER_VERIFICATION_NOT_READY"
        }
        check(record.getString("bootId") != currentBootId()) { "INSTALLER_REBOOT_NOT_OBSERVED" }
        val observed = InstallerPartitionReader.observe()
        rebindAfterBoot(record, observed, false, true)
        check(observed.getBundle("boot")?.getString("sha256") == record.getString("expectedSha256")) {
            "INSTALLER_PARTITION_CHANGED"
        }
        record.put("state", "BOOT_IMAGE_VERIFIED").put("verifiedBootId", currentBootId()).put("error", "")
        save(directory, record)
        response(record)
    }

    fun restore(taskId: String): Bundle = withLock {
        InstallerPending.assertNoPendingSwitch(File("/data/adb/maplesu-workmode"))
        val directory = taskDirectory(taskId)
        val record = readRecord(directory)
        if (record.getString("state") == "REBOOT_REQUESTED" && record.optString("rebootSourceState") == "RESTORED") {
            return@withLock response(record)
        }
        if (record.getString("state") == "RESTORED") return@withLock response(record)
        check(record.getString("state") in setOf("WRITING", "RESTORING", "RECOVERY_REQUIRED", "REBOOT_REQUIRED", "REBOOT_REQUESTED", "BOOT_IMAGE_VERIFIED")) {
            "INSTALLER_RECOVERY_NOT_REQUIRED"
        }
        val observed = InstallerPartitionReader.observe()
        val expected = rebindAfterBoot(record, observed, false, false)
        if (record.getString("state") in setOf("REBOOT_REQUIRED", "REBOOT_REQUESTED", "BOOT_IMAGE_VERIFIED")) {
            check(observed.getBundle("boot")?.getString("sha256") == record.getString("expectedSha256")) {
                "INSTALLER_PARTITION_CHANGED"
            }
        }
        record.put("restoreBootId", File("/proc/sys/kernel/random/boot_id").readText().trim())
        record.put("restoreRebootRequired", record.optString("bootId").isNotBlank() &&
            record.optString("bootId") != record.getString("restoreBootId"))
        try {
            WritableBoot(expected, false).use { device ->
                check(BlockDeviceTransaction.digest(device) == observed.getBundle("boot")?.getString("sha256")) {
                    "INSTALLER_PARTITION_CHANGED"
                }
                device.revalidate()
                BlockDeviceTransaction.restore(device, File(directory, "recovery.img").toPath(),
                    expected.partitions.getValue("boot").sha256) { state, error ->
                    record.put("state", state).put("error", error)
                    save(directory, record)
                }
            }
        } catch (error: Exception) {
            finishFailure(directory, record, error)
        }
        response(record)
    }

    fun reboot(taskId: String): Boolean = withLock {
        val directory = taskDirectory(taskId)
        val record = readRecord(directory)
        reconcileReboot(directory, record)
        val previousState = record.getString("state")
        val restored = previousState == "RESTORED" && record.optBoolean("restoreRebootRequired")
        check(previousState == "REBOOT_REQUIRED" || restored) { "INSTALLER_REBOOT_NOT_READY" }
        val requestBoot = record.optString(if (restored) "restoreBootId" else "bootId")
        check(requestBoot.isNotBlank() && requestBoot == File("/proc/sys/kernel/random/boot_id").readText().trim()) {
            "INSTALLER_REBOOT_ALREADY_OBSERVED"
        }
        val expected = rebindAfterBoot(record, InstallerPartitionReader.observe(), restored, !restored)
        WritableBoot(expected, !restored).use { device ->
            device.revalidate()
            val expectedHash = if (restored) expected.partitions.getValue("boot").sha256 else record.getString("expectedSha256")
            check(BlockDeviceTransaction.digest(device) == expectedHash) {
                "INSTALLER_PARTITION_CHANGED"
            }
            device.revalidate()
        }
        record.put("state", "REBOOT_REQUESTED").put("rebootSourceState", previousState)
            .put("rebootRequestUptimeMs", android.os.SystemClock.elapsedRealtime())
        save(directory, record)
        try {
            // Fixed normal reboot only; the caller supplies no command, reason or target.
            val command = ProcessBuilder("/system/bin/svc", "power", "reboot").start()
            if (command.waitFor(5, java.util.concurrent.TimeUnit.SECONDS) && command.exitValue() != 0) {
                record.put("state", previousState).put("error", "INSTALLER_REBOOT_FAILED")
                save(directory, record)
                false
            } else true
        } catch (error: Exception) {
            record.put("state", previousState).put("error", "INSTALLER_REBOOT_FAILED")
            save(directory, record)
            false
        }
    }

    private fun response(record: JSONObject) = Bundle().apply {
        val state = record.getString("state")
        val source = record.optString("rebootSourceState")
        val requestBoot = record.optString(if (source == "RESTORED") "restoreBootId" else "bootId")
        val requested = record.optLong("rebootRequestUptimeMs", -1)
        val timeout = state == "REBOOT_REQUESTED" && requested >= 0 && requestBoot == currentBootId() &&
            android.os.SystemClock.elapsedRealtime() - requested >= 30_000
        val restoredAfterReboot = state == "REBOOT_REQUESTED" && source == "RESTORED" &&
            requestBoot.isNotBlank() && requestBoot != currentBootId()
        val effectiveState = if (timeout || restoredAfterReboot) source else state
        putString("taskId", record.getString("taskId"))
        putString("state", effectiveState)
        putBoolean("canRestore", effectiveState in setOf("WRITING", "RESTORING", "RECOVERY_REQUIRED",
            "REBOOT_REQUIRED", "REBOOT_REQUESTED", "BOOT_IMAGE_VERIFIED"))
        putString("error", if (timeout) "INSTALLER_REBOOT_NOT_OBSERVED" else record.getString("error"))
        putString("rebootSourceState", source)
        putString("currentBootId", currentBootId())
        putBoolean("rebootRequired", effectiveState == "REBOOT_REQUIRED" && record.optString("bootId") == currentBootId() ||
            effectiveState == "RESTORED" && record.optBoolean("restoreRebootRequired") &&
            record.optString("restoreBootId") == currentBootId())
        putString("slotSuffix", record.getString("slotSuffix"))
        putString("partition", "boot")
        putString("candidateSha256", record.getString("candidateSha256"))
        putString("partitionSha256", record.optString("expectedSha256"))
        val previousBoot = record.optString("bootId")
        val currentBoot = File("/proc/sys/kernel/random/boot_id").readText().trim()
        val knownBoot = previousBoot.matches(Regex("[0-9a-fA-F-]{36}")) &&
            currentBoot.matches(Regex("[0-9a-fA-F-]{36}"))
        putBoolean("rebootObserved", knownBoot && previousBoot != currentBoot)
        putString("bootObservation", when {
            !knownBoot -> "UNKNOWN"
            previousBoot == currentBoot -> "SAME_BOOT"
            else -> "REBOOT_OBSERVED"
        })
    }

    private fun reconcileReboot(directory: File, record: JSONObject) {
        if (record.optString("state") != "REBOOT_REQUESTED") return
        val requested = record.optLong("rebootRequestUptimeMs", -1)
        val currentBoot = File("/proc/sys/kernel/random/boot_id").readText().trim()
        val previousState = record.optString("rebootSourceState", "REBOOT_REQUIRED")
        val requestBoot = record.optString(if (previousState == "RESTORED") "restoreBootId" else "bootId")
        // A service may die between persisting the request and launching svc. Permit a retry
        // only when the same boot has lasted beyond the normal request handoff period.
        if (requested >= 0 && requestBoot.isNotBlank() && requestBoot == currentBoot &&
            android.os.SystemClock.elapsedRealtime() - requested >= 30_000) {
            record.put("state", previousState).put("error", "INSTALLER_REBOOT_NOT_OBSERVED")
            save(directory, record)
        }
    }

    private fun currentBootId() = File("/proc/sys/kernel/random/boot_id").readText().trim().also {
        check(it.matches(Regex("[0-9a-fA-F-]{36}"))) { "INSTALLER_BOOT_ID_INVALID" }
    }

    // Across boots /dev inodes may change. Bind fresh identities only after stable devices,
    // firmware, slot and all unchanged partition hashes have been checked together.
    private fun rebindAfterBoot(record: JSONObject, observed: Bundle, bootHash: Boolean, kernel: Boolean): InstallerSnapshot {
        val expected = snapshot(record)
        if (record.getString("bootId") == currentBootId()) {
            checkSnapshot(expected, observed, bootHash, kernel)
            return expected
        }
        check(observed.getString("slotSuffix") == expected.slotSuffix &&
            observed.getString("firmware") == expected.firmware &&
            (!kernel || observed.getString("kernelRelease") == expected.kernelRelease) &&
            observed.getStringArrayList("partitions")?.toSet() == expected.partitions.keys) { "INSTALLER_DEVICE_CHANGED" }
        val rebound = expected.partitions.mapValues { (name, partition) ->
            val row = requireNotNull(observed.getBundle(name))
            check(row.getString("resolvedPath") == partition.resolvedPath && row.getLong("size") == partition.size &&
                row.getLong("deviceNumber") == requireNotNull(partition.identity).deviceNumber &&
                ((!bootHash && name == "boot") || row.getString("sha256") == partition.sha256)) {
                "INSTALLER_PARTITION_CHANGED"
            }
            partition.copy(identity = BootPartitionIdentity(row.getLong("deviceNumber"), row.getLong("inode"),
                row.getLong("filesystem")))
        }
        return InstallerSnapshot(expected.kernelRelease, expected.firmware, expected.slotSuffix, expected.selinux, rebound)
    }

    private fun snapshot(record: JSONObject): InstallerSnapshot {
        check(record.getInt("schema") == 1) { "INSTALLER_RECORD_INVALID" }
        val slot = InstallerSnapshotParser.slot(record.getString("slotSuffix"))
        val rows = record.getJSONObject("partitions")
        val partitions = rows.keys().asSequence().associateWith { name ->
            val row = rows.getJSONObject(name)
            InstallerSnapshotParser.partition(name, slot, row.getString("resolvedPath"),
                row.getLong("size").toString(),
                "${row.getString("sha256")}  ${InstallerSnapshotParser.partitionPath(name, slot)}",
                BootPartitionIdentity(row.getLong("deviceNumber"), row.getLong("inode"), row.getLong("filesystem")))
        }
        return InstallerSnapshot(record.getString("kernelRelease"), record.getString("firmware"), slot,
            record.optString("selinux", "Unknown"), partitions)
    }

    private fun checkSnapshot(expected: InstallerSnapshot, bundle: Bundle, bootHash: Boolean, kernel: Boolean) {
        // The service is the source here; decoding's app caller/pid checks belong at the Binder client.
        // `selinux` is deliberately not compared: recorded evidence, never a write gate.
        check(bundle.getString("slotSuffix") == expected.slotSuffix &&
            bundle.getString("firmware") == expected.firmware &&
            (!kernel || bundle.getString("kernelRelease") == expected.kernelRelease) &&
            bundle.getStringArrayList("partitions")?.toSet() == expected.partitions.keys) { "INSTALLER_DEVICE_CHANGED" }
        expected.partitions.forEach { (name, partition) ->
            val row = requireNotNull(bundle.getBundle(name))
            val identity = requireNotNull(partition.identity)
            check(row.getString("resolvedPath") == partition.resolvedPath && row.getLong("size") == partition.size &&
                row.getLong("deviceNumber") == identity.deviceNumber && row.getLong("inode") == identity.inode &&
                row.getLong("filesystem") == identity.filesystem &&
                ((!bootHash && name == "boot") || row.getString("sha256") == partition.sha256)) {
                "INSTALLER_PARTITION_CHANGED"
            }
        }
    }

    private fun taskDirectory(taskId: String): File {
        require(UUID.fromString(taskId).toString() == taskId) { "INSTALLER_TASK_INVALID" }
        val directory = File(root, taskId)
        requirePrivateDirectory(directory)
        return directory
    }

    private fun readRecord(directory: File): JSONObject {
        requirePrivateDirectory(directory)
        val file = File(directory, "record.json")
        check(file.length() in 1..64 * 1024) { "INSTALLER_RECORD_INVALID" }
        return JSONObject(file.readText()).also {
            check(it.getString("taskId") == directory.name) { "INSTALLER_RECORD_INVALID" }
        }
    }

    private fun save(directory: File, record: JSONObject) {
        try {
            val temporary = File(directory, "record.pending")
            FileOutputStream(temporary).use {
                Os.fchmod(it.fd, 0x180)
                it.write(record.toString().toByteArray(Charsets.UTF_8))
                it.fd.sync()
            }
            Files.move(temporary.toPath(), File(directory, "record.json").toPath(),
                StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
            syncDirectory(directory)
        } catch (error: android.system.ErrnoException) {
            throw IOException("INSTALLER_JOURNAL_WRITE_FAILED", error)
        }
    }

    /**
     * The single cross-process partition-write lock is install.lock (02-switch-contract §5.5).
     * The mechanics live in [InstallerDeviceLock] so the mode-switch service takes exactly the
     * same lock; this keeps the pre-existing boot-install behaviour unchanged.
     */
    private fun <T> withLock(action: () -> T): T = InstallerDeviceLock.withDeviceLock(root, action)

    private fun requirePrivateDirectory(directory: File) {
        val stat = Os.lstat(directory.path)
        check(OsConstants.S_ISDIR(stat.st_mode) && stat.st_uid == 0 && stat.st_mode and 0x3f == 0) {
            "INSTALLER_STATE_DIRECTORY_INVALID"
        }
    }

    private fun syncDirectory(directory: File) {
        val fd = Os.open(directory.path, OsConstants.O_RDONLY or OsConstants.O_CLOEXEC or OsConstants.O_NOFOLLOW, 0)
        try {
            check(OsConstants.S_ISDIR(Os.fstat(fd).st_mode)) { "INSTALLER_STATE_DIRECTORY_INVALID" }
            Os.fsync(fd)
        } finally { Os.close(fd) }
    }

    private fun errorCode(error: Exception): String = error.message?.takeIf {
        it.matches(Regex("INSTALLER_[A-Z_]+"))
    } ?: "INSTALLER_OPERATION_FAILED"

    private fun finishFailure(directory: File, record: JSONObject, error: Exception) {
        when (record.getString("state")) {
            // sync, full readback and the durable final journal already succeeded. A later close
            // failure does not turn that verified result into an unverified partial write.
            "RESTORED", "REBOOT_REQUIRED", "REBOOT_REQUESTED" -> record.put("cleanupError", errorCode(error))
            "PREPARED" -> record.put("state", "FAILED_BEFORE_WRITE").put("error", errorCode(error))
            else -> record.put("state", "RECOVERY_REQUIRED").put("error", errorCode(error))
        }
        save(directory, record)
    }

    private class WritableBoot(private val snapshot: InstallerSnapshot, private val kernel: Boolean = true) :
        BlockDeviceTransaction.Device {
        private val partition = snapshot.partitions.getValue("boot")
        private val identity = requireNotNull(partition.identity)
        private val access = BlockPartitionAccess(partition.resolvedPath, true, ::verifyDescriptor)
        private val fd get() = access.descriptor
        override fun size() = partition.size
        override fun revalidate() = io { access.revalidate() }
        private fun verifyDescriptor(fd: FileDescriptor) {
            val stat = Os.fstat(fd)
            val link = Os.stat(partition.path)
            check(OsConstants.S_ISBLK(stat.st_mode) && OsConstants.S_ISBLK(link.st_mode) &&
                stat.st_rdev == identity.deviceNumber && stat.st_ino == identity.inode &&
                stat.st_dev == identity.filesystem && link.st_rdev == stat.st_rdev &&
                link.st_ino == stat.st_ino && link.st_dev == stat.st_dev &&
                File(partition.path).canonicalPath == partition.resolvedPath &&
                Os.lseek(fd, 0, OsConstants.SEEK_END) == partition.size) { "INSTALLER_PARTITION_CHANGED" }
            InstallerPartitionReader.verifyRuntime(snapshot, kernel)
        }
        override fun read(offset: Long, buffer: ByteArray, length: Int) = io { Os.pread(fd, buffer, 0, length, offset) }
        override fun write(offset: Long, buffer: ByteArray, start: Int, length: Int) =
            io { Os.pwrite(access.writableDescriptor(), buffer, start, length, offset) }
        override fun sync() = io { access.sync() }
        override fun close() = io { access.close() }

        private fun <T> io(action: () -> T): T = try { action() }
            catch (error: android.system.ErrnoException) { throw IOException("INSTALLER_DEVICE_IO_FAILED", error) }
            catch (error: InterruptedException) {
                Thread.currentThread().interrupt()
                throw IOException("INSTALLER_CANCELLED", error)
            }
    }
}
