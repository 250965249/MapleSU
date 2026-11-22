package dev.maplesu.manager.installer

import android.system.Os
import android.system.OsConstants
import dev.maplesu.installer.BlockDeviceTransaction
import java.io.File
import java.nio.file.Files

// Replace only JNI and Android transport. Compile the production access class, writable adapter,
// snapshot types and complete commit/readback/rollback transaction without rewriting their logic.
internal object BlockPartitionControl { fun readOnly(descriptor: Int, desired: Int) = Os.control(descriptor, desired) }
internal object InstallerPartitionReader {
    fun verifyRuntime(snapshot: InstallerSnapshot, requireKernel: Boolean) {
        check(snapshot.kernelRelease == "fixture" && requireKernel)
    }
}

fun main() {
    val directory = Files.createTempDirectory("maplesu-block-access-").toFile()
    var passed = 0
    val failures = mutableListOf<String>()
    try {
        fun case(name: String, action: () -> Unit) {
            try {
                action(); passed++
                println("PASS $name")
            } catch (error: Throwable) {
                failures += "$name: ${error.message}"
                println("FAIL ${failures.last()}")
            }
        }
        fun commit(flag: Int, locked: Boolean, configure: () -> Unit = {}, expectedState: String = "REBOOT_REQUIRED",
                   expectedError: String = ""): Int {
            Os.reset(flag, locked); configure()
            val original = Os.bytes.clone()
            val recovery = File(directory, "pre.img").apply { writeBytes(original) }
            val candidate = File(directory, "candidate.img").apply { writeBytes(ByteArray(4096) { 8 }) }
            val path = File(directory, "block").canonicalPath
            val hash = BlockDeviceTransaction.paddedDigest(recovery.toPath(), original.size.toLong())
            val snapshot = InstallerSnapshot("fixture", "fixture", "", "Enforcing", mapOf("boot" to
                BootPartitionSnapshot("boot", path, path, original.size.toLong(), hash, BootPartitionIdentity(5, 7, 9))))
            val result = AndroidWritablePartition(snapshot, "boot").open().use { device ->
                BlockDeviceTransaction.commit(device, candidate.toPath(),
                    BlockDeviceTransaction.paddedDigest(candidate.toPath(), candidate.length()), recovery.toPath(), hash) { _, _ -> }
            }
            check(result.state == expectedState && result.error == expectedError) {
                "flag=$flag driverLocked=$locked expected=$expectedState/$expectedError actual=${result.state}/${result.error}"
            }
            check(Os.readOnly == flag) { "original block flag was not restored" }
            check(Os.descriptors.isEmpty()) { "descriptor leaked after transaction" }
            if (expectedState == "REBOOT_REQUIRED") {
                val expected = ByteArray(original.size).also { ByteArray(4096) { 8 }.copyInto(it) }
                check(Os.bytes.contentEquals(expected)) { "full transaction/readback mismatch" }
            } else check(Os.bytes.contentEquals(original)) { "failed transaction did not restore PRE" }
            return Os.sets
        }
        case("dispatch-clear-even-when-flag-is-zero") { check(commit(0, true) == 1) }
        case("ordinary-writable-partition") { check(commit(0, false) == 1) }
        case("restore-initial-readonly-flag") { check(commit(1, true) == 3) }
        case("query-error") {
            commit(0, false, { Os.queryError = OsConstants.ENOTTY }, "RESTORED", "INSTALLER_PARTITION_WRITE_PREPARE_FAILED")
        }
        case("set-error") {
            commit(0, false, { Os.setError = OsConstants.EACCES }, "RESTORED", "INSTALLER_PARTITION_WRITE_PREPARE_FAILED")
        }
        case("write-open-denied") {
            commit(1, true, { Os.denyWriteOpen = true }, "RESTORED", "INSTALLER_DEVICE_IO_FAILED")
        }
        case("partial-write-rollback") {
            commit(0, true, { Os.failWriteAt = 2 }, "RESTORED", "INSTALLER_DEVICE_IO_FAILED")
        }
        case("readonly-partial-write-rollback") {
            commit(1, true, { Os.failWriteAt = 2 }, "RESTORED", "INSTALLER_DEVICE_IO_FAILED")
        }
        case("write-only-open-like-ksu") { commit(0, false, { Os.denyReadWriteOpen = true }) }
        case("clear-after-writer-open-like-ksu") { commit(0, false, { Os.lockOnWriteOpen = true }) }
        case("clear-through-writer-like-ksu") { commit(0, false, { Os.requireWritableControl = true }) }
        case("readonly-clear-after-writer-open") { commit(1, true, { Os.lockOnWriteOpen = true }) }
        case("writer-control-failure-restores-flag") {
            commit(1, true, { Os.writeControlError = OsConstants.EPERM }, "RESTORED", "INSTALLER_PARTITION_WRITE_PREPARE_FAILED")
        }
        case("writer-identity-checked-before-control") {
            check(commit(0, false, { Os.writeIdentityChanged = true }, "RESTORED", "INSTALLER_PARTITION_CHANGED") == 0)
        }
        case("write-handle-sync-failure-rolls-back") {
            commit(0, false, { Os.failSyncAt = 1 }, "RESTORED", "INSTALLER_DEVICE_IO_FAILED")
        }
        case("combined-writer-contract") {
            commit(0, true, { Os.denyReadWriteOpen = true; Os.lockOnWriteOpen = true; Os.requireWritableControl = true })
        }
        case("revalidation-keeps-both-identities-bound") {
            Os.reset(0, false)
            val observed = mutableListOf<Int>()
            BlockPartitionAccess(File(directory, "identities").canonicalPath, true, {
                observed += Os.descriptors.getValue(it).mode
            }).use { access ->
                val writer = access.writableDescriptor()
                observed.clear()
                access.revalidate()
                check(observed == listOf(OsConstants.O_RDONLY, OsConstants.O_WRONLY))
                check(access.descriptor !== writer && Os.descriptors.getValue(writer).mode == OsConstants.O_WRONLY)
            }
            check(Os.descriptors.isEmpty())
        }
        case("read-only-observation-does-not-prepare") {
            Os.reset(0, true)
            BlockPartitionAccess(File(directory, "readonly").canonicalPath, false, {}).use {
                check(Os.sets == 0)
                val error = runCatching { it.writableDescriptor() }.exceptionOrNull()
                check(error?.message == "INSTALLER_READ_ONLY" && Os.sets == 0)
            }
            check(Os.descriptors.isEmpty())
        }
        println("BlockPartitionAccess: $passed passed, ${failures.size} failed; no device access")
        check(failures.isEmpty()) { failures.joinToString("\n") }
    } finally { directory.deleteRecursively() }
}
