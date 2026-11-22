package dev.maplesu.manager.recovery

import java.io.File
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.nio.file.attribute.PosixFilePermissions
import java.util.UUID

/** Root-only ticket. Web status deliberately exposes no confirmation secret. */
class ManagerRestoreHandover(
    private val ticket: File = File(PATH),
) {
    fun pending(): Boolean = read()?.first == "pending"

    fun confirmed(): Boolean = read()?.first == "confirmed"

    fun prepare(): RecoveryCleanupResult = runCatching {
        if (!pending()) write("pending", UUID.randomUUID().toString())
        check(pending())
        RecoveryCleanupResult(true, steps = listOf("await_manager_confirmation:pending"))
    }.getOrElse { RecoveryCleanupResult(false, "RECOVERY_HANDOVER_WRITE_FAILED") }

    fun confirm(
        nonce: String,
        managerReady: () -> Boolean,
        finalize: () -> RecoveryCleanupResult,
    ): RecoveryCleanupResult {
        val saved = read() ?: return RecoveryCleanupResult(false, "RECOVERY_HANDOVER_MISSING")
        if (nonce != saved.second) return RecoveryCleanupResult(false, "RECOVERY_HANDOVER_MISMATCH")
        if (saved.first == "confirmed") return RecoveryCleanupResult(true)
        if (!runCatching(managerReady).getOrDefault(false)) {
            return RecoveryCleanupResult(false, "RECOVERY_MANAGER_NOT_READY")
        }
        val finished = runCatching(finalize).getOrElse {
            RecoveryCleanupResult(false, "RECOVERY_CONFIRM_EXCEPTION")
        }
        if (!finished.ok) return finished
        return runCatching {
            write("confirmed", nonce)
            check(read() == ("confirmed" to nonce))
            finished
        }.getOrElse { RecoveryCleanupResult(false, "RECOVERY_HANDOVER_WRITE_FAILED") }
    }

    private fun read(): Pair<String, String>? = runCatching {
        LINE.matchEntire(ticket.readText().trim())?.let { it.groupValues[1] to it.groupValues[2] }
    }.getOrNull()

    private fun write(stage: String, nonce: String) {
        ticket.parentFile?.mkdirs()
        val temp = File(ticket.path + ".tmp")
        temp.writeText("$stage:$nonce\n")
        try {
            Files.setPosixFilePermissions(temp.toPath(), PosixFilePermissions.fromString("rw-------"))
        } catch (_: UnsupportedOperationException) {
            // Windows host fixtures have no POSIX permissions; the device filesystem does.
        }
        Files.move(temp.toPath(), ticket.toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
    }

    companion object {
        const val PATH = "${RecoveryPaths.DIR}/manager-restore.ticket"
        val LINE = Regex("^(pending|confirmed):([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})$")
    }
}
