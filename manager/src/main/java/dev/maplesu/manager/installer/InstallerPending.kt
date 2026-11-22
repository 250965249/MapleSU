package dev.maplesu.manager.installer

import org.json.JSONObject
import java.io.File
import java.io.IOException
import java.nio.file.Files
import java.util.Properties

/**
 * Recovery-state interpretation and live writer exclusion shared by both partition writers.
 * A journal survives process death/reinstallation; it is never evidence of a running writer.
 */
internal object InstallerPending {
    const val MODE_SWITCH_LEASE_FILE = "mode-switch-lease.properties"
    const val MODE_SWITCH_RECOVERY_ROOT = "/data/local/maplesu-recovery"
    fun signedInstallRoot(recoveryRoot: File = File(MODE_SWITCH_RECOVERY_ROOT)) = File(recoveryRoot, "signed-installs")
    /** Boot-install states eligible for recovery reconciliation. */
    val installActiveStates = setOf("PREPARING", "PREPARED", "WRITING", "RESTORING", "RECOVERY_REQUIRED")

    /** Non-terminal switch states retained for recovery and status. */
    val switchPendingStates = setOf("BEGIN", "SNAPSHOT", "PRODUCE", "COMMIT", "REBOOT_REQUIRED",
        "VERIFYING", "ROLLING_BACK", "RECOVERY_REQUIRED")

    /** Completed switch states (§3.2 `TERMINAL_STATES`). */
    val switchTerminalStates = setOf("VERIFIED", "ROLLED_BACK", "FAILED_PRE_WRITE", "CANCELLED")

    fun isPendingInstallState(state: String?): Boolean = state != null && state in installActiveStates

    fun isPendingSwitchState(state: String?): Boolean = state != null && state in switchPendingStates

    /** Full-image reconciliation under the device lock; a status read preserves preparations. */
    fun reconciledInstallState(record: JSONObject, snapshot: InstallerSnapshot?, currentBootId: String,
                               cancelPrepared: Boolean = true): String? {
        val state = record.optString("state")
        if (!isPendingInstallState(state)) return null
        if (state == "PREPARING" || state == "PREPARED") return if (cancelPrepared) "CANCELLED" else null
        snapshot ?: return null
        val before = record.optJSONObject("snapshot") ?: record
        if (before.optString("slotSuffix") != snapshot.slotSuffix ||
            before.optString("firmware") != snapshot.firmware) return null
        val partitions = before.optJSONObject("partitions") ?: return null
        val signing = when (record.optString("signingMode")) {
            "AOSP" -> setOf("recovery", "vbmeta_system", "vbmeta")
            "NON_CHAINED", "CHAINED" -> setOf("vbmeta")
            else -> emptySet()
        }
        val tracked = setOf("boot", "init_boot") + signing +
            if (partitions.has("vendor_boot")) setOf("vendor_boot") else emptySet()
        val names = partitions.keys().asSequence().filter { it in tracked }.toList()
        if ("boot" !in names || names.toSet() != snapshot.partitions.keys.filter { it in tracked }.toSet()) return null
        if (names.any { name -> partitions.getJSONObject(name).optLong("size") != snapshot.partitions.getValue(name).size }) return null
        // rdev/inode can change across boots; full image digests, sizes, firmware and slot are stable.
        if (names.all { name -> partitions.getJSONObject(name).optString("sha256") == snapshot.partitions.getValue(name).sha256 }) {
            return "RESTORED"
        }
        val expected = record.optJSONObject("expected")
        if (names.any { name ->
                val hash = expected?.optString(name) ?: if (name == "boot") record.optString("expectedSha256")
                    else partitions.getJSONObject(name).optString("sha256")
                hash != snapshot.partitions.getValue(name).sha256
            }) return null
        val initialBootId = record.optString("bootId")
        if (initialBootId.isBlank() || currentBootId.isBlank()) return null
        return if (initialBootId == currentBootId) "REBOOT_REQUIRED" else "BOOT_IMAGE_VERIFIED"
    }

    /** Legacy entry name: exclusion belongs to the live writer, never to an on-disk state. */
    @Suppress("UNUSED_PARAMETER")
    fun assertNoPendingInstall(installerRoot: File, sameSwitchId: String = "",
                               recoveryRoot: File = File(MODE_SWITCH_RECOVERY_ROOT)) {
        InstallerDeviceLock.assertNoActiveWriter(installerRoot)
    }

    /**
     * A previous switch is recovery evidence, not a lease on future writes. The physical lock
     * covers both writers, including a helper that is still running in another process.
     */
    @Suppress("UNUSED_PARAMETER")
    fun assertNoPendingSwitch(control: File, sameSwitchId: String = "",
                              installerRoot: File = InstallerDeviceLock.defaultRoot,
                              recoveryRoot: File = File(MODE_SWITCH_RECOVERY_ROOT)) {
        InstallerDeviceLock.assertNoActiveWriter(installerRoot)
    }

    fun modeSwitchLeaseId(installerRoot: File,
                          recoveryRoot: File = File(MODE_SWITCH_RECOVERY_ROOT)): String? {
        val legacy = readLeaseAt(installerRoot)
        val recovery = readLeaseAt(recoveryRoot)
        if (legacy != null && recovery != null && legacy != recovery) {
            throw IOException("INSTALLER_MODE_SWITCH_LEASE_INVALID")
        }
        return recovery ?: legacy
    }

    private fun readLeaseAt(directory: File): String? {
        val file = File(directory, MODE_SWITCH_LEASE_FILE)
        if (!file.exists() && !Files.isSymbolicLink(file.toPath())) return null
        try {
            check(file.isFile && !Files.isSymbolicLink(file.toPath()) && file.length() in 1..4096)
            val properties = Properties().apply { file.inputStream().use(::load) }
            return properties.getProperty("switchId").also {
                check(it != null && it.matches(Regex("[0-9a-fA-F-]{36}")))
            }
        } catch (error: Exception) {
            throw IOException("INSTALLER_MODE_SWITCH_LEASE_INVALID", error)
        }
    }

}
