package dev.maplesu.manager.workmode.service

import dev.maplesu.manager.installer.InstallerDeviceLock
import dev.maplesu.manager.installer.InstallerPending
import dev.maplesu.manager.workmode.control.ControlPermissions
import dev.maplesu.manager.workmode.switch.HookResult
import java.io.Closeable
import java.io.File
import java.io.FileOutputStream
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.util.Properties

/** One root-owned lease spans teardown, data moves, partition writes and compensation. */
internal class ModeSwitchRootLease(
    private val root: File = InstallerDeviceLock.defaultRoot,
    private val acquireLock: () -> Closeable = { InstallerDeviceLock.acquire(root) },
    private val syncDirectory: (File) -> Unit = InstallerDeviceLock::syncStateDirectory,
    private val recoveryRoot: File = File(InstallerPending.MODE_SWITCH_RECOVERY_ROOT),
) : Closeable {
    private var held: Closeable? = null
    private var switchId: String? = null

    @Synchronized
    fun acquire(id: String): HookResult {
        if (!valid(id)) return HookResult.failed("INSTALLER_TASK_INVALID")
        if (held != null) return if (switchId == id) HookResult.OK else HookResult.failed(BUSY)
        var acquired: Closeable? = null
        return try {
            acquired = acquireLock()
            // Owning the kernel lock proves that no previous writer is running. In particular,
            // do not cancel this switch's own native PREPARED task while acquiring its lease.
            var parent: File? = recoveryRoot.absoluteFile
            while (parent != null) {
                check(!Files.isSymbolicLink(parent.toPath())) { "INSTALLER_STATE_DIRECTORY_INVALID" }
                parent = parent.parentFile
            }
            ControlPermissions.ensureDir(recoveryRoot)
            ControlPermissions.setPermissions(recoveryRoot, 0x1c0)
            ControlPermissions.requirePrivateDir(recoveryRoot)
            // Publish outside the SDK's cleanup tree before its legacy companion.
            publish(recoveryRoot, id)
            publish(root, id)
            held = acquired
            switchId = id
            acquired = null
            HookResult.OK
        } catch (error: Exception) {
            HookResult.failed(error.message?.takeIf { it.matches(Regex("[A-Z_]+")) } ?: BUSY)
        } finally { acquired?.close() }
    }

    @Synchronized
    fun release(id: String): HookResult {
        if (!valid(id)) return HookResult.failed("INSTALLER_TASK_INVALID")
        if (switchId != null && switchId != id) return HookResult.failed(BUSY)
        return try {
            // Even an idempotent release checks the record while owning the same kernel lock.
            if (held == null) {
                held = acquireLock()
                switchId = id
            }
            val file = File(root, InstallerPending.MODE_SWITCH_LEASE_FILE)
            check(!file.exists() || file.delete()) { "INSTALLER_MODE_SWITCH_LEASE_CLEAR_FAILED" }
            if (root.exists()) syncDirectory(root)
            val durable = File(recoveryRoot, InstallerPending.MODE_SWITCH_LEASE_FILE)
            check(!durable.exists() || durable.delete()) { "INSTALLER_MODE_SWITCH_LEASE_CLEAR_FAILED" }
            if (recoveryRoot.exists()) syncDirectory(recoveryRoot)
            HookResult.OK
        } catch (error: Exception) {
            HookResult.failed(error.message?.takeIf { it.matches(Regex("[A-Z_]+")) } ?: "INSTALLER_MODE_SWITCH_LEASE_CLEAR_FAILED")
        } finally { close() }
    }

    @Synchronized
    fun isHeld(): Boolean = held != null

    /** Binder image operations for this switch reuse the exact lock held by the helper.
     * Other tasks still acquire normally and encounter the kernel lock. */
    @Synchronized
    fun <T> withInstallLock(id: String, action: () -> T): T =
        if (held != null && switchId == id) InstallerDeviceLock.withHeldLease(root, action) else action()

    /** Process teardown releases the descriptor, while recovery intent remains on disk. */
    @Synchronized
    override fun close() {
        try { held?.close() } finally { held = null; switchId = null }
    }

    private fun publish(directory: File, id: String) {
        val file = File(directory, InstallerPending.MODE_SWITCH_LEASE_FILE)
        val staging = File(directory, file.name + ".new")
        FileOutputStream(staging).use { output ->
            Properties().apply { setProperty("switchId", id) }.store(output, null)
            output.fd.sync()
        }
        Files.move(staging.toPath(), file.toPath(), StandardCopyOption.REPLACE_EXISTING,
            StandardCopyOption.ATOMIC_MOVE)
        syncDirectory(directory)
    }

    private fun valid(id: String) = id.matches(Regex("[0-9a-fA-F-]{36}"))

    companion object { const val BUSY = "INSTALLER_TRANSACTION_BUSY" }
}
