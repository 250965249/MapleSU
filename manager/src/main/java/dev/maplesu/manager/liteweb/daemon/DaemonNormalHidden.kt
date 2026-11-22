package dev.maplesu.manager.liteweb.daemon

import dev.maplesu.manager.liteweb.LiteHiddenPort
import dev.maplesu.manager.liteweb.LiteHiddenResult
import dev.maplesu.manager.recovery.RecoveryBundle
import dev.maplesu.manager.recovery.RecoveryCleanupResult
import dev.maplesu.manager.recovery.RecoveryPaths
import dev.maplesu.manager.litehidden.ParasitePaths
import java.io.File

/** Every call starts a fresh helper which acquires its own KSU driver FD and uses the root valve. */
class DaemonNormalKernel(private val shell: DaemonShell = DaemonRuntimeShell) {
    fun ready(): Boolean = execute("readiness") != null
    fun state(): Boolean? = execute("state")
    fun set(enabled: Boolean): Boolean = execute(if (enabled) "on" else "off") == enabled

    private fun execute(operation: String): Boolean? = runCatching {
        val result = shell.run("'${RecoveryPaths.LIB_DIR}/libksud_ksu.so' normal-recovery $operation")
        val lines = result.output.lineSequence().map(String::trim).filter { it.startsWith(MARKER) }.toList()
        if (result.code != 0 || lines.size != 1) return null
        when (lines.single()) {
            "$MARKER operation=$operation stealth=0" -> false
            "$MARKER operation=$operation stealth=1" -> true
            else -> null
        }
    }.getOrNull()

    private companion object { const val MARKER = "MAPLESU_NORMAL_RECOVERY_V1" }
}

/** Fixed Normal transaction: prove independent restoration, hide, then synchronously remove the manager. */
class DaemonNormalHidden(
    private val bundle: RecoveryBundle,
    private val mode: () -> String?,
    private val kernel: DaemonNormalKernel,
    private val hiddenFile: LiteHiddenPort,
    private val uninstall: () -> String,
    private val hostBackupsAbsent: () -> Boolean = {
        val root = File(ParasitePaths.HOST_BACKUP_ROOT)
        !root.exists() || root.listFiles()?.none {
            File(it, ParasitePaths.MANIFEST_NAME).exists() || File(it, ParasitePaths.BACKUP_MARKER_NAME).exists()
        } == true
    },
    private val independentCodeReady: () -> Boolean = { DaemonRecoveryCode.ready() },
    private val bootReady: () -> Boolean = {
        val file = File(dev.maplesu.manager.litehidden.NormalRecoveryBoot.PATH)
        file.isFile && file.canExecute() && file.readText() == dev.maplesu.manager.litehidden.NormalRecoveryBoot.content()
    },
    private val managerInstalled: () -> Boolean? = { null },
) {
    fun ready(): Boolean = runCatching {
        val verified = bundle.verify()
        val manifest = verified.manifest
        mode() == "KSU" && independentCodeReady() && bootReady() && hostBackupsAbsent() && verified.ok && manifest?.packageName == DaemonManagerUninstall.PACKAGE &&
            manifest.items.any { it.role == "NORMAL_RECOVERY_HELPER" && it.relativePath == "lib/libksud_ksu.so" } && kernel.ready()
    }.getOrDefault(false)

    @Synchronized
    fun activate(): String {
        if (!ready()) return failure("NORMAL_INDEPENDENT_RECOVERY_UNVERIFIED")
        val previous = kernel.state() ?: return failure("NORMAL_KERNEL_STATE_UNAVAILABLE")
        val previousFile = hiddenFile.currentHidden()
        if (!kernel.set(true) || kernel.state() != true) {
            return failure(if (rollback(previous, previousFile)) "NORMAL_STEALTH_ON_UNVERIFIED" else "NORMAL_STEALTH_ROLLBACK_FAILED")
        }
        val written = hiddenFile.setHidden(true, null)
        if (written !is LiteHiddenResult.Ok || hiddenFile.currentHidden() != true) {
            return failure(if (rollback(previous, previousFile)) "NORMAL_HIDDEN_STATE_UNVERIFIED" else "NORMAL_STEALTH_ROLLBACK_FAILED")
        }
        val result = runCatching(uninstall).getOrNull()
        if (result == SUCCESS) return result
        // PM may have removed the app before a later receipt/readback failure. Preserve boot recovery
        // unless a fresh PM query proves that the manager is still installed.
        if (runCatching(managerInstalled).getOrNull() != true) return failure("NORMAL_UNINSTALL_UNVERIFIED")
        val reverted = rollback(previous, previousFile)
        return failure(if (reverted) "NORMAL_UNINSTALL_UNVERIFIED" else "NORMAL_STEALTH_ROLLBACK_FAILED")
    }

    private fun rollback(previous: Boolean, previousFile: Boolean?): Boolean {
        val kernelOk = kernel.set(previous) && kernel.state() == previous
        val file = previousFile ?: false
        hiddenFile.setHidden(file, null)
        return kernelOk && hiddenFile.currentHidden() == file
    }

    /** Full restore is not complete until the actual cached kernel state is read back OFF. */
    fun restoreKernel(): RecoveryCleanupResult {
        if (mode() != "KSU" || !runCatching(hostBackupsAbsent).getOrDefault(false)) {
            return RecoveryCleanupResult(false, "NORMAL_RECOVERY_MODE_MISMATCH")
        }
        if (!kernel.set(false) || kernel.state() != false) {
            return RecoveryCleanupResult(false, "NORMAL_STEALTH_OFF_UNVERIFIED", listOf("kernel_stealth_off:failed"))
        }
        return RecoveryCleanupResult(true, steps = listOf("kernel_stealth_off:ok"))
    }

    fun removeBootEntry(shell: DaemonShell = DaemonRuntimeShell): RecoveryCleanupResult {
        val result = runCatching { shell.run(dev.maplesu.manager.litehidden.NormalRecoveryBoot.removeScript()) }.getOrNull()
        val ok = result?.code == 0 && result.output.lineSequence().count { it.trim() == dev.maplesu.manager.litehidden.NormalRecoveryBoot.REMOVED } == 1
        return RecoveryCleanupResult(ok, if (ok) "" else "NORMAL_BOOT_CLEANUP_FAILED", listOf("normal_boot_cleanup:${if (ok) "ok" else "failed"}"))
    }

    private fun failure(code: String) = """{"ok":false,"code":"$code"}"""

    companion object {
        const val SUCCESS = """{"ok":true,"state":"absent","data":"retained"}"""
    }
}

internal fun daemonModeSuperuserPort(
    mode: String?,
    ultraPort: () -> dev.maplesu.manager.liteweb.LiteWebSuperuserPort,
    normalPort: () -> dev.maplesu.manager.liteweb.LiteWebSuperuserPort = { DaemonNormalSuperuserPort(DaemonRuntimeShell) },
): dev.maplesu.manager.liteweb.LiteWebSuperuserPort =
    when (mode) {
        "LITE" -> ultraPort()
        "KSU" -> normalPort()
        else -> dev.maplesu.manager.liteweb.UnavailableSuperuserPort
    }

class DaemonNormalRuntimeFacts(private val kernel: DaemonNormalKernel) : DaemonRuntimeSource {
    override fun snapshot(): DaemonRuntimeSnapshot = if (kernel.state() != null) {
        DaemonRuntimeSnapshot(mode = "KSU", rootBackend = "KSU", probe = "Running", source = "normal_recovery_helper")
    } else DaemonRuntimeSnapshot()

    override fun ultraModules() = DaemonModulesSnapshot(error = "NORMAL_HAS_NO_ULTRA_MODULES")
}
