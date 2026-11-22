package dev.maplesu.manager.runtime

import android.content.Context
import dev.maplesu.manager.jailbreak.JailbreakDaemonCommand
import dev.maplesu.manager.jailbreak.JailbreakLeaseStore
import java.io.File
import java.io.IOException

/**
 * Starts the Root executor inside the authenticated lease and returns the local
 * AIDL proxy that speaks to it.
 *
 * DEV-10/DEV-11: the lease shell answers a direct command but never libsu's task
 * layer, so the launcher writes the launch line itself. The line ends with
 * `exec app_process64 ...`: the shell is *replaced* by the executor, which then owns
 * the lease stdin/stdout and serves the line protocol ([JailbreakLeaseProxy]).
 */
object JailbreakLeaseLauncher {
    fun launch(context: Context): IRootManagementService {
        val lease = JailbreakLeaseStore.current()
            ?: throw IllegalStateException("JAILBREAK_LEASE_MISSING")
        val application = context.applicationInfo
        val apk = application.sourceDir ?: throw IllegalStateException("JAILBREAK_APK_PATH_MISSING")
        if (!File(apk).isFile) throw IOException("JAILBREAK_APK_UNREADABLE")
        val command = JailbreakDaemonCommand.launch(apk, context.packageName + ":root:0",
            application.uid, requireNotNull(application.nativeLibraryDir),
            File(context.noBackupFilesDir, "authorizations.bin").absolutePath)
        lease.outputStream.write((command + "\n").toByteArray())
        lease.outputStream.flush()
        // The next line on the lease is read by the executor itself: this is the
        // identity round-trip that proves the executor owns the transport.
        val proxy = JailbreakLeaseProxy(context)
        val state = proxy.status()
        // The consumer exits after the handover, so the lease is kept alive by the
        // executor this call just proved.
        JailbreakLeaseStore.recordExecutor(state.getInt("rootPid", 0))
        check(state.getInt("rootUid", -1) == 0 && state.getInt("rootPid", -1) > 1 &&
            state.getInt("protocol", -1) == 1) { "JAILBREAK_EXECUTOR_IDENTITY" }
        return proxy
    }
}
