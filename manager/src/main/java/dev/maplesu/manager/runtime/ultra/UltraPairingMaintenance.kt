package dev.maplesu.manager.runtime.ultra

import dev.maplesu.manager.compat.ultraPreferences

import android.content.Context
import android.os.Process
import android.os.SystemClock
import android.util.Log
import dev.maplesu.manager.modules.UltraRootKeyStore
import java.util.concurrent.Executor
import java.util.concurrent.Executors

/** Coalesces background work without making the pairing receipt wait for root/file operations. */
internal class UltraMaintenanceQueue(private val executor: Executor, private val now: () -> Long) {
    private val pending = mutableSetOf<String>()
    private var completed: String? = null
    private var completedAt = 0L
    private var succeeded = false

    @Synchronized
    fun request(identity: String, eligible: () -> Boolean, work: () -> Boolean): Boolean {
        val age = now() - completedAt
        if (identity in pending || (identity == completed && age >= 0 &&
            age < if (succeeded) 60_000L else 10_000L)) return false
        pending += identity
        try {
            executor.execute {
                val ok = runCatching { eligible() && work() }.getOrDefault(false)
                synchronized(this) {
                    pending -= identity
                    completed = identity
                    completedAt = now()
                    succeeded = ok
                }
            }
        } catch (_: java.util.concurrent.RejectedExecutionException) {
            pending -= identity
            return false
        }
        return true
    }
}

internal object UltraPairingMaintenance {
    private val queue = UltraMaintenanceQueue(Executors.newSingleThreadExecutor { task ->
        Thread({
            Process.setThreadPriority(Process.THREAD_PRIORITY_BACKGROUND)
            task.run()
        }, "maplesu-ultra-pairing-maintenance").apply { isDaemon = true }
    }, SystemClock::elapsedRealtime)

    private fun allowed(context: Context, key: String, bootId: String) =
        !Thread.currentThread().isInterrupted && UltraEnvironmentAutoSetup.currentBootId() == bootId &&
            !UltraIdentityRecovery.blocked(context) &&
            UltraRootKeyStore.read(context) == key &&
            UltraKeyPairedStore.matchesVerifiedKey(context, key)

    fun request(context: Context, key: String) {
        val app = context.applicationContext
        val bootId = UltraEnvironmentAutoSetup.currentBootId() ?: return
        val identity = java.security.MessageDigest.getInstance("SHA-256").digest(key.toByteArray(Charsets.US_ASCII))
            .joinToString("") { "%02x".format(it.toInt() and 255) } + ":" + bootId
        queue.request(identity, { allowed(app, key, bootId) }) work@{
            val started = SystemClock.elapsedRealtime()
            runCatching {
                if (!allowed(app, key, bootId)) return@work false
                val client = UltraSdkCredentials.client(app, key, bootId)
                UltraSdkLogging.apply(client)
                if (!allowed(app, key, bootId)) return@work false
                // Save the verified key before su/Binder authorization work. A stale
                // no-key UID grant must not prevent permanent recovery material.
                val backup = UltraBackupMaintenance.refresh({ allowed(app, key, bootId) },
                    { UltraEnvironmentInstaller.backupKey(app, key) })
                app.ultraPreferences("ultra-identity-recovery", Context.MODE_PRIVATE).edit()
                    .putString("backup", backup?.reason ?: "BACKUP_UNAVAILABLE")
                    .putLong("backupAt", System.currentTimeMillis()).apply()
                if (!allowed(app, key, bootId)) return@work false
                val whitelist = UltraSelfWhitelist.ensureCurrentAuthority(app, client) { allowed(app, key, bootId) }
                if (!whitelist.succeeded || !allowed(app, key, bootId)) return@work false
                val restored = dev.maplesu.manager.installer.InstallerServiceClient.withService(app, persistent = true) {
                    it.refreshUltraAuthorization(key)
                }
                if (!allowed(app, key, bootId)) return@work false
                whitelist.succeeded && restored == "OK" && backup?.ok == true
            }.onFailure { Log.w("MapleSUUltraPairing", "maintenance deferred: ${it.javaClass.simpleName}") }
                .getOrDefault(false).also {
                    Log.i("MapleSUUltraPairing", "maintenance ok=$it elapsedMs=${SystemClock.elapsedRealtime() - started}")
                }
        }
    }
}
