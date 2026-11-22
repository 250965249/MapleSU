package dev.maplesu.manager.runtime.ultra

/** Shares only completely verified backup/broker maintenance, never a failed or forced observation. */
internal class UltraBackupMaintenance(private val now: () -> Long) {
    companion object {
        /** Bounded retries only for idempotent backup/deployment, never authorization writes. */
        fun refresh(eligible: () -> Boolean, work: () -> UltraRecoveryKeyStore.BackupOutcome?,
                    pause: (Long) -> Unit = Thread::sleep): UltraRecoveryKeyStore.BackupOutcome? {
            var result: UltraRecoveryKeyStore.BackupOutcome? = null
            for (delay in longArrayOf(0L, 250L, 750L)) {
                if (Thread.currentThread().isInterrupted || !eligible()) return result
                if (delay > 0) {
                    try { pause(delay) } catch (_: InterruptedException) {
                        Thread.currentThread().interrupt()
                        return result
                    }
                }
                if (Thread.currentThread().isInterrupted || !eligible()) return result
                result = work()
                if (result?.ok == true) return result
            }
            return result
        }
    }

    data class Identity(val keyFingerprint: String, val bootId: String, val packageName: String, val uid: Int)
    private data class Verified(val identity: Identity, val at: Long, val outcome: UltraRecoveryKeyStore.BackupOutcome)
    private var verified: Verified? = null

    @Synchronized
    fun ensure(
        identity: () -> Identity?,
        force: Boolean = false,
        work: () -> UltraRecoveryKeyStore.BackupOutcome?,
    ): UltraRecoveryKeyStore.BackupOutcome? {
        val scope = identity()
        val cached = verified
        if (!force && scope != null && cached?.identity == scope && now() - cached.at in 0 until 60_000L) {
            return cached.outcome.copy(skipped = true, reason = "RECENTLY_VERIFIED;${cached.outcome.reason}")
        }
        // Clear before work: a failed forced refresh must not resurrect an earlier success.
        verified = null
        val outcome = work()
        if (scope != null && outcome?.ok == true && identity() == scope) verified = Verified(scope, now(), outcome)
        return outcome
    }
}
