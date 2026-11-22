package dev.maplesu.manager.runtime

import java.util.concurrent.atomic.AtomicLong

/**
 * Live restricted-su sessions, indexed by caller uid (design §4.3/§6.8).
 *
 * <p>"Revocation takes effect immediately" has three parts, and this class is the third:
 * a new request is refused by the decision function, a request in its commit phase is
 * refused with `AUTH_REVOKED`, and **an already-established session is terminated**.
 * A revoke therefore reaches the sessions this process owns and sends SIGTERM, then
 * SIGKILL after the grace period. Descendants a child forked are outside this guarantee;
 * the audit line records how many sessions were signalled.
 *
 * <p>Limits are the design's: 4 sessions globally, 2 per uid. Registration is the only
 * place that can refuse for capacity, so the endpoint does not re-implement the check.
 *
 * <p>The process actions are injected so the host test can drive limits and revoke
 * ordering without a device.
 */
class SuSessionRegistry(
    private val globalLimit: Int = 4,
    private val perUidLimit: Int = 2,
    private val idSource: () -> String = { "s" + COUNTER.incrementAndGet() },
    private val now: () -> Long = System::currentTimeMillis,
    private val sleep: (Long) -> Unit = { millis -> Thread.sleep(millis) },
) {
    /** One live child; [terminate] must be non-blocking, [kill] is the hard stop. */
    class Session(
        val id: String,
        val uid: Int,
        val pid: Long,
        val startedAt: Long,
        val terminate: () -> Unit,
        val kill: () -> Unit,
        val retainUntilExit: Boolean = false,
    )

    sealed interface Admission {
        data class Admitted(val session: Session) : Admission
        data class Refused(val reason: String) : Admission
    }

    private val sessions = LinkedHashMap<String, Session>()

    fun admit(
        uid: Int,
        pid: Long,
        terminate: () -> Unit,
        kill: () -> Unit,
        retainUntilExit: Boolean = false,
    ): Admission = synchronized(sessions) {
        if (sessions.size >= globalLimit) {
            return Admission.Refused(
                dev.maplesu.manager.runtime.authorization.SuCodes.SU_SESSION_LIMIT,
            )
        }
        if (sessions.values.count { it.uid == uid } >= perUidLimit) {
            return Admission.Refused(
                dev.maplesu.manager.runtime.authorization.SuCodes.SU_SESSION_LIMIT,
            )
        }
        val session = Session(idSource(), uid, pid, now(), terminate, kill, retainUntilExit)
        sessions[session.id] = session
        Admission.Admitted(session)
    }

    fun release(id: String) {
        synchronized(sessions) { sessions.remove(id) }
    }

    fun activeCount(): Int = synchronized(sessions) { sessions.size }

    fun activeForUid(uid: Int): Int = synchronized(sessions) { sessions.values.count { it.uid == uid } }

    /** Drops every session of a closed endpoint without signalling (the endpoint is gone). */
    fun forget(id: String) = release(id)

    /**
     * Revocation's third leg. SIGTERM first, then SIGKILL after [graceMillis]; returns
     * the number of sessions signalled. Sessions with a real drain receipt stay
     * registered until that owner confirms exit; legacy callbacks keep their behavior.
     *
     * <p>Ordering matters: a session is removed **after** its signal has been issued, so
     * a concurrent `release` cannot make the same pid be signalled twice by mistake.
     */
    @JvmOverloads
    fun killUid(uid: Int, graceMillis: Long = 2_000L): Int {
        val victims = synchronized(sessions) {
            sessions.values.filter { it.uid == uid }.toList()
        }
        if (victims.isEmpty()) return 0
        for (session in victims) {
            runCatching { session.terminate() }
        }
        if (graceMillis > 0) runCatching { sleep(graceMillis) }
        for (session in victims) {
            runCatching { session.kill() }
            if (!session.retainUntilExit) release(session.id)
        }
        return victims.size
    }

    fun killAll(graceMillis: Long = 2_000L): Int {
        val uids = synchronized(sessions) { sessions.values.map { it.uid }.distinct() }
        return uids.sumOf { killUid(it, graceMillis) }
    }

    companion object {
        private val COUNTER = AtomicLong()

        /**
         * The process-wide registry. The endpoint and the provider's `revokeSessions`
         * call must see the same object, or a revoke would signal nothing.
         */
        @JvmStatic
        val shared: SuSessionRegistry = SuSessionRegistry()
    }
}
