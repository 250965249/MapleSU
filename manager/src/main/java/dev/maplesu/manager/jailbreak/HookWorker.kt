package dev.maplesu.manager.jailbreak

import android.content.Context
import android.util.Log
import java.io.File

private const val TAG = "MapleSUHookWorker"

/**
 * The attestation client for the hook route's daemon slot (step-4 D4, design §3.1/§3.2).
 *
 * <p>**What this proves, and what it does not.** The hook route has no lease, so a
 * persisted `status.json` saying `DAEMON_READY` would be a claim with no live transport
 * behind it. The proof is three independent facts:
 *
 *  - **F1** the helper's own verified restore (`HookEvidence`);
 *  - **F2** a live uid-0 process, proved by the *kernel*: `SO_PEERCRED` on the worker's
 *    connection to this process's listener returns `struct ucred`, so `peerUid == 0`
 *    cannot be forged by the App (the App can bind a socket and print `{"uid":0}`, but
 *    the kernel fills the ucred with the App's own uid). `peerPid` must also equal the
 *    `pid` in the reply, which binds "the answer" to "this connection";
 *  - **F3** an independent readback of the policy by that worker, from selinuxfs
 *    descriptors it opened while the window was open.
 *
 * <p>**Non-circular boundary (MF-9).** The worker still reports `uid`/`pid`/`starttime`,
 * but those are echo only; the evidence is the kernel ucred. `starttime` is kept for
 * same-pid reuse detection, never as an identity.
 *
 * <p>**M2 (report `maplesu-ultra-attestation-stability-2026-10-31.md` §5): one dialect.**
 * There used to be a second, forward dialect here: if the socket file existed, this
 * client connected to it, wrote `hello &lt;nonce&gt;` and expected a reply - but the only
 * listener that could be at that path was the App's own 300 s listener
 * ([HookAttestServer]), which speaks the other dialect (it writes `hello`, the worker
 * answers). The forward dial therefore always failed, and its fallback deleted the live
 * listener's socket (R2). It is gone. The one dialect left is the one `bootstrap.c`
 * implements for its reverse connect: **the App listens, the worker connects**.
 */
object HookWorker {
    const val SCHEMA = "maplesu.hook.attest.v1"

    /**
     * M4: where an [Attestation]'s identity comes from.
     *
     * `ucred` is the kernel's `SO_PEERCRED` answer for a connection the worker made to
     * this process's listener. `daemon-record` is only the root-owned file the worker
     * wrote; it is real evidence that a uid-0 worker ran and reads enforcing, but it is
     * **not** a transport proof and must never be described as one (report R3).
     */
    const val SOURCE_UCRED = "ucred"
    const val SOURCE_DAEMON_RECORD = "daemon-record"

    /** The socket name: attempt-prefixed, so a survivor can never collide with it. */
    fun socketName(attemptId: String): String =
        "maplesu-hook-" + attemptId.take(8) + ".sock"

    fun socketFile(directory: File, attemptId: String): File =
        File(directory, socketName(attemptId))

    data class Attestation(
        /** Kernel-filled ucred of the *server* fd (F2). */
        val peerUid: Int,
        val peerPid: Int,
        val replyPid: Int,
        val replyNonce: String?,
        val replyBootId: String?,
        val replyAttempt: String?,
        val domain: String?,
        val enforcing: Int?,
        val starttime: Long?,
        /**
         * What this client sent and asked for, so the comparison is pure. Both sides are
         * `""` on the one remaining dialect - the worker does not echo a nonce - so the
         * check below can only ever refuse a *mismatch*, never pass by accident.
         */
        val nonce: String,
        val bootId: String?,
        val attempt: String?,
        /**
         * L3 su gate fields from the helper's own record (`maplesu-hook-daemon.json`):
         * the 16-hex token and "ARMED"/"UNAVAILABLE". They are *observations* for the
         * status record; the executable gate is [dev.maplesu.manager.runtime.SuGate],
         * which re-reads the file and checks its owner. Null on the socket path, whose
         * reply carries no gate.
         */
        val suToken: String? = null,
        val suGate: String? = null,
        /** M4: [SOURCE_UCRED] or [SOURCE_DAEMON_RECORD]; never upgraded, only recorded. */
        val source: String = SOURCE_UCRED,
    ) {
        /** The kernel's pid, never the reply's: that is the whole point of F2. */
        val workerPid: Int get() = peerPid

        /** True when this is the worker's own file, not a kernel-verified connection. */
        val weak: Boolean get() = source != SOURCE_UCRED
    }

    /**
     * The attestation gate (design §3.5 item 10, §3.6). Pure, so the host tests drive
     * every fail-closed branch. A non-null answer is a `HOOK_BACKEND_NOT_READY:<reason>`
     * reason; null means "the worker answered for this attempt and reads enforcing".
     *
     * @param requireUcred M4: a caller that needs the kernel's own transport proof sets
     *   this. The claim does not, because the record file is the only path some devices
     *   have left; it records [Attestation.source] instead so the acceptance decision can
     *   be made on the evidence rather than on a sentence (report §6/S6).
     */
    fun refusal(attestation: Attestation, requireUcred: Boolean = false): String? = when {
        requireUcred && attestation.source != SOURCE_UCRED -> "worker_evidence_weak"
        attestation.peerUid != 0 -> "worker_identity"
        attestation.peerPid <= 0 -> "worker_identity"
        attestation.peerPid != attestation.replyPid -> "worker_identity"
        attestation.replyNonce == null || attestation.replyNonce != attestation.nonce ->
            "worker_identity"
        attestation.bootId != null && attestation.replyBootId != attestation.bootId ->
            "worker_identity"
        attestation.attempt != null && attestation.replyAttempt != attestation.attempt ->
            "worker_identity"
        attestation.enforcing == null -> "worker_enforcing_unobserved"
        // F3 says "the worker reads the policy"; a live worker that reads 0 means the
        // device is still permissive, which is the same condition F1 refuses.
        attestation.enforcing != 1 -> "restore_not_enforcing"
        else -> null
    }

    /**
     * One handshake with the attempt's worker.
     *
     * @return null when the worker is absent, unreachable or answered nothing usable -
     *         the caller maps that to `HOOK_BACKEND_NOT_READY:worker_unreachable`.
     */
    fun attest(
        context: Context,
        request: JailbreakRequest,
        timeoutMillis: Int = 1500,
    ): Attestation? = attest(context, request.attemptId, request.bootId, timeoutMillis)

    fun attest(
        context: Context,
        attemptId: String?,
        bootId: String?,
        timeoutMillis: Int = 1500,
    ): Attestation? {
        if (attemptId.isNullOrBlank()) {
            Log.w(TAG, "attest: no attempt id")
            return null
        }
        /*
         * The worker connects to us (DEV-174), so by the time the claim runs the answer
         * is normally already on disk. Reading it first avoids opening a second listener
         * that nobody will ever connect to - and avoids the seconds that listener would
         * otherwise wait before giving up.
         */
        HookAttestServer.read(context, attemptId, bootId)?.let {
            Log.w(TAG, "attest: recorded answer reused (pid=" + it.peerPid +
                " source=" + it.source + ")")
            return it
        }
        /*
         * M2: no forward dial. The listener belongs to this process, so the only thing a
         * claim may do is wait - bounded - for the worker's own connection, which is what
         * [HookAttestServer.handshake] records. It arms the listener if the attempt has
         * none and reuses it otherwise; it never unlinks one.
         */
        Log.w(TAG, "attest: no record yet, waiting " + timeoutMillis + "ms for the worker")
        return HookAttestServer.handshake(context, attemptId, bootId, timeoutMillis)
    }

    /**
     * Is the claim still backed by a live worker? This is the hook route's replacement
     * for `JailbreakLeaseStore.live` (design §3.5 item 12 / P6): a claim expires as soon
     * as the worker stops answering, instead of living until the process dies.
     */
    fun alive(context: Context, attemptId: String?, bootId: String?, timeoutMillis: Int = 600):
        Boolean = attest(context, attemptId, bootId, timeoutMillis) != null
}
