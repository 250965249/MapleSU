package dev.maplesu.manager.jailbreak

import java.util.UUID

/**
 * One jailbreak attempt as the trusted side sees it.
 *
 * The attempt id is created by the caller and travels with every privileged call
 * of that attempt: the provider run, the lease claim and the daemon launch. It is
 * what makes "this attempt produced this endpoint" checkable instead of assumed,
 * so an endpoint left behind by an earlier attempt (or by normal mode) can never
 * answer for a new one.
 */
data class JailbreakRequest(
    val method: String,
    val attemptId: String,
    val bootId: String?,
    /**
     * DirtyFrag parity: the reference implementation can hand a successful
     * escalation over to a soft reboot (its `soft_reboot` preference, default off).
     * MapleSU keeps the same default and performs it from the root executor, so the
     * kernel-side window is closed and the next boot starts from a clean userspace.
     */
    val softReboot: Boolean = true,
    /**
     * Which kernel-side capability should carry this attempt.
     *
     * `null` means "whatever this build can actually do": the in-kernel route when
     * an exact spec for this release is packaged, otherwise the existing lease
     * route. `"ir"` forces the in-kernel route so a test or a diagnostic can demand
     * it and get `MAPLESU_IR_UNSUPPORTED:<release>` instead of a silent fallback.
     * `"hook"` (step-3, D-6) forces the module-dispatched UMH handover; neither
     * `"ir"` nor `"hook"` may fall back to the lease route.
     */
    val rootBackend: String? = null,
) {
    val origin: String get() = "jailbreak:$method:$attemptId"

    companion object {
        /** Match GhostLock's 300 s App run budget before lease delivery. */
        const val GHOSTLOCK_HANDOVER_TIMEOUT_SECONDS = 300L
        // Covers the retained boot/plant polling loops and the shared handover.
        const val MAPLESU_93260_TIMEOUT_SECONDS = 3_600L

        /** Our own in-kernel installer (the IR route). */
        const val BACKEND_IR = "ir"

        /**
         * Step-4 (D-6/D4-11): the module-dispatched UMH handover. Unlike the lease
         * route it has no binder to hand back, so its `DAEMON_READY` is proved by the
         * attestation worker instead (design §3.1 F1+F2+F3).
         */
        const val BACKEND_HOOK = "hook"

        /**
         * The KernelSU carrier: MapleSU_Normal (`WorkMode.KSU`). This is a *target*,
         * not a variant of our own module — the kernel payload is `kernelsu.ko` plus
         * its userspace daemon, so it has its own fail-closed route and its own
         * `DAEMON_READY` proof.
         */
        const val BACKEND_KSU = "ksu"

        /** GhostSam provider route (MapleSU-side V2 adapter, RAW_ROOT_LEASE only). */
        const val BACKEND_GHOSTSAM = "ghostsam"

        /**
         * Every backend this build knows. An unknown value must fail closed: before
         * this set existed, `rootBackend = "anything"` silently fell through to the
         * lease route, which is how a mistyped target could install the wrong thing
         * and still report success. `null` is *not* a member here: it means "decide
         * from what is packaged", which is a deliberate choice, not an unknown value.
         */
        val KNOWN_BACKENDS: Set<String> = setOf(BACKEND_IR, BACKEND_HOOK, BACKEND_KSU, BACKEND_GHOSTSAM)

        /**
         * Backends this build can actually route *today*.
         *
         * A value in [KNOWN_BACKENDS] but not here is a **declared but unimplemented**
         * target. That distinction mattered while `escalateKsu` did not exist: a
         * declared target without a route fell
         * through the `wantsIr` test straight into the lease branch and install
         * something else while reporting success — harder to notice than a typo,
         * because the name looks supported. `escalateKsu` landing is what moves
         * [BACKEND_KSU] into this set.
         */
        val ROUTABLE_BACKENDS: Set<String> =
            setOf(BACKEND_IR, BACKEND_HOOK, BACKEND_KSU, BACKEND_GHOSTSAM)

        /**
         * Returns the stable failure token for a target this build cannot deliver, or
         * null when it is routable. The token carries the user-facing target name
         * (`normal` / `ultra`) and the running release, because that is what a report
         * and a device log will need to identify the request.
         */
        fun unsupportedTarget(value: String?, release: String?): String? = when {
            value == null -> null
            value in ROUTABLE_BACKENDS -> null
            value == BACKEND_KSU -> "MAPLESU_TARGET_UNSUPPORTED:normal:" + (release ?: "unknown")
            else -> "JAILBREAK_BACKEND_UNKNOWN:$value"
        }

        /**
         * Returns null when the value is usable, or the stable failure token when it
         * is not. The token names the offending value so a log line is enough to see
         * which caller sent it.
         */
        fun validateBackend(value: String?): String? = when {
            value == null -> null
            value in KNOWN_BACKENDS -> null
            else -> "JAILBREAK_BACKEND_UNKNOWN:$value"
        }

        fun create(method: JailbreakMethod, rootBackend: String? = null): JailbreakRequest =
            JailbreakRequest(
                method = method.wireName,
                attemptId = UUID.randomUUID().toString(),
                bootId = DirtyfragAttempt.readBootId(),
                softReboot = true,
                rootBackend = rootBackend,
            )

        /**
         * Step-4 (MF-1): `rootBackend` has to travel with the request. When the
         * provider rebuilt it without this field, `request.rootBackend` was always
         * null inside `NativeSuDirectoryProvider`, so the hook branch could never be
         * reached and the `DAEMON_READY` write point was dead code no matter what the
         * executor did.
         */
        fun of(method: String, attemptId: String, rootBackend: String? = null):
            JailbreakRequest = JailbreakRequest(
                method = method,
                attemptId = attemptId,
                bootId = DirtyfragAttempt.readBootId(),
                rootBackend = rootBackend,
            )
    }
}
