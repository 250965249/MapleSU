package dev.maplesu.manager.runtime

import android.content.Context
import dev.maplesu.manager.jailbreak.DirtyfragAttempt
import dev.maplesu.manager.jailbreak.JailbreakStatus
import dev.maplesu.manager.jailbreak.carrierBindsAttempt

/**
 * One trusted runtime state for both modes.
 *
 * <p>R02 (review 2026-10-26): readiness used to mean "this App has a normal-mode
 * MapleSU credential", so a clean install with a working jailbreak daemon was
 * still reported as not ready. Readiness is now resolved from whichever transport
 * actually exists: the MapleSU credential/executor, or the live provider lease of
 * the current boot. Nothing here is a persisted "installed" boolean - a stale
 * record expires on boot change, owner death or lease death, and the answer falls
 * back to a clear state instead of a permanent true.
 */
object TrustedRuntime {
    enum class Origin { NONE, NORMAL_MAPLESU, JAILBREAK }

    data class State(
        val origin: Origin,
        val ready: Boolean,
        val attemptId: String? = null,
        val restoreState: String? = null,
        val detail: String? = null,
    ) {
        val jailbreak: Boolean get() = origin == Origin.JAILBREAK
    }

    fun state(context: Context): State {
        val application = context.applicationContext
        if (runCatching { MapleSuRuntime.isReady(application) }.getOrDefault(false)) {
            return State(Origin.NORMAL_MAPLESU, true)
        }
        return jailbreakState(application)
    }

    /** Lease checks must never probe the boot-credential executor as a side effect. */
    internal fun jailbreakState(context: Context): State {
        val application = context.applicationContext
        // Only ask the trusted process when a record actually claims a live
        // attempt; otherwise this would start `:root_directory` on every read.
        val bootId = DirtyfragAttempt.readBootId()
        return jailbreakState(JailbreakStatus.read(application), bootId) {
            val probe = NativeSuDaemon.probeStatus(application)
            if (probe == null) {
                State(Origin.NONE, false, detail = "JAILBREAK_PROBE_UNAVAILABLE")
            } else {
                val live = probe.getBoolean("leaseLive", false)
                val stage = probe.getString("stage")
                if (live && stage == JailbreakStatus.STAGE_DAEMON_READY &&
                    probe.getString("bootId") == bootId) {
                    State(Origin.JAILBREAK, true, probe.getString("attemptId"),
                        probe.getString("restoreState"))
                } else {
                    State(Origin.NONE, false, detail = "JAILBREAK_" + (stage ?: "UNKNOWN"))
                }
            }
        }
    }

    internal fun jailbreakState(
        record: JailbreakStatus?,
        currentBootId: String?,
        probe: () -> State,
    ): State {
        if (record == null) return State(Origin.NONE, false,
            detail = "JAILBREAK_NO_ATTEMPT")
        if (record.stage != JailbreakStatus.STAGE_DAEMON_READY) {
            return State(Origin.NONE, false, record.attemptId,
                record.restoreState, "JAILBREAK_" + record.stage)
        }
        // Both persisted proofs and the legacy provider probe must belong to this
        // kernel boot. A userspace restart keeps this identity; a full reboot does not.
        if (currentBootId.isNullOrBlank() || record.bootId != currentBootId ||
            record.attemptId.isNullOrBlank() || record.derived?.bootChanged == true ||
            record.failure != null) {
            return State(Origin.NONE, false, record.attemptId, record.restoreState,
                "JAILBREAK_NO_CURRENT_BOOT_PROOF")
        }
        /*
         * §6.2/T2: a carrier proof bound to this attempt and boot is the authority for
         * readiness. The provider probe stays as the legacy path for records written
         * before T6 starts filling proofs.
         */
        val carrier = record.carrier
        if (carrier != null && carrierBindsAttempt(record) && record.derived?.bootChanged != true &&
            carrier.probe?.exitCode == 0 && carrier.probe.uid == 0) {
            return State(Origin.JAILBREAK, true, record.attemptId, record.restoreState)
        }
        val observed = probe()
        return if (observed.ready && observed.origin == Origin.JAILBREAK &&
            observed.attemptId == record.attemptId) {
            observed
        } else {
            State(Origin.NONE, false, record.attemptId, record.restoreState,
                observed.detail ?: "JAILBREAK_PROBE_ATTEMPT_MISMATCH")
        }
    }

    fun ready(context: Context): Boolean = state(context).ready

    fun origin(context: Context): Origin = state(context).origin
}
