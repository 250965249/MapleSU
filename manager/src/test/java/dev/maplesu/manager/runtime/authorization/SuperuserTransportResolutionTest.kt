package dev.maplesu.manager.runtime.authorization

import dev.maplesu.manager.jailbreak.JailbreakRequest
import dev.maplesu.manager.jailbreak.JailbreakStatus
import dev.maplesu.manager.runtime.SuGate
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Host regression for the hook route's transport resolution (2026-10-31).
 *
 * <p>The Manager's transaction has one place that decides *how* root is reached:
 * [SuperuserControl.resolve]. On the Ultra/hook route that decision must be read from
 * the helper's root-owned record for the live attempt ([SuGate.read] + the status the
 * provider published), not from anything a UI process remembers. The gate that is used
 * for the command must then be exactly the one the decision approved.
 *
 * <p>Every test below is a refusal test except the first: a missing/expired stage, a
 * status that never mirrored `ARMED`, a gate bound to another attempt or boot, a
 * malformed/zero token or an unarmed record must all resolve to "no hook transport",
 * and the caller answers `SU_TRANSPORT_UNAVAILABLE`. There is no fallback to the
 * direct route on a hook-mode attempt.
 */
class SuperuserTransportResolutionTest {

    private val attempt = "84c22925-bb76-4ae0-804d-9ed023a69de0"
    private val boot = "15df128e-5b93-4fe7-8ed5-c785dec3c0c8"
    private val token = "0123456789abcdef"

    private fun status(
        stage: String = JailbreakStatus.STAGE_DAEMON_READY,
        suGate: String? = SuGate.ARMED,
        attemptId: String? = attempt,
        bootId: String? = boot,
        rootBackend: String? = JailbreakRequest.BACKEND_HOOK,
    ): JailbreakStatus = JailbreakStatus(
        method = "dirtyfrag",
        stage = stage,
        message = "hook backend: worker record for this attempt",
        startedAtMillis = 1_000,
        updatedAtMillis = 2_000,
        bootId = bootId,
        attemptId = attemptId,
        rootBackend = rootBackend,
        suGate = suGate,
    )

    private fun document(
        suToken: String? = token,
        suGate: String? = SuGate.ARMED,
        attemptId: String? = attempt,
        bootId: String? = boot,
    ): String = buildString {
        append("{\"schema\":\"maplesu.hook.attest.v1\",\"pid\":4242,\"uid\":0")
        append(",\"domain\":\"u:r:kernel:s0\"")
        if (attemptId != null) append(",\"attempt\":\"").append(attemptId).append('"')
        if (bootId != null) append(",\"bootId\":\"").append(bootId).append('"')
        if (suToken != null) append(",\"suToken\":\"").append(suToken).append('"')
        if (suGate != null) append(",\"suGate\":\"").append(suGate).append('"')
        append(",\"enforcingFinal\":1}")
    }

    private fun gate(
        suToken: String? = token,
        suGate: String? = SuGate.ARMED,
        attemptId: String? = attempt,
        bootId: String? = boot,
    ): SuGate.Gate = SuGate.parse(document(suToken, suGate, attemptId, bootId), attempt, boot)

    @Test
    fun bootSdkKeepsTheAuthorityReachableAfterManagerRestore() {
        assertEquals(SuperuserControl.Transport.BOOT_SDK, SuperuserControl.transportOf(false, true, bootSdk = true))
        assertEquals(SuperuserControl.Transport.HOOK, SuperuserControl.transportOf(true, true, bootSdk = true))
        assertEquals(SuperuserControl.Transport.NONE, SuperuserControl.transportOf(false, true, bootSdk = false))
    }

    // --- the one allow case ---------------------------------------------------

    @Test
    fun `hook transport resolves from an armed gate bound to the live daemon-ready attempt`() {
        val live = status()
        val record = gate()
        val resolved = SuperuserControl.hookGate(live, record)
        assertTrue("an ARMED, bound gate at DAEMON_READY is the hook transport", resolved.armed)
        assertEquals(SuGate.ARMED, resolved.state)
        assertEquals(token, resolved.suToken!!.hex)
        // The gate travels with the decision: the caller cannot substitute another read.
        assertSame(record, resolved)
        assertEquals(SuperuserControl.Transport.HOOK, SuperuserControl.transportOf(true, false))
    }

    // --- stage, status and gate must all agree -------------------------------

    @Test
    fun `an attempt that did not reach DAEMON_READY has no hook transport`() {
        for (stage in listOf(
            JailbreakStatus.STAGE_IDLE,
            JailbreakStatus.STAGE_TARGET_CHECKED,
            JailbreakStatus.STAGE_PROVIDER_RUNNING,
            JailbreakStatus.STAGE_HANDOFF_AUTHENTICATED,
            JailbreakStatus.STAGE_ROOT_WORKER_OBSERVED,
            JailbreakStatus.STAGE_FAILED,
            JailbreakStatus.STAGE_EXPIRED,
            JailbreakStatus.STAGE_CANCELLED,
        )) {
            val resolved = SuperuserControl.hookGate(status(stage = stage), gate())
            assertFalse("stage=$stage must fail closed", resolved.armed)
            assertEquals(SuGate.UNAVAILABLE, resolved.state)
        }
    }

    @Test
    fun `a missing status has no hook transport even with a perfectly armed record`() {
        assertFalse(SuperuserControl.hookGate(null, gate()).armed)
    }

    @Test
    fun `a status that did not mirror ARMED fails closed even when the daemon record is armed`() {
        for (mirrored in listOf(null, SuGate.UNAVAILABLE, "armed", "")) {
            val resolved = SuperuserControl.hookGate(status(suGate = mirrored), gate())
            assertFalse("status suGate=$mirrored must fail closed", resolved.armed)
        }
    }

    @Test
    fun `a gate bound to another attempt or another boot fails closed`() {
        val otherAttempt = SuGate.parse(
            document(attemptId = "another-attempt"), attempt, boot,
        )
        val otherBoot = SuGate.parse(
            document(bootId = "another-boot"), attempt, boot,
        )
        val unbound = SuGate.parse(document(attemptId = null), attempt, boot)
        val noAttemptId = SuperuserControl.hookGate(status(attemptId = null), gate())
        val noBootId = SuperuserControl.hookGate(status(bootId = null), gate())
        for ((name, resolved) in listOf(
            "other-attempt" to SuperuserControl.hookGate(status(), otherAttempt),
            "other-boot" to SuperuserControl.hookGate(status(), otherBoot),
            "unbound-record" to SuperuserControl.hookGate(status(), unbound),
            "status-without-attempt" to noAttemptId,
            "status-without-boot" to noBootId,
        )) {
            assertFalse("$name must fail closed", resolved.armed)
        }
    }

    @Test
    fun `an unarmed or malformed daemon record fails closed even for a DAEMON_READY status`() {
        for ((name, record) in listOf(
            "suGate-unavailable" to gate(suGate = SuGate.UNAVAILABLE),
            "suGate-missing" to gate(suGate = null),
            "zero-token" to gate(suToken = "0000000000000000"),
            "uppercase-token" to gate(suToken = "0123456789ABCDEF"),
            "short-token" to gate(suToken = "0123456789abcde"),
            "prefixed-token" to gate(suToken = "0x0123456789abcdef"),
            "missing-token" to gate(suToken = null),
        )) {
            val resolved = SuperuserControl.hookGate(status(), record)
            assertFalse("$name must fail closed", resolved.armed)
            assertEquals(SuGate.UNAVAILABLE, resolved.state)
        }
    }

    // --- the rest of the transport table is unchanged ------------------------

    @Test
    fun `the non-hook transport table is unchanged`() {
        assertEquals(SuperuserControl.Transport.HOOK, SuperuserControl.transportOf(true, false))
        assertEquals(SuperuserControl.Transport.HOOK, SuperuserControl.transportOf(true, true))
        assertEquals(SuperuserControl.Transport.DIRECT, SuperuserControl.transportOf(false, false))
        assertEquals(SuperuserControl.Transport.NONE, SuperuserControl.transportOf(false, true))
    }
}
