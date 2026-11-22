package dev.maplesu.manager.runtime

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Host regression for the session registry (design §4.3 / §6.8).
 *
 * <p>Two jobs are tested: the capacity limits (which refuse before anything is forked)
 * and the revoke path's ordering - SIGTERM, then the grace period, then SIGKILL - because
 * "revocation takes effect immediately" includes the sessions that already exist.
 */
class SuSessionRegistryTest {
    private val events = mutableListOf<String>()

    private fun registry(
        global: Int = 4,
        perUid: Int = 2,
        sleep: (Long) -> Unit = { millis -> events += "sleep:$millis" },
    ): SuSessionRegistry {
        var counter = 0
        return SuSessionRegistry(
            globalLimit = global,
            perUidLimit = perUid,
            idSource = { "s" + (++counter) },
            now = { 1_000L },
            sleep = sleep,
        )
    }

    private fun SuSessionRegistry.admit(uid: Int, pid: Long): SuSessionRegistry.Admission =
        admit(
            uid, pid,
            terminate = { events += "TERM:$pid" },
            kill = { events += "KILL:$pid" },
        )

    @Test
    fun globalLimitRefusesWithTheSharedCode() {
        val registry = registry(global = 2, perUid = 2)
        for (index in 0 until 2) {
            assertTrue(registry.admit(10_100 + index, index.toLong()) is SuSessionRegistry.Admission.Admitted)
        }
        val refused = registry.admit(10_200, 9)
        assertEquals(
            dev.maplesu.manager.runtime.authorization.SuCodes.SU_SESSION_LIMIT,
            (refused as SuSessionRegistry.Admission.Refused).reason,
        )
        assertEquals(2, registry.activeCount())
    }

    @Test
    fun perUidLimitIsIndependentOfTheGlobalOne() {
        val registry = registry(global = 4, perUid = 2)
        assertTrue(registry.admit(10_123, 1) is SuSessionRegistry.Admission.Admitted)
        assertTrue(registry.admit(10_123, 2) is SuSessionRegistry.Admission.Admitted)
        assertTrue(registry.admit(10_123, 3) is SuSessionRegistry.Admission.Refused)
        assertTrue(registry.admit(10_456, 4) is SuSessionRegistry.Admission.Admitted)
        assertEquals(2, registry.activeForUid(10_123))
    }

    @Test
    fun releaseFreesTheCapacity() {
        val registry = registry(global = 1, perUid = 1)
        val admission = registry.admit(10_123, 1)
        val session = (admission as SuSessionRegistry.Admission.Admitted).session
        assertTrue(registry.admit(10_456, 2) is SuSessionRegistry.Admission.Refused)
        registry.release(session.id)
        assertTrue(registry.admit(10_456, 2) is SuSessionRegistry.Admission.Admitted)
    }

    @Test
    fun revokeSignalsTerminateThenGraceThenKillAndDropsTheSessions() {
        val registry = registry()
        registry.admit(10_123, 11)
        registry.admit(10_123, 12)
        registry.admit(10_456, 13)
        events.clear()

        val killed = registry.killUid(10_123, graceMillis = 2_000)

        assertEquals(2, killed)
        // Order is the contract: every TERM, then the grace, then every KILL.
        assertEquals(listOf("TERM:11", "TERM:12", "sleep:2000", "KILL:11", "KILL:12"), events)
        assertEquals(0, registry.activeForUid(10_123))
        assertEquals(1, registry.activeCount())
    }

    @Test
    fun revokingAUidWithoutSessionsDoesNothing() {
        val registry = registry()
        registry.admit(10_456, 13)
        events.clear()
        assertEquals(0, registry.killUid(10_123))
        assertTrue(events.isEmpty())
    }
}
