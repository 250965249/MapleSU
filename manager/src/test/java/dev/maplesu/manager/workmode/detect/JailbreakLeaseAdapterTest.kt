package dev.maplesu.manager.workmode.detect

import dev.maplesu.manager.jailbreak.JailbreakRequest
import dev.maplesu.manager.jailbreak.JailbreakStatus
import dev.maplesu.manager.jailbreak.Derived
import dev.maplesu.manager.runtime.TrustedRuntime
import dev.maplesu.manager.workmode.detect.probes.JailbreakLeaseAdapter
import org.junit.Assert.*
import org.junit.Test

class JailbreakLeaseAdapterTest {
    private val hook = JailbreakStatus(
        method = "dirtyfrag", stage = JailbreakStatus.STAGE_DAEMON_READY,
        message = "historical proof", startedAtMillis = 1, updatedAtMillis = 1,
        bootId = "boot", attemptId = "attempt", rootBackend = JailbreakRequest.BACKEND_HOOK,
    )

    private fun adapter(
        status: () -> JailbreakStatus?,
        reprove: () -> String?,
        lease: () -> TrustedRuntime.State,
    ) = JailbreakLeaseAdapter(status, reprove, lease, bootId = { "boot" })

    @Test fun hookRequiresRealRecoveryEvenWhenHistoricalStateSaysReady() {
        val probe = adapter({ hook }, { null }, { error("must not trust old proof") })
        assertFalse(probe.valid())
    }

    @Test fun recoveredHookRecognizesOnlyTheSameAttempt() {
        assertTrue(adapter({ hook }, { "attempt" }, { error("lease") }).valid())
        assertFalse(adapter({ hook }, { "other" }, { error("lease") }).valid())
    }

    @Test fun failedHookProbeDoesNotFallBackToHistoricalState() {
        assertFalse(adapter({ hook }, { error("probe") }, { error("lease") }).valid())
    }

    @Test fun normalLeaseKeepsTheExistingReadinessRule() {
        val ready = TrustedRuntime.State(TrustedRuntime.Origin.JAILBREAK, true)
        assertTrue(adapter({ hook.copy(rootBackend = null) }, { error("hook") }, { ready }).valid())
        assertFalse(adapter({ null }, { error("hook") }, { ready.copy(ready = false) }).valid())
    }

    @Test fun ordinaryBootRootDoesNotBecomeAJailbreakLease() {
        val normal = TrustedRuntime.State(TrustedRuntime.Origin.NORMAL_MAPLESU, true)
        assertFalse(adapter({ null }, { error("hook") }, { normal }).valid())
    }

    @Test fun noAttemptDoesNotProbeAnyRuntime() {
        var reads = 0
        val probe = adapter({ null }, { reads++; null }, {
            reads++
            TrustedRuntime.State(TrustedRuntime.Origin.NONE, false)
        })
        assertFalse(probe.valid())
        assertEquals("No session record means there is no lease to verify", 0, reads)
    }

    @Test fun incompleteAttemptDoesNotProbeAnyRuntime() {
        var reads = 0
        val probe = adapter({ hook.copy(stage = "pending") }, { reads++; null }, {
            reads++
            TrustedRuntime.State(TrustedRuntime.Origin.NONE, false)
        })
        assertFalse(probe.valid())
        assertEquals(0, reads)
    }

    @Test fun rebootedHookDoesNotRecoverThePreviousBootsSession() {
        val previousBoot = hook.copy().withDerived(Derived(bootChanged = true))
        var reads = 0
        val probe = adapter({ previousBoot }, { reads++; "attempt" }, {
            reads++
            TrustedRuntime.State(TrustedRuntime.Origin.JAILBREAK, true)
        })
        assertFalse("A reboot must send detection past the expired jailbreak lease", probe.valid())
        assertEquals("Do not start the old provider while detecting the new boot", 0, reads)
    }

    @Test fun rebootedNormalDoesNotProbeThePreviousBootsLease() {
        val previousBoot = hook.copy(rootBackend = JailbreakRequest.BACKEND_KSU)
            .withDerived(Derived(bootChanged = true))
        var reads = 0
        val probe = adapter({ previousBoot }, { reads++; null }, {
            reads++
            TrustedRuntime.State(TrustedRuntime.Origin.JAILBREAK, true)
        })
        assertFalse(probe.valid())
        assertEquals(0, reads)
    }

    @Test fun missingOrMismatchedBootNeverStartsEitherRuntime() {
        for (saved in listOf<String?>(null, "", "previous-boot")) {
            var reads = 0
            val probe = adapter({ hook.copy(bootId = saved) }, { reads++; "attempt" }, {
                reads++
                TrustedRuntime.State(TrustedRuntime.Origin.JAILBREAK, true)
            })
            assertFalse(probe.valid())
            assertEquals(0, reads)
        }
        var reads = 0
        val probe = JailbreakLeaseAdapter({ hook }, { reads++; "attempt" }, {
            reads++
            TrustedRuntime.State(TrustedRuntime.Origin.JAILBREAK, true)
        }, bootId = { null })
        assertFalse(probe.valid())
        assertEquals(0, reads)
    }

    @Test fun failedCurrentBootRecordDoesNotRecover() {
        val probe = adapter({ hook.copy(failure = "failed") }, { error("hook") }, { error("lease") })
        assertFalse(probe.valid())
    }
}
