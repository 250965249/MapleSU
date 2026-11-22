package dev.maplesu.manager.jailbreak

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The route decision used to be a bare string comparison, so any value the executor
 * did not recognise (`"ksu"`, a typo, an empty string) silently took the lease route.
 * A caller that asked for the KernelSU target could therefore get a completely
 * different installation and still see the attempt reported as a success.
 *
 * These tests pin the fail-closed behaviour and the exact token shape, because that
 * token is what a device log will show when the mistake happens again.
 */
class JailbreakBackendValidationTest {

    @Test
    fun everyDeclaredBackendIsAccepted() {
        for (backend in JailbreakRequest.KNOWN_BACKENDS) {
            assertNull("declared backend must be usable: $backend",
                JailbreakRequest.validateBackend(backend))
        }
    }

    @Test
    fun theDeclaredSetIsExactlyTheThreeRoutes() {
        // Named explicitly: adding a backend must be a deliberate edit here, not a
        // side effect of appending to a set somewhere else.
        assertEquals(setOf("ir", "hook", "ksu"), JailbreakRequest.KNOWN_BACKENDS)
        assertEquals("ir", JailbreakRequest.BACKEND_IR)
        assertEquals("hook", JailbreakRequest.BACKEND_HOOK)
        assertEquals("ksu", JailbreakRequest.BACKEND_KSU)
    }

    @Test
    fun nullMeansAutoAndIsNotAnUnknownValue() {
        // null is "decide from what is packaged", which is a deliberate choice.
        assertNull(JailbreakRequest.validateBackend(null))
    }

    @Test
    fun anUnknownBackendFailsClosedAndNamesItself() {
        assertEquals("JAILBREAK_BACKEND_UNKNOWN:magisk",
            JailbreakRequest.validateBackend("magisk"))
        assertEquals("JAILBREAK_BACKEND_UNKNOWN:",
            JailbreakRequest.validateBackend(""))
        assertEquals("JAILBREAK_BACKEND_UNKNOWN:IR",
            JailbreakRequest.validateBackend("IR"))
    }

    @Test
    fun theTargetIsPartOfTheRequestAndSurvivesTheWireForm() {
        // The provider rebuilds the request from extras; if the backend did not
        // travel with it, every branch downstream would see null.
        val request = JailbreakRequest.of("dirtyfrag", "attempt-1", JailbreakRequest.BACKEND_KSU)
        assertEquals(JailbreakRequest.BACKEND_KSU, request.rootBackend)
        assertTrue(JailbreakRequest.validateBackend(request.rootBackend) == null)
    }

    @Test
    fun anUnknownTargetStillFailsClosedWithItsOwnName() {
        // Keep the closed-shape guard alive even though every declared target now has
        // a route: an unknown value must never reach the lease branch.
        assertEquals("JAILBREAK_BACKEND_UNKNOWN:ksu-next",
            JailbreakRequest.unsupportedTarget("ksu-next", "6.6.89-test"))
    }

    @Test
    fun routableTargetsAreNotReportedUnsupported() {
        assertNull(JailbreakRequest.unsupportedTarget(JailbreakRequest.BACKEND_IR, "any"))
        assertNull(JailbreakRequest.unsupportedTarget(JailbreakRequest.BACKEND_HOOK, "any"))
        // null stays "decide from what is packaged".
        assertNull(JailbreakRequest.unsupportedTarget(null, "any"))
    }

    @Test
    fun theRoutableSetCanNeverBeLargerThanTheKnownSet() {
        assertTrue(JailbreakRequest.KNOWN_BACKENDS.containsAll(JailbreakRequest.ROUTABLE_BACKENDS))
    }

    @Test
    fun everyKnownTargetIsNowRoutable() {
        // escalateKsu landed, so a declared target that is not routable would mean a
        // caller can select a target this build cannot deliver - the exact hole the
        // unsupportedTarget() gate exists for.
        assertEquals(JailbreakRequest.KNOWN_BACKENDS, JailbreakRequest.ROUTABLE_BACKENDS)
        assertNull(JailbreakRequest.unsupportedTarget(JailbreakRequest.BACKEND_KSU, "6.6.89"))
    }
}
