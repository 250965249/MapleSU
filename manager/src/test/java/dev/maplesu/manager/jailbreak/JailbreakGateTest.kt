package dev.maplesu.manager.jailbreak

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.nio.charset.StandardCharsets

/**
 * Regression tests for the gates the review asked for: the restoration state
 * machine (R04), the failure frame that replaces a provider timeout (R05), the
 * attempt-scoped lease (R03/R11), the exact-target verdict (R09/R10) and the
 * Ghostlock profile resolver (R01). They run on the host, so a later edit cannot
 * quietly turn a verified restore back into an assumed one.
 */
class JailbreakGateTest {
    private fun restore(applied: Int, origin: Int, enforcing: Int, checkreqprot: Int = 0,
                        policy: Int = 0, errno: Int = 0): ByteArray =
        byteArrayOf('P'.code.toByte(), applied.toByte(), origin.toByte(), enforcing.toByte(),
            checkreqprot.toByte(), policy.toByte(),
            (errno ushr 24).toByte(), (errno ushr 16).toByte(), (errno ushr 8).toByte(),
            errno.toByte())

    @Test fun observedRestoreProvesTheEntryPolicy() {
        val restore = LeaseProtocol.readRestore(ByteArrayInputStream(restore(1, 0, 1)))
        assertEquals("RESTORED_OBSERVED", restore.state())
        assertTrue(restore.verified())
        assertTrue(restore.provesEntryPolicy())
        assertTrue(restore.admitsHandover())
    }

    @Test fun baselineRestoreIsVerifiedButNeverProvesTheEntryPolicy() {
        val restore = LeaseProtocol.readRestore(ByteArrayInputStream(restore(3, 1, 1)))
        assertEquals("RESTORED_BASELINE", restore.state())
        assertTrue(restore.verified())
        assertFalse("a baseline value is not the observed entry value", restore.provesEntryPolicy())
        assertTrue(restore.admitsHandover())
    }

    @Test fun failedRestoreMustNotAdmitAHandover() {
        val restore = LeaseProtocol.readRestore(ByteArrayInputStream(restore(0, 1, 0xff)))
        assertTrue(restore.failed())
        assertFalse(restore.verified())
        assertFalse(restore.admitsHandover())
    }

    @Test fun providerOwnedRestoreIsNotApplicable() {
        val restore = LeaseProtocol.readRestore(ByteArrayInputStream(restore(2, 3, 0xff)))
        assertEquals("PROVIDER_OWNED", restore.state())
        assertFalse(restore.applicable())
        assertFalse(restore.provesEntryPolicy())
    }

    @Test(expected = IOException::class)
    fun changedPolicyInvalidatesTheRestore() {
        LeaseProtocol.readRestore(ByteArrayInputStream(restore(1, 0, 1, policy = 1)))
    }

    @Test(expected = IOException::class)
    fun restoredWithoutReadbackIsRejected() {
        LeaseProtocol.readRestore(ByteArrayInputStream(restore(1, 0, 0xff)))
    }

    @Test(expected = IOException::class)
    fun assumedValueCannotClaimToBeObserved() {
        LeaseProtocol.readRestore(ByteArrayInputStream(restore(1, 1, 1)))
    }

    @Test fun failureFrameReplacesTheProviderTimeout() {
        val frame = byteArrayOf('F'.code.toByte(), 5, 0, 0, 0)
        val error = runCatching { LeaseProtocol.readReady(ByteArrayInputStream(frame)) }.exceptionOrNull()
        assertTrue("expected a typed failure, got " + error,
            error is IOException && error.message == "LEASE_CONSUMER_FAILED:PEER")
    }

    @Test fun shellFrameStillCarriesThePid() {
        val frame = ByteArrayOutputStream().apply {
            write('R'.code); write(0); write(0); write(0x30); write(0x39)
        }.toByteArray()
        assertEquals(12345, LeaseProtocol.readReady(ByteArrayInputStream(frame)))
    }

    @Test(expected = IOException::class)
    fun unknownFrameIsNotAConfirmation() {
        LeaseProtocol.readReady(ByteArrayInputStream(byteArrayOf('Z'.code.toByte(), 0, 0, 0, 0)))
    }

    @Test fun stageMachinesNeverMoveBackwards() {
        val started = status(JailbreakStatus.STAGE_PROVIDER_RUNNING)
        val forward = started.advance(status(JailbreakStatus.STAGE_HANDOFF_AUTHENTICATED))
        assertEquals(JailbreakStatus.STAGE_HANDOFF_AUTHENTICATED, forward.stage)
        val failure = runCatching {
            forward.advance(status(JailbreakStatus.STAGE_PROVIDER_RUNNING))
        }.exceptionOrNull()
        assertTrue("a regression must be rejected", failure is IllegalArgumentException)
        // A failure is allowed from any stage.
        assertEquals(JailbreakStatus.STAGE_FAILED,
            forward.advance(status(JailbreakStatus.STAGE_FAILED)).stage)
    }

    private fun status(stage: String) = JailbreakStatus(
        method = "dirtyfrag", stage = stage, message = "", startedAtMillis = 0,
        updatedAtMillis = 0, bootId = "b", attemptId = "a")

    @Test fun exactTargetVerdictRefusesAnUnmeasuredBuild() {
        val verified = JailbreakTargets.verified().first()
        assertEquals(JailbreakTargets.Verdict.VERIFIED_TARGET,
            JailbreakTargets.verdict(verified.provider(), verified.kernelRelease(),
                verified.fingerprint(), verified.soc(), verified.securityPatch(), true))
        // Same KMI family, different build fingerprint: a candidate, not a target.
        assertEquals(JailbreakTargets.Verdict.KMI_CANDIDATE,
            JailbreakTargets.verdict(verified.provider(), verified.kernelRelease(),
                "Other/Build/Keys:16/OTHER/OTHER:user/release-keys", verified.soc(),
                verified.securityPatch(), true))
        // Different SoC or patch level is refused as well.
        assertEquals(JailbreakTargets.Verdict.KMI_CANDIDATE,
            JailbreakTargets.verdict(verified.provider(), verified.kernelRelease(),
                verified.fingerprint(), "SM0000", verified.securityPatch(), true))
        assertEquals(JailbreakTargets.Verdict.KMI_CANDIDATE,
            JailbreakTargets.verdict(verified.provider(), verified.kernelRelease(),
                verified.fingerprint(), verified.soc(), "2020-01-01", true))
        // Not even the family is packaged.
        assertEquals(JailbreakTargets.Verdict.UNSUPPORTED,
            JailbreakTargets.verdict(verified.provider(), "4.19.0", verified.fingerprint(),
                verified.soc(), verified.securityPatch(), false))
    }

    @Test fun targetIdentityIsStableAndDistinct() {
        val one = JailbreakTargets.targetId("dirtyfrag", "r", "f", "s", "p")
        val two = JailbreakTargets.targetId("dirtyfrag", "r", "f", "s", "p")
        val other = JailbreakTargets.targetId("dirtyfrag", "r", "f2", "s", "p")
        assertEquals(one, two)
        assertNotEquals(one, other)
        assertEquals(64, one.length)
    }

    // --- Ghostlock profile resolution (R01) -------------------------------------

    private val profileRoot = "ghostlock"
    private val base = "release = \"6.6.89-test\"\nschema_version = 1\n"
    private val included = "credential = 1\n"

    private fun manifest(profiles: String, files: String) = """
        {"profiles": [$profiles], "profileFiles": [$files], "profileRoot": "$profileRoot"}
    """.trimIndent().toByteArray(StandardCharsets.UTF_8)

    private fun digest(text: String): String {
        val digest = java.security.MessageDigest.getInstance("SHA-256")
        return digest.digest(text.toByteArray(StandardCharsets.UTF_8))
            .joinToString("") { "%02x".format(it) }
    }

    private fun resolver(documents: Map<String, String>, releases: List<Pair<String, String>>) =
        GhostlockProfiles.fromIndex(
            releases.associate { it.first to it.second },
            documents.mapValues { digest(it.value) },
            { path -> documents[path.removePrefix("$profileRoot/")]?.toByteArray(StandardCharsets.UTF_8) },
            profileRoot)

    @Test fun exactProfileIsResolvedAndIncludesAreExpanded() {
        val resolver = resolver(
            mapOf("6.6.89-test.conf" to base + "include \"6x.conf\"\n", "6x.conf" to included),
            listOf("6.6.89-test" to "6.6.89-test.conf"))
        val profile = resolver.resolve("6.6.89-test")
        val text = String(profile.document(), StandardCharsets.UTF_8)
        assertTrue("the include must be expanded", text.contains("credential = 1"))
        assertFalse(text.contains("include"))
        assertEquals(1, text.split("release = \"6.6.89-test\"").size - 1)
    }

    @Test fun unprofiledReleaseIsRefusedByName() {
        val resolver = resolver(mapOf("a.conf" to base), listOf("a" to "a.conf"))
        val error = runCatching { resolver.resolve("6.6.89-other") }.exceptionOrNull()
        assertTrue("unexpected: " + error,
            error is IOException && error.message == "GHOSTLOCK_EXACT_PROFILE_MISSING:6.6.89-other")
    }

    @Test fun profileWithForeignReleaseIsRefused() {
        val resolver = resolver(mapOf("a.conf" to base), listOf("b" to "a.conf"))
        val error = runCatching { resolver.resolve("b") }.exceptionOrNull()
        assertTrue("unexpected: " + error,
            error is IOException && error.message!!.startsWith("GHOSTLOCK_PROFILE_RELEASE_MISMATCH"))
    }

    @Test fun tamperedProfileDigestIsRefused() {
        val resolver = GhostlockProfiles.fromIndex(
            mapOf("a" to "a.conf"), mapOf("a.conf" to "0".repeat(64)),
            { _ -> base.toByteArray(StandardCharsets.UTF_8) }, profileRoot)
        val error = runCatching { resolver.resolve("a") }.exceptionOrNull()
        assertTrue("unexpected: " + error,
            error is IOException && error.message == "GHOSTLOCK_PROFILE_DIGEST_MISMATCH:a.conf")
    }

    @Test fun includeCycleIsRefused() {
        val resolver = resolver(
            mapOf("a.conf" to "include \"b.conf\"\n", "b.conf" to "include \"a.conf\"\n"),
            listOf("a" to "a.conf"))
        val error = runCatching { resolver.resolve("a") }.exceptionOrNull()
        assertTrue("unexpected: " + error,
            error is IOException && error.message!!.startsWith("GHOSTLOCK_INCLUDE_CYCLE"))
    }

    // --- Admission ---------------------------------------------------------------

    private fun target(release: String) = JailbreakTarget(
        androidRelease = "16", sdk = 36, kernelRelease = release, abi = "arm64-v8a",
        manufacturer = "OnePlus", soc = "SM8750", fingerprint = "fp", bootId = "b",
        selinuxState = "unknown")

    @Test fun ghostlockAdmissionFollowsThePackagedProfiles() {
        val released = JailbreakAdmission.assess(JailbreakMethod.GHOSTLOCK,
            target("6.6.89-test"), setOf("6.6.89-test"))
        assertTrue(released.canStart)
        val missing = JailbreakAdmission.assess(JailbreakMethod.GHOSTLOCK,
            target("6.6.89-other"), setOf("6.6.89-test"))
        // No exact profile is a warning, not a disable: the user may still try.
        assertTrue(missing.canStart)
        assertTrue(JailbreakBlocker.GHOSTLOCK_EXACT_PROFILE_MISSING in missing.warnings)
    }

    @Test fun dirtyfragAdmissionWarnsAboutAnUnmeasuredBuildButAllowsIt() {
        val candidate = JailbreakAdmission.assess(JailbreakMethod.DIRTYFRAG,
            target("6.6.89-android15-8-gdeadbeef-4k"), verifiedTarget = false)
        assertTrue(candidate.canStart)
        assertTrue(JailbreakBlocker.TARGET_NOT_VERIFIED in candidate.warnings)
        val verified = JailbreakAdmission.assess(JailbreakMethod.DIRTYFRAG,
            target("6.6.89-android15-8-gdeadbeef-4k"), verifiedTarget = true)
        // License is still a distribution gate, not a runtime blocker.
        assertTrue(verified.canStart)
    }
}
