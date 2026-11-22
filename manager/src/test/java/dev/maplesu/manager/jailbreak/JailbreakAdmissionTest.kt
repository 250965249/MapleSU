package dev.maplesu.manager.jailbreak

import org.junit.Assert.*
import org.junit.Test

class JailbreakAdmissionTest {
    private val target = JailbreakTarget(
        androidRelease = "16",
        sdk = 36,
        kernelRelease = "6.6.89-android15-8-g7e1f3c083cc6-abogki467167594-4k",
        abi = "arm64-v8a",
        manufacturer = "OnePlus",
        soc = "SM8750",
        fingerprint = "OnePlus/PLQ110/OP6113L1:16/BP2A.250605.015/B.48f7ba8-2511085-251139b:user/release-keys",
        bootId = "5334f916-9a56-4267-8d79-cb67a4782ece",
        selinuxState = "Enforcing",
    )

    @Test fun pinsTheCorrectSourceForEachMethod() {
        val commits = mapOf(
            JailbreakMethod.GHOSTLOCK to "b67359641c8663e5184abba73ecdf2c456dce3e7",
            JailbreakMethod.DIRTYFRAG to "ccd61e7c516df1469d335e41638e881328136dbc",
        )
        for ((method, commit) in commits) {
            val result = JailbreakAdmission.assess(method, target)
            assertEquals(method, result.method)
            assertEquals(commit, result.sourceCommit)
        }
    }

    @Test fun exactKernelFamilyIsRecordedWhenKnown() {
        val expected = mapOf(
            "6.6.89-android15-8-g7e1f3c083cc6-abogki467167594-4k" to "android15-6.6",
            "6.1.166-android14-12-gabc" to "android14-6.1",
            "6.12.76-android16-8-gabc" to "android16-6.12",
            "6.18.4-android17-8-gabc" to "android17-6.18",
            "5.10.236-android12-9-gabc" to "android12-5.10",
        )
        for ((release, kmi) in expected) {
            val result = JailbreakAdmission.assess(JailbreakMethod.DIRTYFRAG, target.copy(kernelRelease = release), verifiedTarget = true)
            assertEquals(kmi, result.kmi)
            assertTrue(result.blockers.isEmpty())
            assertTrue(result.canStart)
        }
    }

    @Test fun unlistedKernelStaysAttemptableWithAWarning() {
        // Native module selection decides whether these releases can run.
        for (release in listOf(
            "6.6.89", "6.6", "5.10", "6.98.1-android15-8-gabc",
            "6.6.89-android16-8-gabc", "SUCCESS", "uid=0(root)", "unknown",
        )) {
            val result = JailbreakAdmission.assess(JailbreakMethod.DIRTYFRAG, target.copy(kernelRelease = release), verifiedTarget = true)
            // Product policy: a provider is never silently disabled for being
            // unmeasured - the attempt runs and the provider reports its own outcome.
            // A value that destroys target identity is a structural problem instead.
            if (release == "unknown") {
                assertFalse("identity-missing release admitted", result.canStart)
                assertTrue(JailbreakBlocker.TARGET_IDENTITY_MISSING in result.blockers)
            } else {
                assertTrue("provider disabled for $release", result.canStart)
            }
        }
    }

    @Test fun ghostlockWithoutAPackagedExactProfileStillCanBeAttempted() {
        val result = JailbreakAdmission.assess(JailbreakMethod.GHOSTLOCK, target, ghostlockReleases = emptySet())
        assertTrue(result.canStart)
        assertTrue(JailbreakBlocker.GHOSTLOCK_EXACT_PROFILE_MISSING in result.warnings)
        for (release in listOf("6.6.89-android15-8-g7e1f3c083cc6", "5.10.236-android12-9",
            "6.6.127-4k-g46a034eca005-dirty")) {
            val other = JailbreakAdmission.assess(JailbreakMethod.GHOSTLOCK, target.copy(kernelRelease = release), ghostlockReleases = emptySet())
            assertTrue(JailbreakBlocker.GHOSTLOCK_EXACT_PROFILE_MISSING in other.warnings)
        }
    }

    @Test fun missingAttemptIdentityFieldsRemainBlocked() {
        for (value in listOf("", "   ", "unknown", "null")) {
            val incompleteTargets = listOf(
                target.copy(kernelRelease = value),
                target.copy(abi = value),
                target.copy(bootId = value),
            )
            for (candidate in incompleteTargets) {
                for (method in JailbreakMethod.entries) {
                    val result = JailbreakAdmission.assess(method, candidate)
                    assertFalse(result.canStart)
                    assertTrue(JailbreakBlocker.TARGET_IDENTITY_MISSING in result.blockers)
                }
            }
        }
    }

    @Test fun dirtyfragTreatsVendorMetadataAsObservations() {
        for (value in listOf("", "unknown", "null")) {
            val incompleteTargets = listOf(target.copy(androidRelease = value),
                target.copy(manufacturer = value), target.copy(soc = value),
                target.copy(fingerprint = value))
            for (incomplete in incompleteTargets) {
                assertTrue(JailbreakAdmission.assess(JailbreakMethod.DIRTYFRAG, incomplete).canStart)
                assertFalse(JailbreakAdmission.assess(JailbreakMethod.GHOSTLOCK, incomplete).canStart)
            }
        }
    }

    @Test fun nonPositiveSdkRemainsBlocked() {
        for (sdk in listOf(0, -1)) {
            for (method in JailbreakMethod.entries) {
                val result = JailbreakAdmission.assess(method, target.copy(sdk = sdk))
                assertFalse(result.canStart)
                assertTrue(JailbreakBlocker.TARGET_IDENTITY_MISSING in result.blockers)
            }
        }
    }

    @Test fun onlyThePackagedArm64AbiAvoidsTheAbiBlocker() {
        for (abi in listOf("", "unknown", "x86_64", "armeabi-v7a", "aarch64")) {
            for (method in JailbreakMethod.entries) {
                val result = JailbreakAdmission.assess(method, target.copy(abi = abi))
                assertFalse(result.canStart)
                assertTrue(JailbreakBlocker.ABI_UNSUPPORTED in result.blockers)
            }
        }
    }

    @Test fun reportedEnforcingStateIsRecordedNotTreatedAsRestoration() {
        // An ordinary App cannot read selinuxfs, so the value is an observation:
        // it never participates in exact-target identity and never stands in for
        // the restoration the privileged consumer reports.
        for (state in listOf("Enforcing", "Permissive", "unknown", "")) {
            val result = JailbreakAdmission.assess(JailbreakMethod.DIRTYFRAG, target.copy(selinuxState = state), verifiedTarget = true)
            assertFalse(result.blockers.any { it.name.contains("SELINUX") })
            assertFalse(JailbreakBlocker.TARGET_IDENTITY_MISSING in result.blockers)
            assertTrue(result.canStart)
        }
    }

    @Test fun dirtyFragTracksItsUnresolvedLicenseAsANote() {
        val dirtyFrag = JailbreakAdmission.assess(JailbreakMethod.DIRTYFRAG, target, verifiedTarget = true)
        val ghostlock = JailbreakAdmission.assess(JailbreakMethod.GHOSTLOCK, target, ghostlockReleases = emptySet())
        assertTrue(dirtyFrag.notes.contains("license-unresolved"))
        assertFalse(ghostlock.notes.contains("license-unresolved"))
        // A distribution gate does not silently become a runtime capability claim.
        assertTrue(dirtyFrag.canStart)
        assertTrue(ghostlock.canStart)
    }

    @Test fun unsupportedKernelIsReportedAsAWarningNotADisable() {
        val result = JailbreakAdmission.assess(JailbreakMethod.DIRTYFRAG, target.copy(kernelRelease = "6.6.89"))
        assertTrue(JailbreakBlocker.EXACT_KMI_UNSUPPORTED in result.warnings)
        assertTrue(result.canStart)
        assertNull(result.kmi)
    }
}
