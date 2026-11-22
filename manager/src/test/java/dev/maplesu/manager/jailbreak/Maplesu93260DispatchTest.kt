package dev.maplesu.manager.jailbreak

import me.yuki.fina.adbroot.core.KernelCatalog
import me.yuki.fina.adbroot.core.KernelProfiles
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Admission is the first gate the user sees, so it must name what it detected
 * and why it refused. Only the packaged exact build may start; a recognised
 * variant without payload and an unknown build stay distinct outcomes.
 */
class Maplesu93260DispatchTest {
    private fun catalog(): KernelCatalog {
        val file = listOf(
            File("../jailbreak-providers/maplesu-93260/profiles.json"),
            File("jailbreak-providers/maplesu-93260/profiles.json"),
            File("../../jailbreak-providers/maplesu-93260/profiles.json"),
        ).firstOrNull { it.isFile } ?: error("profiles.json not found")
        return KernelCatalog.parse(JSONObject(file.readText()))
    }

    private fun target(release: String) = JailbreakTarget(
        androidRelease = "16",
        sdk = 36,
        kernelRelease = release,
        abi = "arm64-v8a",
        manufacturer = "vivo",
        soc = "SM8750",
        fingerprint = "vivo/PD2546/PD2546:16/BP2A.250605.015/B.x:user/release-keys",
        bootId = "boot-a",
        selinuxState = "Enforcing",
        securityPatch = "2026-10-01",
        model = "iQOO 15 Ultra",
        device = "PD2546",
    )

    private fun assess(release: String) = JailbreakAdmission.assess(
        JailbreakMethod.MAPLESU_93260, target(release),
        maplesu93260Catalog = catalog())

    @Test fun packagedBuildIsAdmittedAndNamesItsProfile() {
        val assessment = assess(KernelProfiles.DEFAULT_RELEASE)
        assertTrue("blockers: " + assessment.blockers, assessment.canStart)
        assertEquals(KernelProfiles.DEFAULT_ID, assessment.profileKey)
        assertEquals(KernelProfiles.DEFAULT_VARIANT, assessment.methodLabel)
        assertEquals("android16-6.12", assessment.kmi)
        assertTrue(assessment.notes.contains("profile:" + KernelProfiles.DEFAULT_ID))
    }

    @Test fun plantBuildIsAdmittedAndNamesItsProfile() {
        val assessment = assess("6.12.69-android16-6-g242e1a07f878-ab15865446-4k")
        assertTrue("blockers: " + assessment.blockers, assessment.canStart)
        assertEquals("plant-61269-242e1a07f878", assessment.profileKey)
        assertEquals("CVE-2026-98260-6.12.69", assessment.methodLabel)
        assertEquals("android16-6.12", assessment.kmi)
        assertTrue(assessment.notes.contains("profile:plant-61269-242e1a07f878"))
        assertFalse(assessment.blockers.contains(
            JailbreakBlocker.MAPLESU_93260_PROFILE_NOT_PACKAGED))
    }

    @Test fun unknownBuildKeepsTheOriginalBlocker() {
        val assessment = assess("6.12.58-android16-6-gdeadbeef1234-ab99999999-4k")
        assertFalse(assessment.canStart)
        assertTrue(assessment.blockers.contains(
            JailbreakBlocker.MAPLESU_93260_KERNEL_UNSUPPORTED))
        assertFalse(assessment.blockers.contains(
            JailbreakBlocker.MAPLESU_93260_PROFILE_NOT_PACKAGED))
        assertNull(assessment.methodLabel)
    }

    @Test fun anotherVendorBuildInTheSameFamilyIsNotEvidence() {
        // Same 6.12.58 family and the same KMI, but a different commit: must refuse.
        val changed = KernelProfiles.DEFAULT_RELEASE.replace("dd6fd5c98918", "376529f3e739")
        val assessment = assess(changed)
        assertFalse(assessment.canStart)
        assertTrue(assessment.blockers.contains(
            JailbreakBlocker.MAPLESU_93260_KERNEL_UNSUPPORTED))
        assertEquals("android16-6.12", assessment.kmi)
    }

    @Test fun sixSixBuildIsAdmittedThroughItsPlant() {
        val assessment = assess("6.6.118-android15-8-g9bc34d5b0c79-abogki537459655-4k")
        assertTrue("blockers: " + assessment.blockers, assessment.canStart)
        assertEquals("plant-66118-9bc34d5b0c79", assessment.profileKey)
        assertEquals("CVE-2026-98260-6.6.118", assessment.methodLabel)
        assertEquals("android15-6.6", assessment.kmi)
    }
}
