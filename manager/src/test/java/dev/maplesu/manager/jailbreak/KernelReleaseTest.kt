package dev.maplesu.manager.jailbreak

import me.yuki.fina.adbroot.core.KernelProfiles
import me.yuki.fina.adbroot.core.KernelRelease
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The 98260 dispatch keys on the exact `uname -r` string, so parsing must be
 * tolerant of the formats vendors actually ship and must never invent a part it
 * did not read.
 */
class KernelReleaseTest {
    @Test fun parsesTheRetainedDefaultBuild() {
        val release = KernelRelease.parse(KernelProfiles.DEFAULT_RELEASE)
        assertTrue(release.valid)
        assertEquals("6.12.58", release.version)
        assertEquals("6.12.58", release.family)
        assertEquals(6, release.major)
        assertEquals(12, release.minor)
        assertEquals(58, release.patch)
        assertEquals(16, release.androidRelease)
        assertEquals(6, release.generation)
        assertEquals("dd6fd5c98918", release.gitHash)
        assertEquals("abogki543627742", release.buildId)
        assertEquals(543627742L, release.vendorBuildId)
        assertEquals("4k", release.pageSize)
        assertEquals("android16-6.12", release.kmi)
        assertEquals("6.12.58-android16-6-gdd6fd5c98918-abogki543627742-4k", release.raw)
        assertTrue(release.pinned)
    }

    @Test fun parsesAnAospBuildIdAndAPageSizeOtherThanFourK() {
        val release = KernelRelease.parse("6.12.69-android16-6-g242e1a07f878-ab15865446-16k")
        assertTrue(release.valid)
        assertEquals("242e1a07f878", release.gitHash)
        assertEquals("ab15865446", release.buildId)
        assertNull(release.vendorBuildId)
        assertEquals("16k", release.pageSize)
        assertEquals("android16-6.12", release.kmi)
    }

    @Test fun parsesTheSixSixFamilyKmiAndGeneration() {
        val release = KernelRelease.parse(
            "6.6.118-android15-8-g9bc34d5b0c79-abogki537459655-4k")
        assertEquals("android15-6.6", release.kmi)
        assertEquals(8, release.generation)
        assertEquals("6.6.118", release.version)
    }

    @Test fun parsesAProcVersionLineToTheSameReleaseToken() {
        val release = KernelRelease.parse(
            "Linux version 6.12.58-android16-6-gdd6fd5c98918-abogki543627742-4k " +
                "(builder@host) (clang 18.0) #1 SMP PREEMPT")
        assertEquals("6.12.58-android16-6-gdd6fd5c98918-abogki543627742-4k", release.raw)
        assertEquals("android16-6.12", release.kmi)
    }

    @Test fun bareVersionUsesTheStandardGkiMapping() {
        val release = KernelRelease.parse("6.12.58")
        assertTrue(release.valid)
        assertNull(release.androidRelease)
        assertEquals("android16-6.12", release.kmi)
        assertFalse(release.pinned)
    }

    @Test fun unknownFamilyStaysUnmapped() {
        val release = KernelRelease.parse("4.19.157-perf")
        assertTrue(release.valid)
        assertEquals("4.19.157", release.version)
        assertNull(release.kmi)
    }

    @Test fun unreadableValuesAreInvalidAndNeverMatch() {
        for (value in listOf(null, "", "  ", "unknown", "null", "Linux version")) {
            val release = KernelRelease.parse(value)
            assertFalse("must stay invalid: " + value, release.valid)
        }
    }
}
