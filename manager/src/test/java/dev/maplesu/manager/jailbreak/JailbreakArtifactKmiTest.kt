package dev.maplesu.manager.jailbreak

import org.junit.Assert.assertEquals
import org.junit.Test

class JailbreakArtifactKmiTest {
    @Test fun moduleDigestBelongsToTheObservedFamily() {
        val entry = JailbreakArtifacts.Entry("libdfroot.so", "native", 1, "", "minimal", "",
            mapOf("android14-6.1" to "module61", "android15-6.6" to "module66"))
        assertEquals("module61", entry.koSha256("android14-6.1"))
        assertEquals("module66", entry.koSha256("android15-6.6"))
        assertEquals("", entry.koSha256(""))
        assertEquals("", entry.koSha256("android16-6.12"))
    }

    @Test fun legacySingleModuleDigestOnlyDescribesItsOwnFamily() {
        val entry = JailbreakArtifacts.Entry("libdfroot.so", "native", 1,
            "android15-6.6", "minimal", "legacy", emptyMap())
        assertEquals("legacy", entry.koSha256("android15-6.6"))
        assertEquals("", entry.koSha256("android14-6.1"))
        assertEquals("", entry.koSha256(""))
    }
}
