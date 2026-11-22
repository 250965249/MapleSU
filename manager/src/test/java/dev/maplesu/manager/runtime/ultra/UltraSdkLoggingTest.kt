package dev.maplesu.manager.runtime.ultra

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** P0 安全：Ultra SDK 日志默认关闭、显式诊断才开；日志/回执中不得出现 rootKey。 */
class UltraSdkLoggingTest {
    private val sampleKey = "A1".repeat(24)

    @After
    fun tearDown() {
        UltraSdkLogging.setExplicitDiagnostics(false)
    }

    @Test
    fun sdkLoggingDefaultsToDisabled() {
        assertFalse(UltraSdkLogging.shouldEnable())
    }

    @Test
    fun onlyExplicitDiagnosticsEnablesSdkLogging() {
        UltraSdkLogging.setExplicitDiagnostics(true)
        assertTrue(UltraSdkLogging.shouldEnable())
        UltraSdkLogging.setExplicitDiagnostics(false)
        assertFalse(UltraSdkLogging.shouldEnable())
    }

    @Test
    fun sampleKeyIsDetectedAndRedacted() {
        assertEquals(48, sampleKey.length)
        assertTrue(UltraSdkLogging.containsKeyLike(sampleKey))
        assertFalse(UltraSdkLogging.redact("key : $sampleKey").contains(sampleKey))
        assertTrue(UltraSdkLogging.redact("key : $sampleKey").contains("<REDACTED-KEY>"))
    }

    @Test
    fun sha256AndShortStringsAreNotMistakenForKeys() {
        val sha = "a".repeat(64)
        assertFalse(UltraSdkLogging.containsKeyLike(sha))
        assertFalse(UltraSdkLogging.containsKeyLike("key length=48"))
        assertEquals(sha, UltraSdkLogging.redact(sha))
        assertFalse(UltraSdkLogging.containsKeyLike(null))
        assertEquals("", UltraSdkLogging.redact(null))
    }

    @Test
    fun logStyleMessageRedactionCoversMixedText() {
        val message = "paired rootKey=$sampleKey state=Running"
        val redacted = UltraSdkLogging.redact(message)
        assertFalse(redacted.contains(sampleKey))
        assertTrue(redacted.contains("state=Running"))
    }
}
