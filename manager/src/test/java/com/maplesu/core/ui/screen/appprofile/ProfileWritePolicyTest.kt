package com.maplesu.core.ui.screen.appprofile

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class ProfileWritePolicyTest {
    @Test fun olderFailureNeverRollsBackANewerOptimisticChoice() {
        val policy = ProfileWritePolicy("initial")
        val first = policy.request()
        val second = policy.request()
        assertFalse(policy.isLatest(first))
        assertTrue(policy.isLatest(second))
        assertNull(policy.complete(first, "grant", saved = false))
        assertEquals("revoke", policy.complete(second, "revoke", saved = true)?.profile)
    }

    @Test fun newestFailureRollsBackToLastSuccessfulWriteNotPreviousOptimisticValue() {
        val policy = ProfileWritePolicy("initial")
        val first = policy.request()
        val second = policy.request()
        assertNull(policy.complete(first, "grant", saved = true))
        val result = policy.complete(second, "revoke", saved = false)
        assertEquals("grant", result?.profile)
        assertFalse(result!!.saved)
    }

    @Test fun multipleFailuresKeepTheConfirmedProfile() {
        val policy = ProfileWritePolicy("initial")
        val first = policy.request()
        val second = policy.request()
        assertNull(policy.complete(first, "first", saved = false))
        assertEquals("initial", policy.complete(second, "second", saved = false)?.profile)
    }

    @Test fun latestSuccessPublishesTheFullSubmittedValue() {
        data class Profile(val allow: Boolean, val domain: String, val groups: List<Int>)
        val initial = Profile(false, "custom-domain", listOf(123, 456))
        val policy = ProfileWritePolicy(initial)
        val desired = initial.copy(allow = true)
        val result = policy.complete(policy.request(), desired, saved = true)
        assertEquals(desired, result?.profile)
        assertTrue(result!!.saved)
    }

    @Test fun screenPreservesProfileAndSerializesBackendCalls() {
        val source = File("src/main/java/com/maplesu/core/ui/screen/appprofile/AppProfileScreen.kt").readText()
        assertTrue(source.contains("val profileToSave = updatedProfile.copy("))
        assertTrue(source.contains("saveMutex.withLock"))
        assertTrue(source.contains("policy.complete(request, profileToSave, saved)"))
        assertFalse(source.contains("profile = previousProfile"))
        assertTrue(source.contains("if (saving) return@LaunchedEffect"))
    }
}
