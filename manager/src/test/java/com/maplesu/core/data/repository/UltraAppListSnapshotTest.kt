package com.maplesu.core.data.repository

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.runBlocking

class UltraAppListSnapshotTest {
    @Test fun packageDiscoveryAndSdkRefreshOverlapButProjectionWaitsForBoth() = runBlocking {
        val packagesStarted = CountDownLatch(1)
        val grantsStarted = CountDownLatch(1)
        val (packages, snapshot) = UltraAppListSnapshot.withPackages(
            packages = {
                packagesStarted.countDown()
                check(grantsStarted.await(1, TimeUnit.SECONDS)) { "Package discovery waited for SDK refresh" }
                listOf("dev.allowed", "dev.other")
            },
            refresh = {
                grantsStarted.countDown()
                check(packagesStarted.await(1, TimeUnit.SECONDS)) { "SDK refresh waited for package discovery" }
                true
            },
            grantedPackages = { setOf("dev.allowed") },
        )
        assertEquals(listOf(true, false), packages.map { snapshot.isGranted(it, 10001) })
    }

    @Test fun parallelLoadStillRejectsAnUnconfirmedAuthorizationSnapshot() = runBlocking {
        var reads = 0
        val error = runCatching {
            UltraAppListSnapshot.withPackages({ listOf("dev.old") }, { false }, { reads++; setOf("dev.old") })
        }.exceptionOrNull()
        assertEquals("ULTRA_AUTH_REFRESH_FAILED", error?.message)
        assertEquals(0, reads)
    }

    @Test fun refreshCompletesBeforeTheSingleAuthorizationRead() {
        val calls = mutableListOf<String>()
        val snapshot = UltraAppListSnapshot.read(
            refresh = { calls += "refresh"; true },
            grantedPackages = { calls += "packages"; setOf("dev.allowed") },
        )
        assertEquals(listOf("refresh", "packages"), calls)
        assertTrue(snapshot.isGranted("dev.allowed", 10001))
        assertFalse(snapshot.isGranted("dev.other", 10002))
    }

    @Test fun failedRefreshDoesNotPublishAnOldOrInitiallyEmptyAuthorizationSet() {
        var reads = 0
        val failure = runCatching {
            UltraAppListSnapshot.read({ false }, { reads++; setOf("dev.old") })
        }.exceptionOrNull()
        assertTrue(failure is IllegalStateException)
        assertEquals("ULTRA_AUTH_REFRESH_FAILED", failure?.message)
        assertEquals(0, reads)
    }

    @Test fun aSuccessfullyReadEmptySetIsAValidSnapshot() {
        val snapshot = UltraAppListSnapshot.read({ true }, { emptySet() })
        assertEquals(0, snapshot.size)
        assertFalse(snapshot.isGranted("dev.allowed", 10001))
    }

    @Test fun theWholeBatchUsesACopyOfOneAuthorizationSnapshot() {
        val source = linkedSetOf("dev.allowed", "dev.second")
        val snapshot = UltraAppListSnapshot.read({ true }, { source })
        source.clear()
        source += "dev.new"
        assertEquals(2, snapshot.size)
        assertTrue(snapshot.isGranted("dev.allowed", 10001))
        assertFalse(snapshot.isGranted("dev.new", 10002))
    }

    @Test fun sharedUidPackagesKeepTheirIndividualPackageGlobalMembership() {
        val snapshot = UltraAppListSnapshot.read({ true }, { setOf("dev.allowed") })
        assertTrue(snapshot.isGranted("dev.allowed", 10001))
        assertFalse(snapshot.isGranted("dev.other", 10001))
        assertTrue(snapshot.isGranted("dev.allowed", 1010001))
    }

    @Test fun webViewZygoteIsNeverPresentedAsAuthorized() {
        val snapshot = UltraAppListSnapshot.read({ true }, { setOf("webview_zygote", "dev.allowed") })
        assertFalse(snapshot.isGranted("webview_zygote", 1053))
        assertFalse(snapshot.isGranted("dev.allowed", 1053))
    }

    @Test fun hundredsOfRowsDoNotRepeatTheSdkOrIdentityRead() {
        var refreshes = 0
        var reads = 0
        val snapshot = UltraAppListSnapshot.read(
            { refreshes++; true }, { reads++; setOf("dev.app1", "dev.app544") },
        )
        val allowed = (0 until 545).map { snapshot.isGranted("dev.app$it", 10000 + it) }
        assertEquals(1, refreshes)
        assertEquals(1, reads)
        assertEquals(2, allowed.count { it })
    }

    @Test fun aThrownSdkFailureDoesNotReadOrProjectTheOldSet() {
        var reads = 0
        val expected = IllegalStateException("FIXTURE_SDK_FAILURE")
        val failure = runCatching {
            UltraAppListSnapshot.read({ throw expected }, { reads++; emptySet() })
        }.exceptionOrNull()
        assertTrue(failure === expected)
        assertEquals(0, reads)
    }
}
