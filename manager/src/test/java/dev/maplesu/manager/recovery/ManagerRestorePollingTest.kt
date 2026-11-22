package dev.maplesu.manager.recovery

import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.CancellationException
import org.junit.Assert.*
import org.junit.Test
import java.io.File

class ManagerRestorePollingTest {
    @Test fun restoreConfirmationUsesTheCurrentSdkOwner() {
        val source = File("src/main/java/dev/maplesu/manager/recovery/ManagerRestoreConfirmation.kt").readText()
        assertTrue(source.contains("UltraEnvRootRunner(UltraSdkCredentials.client(activity))"))
        assertTrue(source.contains("UltraSdkCredentials.read(activity) != null"))
        assertFalse(source.contains("UltraRootKeyStore"))
    }

    @Test fun aConclusiveAbsenceDoesNotPollTheSdkEightTimes() = runBlocking {
        var calls = 0
        val pauses = mutableListOf<Long>()
        val value = readRestoreOnceReady<String>(
            load = { calls++; Result.success(null) },
            pause = { pauses += it },
        )
        assertNull(value)
        assertEquals(1, calls)
        assertTrue(pauses.isEmpty())
    }

    @Test fun temporaryFailuresRetryUntilTheTicketIsReadable() = runBlocking {
        var calls = 0
        val pauses = mutableListOf<Long>()
        val value = readRestoreOnceReady(
            load = { if (++calls < 3) Result.failure(IllegalStateException("busy")) else Result.success("ticket") },
            pause = { pauses += it },
        )
        assertEquals("ticket", value)
        assertEquals(3, calls)
        assertEquals(listOf(1_000L, 1_000L), pauses)
    }

    @Test fun anAbsentTicketAfterABusyReadStopsPolling() = runBlocking {
        var calls = 0
        val pauses = mutableListOf<Long>()
        assertNull(readRestoreOnceReady<String>(
            load = { if (++calls == 1) Result.failure(IllegalStateException("busy")) else Result.success(null) },
            pause = { pauses += it },
        ))
        assertEquals(2, calls)
        assertEquals(listOf(1_000L), pauses)
    }

    @Test fun repeatedFailuresStayBoundedAndDoNotSleepAfterTheLastAttempt() = runBlocking {
        var calls = 0
        val pauses = mutableListOf<Long>()
        assertNull(readRestoreOnceReady<String>(
            load = { calls++; Result.failure(IllegalStateException("busy")) },
            pause = { pauses += it },
        ))
        assertEquals(8, calls)
        assertEquals(7, pauses.size)
    }

    @Test fun foregroundStartupWaitsForLateIdentityRecovery() = runBlocking {
        var calls = 0
        var pauses = 0
        val ticket = readRestoreOnceReady(
            attempts = 30,
            load = {
                if (++calls < 18) Result.failure(IllegalStateException("RESTORE_KEY_NOT_READY"))
                else Result.success("pending-ticket")
            },
            pause = { pauses++ },
        )
        assertEquals("pending-ticket", ticket)
        assertEquals(18, calls)
        assertEquals(17, pauses)
    }

    @Test fun leavingForegroundCancelsObservationInsteadOfRetrying() = runBlocking {
        var calls = 0
        try {
            readRestoreOnceReady<String>(
                load = { calls++; Result.failure(CancellationException("background")) },
                pause = { error("cancelled observation must not pause or retry") },
            )
            fail("cancellation must propagate to repeatOnLifecycle")
        } catch (_: CancellationException) {
            assertEquals(1, calls)
        }
    }
}
