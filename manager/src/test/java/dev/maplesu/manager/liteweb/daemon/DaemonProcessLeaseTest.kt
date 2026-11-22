package dev.maplesu.manager.liteweb.daemon

import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

class DaemonProcessLeaseTest {
    @get:Rule val temp = TemporaryFolder()

    @Test fun concurrentLaunchNeverOverwritesOwnersPid() {
        val pid = File(temp.root, "liteweb.pid").apply { writeText("999\n") }
        DaemonProcessLease.acquire(temp.root, "123")!!.use { first ->
            assertEquals("999\n", pid.readText())
            assertNull(DaemonProcessLease.acquire(temp.root, "456"))
            first.publish()
            assertEquals("123\n", pid.readText())
        }
        DaemonProcessLease.acquire(temp.root, "456")!!.use { second ->
            second.publish()
            assertEquals("456\n", pid.readText())
        }
    }

    @Test fun failedStartupDoesNotPublishPidAndReleasesLock() {
        val pid = File(temp.root, "liteweb.pid")
        runCatching { DaemonProcessLease.acquire(temp.root, "123")!!.use { error("bind failed") } }
        assertFalse(pid.exists())
        DaemonProcessLease.acquire(temp.root, "456")!!.use { it.publish() }
        assertEquals("456\n", pid.readText())
    }
}
