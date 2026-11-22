package dev.maplesu.manager.liteweb.daemon

import org.junit.Assert.*
import org.junit.Test

class DaemonProcessIsolationTest {
    @Test fun uidZeroDoesNotMakeAnAppOwnedCgroupIndependent() {
        assertEquals(true, DaemonProcessIsolation.appOwned("0::/uid_10489/pid_100/uid_0"))
        assertEquals(true, DaemonProcessIsolation.appOwned("0::/uid_0/uid_10489/pid_100"))
        assertEquals(true, DaemonProcessIsolation.appOwned("4:memory:/apps/uid_10234\n0::/system/uid_0/pid_100"))
        assertEquals(false, DaemonProcessIsolation.appOwned("4:memory:/\n0::/system/uid_0/pid_100"))
        assertNull(DaemonProcessIsolation.appOwned(""))
        assertNull(DaemonProcessIsolation.appOwned("unreadable"))
    }

    @Test fun migrationIsVerifiedBeforeTheManagerCanBeRemoved() {
        var groups = "0::/uid_10489/pid_100"
        val moved = mutableListOf<Int>()
        val isolation = DaemonProcessIsolation({ groups }, { 200 }) { path, pid ->
            assertTrue(path.endsWith("/cgroup.procs"))
            moved += pid
            groups = "0::/system/uid_0/pid_200"
            true
        }
        assertTrue(isolation.ensure())
        assertEquals(listOf(200), moved)
    }

    @Test fun aSuccessfulWriteWithoutMembershipChangeNeverProvesIsolation() {
        val isolation = DaemonProcessIsolation({ "0::/uid_10489/pid_100" }, { 200 }) { _, _ -> true }
        assertFalse(isolation.ensure())
    }

    @Test fun rootOwnedDaemonsNeedNoMigrationAndUnreadableGroupsFailClosed() {
        assertTrue(DaemonProcessIsolation({ "0::/system/uid_0/pid_200" }, { 200 }) { _, _ -> error("already isolated") }.ensure())
        assertFalse(DaemonProcessIsolation({ null }, { 200 }) { _, _ -> error("unverified membership") }.ensure())
    }
}
