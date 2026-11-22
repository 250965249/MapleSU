package dev.maplesu.manager.liteweb.daemon

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class DaemonSuPackageCatalogTest {
    @Test fun packageCatalogPreservesRealFullUidAndUser() {
        val apps = requireNotNull(DaemonSuPackageCatalog.parse(
            "package:android uid:1000\npackage:com.example.app uid:10123\npackage:com.example.app uid:1010123\n",
        ))
        assertEquals(listOf(1000, 10123, 1010123), apps.map { it.uid })
        assertEquals(listOf(0, 0, 10), apps.map { it.userId })
    }

    @Test fun duplicateRowsAreRemovedButUsersAreDistinct() {
        val apps = requireNotNull(DaemonSuPackageCatalog.parse(
            "package:com.example.app uid:10123\npackage:com.example.app uid:10123\npackage:com.example.app uid:1010123",
        ))
        assertEquals(2, apps.size)
    }

    @Test fun malformedOrErrorOutputIsNotAnEmptyCatalog() {
        for (output in listOf("Error: unsupported user all", "package:com.app", "package:com.app uid:-1",
            "package:com.app uid:999999999999", "package:com.app uid:10123\ntruncated")) {
            assertNull(output, DaemonSuPackageCatalog.parse(output))
        }
    }
}
