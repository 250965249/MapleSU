package dev.maplesu.manager.ksu

import org.junit.Assert.*
import org.junit.Test

class KsuVersionIdentityTest {
    @Test fun kernelIdentityDoesNotProveDaemonCompatibility() {
        assertNull(KsuVersionInfo.parse("version: 32650\nuapi_version: 7\n"))
    }
    @Test fun staleDaemonIsRejectedEvenWhenKernelUsesUapi7() {
        val info = KsuVersionInfo.parse("version: 32650\nuapi_version: 7\nuserspace_version: 32650\nuserspace_uapi_version: 6\n")!!
        assertFalse(info.matchesBuild)
        assertEquals(6, info.uapiVersion)
    }
    @Test fun matchingDaemonReportsItsOwnVersion() {
        val info = KsuVersionInfo.parse("version: 0\nuapi_version: 0\nuserspace_version: 32650\nuserspace_uapi_version: 7\n")!!
        assertTrue(info.matchesBuild)
        assertEquals(32650, info.version)
    }
}
