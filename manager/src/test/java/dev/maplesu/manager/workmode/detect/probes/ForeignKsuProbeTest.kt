package dev.maplesu.manager.workmode.detect.probes

import org.junit.Assert.*
import org.junit.Test

class ForeignKsuProbeTest {
    @Test fun versionAndNonManagerFlagConfirmAForeignKernel() {
        assertEquals(true, ForeignKsuProbe.parseResponse("version: 10940\nflags: 0x1\n"))
    }
    @Test fun recognizedManagerIsNotAForeignKernel() {
        assertNull(ForeignKsuProbe.parseResponse("version: 10940\nflags: 0x2\n"))
    }
    @Test fun versionAloneAndUserspaceVersionNeverExcludeTheManager() {
        assertNull(ForeignKsuProbe.parseResponse("version: 10940\n"))
        assertNull(ForeignKsuProbe.parseResponse("userspace_version: 10940\nflags: 0x0\n"))
    }
    @Test fun nonRespondingKernelIsNotPositiveEvidence() {
        assertEquals(false, ForeignKsuProbe.parseResponse("version: 0\nflags: 0x0\n"))
        assertNull(ForeignKsuProbe.parseResponse("not available"))
    }
}
