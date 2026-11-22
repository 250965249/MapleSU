package dev.maplesu.manager.workmode.service

import org.junit.Assert.*
import org.junit.Test

class ClientStatusCarrierTest {
    @Test fun explicitCarrierWinsOverVivoAndSignatureCompanions() {
        val status = status("init_boot", listOf(row("boot"), row("init_boot"), row("vendor_boot"), row("vbmeta")))
        assertEquals("init_boot", status.carrierCandidate()?.name)
        assertEquals("init_boot-sha", status.carrierCandidate()?.targetSha256)
    }

    @Test fun missingExplicitCarrierDoesNotFallBackToAnotherWrite() {
        assertNull(status("init_boot", listOf(row("boot"), row("vbmeta"))).carrierCandidate())
    }

    @Test fun legacyReceiptAcceptsOnlyOneUnambiguousCarrier() {
        assertEquals("boot", status(null, listOf(row("boot"), row("vendor_boot"))).carrierCandidate()?.name)
        assertNull(status(null, listOf(row("boot"), row("init_boot"))).carrierCandidate())
        assertNull(status(null, listOf(row("boot").copy(role = "RESTORE_SOURCE"))).carrierCandidate())
    }

    private fun row(name: String) = ClientPartition(name, "WRITE_CANDIDATE", 8192, "pre", "$name-sha", "", "VERIFIED")
    private fun status(carrier: String?, rows: List<ClientPartition>) = ClientStatus(
        "id", "VERIFIED", "", "", "KSU", "LITE", "", "", "", false, true, false, false, 0, rows,
        slotSuffix = "_a", targetPartition = carrier, signingMode = "NON_CHAINED")
}
