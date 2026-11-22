package dev.maplesu.manager.installer

import dev.maplesu.manager.workmode.switch.DeviceBootFacts
import dev.maplesu.manager.workmode.switch.BaselineErrors
import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class RecoveredOriginalBaselineProvisionerTest {
    @get:Rule val temporary = TemporaryFolder()

    @Test fun provenOriginalAndIndependentlyCleanInitBootPublishAndReuse() {
        val h = Harness()
        val ready = h.provisioner.ensureBaseline()
        assertTrue(ready is BaselineProvisionOutcome.Ready)
        assertEquals(1, h.bridge.published)
        val manifest = h.bridge.entries.single()
        assertEquals(setOf("boot", "init_boot"), manifest.imageSha256.keys)
        assertEquals(BaselineAtomicFiles.sha256(h.original), manifest.imageSha256["boot"])
        val captures = h.captureCount
        assertTrue((h.provisioner.ensureBaseline() as BaselineProvisionOutcome.Ready).reused)
        assertEquals(captures, h.captureCount)
        assertEquals(1, h.bridge.published)
    }

    @Test fun dirtyInitBootNeverBecomesOriginalJustBecauseBootRoundtripSucceeded() {
        val h = Harness(dirtyInitBoot = true)
        val failed = h.provisioner.ensureBaseline() as BaselineProvisionOutcome.Failed
        assertEquals(BaselineErrors.BASELINE_UNCLEAN, failed.code)
        assertEquals(0, h.bridge.published)
    }

    @Test fun missingRecoveryProofLeavesControlPlaneUntouched() {
        val h = Harness(recoverySucceeds = false)
        assertTrue(h.provisioner.ensureBaseline() is BaselineProvisionOutcome.Failed)
        assertEquals(0, h.bridge.published)
    }

    @Test fun incompleteTopologyOrChangedProbeFailsBeforePublication() {
        val h = Harness()
        h.required = setOf("boot", "init_boot", "vendor_boot")
        assertTrue(h.newProvisioner().ensureBaseline() is BaselineProvisionOutcome.Failed)
        assertEquals(0, h.bridge.published)
        h.required = setOf("boot", "init_boot")
        h.wrongSlot = true
        assertTrue(h.newProvisioner().ensureBaseline() is BaselineProvisionOutcome.Failed)
        assertEquals(0, h.bridge.published)
    }

    @Test fun stagingSpaceAccountsForFullPartitionVerificationCopiesBeforeCapture() {
        val h = Harness()
        h.availableBytes = 300L * 1024 * 1024
        h.partitionSizes = mapOf("boot" to 100L * 1024 * 1024, "init_boot" to 8L * 1024 * 1024)
        val failed = h.provisioner.ensureBaseline() as BaselineProvisionOutcome.Failed
        assertEquals("insufficient recovery staging space", failed.detail)
        assertEquals(0, h.captureCount)
        assertEquals(0, h.bridge.published)
    }

    @Test fun truncatedCurrentPartitionDoesNotReachOriginalRecovery() {
        val h = Harness()
        h.partitionSizes = h.partitionSizes + ("boot" to h.current.size.toLong() + 4096)
        assertTrue(h.provisioner.ensureBaseline() is BaselineProvisionOutcome.Failed)
        assertEquals(0, h.recoveryCount)
        assertEquals(0, h.bridge.published)
    }

    @Test fun deviceChangeDuringCapturePreventsPublication() {
        val h = Harness()
        h.changeSlotAfterCapture = true
        assertTrue(h.provisioner.ensureBaseline() is BaselineProvisionOutcome.Failed)
        assertEquals(0, h.bridge.published)
    }

    @Test fun controlPlaneReadbackIsRequiredAndOwnStagingIsCleaned() {
        val h = Harness()
        h.bridge.corruptReadback = true
        assertTrue(h.provisioner.ensureBaseline() is BaselineProvisionOutcome.Failed)
        assertEquals(1, h.bridge.published)
        assertTrue(File(h.root, "staging").listFiles().orEmpty().isEmpty())
        assertTrue(h.original.isFile)
    }

    private inner class Harness(dirtyInitBoot: Boolean = false, private val recoverySucceeds: Boolean = true) {
        val root = temporary.newFolder()
        val device = DeviceBootFacts("_b", "fixture-build", "6.6.89-fixture")
        val original = File(root, "retained.img").apply { writeBytes(boot()) }
        val current = boot().apply { this[4096] = 8 }
        val initBoot = boot(cpio(if (dirtyInitBoot) "kernelsu.ko" else "init"))
        val bridge = LocalBridge()
        var captureCount = 0
        var recoveryCount = 0
        var wrongSlot = false
        var changeSlotAfterCapture = false
        var required = setOf("boot", "init_boot")
        var availableBytes = 8L shl 30
        var partitionSizes = mapOf("boot" to current.size.toLong(), "init_boot" to initBoot.size.toLong())
        private val capture = object : BaselineLiveCapturePort {
            override fun probe() = BaselineCaptureProbe(if (wrongSlot || changeSlotAfterCapture && captureCount > 0) "_a" else device.slot,
                device.firmware, device.kernelRelease, "Enforcing",
                mapOf("boot" to "/dev/block/by-name/boot_b", "init_boot" to "/dev/block/by-name/init_boot_b"),
                partitionSizes)
            override fun writeMarkers(): BaselineWriteMarkers? = error("not a clean live-capture claim")
            override fun copy(name: String, destination: File): BaselineCapturedImage {
                captureCount++
                destination.parentFile?.mkdirs()
                destination.writeBytes(if (name == "boot") current else initBoot)
                return BaselineCapturedImage(name, destination, destination.length(), BaselineAtomicFiles.sha256(destination))
            }
        }
        val provisioner get() = newProvisioner()
        fun newProvisioner() = RecoveredOriginalBaselineProvisioner(bridge, capture, File(root, "staging"),
            { device }, { _, output -> recoveryCount++; if (recoverySucceeds) {
                output.mkdirs(); original.copyTo(File(output, "original.img"))
            } else null }, { availableBytes }, required)
    }

    private class LocalBridge : BaselineControlPlaneBridge {
        var entries = emptyList<BaselineControlPlaneEntry>()
        var published = 0
        var corruptReadback = false
        override fun probe() = entries
        override fun publish(id: String, localDirectory: File, expectedSha256: Map<String, String>): Boolean {
            published++
            val manifest = File(localDirectory, "manifest.json").readText()
            entries = listOf(BaselineControlPlaneEntry(id, manifest,
                BaselineAtomicFiles.sha256(File(localDirectory, "manifest.json")),
                File(localDirectory, "manifest.json.sha256").readText().trim(),
                if (corruptReadback) emptyMap() else expectedSha256,
                expectedSha256.keys.associateWith { File(localDirectory, "$it.img").length() }))
            return true
        }
    }

    private fun boot(ramdisk: ByteArray = ByteArray(0)): ByteArray {
        val kernelSize = if (ramdisk.isEmpty()) 4096 else 0
        val bytes = ByteArray(if (ramdisk.isEmpty()) 8192 else 4096 + ((ramdisk.size + 4095) / 4096) * 4096)
        ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).apply {
            put("ANDROID!".toByteArray()); putInt(8, kernelSize); putInt(12, ramdisk.size)
            putInt(20, 1584); putInt(40, 4)
        }
        ramdisk.copyInto(bytes, 4096 + kernelSize)
        return bytes
    }

    private fun cpio(name: String): ByteArray {
        val out = ByteArrayOutputStream()
        for (entry in listOf(name, "TRAILER!!!")) {
            val header = ByteArray(110) { '0'.code.toByte() }
            "070701".toByteArray().copyInto(header)
            "%08x".format(0x81a4).toByteArray().copyInto(header, 14)
            "%08x".format(entry.length + 1).toByteArray().copyInto(header, 94)
            out.write(header); out.write((entry + "\u0000").toByteArray())
            while (out.size() % 4 != 0) out.write(0)
        }
        return out.toByteArray()
    }
}
