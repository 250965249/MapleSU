package dev.maplesu.manager.installer

import dev.maplesu.manager.workmode.control.ControlJsonCodec
import dev.maplesu.manager.workmode.control.ControlPaths
import dev.maplesu.manager.workmode.detect.Clock
import dev.maplesu.manager.workmode.storage.MoveSet
import dev.maplesu.manager.workmode.switch.AvbFacts
import dev.maplesu.manager.workmode.switch.BaselineErrors
import dev.maplesu.manager.workmode.switch.BaselineManifest
import dev.maplesu.manager.workmode.switch.BaselinePartition
import dev.maplesu.manager.workmode.switch.BaselineProvenance
import dev.maplesu.manager.workmode.switch.BaselineResult
import dev.maplesu.manager.workmode.switch.BaselineRules
import dev.maplesu.manager.workmode.switch.BaselineState
import dev.maplesu.manager.workmode.switch.DeviceBootFacts
import dev.maplesu.manager.workmode.switch.FileBaselineStore
import dev.maplesu.manager.workmode.switch.ModeSwitchCodes
import dev.maplesu.manager.workmode.switch.PatchMarkers
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.IOException
import java.nio.file.Files
import java.security.MessageDigest
import java.util.zip.GZIPOutputStream

/**
 * W4a（`50-w4a-capture-first.md`）主机测试：**抓取优先**的基线获取。
 *
 * 断言的是"用户点一次"的硬语义（无设备、无 root、无 Android）：
 * - 源顺序 `① 复用 → ② 现场抓取 → ③ 随包资产（仅兜底）`；
 * - 抓取**只读**分区、**零 dd 复用**、失败即显式错误码且控制面保持干净；
 * - `clean` 只来自真实 cleanliness 结论（不再有任何 `clean = true` 硬写）；
 * - id 内容派生（slot + firmware + sha256(boot)）；
 * - 恢复目录落在 NEVER_MOVE 的 `maplesu-workmode` 子树里。
 */
class BaselineCaptureFirstTest {

    private class TestClock(var now: Long = 11_000L) : Clock {
        override fun nowMillis(): Long = now
    }

    // ------------------------------------------------------------------ fixtures

    /** 与 `BaselineCleanlinessTest` / `BaselineProvisionerTest` 同构的最小 boot 容器。 */
    private fun bootContainer(ramdisk: ByteArray, kernelSize: Int = 64): ByteArray {
        val page = 4096
        val kernel = ByteArray(kernelSize) { (it and 0xFF).toByte() }
        val offset = ((page + kernel.size + page - 1) / page) * page
        val size = ((offset + ramdisk.size + page - 1) / page) * page
        val image = ByteArray(size)
        val buffer = java.nio.ByteBuffer.wrap(image).order(java.nio.ByteOrder.LITTLE_ENDIAN)
        buffer.put("ANDROID!".toByteArray(Charsets.US_ASCII))
        buffer.putInt(8, kernel.size)
        buffer.putInt(16, ramdisk.size)
        buffer.putInt(24, 0)
        buffer.putInt(36, page)
        buffer.putInt(40, 0)
        System.arraycopy(kernel, 0, image, page, kernel.size)
        if (ramdisk.isNotEmpty()) System.arraycopy(ramdisk, 0, image, offset, ramdisk.size)
        return image
    }

    private fun cpioGzip(entries: List<Pair<String, ByteArray>>): ByteArray {
        val cpio = ByteArrayOutputStream()

        fun field(header: ByteArray, value: Int, offset: Int) {
            val text = "%08x".format(value)
            for (index in 0 until 8) header[offset + index] = text[index].code.toByte()
        }

        fun writeEntry(name: String, data: ByteArray) {
            val nameBytes = (name + "\u0000").toByteArray(Charsets.UTF_8)
            val header = ByteArray(110) { '0'.code.toByte() }
            "070701".toByteArray(Charsets.US_ASCII).copyInto(header, 0)
            field(header, 1, 6); field(header, 0x81A4, 14); field(header, 1, 38)
            field(header, data.size, 54); field(header, nameBytes.size, 94); field(header, 0, 102)
            cpio.write(header)
            cpio.write(nameBytes)
            while (cpio.size() % 4 != 0) cpio.write(0)
            cpio.write(data)
            while (cpio.size() % 4 != 0) cpio.write(0)
        }

        for ((name, data) in entries) writeEntry(name, data)
        // A newc stream ends with a real "TRAILER!!!" entry. An all-'0' header (namesize = 0) is
        // *not* a valid cpio stream — RamdiskInspector reports INVALID_CPIO_HEADER for it, so the
        // fixture would look like a corrupt image instead of a stock one.
        val trailerName = "TRAILER!!!\u0000".toByteArray(Charsets.UTF_8)
        val trailer = ByteArray(110) { '0'.code.toByte() }
        "070701".toByteArray(Charsets.US_ASCII).copyInto(trailer, 0)
        field(trailer, 1, 6); field(trailer, 0x81A4, 14); field(trailer, 1, 38)
        field(trailer, trailerName.size, 94); field(trailer, 0, 102)
        cpio.write(trailer)
        cpio.write(trailerName)
        while (cpio.size() % 4 != 0) cpio.write(0)
        val out = ByteArrayOutputStream()
        GZIPOutputStream(out).use { it.write(cpio.toByteArray()) }
        return out.toByteArray()
    }

    private fun stockRamdisk(): ByteArray = cpioGzip(
        listOf("init" to byteArrayOf(1, 2, 3), "system/bin/sh" to byteArrayOf(4, 5, 6)),
    )

    private fun ksuRamdisk(): ByteArray = cpioGzip(
        listOf(
            "init" to byteArrayOf(1, 2, 3),
            "init.real" to byteArrayOf(4, 5),
            "kernelsu.ko" to byteArrayOf(9, 9, 9, 9),
        ),
    )

    private fun sha(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes)
            .joinToString("") { "%02x".format(it.toInt() and 0xFF) }

    // ------------------------------------------------------------------ fakes

    /** 用本地目录模拟控制面（等价于 root 侧 `cp -a + mv`）。 */
    private class LocalBridge(private val plane: File) : BaselineControlPlaneBridge {
        var publishCalls = 0
        var failPublish = false
        var probeUnreadable = false

        override fun probe(): List<BaselineControlPlaneEntry>? {
            if (probeUnreadable) return null
            val baseline = File(plane, "boot/baseline")
            if (!baseline.isDirectory) return emptyList()
            return baseline.listFiles { file -> file.isDirectory }?.mapNotNull { directory ->
                val manifestFile = File(directory, "manifest.json")
                if (!manifestFile.isFile) return@mapNotNull null
                val raw = manifestFile.readText(Charsets.UTF_8)
                val shas = LinkedHashMap<String, String>()
                val sizes = LinkedHashMap<String, Long>()
                for (partition in listOf("boot", "init_boot")) {
                    val image = File(directory, "$partition.img")
                    if (!image.isFile) continue
                    shas[partition] = shaOf(image.readBytes())
                    sizes[partition] = image.length()
                }
                BaselineControlPlaneEntry(
                    id = directory.name,
                    manifestJson = raw,
                    manifestSha256 = shaOf(raw.toByteArray(Charsets.UTF_8)),
                    shaFile = File(directory, "manifest.json.sha256")
                        .takeIf { it.isFile }?.readText(Charsets.UTF_8)?.trim().orEmpty(),
                    imageSha256 = shas,
                    imageSize = sizes,
                )
            }.orEmpty()
        }

        override fun publish(id: String, localDirectory: File, expectedSha256: Map<String, String>): Boolean {
            if (failPublish) return false
            publishCalls++
            val destination = File(plane, "boot/baseline/$id")
            if (destination.exists()) return false
            localDirectory.copyRecursively(destination, overwrite = true)
            return true
        }

        private fun shaOf(bytes: ByteArray): String =
            MessageDigest.getInstance("SHA-256").digest(bytes)
                .joinToString("") { "%02x".format(it.toInt() and 0xFF) }
    }

    private inner class FakeLiveCapture(
        var probeValue: BaselineCaptureProbe?,
        private val contents: Map<String, ByteArray>,
        var markers: BaselineWriteMarkers? = BaselineWriteMarkers(false, 0, 0),
    ) : BaselineLiveCapturePort {
        var copyCalls = 0
        var failCopy = false

        override fun probe(): BaselineCaptureProbe? = probeValue

        override fun writeMarkers(): BaselineWriteMarkers? = markers

        override fun copy(name: String, destination: File): BaselineCapturedImage {
            copyCalls++
            if (failCopy) {
                throw BaselineCaptureFault(BaselineCaptureCodes.CAPTURE_READ_FAILED, "$name: dd failed")
            }
            val bytes = contents[name]
                ?: throw BaselineCaptureFault(BaselineCaptureCodes.CAPTURE_READ_FAILED, "$name: no node")
            destination.parentFile?.mkdirs()
            destination.writeBytes(bytes)
            return BaselineCapturedImage(name, destination, bytes.size.toLong(), sha(bytes))
        }
    }

    private inner class Harness(
        includeInitBoot: Boolean,
        bootRamdisk: ByteArray,
        initBootRamdisk: ByteArray,
    ) {
        val root: File = Files.createTempDirectory("maplesu-capture-first-").toFile()
        val clock = TestClock()
        val device = DeviceBootFacts(SLOT, FIRMWARE, KERNEL_RELEASE)
        val bootBytes = bootContainer(bootRamdisk)
        val initBootBytes = bootContainer(initBootRamdisk)
        val contents = LinkedHashMap<String, ByteArray>().apply {
            put("boot", bootBytes)
            if (includeInitBoot) put("init_boot", initBootBytes)
        }
        val devices = LinkedHashMap<String, String>().apply {
            put("boot", "/dev/block/by-name/boot_a")
            if (includeInitBoot) put("init_boot", "/dev/block/by-name/init_boot_a")
        }
        val sizes = contents.mapValues { it.value.size.toLong() }
        val plane: File = File(root, "control-plane")
        val bridge = LocalBridge(plane)
        val capture = FakeLiveCapture(
            BaselineCaptureProbe(SLOT, FIRMWARE, KERNEL_RELEASE, "Enforcing", devices, sizes),
            contents,
        )

        fun provisioner(
            stockFallback: BaselineProvisioner? = null,
            freeBytes: () -> Long = { 8L shl 30 },
            installerRecovery: BaselineProvisioner? = null,
        ): BaselineProvisioner = CaptureFirstBaselineProvisioner(
            bridge = bridge,
            capture = capture,
            stagingRoot = File(root, "app-cache"),
            deviceFacts = { device },
            cleanliness = RamdiskBaselineCleanliness(),
            stockFallback = stockFallback,
            freeBytes = freeBytes,
            clock = clock,
            installerRecovery = installerRecovery,
        )

        fun fingerprint(plane: File = this.plane): Map<String, String> {
            if (!plane.isDirectory) return emptyMap()
            return plane.walkTopDown().filter { it.isFile }.associate { file ->
                file.relativeTo(plane).path.replace('\\', '/') to "${file.length()}:${sha(file.readBytes())}"
            }
        }

        fun close() {
            root.deleteRecursively()
        }

        fun manifestOf(id: String): BaselineManifest? {
            val file = File(plane, "boot/baseline/$id/manifest.json")
            if (!file.isFile) return null
            return ControlJsonCodec.decodeOrNull(
                file.readText(Charsets.UTF_8), BaselineManifest.serializer(),
            )
        }
    }

    private fun withHarness(
        includeInitBoot: Boolean = true,
        bootRamdisk: ByteArray = ByteArray(0),
        initBootRamdisk: ByteArray = stockRamdisk(),
        block: (Harness) -> Unit,
    ) {
        val harness = Harness(includeInitBoot, bootRamdisk, initBootRamdisk)
        try {
            block(harness)
        } finally {
            harness.close()
        }
    }

    private fun ready(outcome: BaselineProvisionOutcome): BaselineProvisionOutcome.Ready {
        assertTrue("expected Ready but was $outcome", outcome is BaselineProvisionOutcome.Ready)
        return outcome as BaselineProvisionOutcome.Ready
    }

    private fun failed(outcome: BaselineProvisionOutcome, code: String): BaselineProvisionOutcome.Failed {
        assertTrue("expected Failed but was $outcome", outcome is BaselineProvisionOutcome.Failed)
        val failure = outcome as BaselineProvisionOutcome.Failed
        assertEquals("code (detail=${failure.detail})", code, failure.code)
        return failure
    }

    // ------------------------------------------------------------------ ② 现场抓取

    @Test
    fun capturesLivePartitionsAndPublishesWithoutAnyPin() = withHarness { h ->
        val outcome = ready(h.provisioner().ensureBaseline())
        assertFalse("首次必须是现场抓取，不得声称复用", outcome.reused)
        assertEquals(BaselineProvenance.PRE_FIRST_WRITE_CAPTURE, outcome.provenance)
        // 真的读了两个分区各一次（只读 dd 一次，不多读）。
        assertEquals(2, h.capture.copyCalls)
        assertEquals(1, h.bridge.publishCalls)
        // 控制面里就是消费方读的那份字节。
        val boot = File(h.plane, "boot/baseline/${outcome.id}/boot.img")
        val initBoot = File(h.plane, "boot/baseline/${outcome.id}/init_boot.img")
        assertTrue(boot.isFile)
        assertTrue(initBoot.isFile)
        assertEquals(sha(h.bootBytes), sha(boot.readBytes()))
        assertEquals(sha(h.initBootBytes), sha(initBoot.readBytes()))
        // id 内容派生：bl-<slot>-<fw8>-<boot12>
        assertTrue("id=${outcome.id}", Regex("^bl-a-[0-9a-f]{8}-[0-9a-f]{12}$").matches(outcome.id))
        assertTrue(BaselineIdentity.isValidId(outcome.id))
        val manifest = h.manifestOf(outcome.id)
        assertNotNull(manifest)
        assertTrue("clean 必须来自 cleanliness 结论", manifest!!.clean)
        assertTrue(manifest.patchMarkers.allAbsent)
        assertEquals(BaselineProvenance.PRE_FIRST_WRITE_CAPTURE, manifest.provenance)
        assertEquals(2, manifest.partitions.size)
        assertTrue(manifest.partitions.all { it.avbTailPreserved })
        // App 暂存必须清干净（不把 96–200 MiB 留在 cacheDir）。
        assertFalse(File(h.root, "app-cache/baseline-capture").exists())
    }

    @Test
    fun emptyRamdiskStockBootIsCapturable() = withHarness(bootRamdisk = ByteArray(0)) { h ->
        // stock GKI boot.img 的 ramdisk_size 就是 0：`EMPTY_RAMDISK` 是"没有可植入面"，
        // 不是"损坏"。抓取路径与 import 路径走同一个 cleanliness 实现，必须同样放行。
        val outcome = ready(h.provisioner().ensureBaseline())
        assertEquals(BaselineState.PRESENT_OK, h.manifestOf(outcome.id)?.let { manifest ->
            BaselineRules.evaluate(
                manifest, h.device, false, { name ->
                    File(h.plane, "boot/baseline/${outcome.id}/$name.img")
                        .takeIf { it.isFile }?.let { sha(it.readBytes()) }
                },
            ).state
        })
    }

    @Test
    fun secondRunReusesWithoutAnyCaptureOrPublish() = withHarness { h ->
        val first = ready(h.provisioner().ensureBaseline())
        val before = h.fingerprint()
        val callsBefore = h.capture.copyCalls
        val publishBefore = h.bridge.publishCalls

        val second = ready(h.provisioner().ensureBaseline())
        assertTrue("② 之后的第二次必须复用", second.reused)
        assertEquals(first.id, second.id)
        assertEquals("复用不得再 dd", callsBefore, h.capture.copyCalls)
        assertEquals("复用不得再发布", publishBefore, h.bridge.publishCalls)
        assertEquals("复用不得改写控制面", before, h.fingerprint())
    }

    @Test
    fun originalBaselineIsReusedAfterUltraInstallationWithoutOverwritingIt() = withHarness { h ->
        val first = ready(h.provisioner().ensureBaseline())
        val before = h.fingerprint()
        val copyCalls = h.capture.copyCalls
        h.capture.markers = BaselineWriteMarkers(
            false, 0, 0, modulePresent = true,
            installerTransactions = 1, ultraEnvironmentPresent = true,
        )
        val second = ready(h.provisioner().ensureBaseline())
        assertTrue(second.reused)
        assertEquals(first.id, second.id)
        assertEquals(copyCalls, h.capture.copyCalls)
        assertEquals(1, h.bridge.publishCalls)
        assertEquals(before, h.fingerprint())
    }

    @Test
    fun missingManifestSidecarIsNotReusedAsTrustedOriginal() = withHarness { h ->
        val first = ready(h.provisioner().ensureBaseline())
        File(h.plane, "boot/baseline/${first.id}/manifest.json.sha256").delete()
        h.capture.markers = BaselineWriteMarkers(false, 0, 0, installerTransactions = 1)
        val copies = h.capture.copyCalls
        failed(h.provisioner().ensureBaseline(), BaselineErrors.BASELINE_PROVENANCE_UNKNOWN)
        assertEquals(copies, h.capture.copyCalls)
        assertEquals(1, h.bridge.publishCalls)
    }

    @Test
    fun missingDeclaredInitBootIsNotReused() = withHarness { h ->
        val first = ready(h.provisioner().ensureBaseline())
        File(h.plane, "boot/baseline/${first.id}/init_boot.img").delete()
        h.capture.markers = BaselineWriteMarkers(false, 0, 0, ultraEnvironmentPresent = true)
        val copies = h.capture.copyCalls
        failed(h.provisioner().ensureBaseline(), BaselineErrors.BASELINE_PROVENANCE_UNKNOWN)
        assertEquals(copies, h.capture.copyCalls)
        assertEquals(1, h.bridge.publishCalls)
    }

    @Test
    fun bootOnlyBaselineDoesNotSatisfyDeviceWithInitBoot() = withHarness { h ->
        val fullProbe = h.capture.probeValue!!
        h.capture.probeValue = fullProbe.copy(
            devices = fullProbe.devices.filterKeys { it == "boot" },
            sizes = fullProbe.sizes.filterKeys { it == "boot" },
        )
        val first = ready(h.provisioner().ensureBaseline())
        assertEquals(listOf("boot"), h.manifestOf(first.id)!!.partitions.map { it.name })
        h.capture.probeValue = fullProbe
        h.capture.markers = BaselineWriteMarkers(false, 0, 0, installerTransactions = 1)
        failed(h.provisioner().ensureBaseline(), BaselineErrors.BASELINE_PROVENANCE_UNKNOWN)
        assertEquals(1, h.capture.copyCalls)
        assertEquals(1, h.bridge.publishCalls)
    }

    @Test
    fun bootOnlyDeviceCapturesAndReusesBootOnlyBaseline() = withHarness(includeInitBoot = false) { h ->
        val first = ready(h.provisioner().ensureBaseline())
        assertEquals(1, h.capture.copyCalls)
        val manifest = h.manifestOf(first.id)!!
        assertEquals(listOf("boot"), manifest.partitions.map { it.name })
        val second = ready(h.provisioner().ensureBaseline())
        assertTrue("boot-only 基线也必须能复用", second.reused)
        assertEquals(first.id, second.id)
    }

    // ------------------------------------------------------------------ 失败语义

    @Test
    fun captureFailureIsExplicitAndFallsBackToStockOnly() = withHarness { h ->
        h.capture.failCopy = true
        val stock = BaselineProvisioner {
            BaselineProvisionOutcome.Ready("bl-stock", reused = false, provenance = BaselineProvenance.OEM_PACKAGE)
        }
        val outcome = ready(h.provisioner(stockFallback = stock).ensureBaseline())
        assertEquals("bl-stock", outcome.id)
        assertEquals(BaselineProvenance.OEM_PACKAGE, outcome.provenance)
        assertEquals("抓取失败不得发布任何字节", 0, h.bridge.publishCalls)
        assertTrue(h.fingerprint().isEmpty())
        assertFalse(File(h.root, "app-cache/baseline-capture").exists())
    }

    @Test
    fun captureFailureWithoutStockIsExplicitAndLeavesControlPlaneClean() = withHarness { h ->
        h.capture.failCopy = true
        failed(h.provisioner().ensureBaseline(), BaselineCaptureCodes.CAPTURE_READ_FAILED)
        assertEquals(0, h.bridge.publishCalls)
        assertTrue(h.fingerprint().isEmpty())
    }

    @Test
    fun uncleanLiveImageIsNeverCaptured() = withHarness(initBootRamdisk = ksuRamdisk()) { h ->
        val stock = BaselineProvisioner {
            BaselineProvisionOutcome.Failed(BaselineErrors.BASELINE_CAPTURE_UNSUPPORTED, "no pins")
        }
        val failure = failed(h.provisioner(stockFallback = stock).ensureBaseline(), BaselineErrors.BASELINE_UNCLEAN)
        assertTrue("detail 必须能看出两条路都试过: ${failure.detail}", failure.detail.contains("stock:"))
        assertEquals(0, h.bridge.publishCalls)
        assertTrue("不干净的镜像绝不落控制面", h.fingerprint().isEmpty())
    }

    @Test
    fun earlierWriteMarkersBlockCaptureAndFallBack() = withHarness { h ->
        h.capture.markers = BaselineWriteMarkers(
            installedJson = false, takeoverEntries = 1, switchJournals = 0,
        )
        val stock = BaselineProvisioner {
            BaselineProvisionOutcome.Failed(BaselineErrors.BASELINE_CAPTURE_UNSUPPORTED, "no pins")
        }
        failed(
            h.provisioner(stockFallback = stock).ensureBaseline(),
            BaselineErrors.BASELINE_PROVENANCE_UNKNOWN,
        )
        assertEquals("有写盘证据时连 dd 都不该发生", 0, h.capture.copyCalls)
        assertTrue(h.fingerprint().isEmpty())
    }

    @Test
    fun unreadableWriteMarkersBlockCapture() = withHarness { h ->
        h.capture.markers = null
        failed(h.provisioner().ensureBaseline(), BaselineErrors.BASELINE_PROVENANCE_UNKNOWN)
        assertEquals(0, h.capture.copyCalls)
    }

    @Test
    fun installerHistoryBlocksCaptureBeforeReadingEitherPartition() = withHarness { h ->
        h.capture.markers = BaselineWriteMarkers(false, 0, 0, installerTransactions = 1)
        failed(h.provisioner().ensureBaseline(), BaselineErrors.BASELINE_PROVENANCE_UNKNOWN)
        assertEquals(0, h.capture.copyCalls)
        assertEquals(0, h.bridge.publishCalls)
    }

    @Test
    fun ultraEnvironmentBlocksEmptyRamdiskKernelCapture() = withHarness { h ->
        h.capture.markers = BaselineWriteMarkers(false, 0, 0, ultraEnvironmentPresent = true)
        failed(h.provisioner().ensureBaseline(), BaselineErrors.BASELINE_PROVENANCE_UNKNOWN)
        assertEquals(0, h.capture.copyCalls)
        assertEquals(0, h.bridge.publishCalls)
    }

    private inner class FakeInstallerRecovery(
        private val h: Harness,
        var record: InstallerRecoveryRecord = InstallerRecoveryRecord(
            schema = 1,
            taskId = "7f197b90-7cb7-4a87-94b3-4cf59dd9120a",
            state = "BOOT_IMAGE_VERIFIED",
            kernelRelease = KERNEL_RELEASE,
            firmware = FIRMWARE,
            slotSuffix = SLOT,
            partitions = h.contents.mapValues { (name, bytes) ->
                InstallerRecoveryPartition("/dev/block/$name", bytes.size.toLong(), sha(bytes))
            },
        ),
    ) : InstallerRecoverySource {
        var bootCopies = 0
        override fun records(): List<InstallerRecoveryRecord> = listOf(record)
        override fun copyBoot(record: InstallerRecoveryRecord, destination: File): BaselineCapturedImage {
            bootCopies++
            destination.parentFile?.mkdirs()
            destination.writeBytes(h.bootBytes)
            return BaselineCapturedImage("boot", destination, h.bootBytes.size.toLong(), sha(h.bootBytes))
        }
    }

    private fun recoveryProvisioner(
        h: Harness,
        recovery: FakeInstallerRecovery,
        stockPinned: Boolean = true,
        device: DeviceBootFacts = h.device,
    ) = InstallerRecoveryBaselineProvisioner(
        bridge = h.bridge,
        recovery = recovery,
        capture = h.capture,
        stagingRoot = File(h.root, "recovery-cache"),
        deviceFacts = { device },
        trustedOriginalBoot = { _, release -> stockPinned && release == KERNEL_RELEASE },
        freeBytes = { 8L shl 30 },
        clock = h.clock,
    )

    @Test
    fun independentlyPinnedInstallerOriginalCanRestoreTheBaselineChannel() = withHarness { h ->
        h.capture.markers = BaselineWriteMarkers(false, 0, 0, installerTransactions = 1, ultraEnvironmentPresent = true)
        val historical = FakeInstallerRecovery(h)
        val imported = ready(h.provisioner(installerRecovery = recoveryProvisioner(h, historical)).ensureBaseline())
        assertFalse(imported.reused)
        assertEquals(1, historical.bootCopies)
        assertEquals("only unchanged init_boot is read live", 1, h.capture.copyCalls)
        assertEquals(1, h.bridge.publishCalls)
        assertEquals(sha(h.bootBytes), sha(File(h.plane, "boot/baseline/${imported.id}/boot.img").readBytes()))
        assertEquals(sha(h.initBootBytes), sha(File(h.plane, "boot/baseline/${imported.id}/init_boot.img").readBytes()))
        assertTrue(h.manifestOf(imported.id)!!.clean)
        assertFalse(File(h.root, "recovery-cache/recovery-${historical.record.taskId}").exists())
    }

    @Test
    fun historicalStockPinUsesOriginalReleaseAfterWorkModeKernelChange() = withHarness { h ->
        val historical = FakeInstallerRecovery(h)
        val running = h.device.copy(firmware = "mode-reported-firmware", kernelRelease = "6.6.115-android15-8-normal")
        h.capture.probeValue = h.capture.probeValue!!.copy(firmware = running.firmware, kernelRelease = running.kernelRelease)
        val imported = ready(recoveryProvisioner(h, historical, device = running).ensureBaseline())
        assertFalse(imported.reused)
        assertEquals(1, historical.bootCopies)
        assertEquals(1, h.bridge.publishCalls)
        assertEquals(sha(h.bootBytes), sha(File(h.plane, "boot/baseline/${imported.id}/boot.img").readBytes()))
        assertTrue(h.manifestOf(imported.id)!!.clean)
    }

    @Test
    fun historicalReleaseWithoutIndependentStockPinStillRejectsImport() = withHarness { h ->
        val historical = FakeInstallerRecovery(h)
        historical.record = historical.record.copy(kernelRelease = "untrusted-original-release")
        val failure = failed(recoveryProvisioner(h, historical).ensureBaseline(), BaselineErrors.BASELINE_PROVENANCE_UNKNOWN)
        assertTrue(failure.detail.contains("trusted stock pin"))
        assertEquals(0, h.bridge.publishCalls)
    }

    @Test
    fun installerDigestAloneDoesNotProveOriginalKernelCleanliness() = withHarness { h ->
        h.capture.markers = BaselineWriteMarkers(false, 0, 0, installerTransactions = 1)
        val historical = FakeInstallerRecovery(h)
        val result = h.provisioner(installerRecovery = recoveryProvisioner(h, historical, stockPinned = false))
            .ensureBaseline()
        val failure = failed(result, BaselineErrors.BASELINE_PROVENANCE_UNKNOWN)
        assertTrue(failure.detail.contains("trusted stock pin"))
        assertEquals(0, h.capture.copyCalls)
        assertEquals(0, h.bridge.publishCalls)
    }

    @Test
    fun oldRecordCannotSupplyMissingOriginalInitBootBytes() = withHarness { h ->
        val historical = FakeInstallerRecovery(h)
        val partitions = historical.record.partitions.toMutableMap()
        partitions["init_boot"] = partitions.getValue("init_boot").copy(sha256 = "a".repeat(64))
        historical.record = historical.record.copy(partitions = partitions)
        h.capture.markers = BaselineWriteMarkers(false, 0, 0, installerTransactions = 1)
        val failure = failed(
            h.provisioner(installerRecovery = recoveryProvisioner(h, historical)).ensureBaseline(),
            BaselineErrors.BASELINE_PROVENANCE_UNKNOWN,
        )
        assertTrue(failure.detail.contains("original init_boot bytes missing"))
        assertEquals(0, h.bridge.publishCalls)
    }

    @Test
    fun historicalRecoveryRequiresTheSameSlot() = withHarness { h ->
        val historical = FakeInstallerRecovery(h)
        historical.record = historical.record.copy(firmware = "another-firmware", slotSuffix = "_b")
        val failure = failed(recoveryProvisioner(h, historical).ensureBaseline(), BaselineErrors.BASELINE_PROVENANCE_UNKNOWN)
        assertTrue(failure.detail.contains("no matching private installer recovery record"))
        assertEquals(0, historical.bootCopies)
        assertEquals(0, h.capture.copyCalls)
        assertEquals(0, h.bridge.publishCalls)
    }

    @Test
    fun historicalRecordWithoutInitBootDoesNotImportOnDualPartitionDevice() = withHarness { h ->
        val historical = FakeInstallerRecovery(h)
        historical.record = historical.record.copy(partitions = historical.record.partitions.filterKeys { it == "boot" })
        failed(recoveryProvisioner(h, historical).ensureBaseline(), BaselineErrors.BASELINE_PROVENANCE_UNKNOWN)
        assertEquals(0, historical.bootCopies)
        assertEquals(0, h.capture.copyCalls)
        assertEquals(0, h.bridge.publishCalls)
    }

    @Test
    fun pinnedKernelStillRequiresCleanInitBootRamdisk() = withHarness(initBootRamdisk = ksuRamdisk()) { h ->
        val historical = FakeInstallerRecovery(h)
        val failure = failed(recoveryProvisioner(h, historical).ensureBaseline(), BaselineErrors.BASELINE_PROVENANCE_UNKNOWN)
        assertTrue(failure.detail.contains(BaselineErrors.BASELINE_UNCLEAN))
        assertEquals(0, h.bridge.publishCalls)
    }

    @Test
    fun spaceIsCheckedBeforeAnyCapture() = withHarness { h ->
        failed(h.provisioner(freeBytes = { 1024L }).ensureBaseline(), ModeSwitchCodes.SPACE_INSUFFICIENT)
        assertEquals(0, h.capture.copyCalls)
        assertTrue(h.fingerprint().isEmpty())
    }

    @Test
    fun unreadableControlPlaneFailsBeforeCapture() = withHarness { h ->
        h.bridge.probeUnreadable = true
        failed(h.provisioner().ensureBaseline(), ModeSwitchCodes.ROOT_UNAVAILABLE)
        assertEquals(0, h.capture.copyCalls)
    }

    @Test
    fun publishFailureIsExplicit() = withHarness { h ->
        h.bridge.failPublish = true
        failed(h.provisioner().ensureBaseline(), BaselineCaptureCodes.CAPTURE_WRITE_FAILED)
        assertTrue(h.fingerprint().isEmpty())
    }

    // ------------------------------------------------------------------ id / clean 规则

    @Test
    fun idIsDerivedFromSlotFirmwareAndBootBytes() {
        val base = snapshotOf("_a", "fw-1", "bootsha")
        val id = BaselineIdentity.fromSnapshot(base)
        assertEquals(id, BaselineIdentity.fromSnapshot(base))
        assertTrue(Regex("^[A-Za-z0-9._-]{1,64}$").matches(id))
        // slot 参与：A/B 两份基线不得互相覆盖。
        assertFalse(id == BaselineIdentity.fromSnapshot(snapshotOf("_b", "fw-1", "bootsha")))
        // firmware 参与：换固件必须换目录。
        assertFalse(id == BaselineIdentity.fromSnapshot(snapshotOf("_a", "fw-2", "bootsha")))
        // boot 字节参与：换了 boot 就是另一份基线。
        assertFalse(id == BaselineIdentity.fromSnapshot(snapshotOf("_a", "fw-1", "othersha")))
        // 时间戳不参与：同一份字节永远同一个 id（否则每次都重新 dd）。
        assertEquals(id, BaselineIdentity.fromSnapshot(base))
        assertFalse("时间戳 id 必须消失", Regex("^bl-\\d+$").matches(id))
    }

    private fun snapshotOf(slot: String, firmware: String, bootSha: String): BaselineDeviceSnapshot =
        BaselineDeviceSnapshot(
            slot = slot,
            firmware = firmware,
            kernelRelease = KERNEL_RELEASE,
            selinux = "Enforcing",
            partitions = mapOf(
                "boot" to BaselinePartitionFacts("boot", 4096, bootSha),
            ),
        )

    @Test
    fun invalidIdIsRejectedBeforeAnyWrite() = withHarness { h ->
        val source = FakeSource(mapOf("boot" to h.bootBytes))
        val service = BaselineCaptureService(
            store = FileBaselineStore(
                root = File(h.root, "id-store"),
                deviceFacts = { h.device },
                clock = h.clock,
                materializer = InstallerBaselineMaterializer(
                    source = source,
                    cleanliness = FixedCleanliness(cleanReport(listOf("boot"))),
                    evidence = BaselinePatchEvidencePort {
                        BaselinePatchEvidence(true, false, null, "never-written")
                    },
                    clock = h.clock,
                ),
            ),
            source = source,
            clock = h.clock,
            newBaselineId = { "../escape" },
        )
        val failure = service.capture() as BaselineResult.Failed
        assertEquals(BaselineErrors.BASELINE_CORRUPT, failure.code)
        assertTrue(failure.detail.contains("invalid baseline id"))
    }

    @Test
    fun requestManifestNoLongerNeedsCleanDeclaration() {
        val manifest = BaselineManifest(
            id = "bl-a-x",
            createdAt = 1L,
            provenance = BaselineProvenance.PRE_FIRST_WRITE_CAPTURE,
            clean = false,
            verifiedAt = 0L,
            slot = SLOT,
            firmware = FIRMWARE,
            kernelRelease = KERNEL_RELEASE,
            partitions = listOf(BaselinePartition("boot", 8, "a".repeat(64), true)),
            avb = AvbFacts(vbmetaPresent = false, verificationDisabled = false),
            patchMarkers = PatchMarkers(),
        )
        // manifest-only 路径（无 materializer）：请求里的 clean 就是唯一证明 ⇒ 必须为 true。
        assertEquals(BaselineErrors.BASELINE_UNCLEAN, BaselineRules.validateCapture(manifest))
        // 有 materializer：clean 由真实字节 + cleanliness 重写 ⇒ 请求不需要（也不该）硬写。
        assertNull(BaselineRules.validateCapture(manifest, requireCleanProof = false))
        // 其余判据仍然 fail-closed。
        assertEquals(
            BaselineErrors.BASELINE_PROVENANCE_UNKNOWN,
            BaselineRules.validateCapture(manifest.copy(provenance = "STUDY"), requireCleanProof = false),
        )
    }

    @Test
    fun storedCleanComesFromReportNotFromRequest() = withHarness { h ->
        // report 说干净但 markers 里有一条（不一致的报告）：落盘 manifest 必须跟着 report，
        // 不能因为"请求 manifest 曾经写 true"而变成全 absent。
        val report = cleanReport(listOf("boot", "init_boot")).copy(
            patchMarkers = PatchMarkers(ksuKo = true),
        )
        val store = FileBaselineStore(
            root = File(h.root, "clean-store"),
            deviceFacts = { h.device },
            clock = h.clock,
            materializer = InstallerBaselineMaterializer(
                source = FakeSource(h.contents),
                cleanliness = FixedCleanliness(report),
                evidence = BaselinePatchEvidencePort {
                    BaselinePatchEvidence(true, false, null, "never-written")
                },
                clock = h.clock,
            ),
        )
        val service = BaselineCaptureService(
            store = store,
            source = FakeSource(h.contents),
            clock = h.clock,
        )
        val result = service.capture()
        assertTrue("expected Ok but was $result", result is BaselineResult.Ok)
        val manifest = (result as BaselineResult.Ok).manifest
        assertEquals(PatchMarkers(ksuKo = true), manifest.patchMarkers)
        assertEquals(report.clean, manifest.clean)
        // 结论自洽：带 patch marker 的基线不可能被判成 PRESENT_OK（consumer 会 IMPORT_REQUIRED）。
        assertFalse(BaselineRules.evaluate(manifest, h.device).state == BaselineState.PRESENT_OK)
    }

    @Test
    fun serviceReusesExistingBaselineWithoutSecondRead() = withHarness { h ->
        val source = FakeSource(h.contents)
        val store = FileBaselineStore(
            root = File(h.root, "reuse-store"),
            deviceFacts = { h.device },
            clock = h.clock,
            materializer = InstallerBaselineMaterializer(
                source = source,
                cleanliness = FixedCleanliness(cleanReport(listOf("boot", "init_boot"))),
                evidence = BaselinePatchEvidencePort {
                    BaselinePatchEvidence(true, false, null, "never-written")
                },
                clock = h.clock,
            ),
        )
        val service = BaselineCaptureService(
            store = store,
            source = source,
            clock = h.clock,
            newBaselineId = BaselineIdentity::fromSnapshot,
        )
        val first = service.capture() as BaselineResult.Ok
        val reads = source.readCalls
        val second = service.capture()
        assertTrue("第二次必须复用而不是失败/重抓", second is BaselineResult.Ok)
        assertEquals(first.manifest.id, (second as BaselineResult.Ok).manifest.id)
        assertEquals("复用必须零 dd", reads, source.readCalls)
        assertTrue(Regex("^bl-a-[0-9a-f]{8}-[0-9a-f]{12}$").matches(first.manifest.id))
    }

    // ------------------------------------------------------------------ root 脚本（解析层）

    @Test
    fun rootCaptureScriptsParseTheirOwnOutputAndFailClosedWithoutMarkers() {
        val capture = RootScriptBaselineCapture(
            runner = dev.maplesu.manager.workmode.superuser.RootScriptRunner { _ ->
                dev.maplesu.manager.workmode.superuser.RootScriptResult(0, "")
            },
            appUid = 10_000,
        )
        val probeOutput = buildString {
            appendLine("SLOT:_a")
            appendLine("FW:$FIRMWARE")
            appendLine("KR:$KERNEL_RELEASE")
            appendLine("PART:boot:/dev/block/by-name/boot_a:4096")
            appendLine("PART:init_boot:/dev/block/by-name/init_boot_a:8192")
            appendLine("SELINUX:Enforcing")
            appendLine("PROBED")
        }
        val probe = capture.parseProbe(probeOutput)
        assertNotNull(probe)
        val probed = probe!!
        assertEquals("_a", probed.slot)
        assertEquals(
            mapOf(
                "boot" to "/dev/block/by-name/boot_a",
                "init_boot" to "/dev/block/by-name/init_boot_a",
            ),
            probed.devices,
        )
        assertEquals(4096L, probed.sizes["boot"])
        // 没有 PROBED 标记 = 读不到（不是"没有分区"）⇒ 必须 null，让调用方显式失败。
        assertNull(capture.parseProbe("SLOT:_a\nFW:x\n"))
        assertNull(capture.parseProbe(probeOutput.replace("init_boot_a:8192", "init_boot_a:invalid")))
        assertNull(capture.parseProbe(probeOutput + "PART:boot:/data/local/tmp/boot:4096\n"))
        // 脚本本身：只读方向 + 槽位拼节点 + 不向 stdout 输出 dd 数据。
        val script = capture.probeScript()
        assertTrue(script.contains("/dev/block/by-name/"))
        assertTrue(script.contains("ro.boot.slot_suffix"))

        val copy = capture.parseCopy("LEN:4096\nSHA:${"a".repeat(64)}\nCOPIED\n")
        assertNotNull(copy)
        val copied = copy!!
        assertEquals(4096L, copied.size)
        assertEquals("a".repeat(64), copied.sha256)
        assertNull("sha 不是 64hex 就必须拒绝", capture.parseCopy("LEN:4096\nSHA:zzz\nCOPIED\n"))
        assertNull(capture.parseCopy("LEN:4096\nSHA:${"a".repeat(64)}\n"))
        val ddScript = capture.copyScript("/dev/block/by-name/boot_a", File("/tmp/x/boot.img"))
        assertTrue("dd 必须是只读方向", ddScript.contains("dd if='/dev/block/by-name/boot_a'"))
        assertTrue(ddScript.contains("2>/dev/null"))
        assertTrue("落盘后必须 chown 回 App uid", ddScript.contains("chown 10000:10000"))

        val cleanOutput = "INSTALLED:0\nTAKEOVER:0\nWORK:0\nMODULE:1\nINSTALLER:0\nPRO:0\nMARKERS\n"
        val clean = capture.parseMarkers(cleanOutput)
        assertNotNull(clean)
        val cleanMarkers = clean!!
        assertTrue(cleanMarkers.neverWritten)
        assertTrue("模块目录只作诊断，不参与 neverWritten", cleanMarkers.modulePresent)
        val written = capture.parseMarkers(cleanOutput.replace("TAKEOVER:0", "TAKEOVER:1"))
        assertNotNull(written)
        assertFalse(written!!.neverWritten)
        assertNull(capture.parseMarkers("TAKEOVER:0\nWORK:0\n"))
        assertNull(capture.parseMarkers("MARKERS\n"))
        assertNull(capture.parseMarkers(cleanOutput.replace("INSTALLER:0\n", "")))
        assertNull(capture.parseMarkers(cleanOutput.replace("ULTRA:0", "ULTRA:2")))
        assertNull(capture.parseMarkers(cleanOutput.replace("INSTALLER:0", "INSTALLER:garbage")))
        assertNull(capture.parseMarkers(cleanOutput.replace("WORK:0", "WORK:-1")))
        assertNull(capture.parseMarkers(cleanOutput + "ULTRA:0\n"))
        val markersScript = capture.markersScript()
        assertTrue(markersScript.contains("/data/adb/maplesu_su_auth"))
        assertTrue(markersScript.contains("/installer/*"))
    }

    @Test
    fun publishScriptAcceptsBootOnlyBaseline() {
        val bridge = RootScriptBaselineBridge(
            runner = dev.maplesu.manager.workmode.superuser.RootScriptRunner { _ ->
                dev.maplesu.manager.workmode.superuser.RootScriptResult(0, "")
            },
        )
        val bootOnly = bridge.publishScript(
            localDirectory = File("/tmp/staging"),
            temporary = "/data/adb/maplesu-workmode/tmp/publish-1",
            destination = "/data/adb/maplesu-workmode/boot/baseline/bl-a-1",
            expectedSha256 = mapOf("boot" to "b".repeat(64)),
            id = "bl-a-1",
        )
        assertTrue(bootOnly.contains("boot.img"))
        assertFalse("boot-only 机型不得要求 init_boot.img", bootOnly.contains("init_boot.img"))
        assertTrue(bootOnly.contains("PUBLISHED:bl-a-1"))
        assertTrue("已存在即失败（绝不覆盖）", bootOnly.contains("exit 7"))
        // 非 64hex 的期望摘要 / 没有 boot 摘要 ⇒ 必须拒绝发布（防"没有 sha 也算成功"）。
        val staging = Files.createTempDirectory("maplesu-publish-").toFile()
        try {
            assertFalse(bridge.publish("bl-a-1", staging, mapOf("boot" to "not-a-sha")))
            assertFalse(bridge.publish("bl-a-1", staging, emptyMap()))
        } finally {
            staging.deleteRecursively()
        }
    }

    // ------------------------------------------------------------------ 恢复目录

    @Test
    fun recoveryDirectoryLivesInNeverMoveSubtree() {
        // 用户要的"恢复目录"= 刷写前纯净镜像的落点：单一物理副本（= 基线库本体）。
        assertEquals(ControlPaths.BASELINE, ControlPaths.RECOVERY_BOOT)
        assertTrue(ControlPaths.RECOVERY_BOOT.startsWith("${ControlPaths.ROOT}/"))
        assertEquals("${ControlPaths.RECOVERY_BOOT}/bl-a-1", ControlPaths.recovery("bl-a-1"))
        // 切模式永远搬不走它（`/data/adb/maplesu` 整树会被 LITE_MOVE_SET 搬走，恢复目录绝不能在那里）。
        assertTrue(MoveSet.isNeverMove(ControlPaths.RECOVERY_BOOT))
        // Identity recovery is also shared; stock images still live only in the baseline store.
        assertTrue(MoveSet.isNeverMove("/data/adb/maplesu/recovery/boot"))
        assertTrue(
            "恢复目录不得落在任何搬移项子树内",
            MoveSet.LITE_MOVE_SET.none { ControlPaths.RECOVERY_BOOT.startsWith("${it.livePath}/") },
        )
    }

    // ------------------------------------------------------------------ 辅助

    private inner class FakeSource(
        private val contents: Map<String, ByteArray>,
    ) : BaselinePartitionSourcePort {
        var readCalls = 0

        override fun snapshot(): BaselineDeviceSnapshot {
            return BaselineDeviceSnapshot(
                slot = SLOT,
                firmware = FIRMWARE,
                kernelRelease = KERNEL_RELEASE,
                selinux = "Enforcing",
                partitions = contents.mapValues { (name, bytes) ->
                    BaselinePartitionFacts(name, bytes.size.toLong(), sha(bytes))
                },
            )
        }

        override fun readPartition(name: String, destination: File): BaselinePartitionRead {
            readCalls++
            val bytes = contents[name] ?: throw IOException("missing $name")
            destination.writeBytes(bytes)
            return BaselinePartitionRead(name, bytes.size.toLong(), sha(bytes))
        }
    }

    private class FixedCleanliness(private val report: BaselineCleanReport) : BaselineCleanlinessPort {
        override fun verify(
            images: Map<String, File>,
            expectedSizes: Map<String, Long>,
            evidence: BaselinePatchEvidence,
        ): BaselineCleanReport = report
    }

    private fun cleanReport(partitions: List<String>): BaselineCleanReport = BaselineCleanReport(
        clean = true,
        patchMarkers = PatchMarkers(),
        avbTailPreserved = partitions.associateWith { true },
        evidence = partitions.map { "$it:form=STOCK" },
    )

    private companion object {
        const val SLOT = "_a"
        const val FIRMWARE = "PLQ110_16.0.7.201(CN01)"
        const val KERNEL_RELEASE = "6.6.89-android15-8-g7e1f3c083cc6-abogki467167594-4k"
    }
}
