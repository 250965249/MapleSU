package dev.maplesu.manager.installer

import dev.maplesu.image.AvbFooter
import dev.maplesu.manager.workmode.switch.BaselineErrors
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.file.Files
import java.util.zip.GZIPOutputStream

/** Host tests for the real RamdiskInspector-based cleanliness proof (P0 §2). */
class BaselineCleanlinessTest {
    private val verifier = RamdiskBaselineCleanliness()

    // ------------------------------------------------------------------ fixtures

    private fun cpioGzip(entries: List<Pair<String, ByteArray>>): ByteArray {
        val cpio = ByteArrayOutputStream()
        for ((name, data) in entries) {
            val nameBytes = (name + "\u0000").toByteArray(Charsets.UTF_8)
            val header = ByteArray(110) { '0'.code.toByte() }
            "070701".toByteArray(Charsets.US_ASCII).copyInto(header, 0)
            fun field(value: Int, offset: Int) {
                val text = "%08x".format(value)
                for (index in 0 until 8) header[offset + index] = text[index].code.toByte()
            }
            field(1, 6); field(0x81A4, 14); field(1, 38); field(data.size, 54)
            field(nameBytes.size, 94); field(0, 102)
            cpio.write(header)
            cpio.write(nameBytes)
            while (cpio.size() % 4 != 0) cpio.write(0)
            cpio.write(data)
            while (cpio.size() % 4 != 0) cpio.write(0)
        }
        val trailer = "TRAILER!!!\u0000".toByteArray(Charsets.UTF_8)
        val header = ByteArray(110) { '0'.code.toByte() }
        "070701".toByteArray(Charsets.US_ASCII).copyInto(header, 0)
        fun field(value: Int, offset: Int) {
            val text = "%08x".format(value)
            for (index in 0 until 8) header[offset + index] = text[index].code.toByte()
        }
        field(1, 6); field(0x81A4, 14); field(1, 38); field(trailer.size, 94)
        cpio.write(header)
        cpio.write(trailer)
        while (cpio.size() % 4 != 0) cpio.write(0)
        val out = ByteArrayOutputStream()
        GZIPOutputStream(out).use { it.write(cpio.toByteArray()) }
        return out.toByteArray()
    }

    private fun bootContainer(ramdisk: ByteArray, kernelSize: Int = 64): ByteArray {
        val page = 4096
        val kernel = ByteArray(kernelSize) { (it and 0xFF).toByte() }
        val offset = ((page + kernel.size + page - 1) / page) * page
        val size = ((offset + ramdisk.size + page - 1) / page) * page
        val image = ByteArray(size)
        val buffer = ByteBuffer.wrap(image).order(ByteOrder.LITTLE_ENDIAN)
        buffer.put("ANDROID!".toByteArray(Charsets.US_ASCII))
        buffer.putInt(8, kernel.size)
        buffer.putInt(16, ramdisk.size)
        buffer.putInt(24, 0)
        buffer.putInt(36, page)
        buffer.putInt(40, 0)
        System.arraycopy(kernel, 0, image, page, kernel.size)
        System.arraycopy(ramdisk, 0, image, offset, ramdisk.size)
        return image
    }

    private fun stockRamdisk(): ByteArray = cpioGzip(
        listOf(
            "init" to byteArrayOf(1, 2, 3),
            "system/bin/sh" to byteArrayOf(4, 5, 6),
        ),
    )

    private fun ksuRamdisk(): ByteArray = cpioGzip(
        listOf(
            "init" to byteArrayOf(1, 2, 3),
            "init.real" to byteArrayOf(4, 5),
            "kernelsu.ko" to byteArrayOf(9, 9, 9, 9),
            "ksu_config" to byteArrayOf(7),
        ),
    )

    private fun tempImage(name: String, bytes: ByteArray): File {
        val root = Files.createTempDirectory("maplesu-baseline-clean-").toFile()
        return File(root, name).apply { writeBytes(bytes) }
    }

    private fun healthyEvidence() = BaselinePatchEvidence(
        readable = true, liteKernelMarker = false, ksuUapi = null, detail = "installed.json",
    )

    private fun verify(
        files: Map<String, File>,
        evidence: BaselinePatchEvidence = healthyEvidence(),
    ): BaselineCleanReport = verifier.verify(
        files,
        files.mapValues { it.value.length() },
        evidence,
    )

    // ------------------------------------------------------------------ tests

    @Test
    fun cleanStockImagesAccepted() {
        val boot = tempImage("boot.img", bootContainer(stockRamdisk()))
        val initBoot = tempImage("init_boot.img", bootContainer(stockRamdisk()))
        val report = verify(mapOf("boot" to boot, "init_boot" to initBoot))
        assertTrue("expected clean but was ${report.code}: ${report.detail}", report.clean)
        assertTrue(report.patchMarkers.allAbsent)
        assertTrue(report.avbTailPreserved.values.all { it })
        assertTrue(report.evidence.any { it.startsWith("boot:") })
    }

    @Test
    fun ksuResidueRamdiskRejected() {
        val boot = tempImage("boot.img", bootContainer(stockRamdisk()))
        val initBoot = tempImage("init_boot.img", bootContainer(ksuRamdisk()))
        val report = verify(mapOf("boot" to boot, "init_boot" to initBoot))
        assertFalse(report.clean)
        assertEquals(BaselineErrors.BASELINE_UNCLEAN, report.code)
        assertTrue(report.patchMarkers.ksuKo)
        assertFalse(report.patchMarkers.allAbsent)
    }

    @Test
    fun liteKernelMarkerRejected() {
        val boot = tempImage("boot.img", bootContainer(stockRamdisk()))
        val report = verify(
            mapOf("boot" to boot),
            healthyEvidence().copy(liteKernelMarker = true),
        )
        assertFalse(report.clean)
        assertEquals(BaselineErrors.BASELINE_UNCLEAN, report.code)
        assertTrue(report.patchMarkers.liteMarker)
    }

    @Test
    fun ultraEvidenceBlocksAnOtherwiseCleanEmptyRamdiskBoot() {
        val boot = tempImage("boot.img", bootContainer(ByteArray(0)))
        val report = verify(
            mapOf("boot" to boot),
            healthyEvidence().copy(ultraKernelMarker = true),
        )
        assertFalse(report.clean)
        assertEquals(BaselineErrors.BASELINE_PROVENANCE_UNKNOWN, report.code)
    }

    @Test
    fun historicalWriteCannotBecomeANewPreWriteBaseline() {
        val boot = tempImage("boot.img", bootContainer(ByteArray(0)))
        val report = verify(
            mapOf("boot" to boot),
            healthyEvidence().copy(priorWriteRecorded = true),
        )
        assertFalse(report.clean)
        assertEquals(BaselineErrors.BASELINE_PROVENANCE_UNKNOWN, report.code)
    }

    @Test
    fun ksuUapiEvidenceRejected() {
        val boot = tempImage("boot.img", bootContainer(stockRamdisk()))
        val report = verify(
            mapOf("boot" to boot),
            healthyEvidence().copy(ksuUapi = 7),
        )
        assertFalse(report.clean)
        assertTrue(report.patchMarkers.ksuKo)
    }

    @Test
    fun unreadableControlEvidenceBlocks() {
        val boot = tempImage("boot.img", bootContainer(stockRamdisk()))
        val report = verify(
            mapOf("boot" to boot),
            BaselinePatchEvidence(readable = false, liteKernelMarker = null, ksuUapi = null),
        )
        assertFalse(report.clean)
        assertEquals(BaselineErrors.BASELINE_PROVENANCE_UNKNOWN, report.code)
    }

    @Test
    fun unknownLiteMarkerBlocks() {
        val boot = tempImage("boot.img", bootContainer(stockRamdisk()))
        val report = verify(
            mapOf("boot" to boot),
            healthyEvidence().copy(readable = true, liteKernelMarker = null),
        )
        assertFalse(report.clean)
        assertEquals(BaselineErrors.BASELINE_PROVENANCE_UNKNOWN, report.code)
    }

    @Test
    fun malformedImageIsCorrupt() {
        val garbage = ByteArray(4096) { ((it * 7) and 0xFF).toByte() }
        val image = tempImage("boot.img", garbage)
        val report = verify(mapOf("boot" to image))
        assertFalse(report.clean)
        assertEquals(BaselineErrors.BASELINE_CORRUPT, report.code)
    }

    // ------------------------------------------------------------ C1: EMPTY_RAMDISK

    @Test
    fun emptyRamdiskBootIsCleanNotCorrupt() {
        // stock GKI boot.img：ramdisk_size = 0（本机 PLQ110 实测）。RamdiskInspector 会返回
        // EMPTY_RAMDISK 且 malformed=true；「没有 ramdisk」不是「ramdisk 损坏」，
        // 因此不得判 CORRUPT / UNCLEAN，只留 no-ramdisk 证据。
        val boot = tempImage("boot.img", bootContainer(ByteArray(0)))
        val initBoot = tempImage("init_boot.img", bootContainer(stockRamdisk()))
        val report = verify(mapOf("boot" to boot, "init_boot" to initBoot))
        assertTrue("expected clean but was ${report.code}: ${report.detail}", report.clean)
        assertTrue(report.patchMarkers.allAbsent)
        assertTrue(
            "missing no-ramdisk note: ${report.evidence}",
            report.evidence.any { it == "boot:no-ramdisk" },
        )
        // 没有 ramdisk 的分区仍然要过 AVB 尾部判定（不能因为跳过 ramdisk 就把结构检查也跳过）。
        assertEquals(true, report.avbTailPreserved["boot"])
        assertEquals(true, report.avbTailPreserved["init_boot"])
    }

    @Test
    fun emptyRamdiskBootWithKsuInitBootStillUnclean() {
        // C1 只是把「无 ramdisk」当「无可扫描面」，绝不放宽其它分区：init_boot 的 KSU 残留
        // 仍必须阻断。
        val boot = tempImage("boot.img", bootContainer(ByteArray(0)))
        val initBoot = tempImage("init_boot.img", bootContainer(ksuRamdisk()))
        val report = verify(mapOf("boot" to boot, "init_boot" to initBoot))
        assertFalse(report.clean)
        assertEquals(BaselineErrors.BASELINE_UNCLEAN, report.code)
        assertTrue(report.patchMarkers.ksuKo)
    }

    @Test
    fun otherMalformedRamdiskStillCorrupt() {
        // 只有 EMPTY_RAMDISK 走分流；其它 malformed（这里是 INVALID_RAMDISK_MAGIC）仍是 CORRUPT。
        val boot = tempImage("boot.img", bootContainer(ByteArray(256) { 0x41 }))
        val report = verify(mapOf("boot" to boot))
        assertFalse(report.clean)
        assertEquals(BaselineErrors.BASELINE_CORRUPT, report.code)
        assertTrue(report.detail.contains("ramdisk malformed"))
    }

    @Test
    fun wrongSizeIsCorrupt() {
        val boot = tempImage("boot.img", bootContainer(stockRamdisk()))
        val report = verifier.verify(
            mapOf("boot" to boot),
            mapOf("boot" to boot.length() + 1),
            healthyEvidence(),
        )
        assertFalse(report.clean)
        assertEquals(BaselineErrors.BASELINE_CORRUPT, report.code)
    }

    @Test
    fun avbFooterOutOfRangeIsRejected() {
        val base = bootContainer(stockRamdisk())
        // 尾部 64B 伪造 AVBf footer：original_image_size 大于分区长度。
        // 字段布局是大端 +12/+20/+28（`AvbFooter`），不是旧的 LE +8/+16/+24。
        val footer = ByteArray(AvbFooter.SIZE)
        "AVBf".toByteArray(Charsets.US_ASCII).copyInto(footer, 0)
        ByteBuffer.wrap(footer).order(ByteOrder.BIG_ENDIAN)
            .putLong(AvbFooter.OFFSET_ORIGINAL_IMAGE_SIZE, base.size.toLong() + 4096)
        footer.copyInto(base, base.size - AvbFooter.SIZE)
        val image = tempImage("boot.img", base)
        val report = verify(mapOf("boot" to image))
        assertFalse(report.clean)
        assertEquals(BaselineCaptureCodes.AVB_TAIL_INVALID, report.code)
        assertEquals(false, report.avbTailPreserved["boot"])
    }

    @Test
    fun avbFooterWithinBoundsAccepted() {
        val base = bootContainer(stockRamdisk())
        // 自洽 footer（大端）：original_image_size 之后紧跟一个 >= MIN_VBMETA 的 vbmeta 区，
        // 且都落在分区内。旧用例用 LE +8/+16/+24 写，那些字节不是这三个字段。
        val footer = ByteArray(AvbFooter.SIZE)
        "AVBf".toByteArray(Charsets.US_ASCII).copyInto(footer, 0)
        val vbmetaOffset = base.size - AvbFooter.SIZE - AvbFooter.MIN_VBMETA
        ByteBuffer.wrap(footer).order(ByteOrder.BIG_ENDIAN)
            .putLong(AvbFooter.OFFSET_ORIGINAL_IMAGE_SIZE, vbmetaOffset.toLong())
            .putLong(AvbFooter.OFFSET_VBMETA_OFFSET, vbmetaOffset.toLong())
            .putLong(AvbFooter.OFFSET_VBMETA_SIZE, AvbFooter.MIN_VBMETA.toLong())
        footer.copyInto(base, base.size - AvbFooter.SIZE)
        val image = tempImage("boot.img", base)
        val report = verify(mapOf("boot" to image))
        assertTrue(report.clean)
        assertEquals(true, report.avbTailPreserved["boot"])
    }
}
