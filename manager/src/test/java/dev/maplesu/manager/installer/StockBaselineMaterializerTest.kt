package dev.maplesu.manager.installer

import dev.maplesu.manager.workmode.control.ControlJsonCodec
import dev.maplesu.manager.workmode.detect.Clock
import dev.maplesu.manager.workmode.switch.AvbFacts
import dev.maplesu.manager.workmode.switch.BaselineCaptureRequest
import dev.maplesu.manager.workmode.switch.BaselineErrors
import dev.maplesu.manager.workmode.switch.BaselineImportRequest
import dev.maplesu.manager.workmode.switch.BaselineManifest
import dev.maplesu.manager.workmode.switch.BaselinePartition
import dev.maplesu.manager.workmode.switch.BaselineProvenance
import dev.maplesu.manager.workmode.switch.BaselineResult
import dev.maplesu.manager.workmode.switch.BaselineState
import dev.maplesu.manager.workmode.switch.DeviceBootFacts
import dev.maplesu.manager.workmode.switch.FileBaselineStore
import dev.maplesu.manager.workmode.switch.PatchMarkers
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.tukaani.xz.LZMA2Options
import org.tukaani.xz.XZOutputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileNotFoundException
import java.nio.ByteBuffer
import java.io.ByteArrayInputStream
import java.nio.ByteOrder
import java.nio.file.Files
import java.security.MessageDigest
import java.util.zip.GZIPOutputStream

/**
 * stock 资产 materializer 的主机测试（无设备、无 root、无 Android AssetManager）。
 *
 * ⚠️ 2026-11-01 `55-asset-slim.md`：本构建**不再随包** `assets/boot-stock/`（12.3 MB 被删，
 * APK 回到体积闸门内，同时去掉"固定机型"）。因此本类的夹具全部是**临时目录里的合成资产**
 * （xz 用同一个 preset 6），覆盖的仍是真实代码路径：pin 解析 → xz 流式解压 → sha/size 校验 →
 * cleanliness 判定 → 原子落位。这条实现现在服务的是「用户导入 OEM 镜像」。
 *
 * 关键断言只有一条：**真的把解压出的镜像字节写进 `baseline/<id>/` 下的 `*.img`**，并且产物能被
 * 既有的 `FileBaselineStore` 解析器判成 `PRESENT_OK`（不只是写了个 manifest）。
 * 所有失败路径都必须给出既有错误码、且不留下半成品目录。
 */
class StockBaselineMaterializerTest {
    private class TestClock(var now: Long = 5_000L) : Clock {
        override fun nowMillis(): Long = now
    }

    // ------------------------------------------------------------------ fixtures

    /** 与 `BaselineCleanlinessTest` 同构的最小 boot 容器（ramdisk 为空时 ramdisk_size = 0）。 */
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
        writeEntry("TRAILER!!!", ByteArray(0))
        val out = ByteArrayOutputStream()
        GZIPOutputStream(out).use { it.write(cpio.toByteArray()) }
        return out.toByteArray()
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

    /** 生产资产是 `xz -6e`（8 MiB 字典）；测试同样用 preset 6，保持字典口径一致。 */
    private fun xz(bytes: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        XZOutputStream(out, LZMA2Options(6)).use { it.write(bytes) }
        return out.toByteArray()
    }

    private fun sha(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes)
            .joinToString("") { "%02x".format(it.toInt() and 0xFF) }

    // ------------------------------------------------------------------ harness

    private inner class Harness(
        val bootBytes: ByteArray,
        val initBootBytes: ByteArray,
    ) {
        val root: File = Files.createTempDirectory("maplesu-stock-baseline-").toFile()
        val assetsDir: File = File(root, "assets").apply { mkdirs() }
        val controlRoot: File = File(root, "control")
        val staging: File = File(root, "staging")
        val clock = TestClock()
        var device = DeviceBootFacts("_a", FIRMWARE, KERNEL_RELEASE)

        /**
         * materializer 真实请求过的 asset entry（逐字，按调用顺序）。
         * `42-fix-asset-path.md` 的回归断言就靠它：**必须**是带根的 entry。
         */
        val opened: MutableList<String> = mutableListOf()

        val materializer = StockBaselineMaterializer(
            assets = StockAssetSource { path ->
                opened += path
                // ★ 模拟真实 `AssetManager`：只认 assets/ 下**真实存在**的 entry，
                // 绝不“自动补根”或“按裸文件名兜底”——旧实现正是靠兜底混过了单测。
                if (!path.startsWith("$ASSET_ROOT/")) throw FileNotFoundException(path)
                val file = File(assetsDir, path.removePrefix("$ASSET_ROOT/"))
                if (!file.isFile) throw FileNotFoundException(path)
                ByteArrayInputStream(file.readBytes())
            },
            deviceFacts = { device },
            clock = clock,
            assetRoot = ASSET_ROOT,
            stagingRoot = staging,
        )
        val store = FileBaselineStore(
            root = controlRoot,
            deviceFacts = { device },
            clock = clock,
            materializer = materializer,
        )

        fun writeAsset(name: String, bytes: ByteArray) {
            File(assetsDir, name).writeBytes(bytes)
        }

        fun writeAssets() {
            writeAsset("boot.img.xz", xz(bootBytes))
            writeAsset("init_boot.img.xz", xz(initBootBytes))
        }

        fun writePins(
            firmware: String = FIRMWARE,
            kernelRelease: String = KERNEL_RELEASE,
            slotAgnostic: Boolean = true,
            bootAsset: String = "boot.img.xz",
            bootSize: Long = bootBytes.size.toLong(),
            bootSha: String = sha(bootBytes),
            initBootSize: Long = initBootBytes.size.toLong(),
            initBootSha: String = sha(initBootBytes),
        ) {
            val json = """
                {
                  "schema": 1,
                  "deviceFirmware": "$firmware",
                  "kernelRelease": "$kernelRelease",
                  "slotAgnostic": $slotAgnostic,
                  "partitions": {
                    "boot": { "asset": "$bootAsset", "size": $bootSize, "sha256": "$bootSha",
                              "kernelSha256": null, "ramdiskSize": 0, "osPatch": null },
                    "init_boot": { "asset": "init_boot.img.xz", "size": $initBootSize,
                                   "sha256": "$initBootSha", "ramdiskSha256": null, "osPatch": "2026-05" }
                  }
                }
            """.trimIndent()
            File(assetsDir, "pins.json").writeText(json, Charsets.UTF_8)
        }

        fun baselineDirectory(id: String = ID): File = File(controlRoot, "boot/baseline/$id")

        /** 形状合法（能过 `validateImport`）但内容可任意篡改的请求 manifest。 */
        fun forgedManifest(id: String = ID): BaselineManifest = BaselineManifest(
            id = id,
            createdAt = 1L,
            provenance = BaselineProvenance.OEM_PACKAGE,
            clean = true,
            verifiedAt = 0L,
            slot = device.slot,
            firmware = device.firmware,
            kernelRelease = device.kernelRelease,
            partitions = listOf(
                BaselinePartition("boot", bootBytes.size.toLong(), sha(bootBytes), true),
                BaselinePartition("init_boot", initBootBytes.size.toLong(), sha(initBootBytes), true),
            ),
            avb = AvbFacts(vbmetaPresent = false, vbmetaSha256 = null, verificationDisabled = false),
            patchMarkers = PatchMarkers(),
            immutable = true,
        )

        fun close() {
            store.closeOpenImages()
            root.deleteRecursively()
        }
    }

    private fun harness(
        bootBytes: ByteArray = bootContainer(stockRamdisk()),
        initBootBytes: ByteArray = bootContainer(stockRamdisk()),
    ): Harness = Harness(bootBytes, initBootBytes)

    private fun withHarness(
        bootBytes: ByteArray = bootContainer(stockRamdisk()),
        initBootBytes: ByteArray = bootContainer(stockRamdisk()),
        block: (Harness) -> Unit,
    ) {
        val harness = harness(bootBytes, initBootBytes)
        try {
            block(harness)
        } finally {
            harness.close()
        }
    }

    private fun assertFailed(result: BaselineResult, code: String): BaselineResult.Failed {
        assertTrue("expected Failed but was $result", result is BaselineResult.Failed)
        val failed = result as BaselineResult.Failed
        assertEquals("code (detail=${failed.detail})", code, failed.code)
        return failed
    }

    private fun assertOk(result: BaselineResult): BaselineResult.Ok {
        assertTrue("expected Ok but was $result", result is BaselineResult.Ok)
        return result as BaselineResult.Ok
    }

    // ------------------------------------------------------------------ happy path

    @Test
    fun importWritesRealImageBytesAndStoreAccepts() = withHarness { h ->
        h.writeAssets()
        h.writePins()
        val prepared = assertOk(h.materializer.prepareImport(ID)).manifest
        assertEquals(BaselineProvenance.OEM_PACKAGE, prepared.provenance)
        assertEquals(2, prepared.partitions.size)

        assertOk(h.store.import(BaselineImportRequest(h.materializer.sourcePath, prepared)))

        val directory = h.baselineDirectory()
        val bootImage = File(directory, "boot.img")
        val initBootImage = File(directory, "init_boot.img")
        assertTrue("boot.img missing", bootImage.isFile)
        assertTrue("init_boot.img missing", initBootImage.isFile)
        // ★ 真的镜像字节（不是只有 manifest）
        assertArrayEquals(h.bootBytes, bootImage.readBytes())
        assertArrayEquals(h.initBootBytes, initBootImage.readBytes())
        assertEquals(h.bootBytes.size.toLong(), bootImage.length())

        // ★ 产物被既有解析器接受
        assertEquals(BaselineState.PRESENT_OK, h.store.verify().state)
        assertEquals(sha(h.bootBytes), h.store.check().bootSha256)
        assertEquals(sha(h.initBootBytes), h.store.check().initBootSha256)

        // ★ 真镜像 + 真 FD（open() 不再是恒 null）
        assertNotNull("open() must return a real fd", h.store.open(ID, "boot"))

        val written = ControlJsonCodec.decodeOrNull(
            File(directory, "manifest.json").readText(Charsets.UTF_8),
            BaselineManifest.serializer(),
        ) ?: throw AssertionError("manifest.json must decode")
        assertEquals(BaselineProvenance.OEM_PACKAGE, written.provenance)
        assertTrue(written.clean)
        assertTrue(written.patchMarkers.allAbsent)
        assertTrue(written.partitions.all { it.avbTailPreserved })
        assertEquals("_a", written.slot)
        assertEquals(FIRMWARE, written.firmware)
        assertEquals(KERNEL_RELEASE, written.kernelRelease)
        assertTrue(written.verifiedAt > 0L)
        assertFalse("staging must be cleaned", h.staging.listFiles().orEmpty().isNotEmpty())
    }

    @Test
    fun emptyRamdiskStockBootIsAccepted() = withHarness(bootBytes = bootContainer(ByteArray(0))) { h ->
        // 本机 stock boot.img 的 ramdisk_size = 0：C1 修好之后必须能落盘（否则 stock 基线永远导入不了）。
        h.writeAssets()
        h.writePins()
        val prepared = assertOk(h.materializer.prepareImport(ID)).manifest
        val imported = assertOk(h.store.import(BaselineImportRequest(h.materializer.sourcePath, prepared)))
        assertEquals(BaselineState.PRESENT_OK, h.store.verify().state)
        assertTrue(imported.manifest.partitions.first { it.name == "boot" }.avbTailPreserved)
        assertArrayEquals(h.bootBytes, File(h.baselineDirectory(), "boot.img").readBytes())
    }

    // ------------------------------------------------- 55-asset-slim：资产不再打包 + fail-closed 占位

    /**
     * 反向断言：**本构建不许再随包 stock 资产**。
     *
     * 12.3 MB 的 `assets/boot-stock/` 曾让 APK 涨到 156,425,576 B（闸门 154,637,475 B），
     * 同时把产品钉死在一台机型上。基线改由「首次写盘前现场抓取」获得，所以这里钉死
     * "资产目录不存在"：谁把它加回来，这条测试立刻红——请先算 APK 体积与机型面。
     */
    @Test
    fun packagedStockAssetsAreNotBundled() {
        val assetsRoot = File("src/main/assets")
        if (!assetsRoot.isDirectory) return // 单测工作目录不是模块根时跳过（同上）
        val packaged = File(assetsRoot, STOCK_ROOT)
        assertFalse(
            "packaged stock assets must stay out of the APK (55-asset-slim): ${packaged.absolutePath}",
            packaged.exists(),
        )
    }

    /**
     * 生产装配用的 fail-closed 占位：没有随包资产时必须**显式** `BASELINE_CAPTURE_UNSUPPORTED`，
     * 而不是写一份"声称干净但没有 `.img`"的 manifest（那会永久占位一份不可覆盖的基线）。
     *
     * 夹具里故意**有** pins 与镜像：占位实现不许读资产，也不许把目录建出来。
     */
    @Test
    fun noStockMaterializerFailsClosedWithoutWritingAnything() = withHarness { h ->
        h.writeAssets()
        h.writePins()
        val request = h.forgedManifest()
        val capture = assertFailed(
            NoStockBaselineMaterializer.capture(
                BaselineCaptureRequest(ID, request),
                h.baselineDirectory(),
            ),
            BaselineErrors.BASELINE_CAPTURE_UNSUPPORTED,
        )
        assertEquals(NoStockBaselineMaterializer.DETAIL, capture.detail)

        val imported = assertFailed(
            NoStockBaselineMaterializer.import(
                BaselineImportRequest("src/main/assets/$ASSET_ROOT", request),
                h.baselineDirectory(),
            ),
            BaselineErrors.BASELINE_CAPTURE_UNSUPPORTED,
        )
        assertEquals(NoStockBaselineMaterializer.DETAIL, imported.detail)
        assertFalse("fail-closed 不许建出 baseline 目录", h.baselineDirectory().exists())
        assertFalse(File(h.baselineDirectory(), "boot.img").exists())
        assertEquals(0, h.opened.size)
    }

    // ------------------------------------------------------------------ asset path（bug 回归）

    /**
     * ★ 真机 2026-10-31 报障的回归：`pins.json` 的 `asset` 是裸文件名，
     * 但 `AssetManager` 只认 `assets/<root>/<asset>`。
     *
     * 断言是**路径逐字**的，不是“能打开就行”：旧实现 `assets.open(pin.asset)`
     * 会请求 `boot.img.xz`（裸名），而真实 `AssetManager` 直接
     * `FileNotFoundException("boot.img.xz")` ⇒ detail 退化成 `boot.img.xz: boot.img.xz`。
     */
    @Test
    fun assetsAreOpenedUnderRootedPathNeverBareNames() = withHarness { h ->
        h.writeAssets()
        h.writePins()
        val prepared = assertOk(h.materializer.prepareImport(ID)).manifest
        // Harness 的 fake 只认带根 entry（真实 AssetManager 语义）⇒ 这里 Ok 就证明拼根生效。
        assertOk(h.store.import(BaselineImportRequest(h.materializer.sourcePath, prepared)))

        val opened = h.opened.toList()
        assertTrue("opened=$opened", opened.contains("$ASSET_ROOT/boot.img.xz"))
        assertTrue("opened=$opened", opened.contains("$ASSET_ROOT/init_boot.img.xz"))
        assertTrue("opened=$opened", opened.contains("$ASSET_ROOT/pins.json"))

        // 裸名一次都不许被请求（旧实现只请求裸名）
        assertFalse("opened=$opened", opened.contains("boot.img.xz"))
        assertFalse("opened=$opened", opened.contains("init_boot.img.xz"))
        assertFalse("opened=$opened", opened.any { !it.startsWith("$ASSET_ROOT/") })
        // 双斜杠 / 前导斜杠同样不许出现（assetRoot 带尾斜杠时的老陷阱）
        assertTrue("opened=$opened", opened.none { it.contains("//") })
        assertTrue("opened=$opened", opened.none { it.startsWith("/") })

        assertEquals(BaselineState.PRESENT_OK, h.store.verify().state)
    }

    /**
     * 生产失败形态的精确复刻：**`pins.json` 读得到、一到解压就没有镜像 entry**。
     *
     * 这个 fake 只提供裸名镜像（= 根目录配错 / 资产没打进包），用来钉死两件事：
     * ① 修好之后仍必须**显式失败**（不能靠裸名碰巧成功，更不能写半份基线）；
     * ② detail 里必须出现资产名，且出现的是**拼根后的路径**（可诊断）。
     */
    @Test
    fun sourceServingOnlyBareNamesFailsExplicitlyWithDetail() = withHarness { h ->
        h.writeAssets()
        h.writePins()
        val bareOnly = StockAssetSource { path ->
            val file = when {
                // pins 走带根路径且能读到（用户现场就是“pins 读得到、解压才炸”）
                path == "$ASSET_ROOT/pins.json" -> File(h.assetsDir, "pins.json")
                // 根目录下不存在任何镜像 entry
                path.contains('/') -> throw FileNotFoundException(path)
                // 只有裸名（旧实现的调用方式）
                else -> File(h.assetsDir, path)
            }
            if (!file.isFile) throw FileNotFoundException(path)
            ByteArrayInputStream(file.readBytes())
        }
        val materializer = StockBaselineMaterializer(
            assets = bareOnly,
            deviceFacts = { h.device },
            clock = h.clock,
            assetRoot = ASSET_ROOT,
            stagingRoot = h.staging,
        )
        val prepared = assertOk(materializer.prepareImport(ID)).manifest
        val failed = assertFailed(
            materializer.import(BaselineImportRequest(materializer.sourcePath, prepared), h.baselineDirectory()),
            BaselineCaptureCodes.IMPORT_SOURCE_MISSING,
        )
        assertTrue("detail=${failed.detail}", failed.detail.contains("boot.img.xz"))
        // 诊断价值：detail 必须点名“试过哪个 entry”，而不是旧版的 `boot.img.xz: boot.img.xz`
        assertTrue("detail=${failed.detail}", failed.detail.contains("$ASSET_ROOT/boot.img.xz"))
        assertNotEquals("detail=${failed.detail}", "boot.img.xz: boot.img.xz", failed.detail)
        assertFalse(h.baselineDirectory().exists())
    }

    /** `pins.asset` 带目录 ⇒ 提前显式拒绝（拼根后会二次嵌套，只会得到看不懂的 FNFE）。 */
    @Test
    fun pinAssetCarryingDirectoryIsRejectedExplicitly() = withHarness { h ->
        h.writeAssets()
        h.writePins(bootAsset = "$ASSET_ROOT/boot.img.xz")
        val failed = assertFailed(
            h.materializer.prepareImport(ID),
            BaselineErrors.BASELINE_CAPTURE_UNSUPPORTED,
        )
        assertTrue("detail=${failed.detail}", failed.detail.contains("bare file name"))
        assertFalse(h.baselineDirectory().exists())
    }

    // ------------------------------------------------------------------ explicit failures

    @Test
    fun firmwareMismatchFailsExplicitly() = withHarness { h ->
        h.writeAssets()
        h.writePins(firmware = "PLQ110_99.9.9.999(CN99)")
        assertFailed(h.materializer.prepareImport(ID), BaselineErrors.BASELINE_CAPTURE_UNSUPPORTED)
        // 即使伪造一个形状合法的请求，materializer 的独立校验也必须拒绝，且不落半成品。
        assertFailed(
            h.store.import(BaselineImportRequest(h.materializer.sourcePath, h.forgedManifest())),
            BaselineErrors.BASELINE_CAPTURE_UNSUPPORTED,
        )
        assertFalse(h.baselineDirectory().exists())
    }

    @Test
    fun kernelReleaseMismatchFailsExplicitly() = withHarness { h ->
        h.writeAssets()
        h.writePins(kernelRelease = "5.10.0-other")
        assertFailed(h.materializer.prepareImport(ID), BaselineErrors.BASELINE_CAPTURE_UNSUPPORTED)
        assertFalse(h.baselineDirectory().exists())
    }

    @Test
    fun missingDeviceFactsFailExplicitly() = withHarness { h ->
        h.writeAssets()
        h.writePins()
        h.device = DeviceBootFacts("", "", "")
        assertFailed(h.materializer.prepareImport(ID), BaselineErrors.BASELINE_PROVENANCE_UNKNOWN)
        assertFalse(h.baselineDirectory().exists())
    }

    @Test
    fun missingAssetEntryFailsExplicitly() = withHarness { h ->
        h.writeAssets()
        h.writePins(bootAsset = "boot-missing.img.xz")
        val prepared = assertOk(h.materializer.prepareImport(ID)).manifest
        assertFailed(
            h.store.import(BaselineImportRequest(h.materializer.sourcePath, prepared)),
            BaselineCaptureCodes.IMPORT_SOURCE_MISSING,
        )
        assertFalse(h.baselineDirectory().exists())
        assertFalse(File(h.baselineDirectory(), "boot.img").exists())
    }

    @Test
    fun shaMismatchFailsExplicitly() = withHarness { h ->
        h.writeAssets()
        h.writePins(bootSha = "0".repeat(64))
        val prepared = assertOk(h.materializer.prepareImport(ID)).manifest
        assertFailed(
            h.store.import(BaselineImportRequest(h.materializer.sourcePath, prepared)),
            BaselineCaptureCodes.CAPTURE_SHA_MISMATCH,
        )
        assertFalse(h.baselineDirectory().exists())
    }

    @Test
    fun sizeMismatchFailsExplicitly() = withHarness { h ->
        h.writeAssets()
        h.writePins(bootSize = h.bootBytes.size.toLong() + 4096)
        val prepared = assertOk(h.materializer.prepareImport(ID)).manifest
        assertFailed(
            h.store.import(BaselineImportRequest(h.materializer.sourcePath, prepared)),
            BaselineCaptureCodes.CAPTURE_SIZE_MISMATCH,
        )
        assertFalse(h.baselineDirectory().exists())
    }

    @Test
    fun ksuResidueInAssetIsRejected() = withHarness(
        initBootBytes = bootContainer(ksuRamdisk()),
    ) { h ->
        // 即便有人把带 KSU 残留的镜像塞进 assets，cleanliness 也必须阻断（不许 clean=true 掩盖）。
        h.writeAssets()
        h.writePins()
        val prepared = assertOk(h.materializer.prepareImport(ID)).manifest
        assertFailed(
            h.store.import(BaselineImportRequest(h.materializer.sourcePath, prepared)),
            BaselineErrors.BASELINE_UNCLEAN,
        )
        assertFalse(h.baselineDirectory().exists())
    }

    @Test
    fun forgedManifestShaIsStale() = withHarness { h ->
        h.writeAssets()
        h.writePins()
        val prepared = assertOk(h.materializer.prepareImport(ID)).manifest
        val forged = prepared.copy(
            partitions = prepared.partitions.map { it.copy(sha256 = "1".repeat(64)) },
        )
        assertFailed(
            h.store.import(BaselineImportRequest(h.materializer.sourcePath, forged)),
            BaselineErrors.BASELINE_STALE,
        )
        assertFalse(h.baselineDirectory().exists())
    }

    @Test
    fun captureIsExplicitlyUnsupported() = withHarness { h ->
        h.writeAssets()
        h.writePins()
        val result = h.materializer.capture(
            BaselineCaptureRequest(ID, h.forgedManifest()),
            h.baselineDirectory(),
        )
        assertFailed(result, BaselineErrors.BASELINE_CAPTURE_UNSUPPORTED)
        // 必须一个字节都没写，也不能建出目录
        assertFalse(h.baselineDirectory().exists())
        assertFalse(h.staging.exists() && h.staging.listFiles().orEmpty().isNotEmpty())
    }

    @Test
    fun existingImagesAreNeverOverwritten() = withHarness { h ->
        h.writeAssets()
        h.writePins()
        val prepared = assertOk(h.materializer.prepareImport(ID)).manifest
        assertOk(h.store.import(BaselineImportRequest(h.materializer.sourcePath, prepared)))
        val before = File(h.baselineDirectory(), "boot.img").readBytes()

        val again = h.store.import(
            BaselineImportRequest(h.materializer.sourcePath, prepared.copy(id = ID)),
        )
        assertFailed(again, BaselineErrors.BASELINE_PROMOTION_FORBIDDEN)
        assertArrayEquals(before, File(h.baselineDirectory(), "boot.img").readBytes())
    }

    private companion object {
        const val ID = "bl-a-3f9c1d2e-8a1b2c3d4e5f"

        /** 已删除的随包资产根（`55-asset-slim`）；夹具仍沿用同一根名做 entry 路径断言。 */
        const val STOCK_ROOT = "boot-stock"
        const val ASSET_ROOT = "boot-stock/PLQ110_16.0.7.201_CN01"
        const val FIRMWARE = "PLQ110_16.0.7.201(CN01)"
        const val KERNEL_RELEASE = "6.6.89-android15-8-g7e1f3c083cc6-abogki467167594-4k"
    }
}
