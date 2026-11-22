package dev.maplesu.manager.installer

import dev.maplesu.manager.workmode.detect.Clock
import dev.maplesu.manager.workmode.switch.BaselineErrors
import dev.maplesu.manager.workmode.switch.BaselineState
import dev.maplesu.manager.workmode.switch.DeviceBootFacts
import dev.maplesu.manager.workmode.switch.FileBaselineStore
import dev.maplesu.manager.workmode.switch.ModeSwitchCodes
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.tukaani.xz.LZMA2Options
import org.tukaani.xz.XZOutputStream
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileNotFoundException
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.file.Files
import java.security.MessageDigest
import java.util.zip.GZIPOutputStream

/**
 * P0-1 第 3 项（第二步：接线层）主机测试：基线自动获取的编排语义。
 *
 * 断言的是"用户点一次"的硬语义（无设备、无 root、无 Android）：
 * - 两个分区都落盘（`boot` + `init_boot`），产物被**既有** `FileBaselineStore` 判成 `PRESENT_OK`；
 * - **复用不写盘**：第二次调用 `reused = true`，且基线目录逐字节不变、暂存区为空；
 * - 任何失败都是既有错误码（不新增码、不假成功），且**不留半成品目录**（不覆盖已有基线）；
 * - 生产编排（App 暂存 → root 发布桥 → 从控制面复核）端到端可用：fake 桥用本地目录模拟
 *   "root 发布"，从而在主机上验证 `probe → staging import → publish → probe` 全链路。
 */
class BaselineProvisionerTest {

    private class TestClock(var now: Long = 7_000L) : Clock {
        override fun nowMillis(): Long = now
    }

    // ------------------------------------------------------------------ fixtures

    /** 与 `BaselineCleanlinessTest` / `StockBaselineMaterializerTest` 同构的最小 boot 容器。 */
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

    private fun stockRamdisk(): ByteArray =
        cpioGzip(listOf("init" to byteArrayOf(1, 2, 3), "system/bin/sh" to byteArrayOf(4, 5, 6)))

    private fun ksuRamdisk(): ByteArray = cpioGzip(
        listOf(
            "init" to byteArrayOf(1, 2, 3),
            "init.real" to byteArrayOf(4, 5),
            "kernelsu.ko" to byteArrayOf(9, 9, 9, 9),
        ),
    )

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
        val bootBytes: ByteArray = bootContainer(stockRamdisk()),
        val initBootBytes: ByteArray = bootContainer(stockRamdisk()),
    ) {
        val root: File = Files.createTempDirectory("maplesu-baseline-provision-").toFile()
        val assetsDir: File = File(root, "assets").apply { mkdirs() }
        val controlRoot: File = File(root, "control").apply { mkdirs() }
        val clock = TestClock()
        var device = DeviceBootFacts("_a", FIRMWARE, KERNEL_RELEASE)

        val materializer = StockBaselineMaterializer(
            assets = StockAssetSource { path ->
                // 与 StockBaselineMaterializerTest 同口径：只认带根的真实 entry（真实 AssetManager 语义），
                // 绝不给裸文件名兜底 —— 否则 `assets.open(pin.asset)` 这种漏拼根会被测试放过。
                if (!path.startsWith("$ASSET_ROOT/")) throw FileNotFoundException(path)
                val file = File(assetsDir, path.removePrefix("$ASSET_ROOT/"))
                if (!file.isFile) throw FileNotFoundException(path)
                ByteArrayInputStream(file.readBytes())
            },
            deviceFacts = { device },
            clock = clock,
            assetRoot = ASSET_ROOT,
            stagingRoot = File(root, "staging"),
        )
        val store = FileBaselineStore(
            root = controlRoot,
            deviceFacts = { device },
            clock = clock,
            materializer = materializer,
        )
        val provisioner = StockBaselineProvisioner(
            store = store,
            materializer = materializer,
            controlRoot = controlRoot,
            deviceFacts = { device },
        )

        fun writeAsset(name: String, bytes: ByteArray) = File(assetsDir, name).writeBytes(bytes)

        fun writeAssets(boot: ByteArray = bootBytes, initBoot: ByteArray = initBootBytes) {
            writeAsset("boot.img.xz", xz(boot))
            writeAsset("init_boot.img.xz", xz(initBoot))
        }

        fun writePins(
            firmware: String = FIRMWARE,
            kernelRelease: String = KERNEL_RELEASE,
            bootBytes: ByteArray = this.bootBytes,
            initBootBytes: ByteArray = this.initBootBytes,
        ) {
            val json = """
                {
                  "schema": 1,
                  "deviceFirmware": "$firmware",
                  "kernelRelease": "$kernelRelease",
                  "slotAgnostic": true,
                  "partitions": {
                    "boot": { "asset": "boot.img.xz", "size": ${bootBytes.size},
                              "sha256": "${sha(bootBytes)}", "ramdiskSize": 0 },
                    "init_boot": { "asset": "init_boot.img.xz", "size": ${initBootBytes.size},
                                   "sha256": "${sha(initBootBytes)}", "osPatch": "2026-05" }
                  }
                }
            """.trimIndent()
            File(assetsDir, "pins.json").writeText(json, Charsets.UTF_8)
        }

        fun baselineDirectory(id: String = BaselineIdentity.fromDevice(device)): File =
            File(controlRoot, "boot/baseline/$id")

        /** 基线目录的指纹（路径 + 大小 + 内容 sha），用来证明"复用零写盘"。 */
        fun fingerprint(): Map<String, String> {
            val base = File(controlRoot, "boot/baseline")
            if (!base.isDirectory) return emptyMap()
            return base.walkTopDown().filter { it.isFile }.associate { file ->
                file.relativeTo(controlRoot).path.replace('\\', '/') to
                    "${file.length()}:${sha(file.readBytes())}"
            }
        }

        fun close() {
            store.closeOpenImages()
            root.deleteRecursively()
        }
    }

    private fun withHarness(
        bootBytes: ByteArray = bootContainer(stockRamdisk()),
        initBootBytes: ByteArray = bootContainer(stockRamdisk()),
        block: (Harness) -> Unit,
    ) {
        val harness = Harness(bootBytes, initBootBytes)
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

    // ------------------------------------------------------------------ 第一层：复用 / 导入

    @Test
    fun firstCallImportsBothPartitionsAndSecondCallReusesWithoutWriting() = withHarness { h ->
        h.writeAssets()
        h.writePins()

        val first = ready(h.provisioner.ensureBaseline())
        assertFalse("首次必须真的建立", first.reused)
        assertEquals("OEM_PACKAGE", first.provenance)
        assertEquals(BaselineIdentity.fromDevice(h.device), first.id)

        val directory = h.baselineDirectory(first.id)
        // ★ 两个分区都要（只备 boot 会让一个方向永远撞 SWITCH_BASELINE_REQUIRED）
        val boot = File(directory, "boot.img")
        val initBoot = File(directory, "init_boot.img")
        assertTrue("boot.img missing", boot.isFile)
        assertTrue("init_boot.img missing", initBoot.isFile)
        assertEquals(h.bootBytes.size.toLong(), boot.length())
        assertEquals(sha(h.bootBytes), sha(boot.readBytes()))
        assertEquals(sha(h.initBootBytes), sha(initBoot.readBytes()))
        // ★ 产物被既有解析器接受（不是"只写了 manifest"）
        assertEquals(BaselineState.PRESENT_OK, h.store.verify().state)
        // ★ 暂存被清理
        assertFalse(File(h.root, "staging").listFiles().orEmpty().isNotEmpty())

        val before = h.fingerprint()
        val second = ready(h.provisioner.ensureBaseline())
        // ★ 复用：不重复解压、不重复写盘
        assertTrue("第二次必须复用", second.reused)
        assertEquals(first.id, second.id)
        assertEquals("复用不得改动任何字节", before, h.fingerprint())
    }

    @Test
    fun missingAssetsFailExplicitlyAndLeaveNoDirectory() = withHarness { h ->
        // 只有 pins（没有 .xz 资产）：必须显式失败，且不得留下任何基线目录。
        h.writePins()
        failed(h.provisioner.ensureBaseline(), BaselineCaptureCodes.IMPORT_SOURCE_MISSING)
        assertFalse(h.baselineDirectory().exists())
        assertTrue(h.fingerprint().isEmpty())
    }

    @Test
    fun firmwareMismatchFailsExplicitly() = withHarness { h ->
        h.writeAssets()
        h.writePins(firmware = "PLQ110_99.9.9.999(CN99)")
        failed(h.provisioner.ensureBaseline(), BaselineErrors.BASELINE_CAPTURE_UNSUPPORTED)
        assertTrue(h.fingerprint().isEmpty())
    }

    @Test
    fun ksuResidueInAssetIsRejectedNotSanitized() = withHarness(
        initBootBytes = bootContainer(ksuRamdisk()),
    ) { h ->
        // 绝不硬写 clean=true 掩盖校验失败：脏资产必须显式 BASELINE_UNCLEAN。
        h.writeAssets()
        h.writePins()
        failed(h.provisioner.ensureBaseline(), BaselineErrors.BASELINE_UNCLEAN)
        assertFalse(h.baselineDirectory().exists())
    }

    @Test
    fun existingBaselineIsNeverOverwritten() = withHarness { h ->
        h.writeAssets()
        h.writePins()
        val first = ready(h.provisioner.ensureBaseline())
        val before = h.fingerprint()

        // 目录已存在但 manifest 被破坏 ⇒ 不复用、也不覆盖（红线：baseline 一旦建立不得被覆盖）。
        val manifest = File(h.baselineDirectory(first.id), "manifest.json")
        manifest.writeText("{not-json", Charsets.UTF_8)
        val corrupted = h.fingerprint()
        val outcome = h.provisioner.ensureBaseline()
        failed(outcome, BaselineErrors.BASELINE_PROMOTION_FORBIDDEN)
        assertEquals("损坏的基线不得被覆盖", corrupted, h.fingerprint())
        assertNotNull(before[baselineRelative(first.id, "boot.img")])
    }

    @Test
    fun verifiedBaselineIsReusedWhenOnlyRuntimeVersionLabelsChange() = withHarness { h ->
        h.writeAssets()
        h.writePins()
        val first = ready(h.provisioner.ensureBaseline())
        val before = h.fingerprint()

        // Ultra / Normal 的运行内核或固件标签变化，不代表已验证原始映像发生变化。
        h.device = DeviceBootFacts("_a", "PLQ110_99.9.9.999(CN99)", "6.6.115-android15-8-normal")
        val second = ready(h.provisioner.ensureBaseline())
        assertTrue("只有运行版本标签变化时复用原始映像", second.reused)
        assertEquals(first.id, second.id)
        assertEquals("复用保持原始映像与manifest逐字节不变", before, h.fingerprint())
    }

    @Test
    fun otherSlotAndChangedImageCannotReuseVerifiedBaseline() = withHarness { h ->
        h.writeAssets()
        h.writePins()
        val first = ready(h.provisioner.ensureBaseline())
        assertNull(h.provisioner.reusable(h.device.copy(slot = "_b")))
        val image = File(h.baselineDirectory(first.id), "boot.img")
        image.writeBytes(image.readBytes().also { bytes -> bytes[bytes.lastIndex] = (bytes.last().toInt() xor 0xff).toByte() })
        assertNull("镜像实际摘要变化仍拒绝复用", h.provisioner.reusable(h.device))
    }

    @Test
    fun incompleteDeviceFactsFailWithoutWriting() = withHarness { h ->
        h.writeAssets()
        h.writePins()
        h.device = DeviceBootFacts("", "", "")
        failed(h.provisioner.ensureBaseline(), BaselineErrors.BASELINE_PROVENANCE_UNKNOWN)
        assertTrue(h.fingerprint().isEmpty())
    }

    // ------------------------------------------------------------------ id

    @Test
    fun idIsDeterministicAndMatchesServiceContract() {
        val device = DeviceBootFacts("_a", FIRMWARE, KERNEL_RELEASE)
        val id = BaselineIdentity.fromDevice(device)
        assertEquals(id, BaselineIdentity.fromDevice(device))
        assertTrue("id 必须匹配 BASELINE_ID: $id", Regex("^[A-Za-z0-9._-]{1,64}$").matches(id))
        // slot 参与 id：A/B 两份基线不得互相覆盖。
        assertFalse(id == BaselineIdentity.fromDevice(device.copy(slot = "_b")))
        assertEquals(listOf("boot", "init_boot"), BaselineIdentity.PARTITIONS)
    }

    // ------------------------------------------------------------------ 第二层：生产编排（发布桥）

    @Test
    fun productionFlowPublishesToControlPlaneAndThenReuses() {
        val harness = Harness()
        try {
            harness.writeAssets()
            harness.writePins()
            val plane = File(harness.root, "control-plane")
            val bridge = LocalControlPlaneBridge(plane)
            val stagingRoot = File(harness.root, "app-cache")
            val provisioner = RootPublishingBaselineProvisioner(
                bridge = bridge,
                stagingRoot = stagingRoot,
                assets = StockAssetSource { path ->
                    val file = File(harness.assetsDir, path.removePrefix("$ASSET_ROOT/"))
                    if (!file.isFile) throw FileNotFoundException(path)
                    ByteArrayInputStream(file.readBytes())
                },
                deviceFacts = { harness.device },
                freeBytes = { 8L shl 30 },
                clock = harness.clock,
            )

            val first = ready(provisioner.ensureBaseline())
            assertFalse(first.reused)
            // ★ 真的发布到"控制面"（消费方读的就是这里），两个分区都在
            val published = File(plane, "boot/baseline/${first.id}")
            assertTrue(File(published, "boot.img").isFile)
            assertTrue(File(published, "init_boot.img").isFile)
            assertTrue(File(published, "manifest.json").isFile)
            assertEquals(sha(harness.bootBytes), sha(File(published, "boot.img").readBytes()))
            assertEquals(1, bridge.publishCalls)
            // ★ App 暂存已清理
            assertFalse(File(stagingRoot, "baseline-import").exists())

            val before = planeFingerprint(plane)
            val second = ready(provisioner.ensureBaseline())
            assertTrue("第二次必须复用控制面基线", second.reused)
            assertEquals(first.id, second.id)
            assertEquals("复用不得再发布/改写", 1, bridge.publishCalls)
            assertEquals(before, planeFingerprint(plane))
        } finally {
            harness.close()
        }
    }

    @Test
    fun publishFailureIsExplicitAndLeavesControlPlaneClean() {
        val harness = Harness()
        try {
            harness.writeAssets()
            harness.writePins()
            val plane = File(harness.root, "control-plane")
            val bridge = LocalControlPlaneBridge(plane).apply { failPublish = true }
            val provisioner = RootPublishingBaselineProvisioner(
                bridge = bridge,
                stagingRoot = File(harness.root, "app-cache"),
                assets = StockAssetSource { path ->
                    val file = File(harness.assetsDir, path.removePrefix("$ASSET_ROOT/"))
                    if (!file.isFile) throw FileNotFoundException(path)
                    ByteArrayInputStream(file.readBytes())
                },
                deviceFacts = { harness.device },
                freeBytes = { 8L shl 30 },
                clock = harness.clock,
            )
            failed(provisioner.ensureBaseline(), BaselineCaptureCodes.CAPTURE_WRITE_FAILED)
            assertEquals(0, bridge.publishCalls)
            assertTrue("控制面必须保持干净", planeFingerprint(plane).isEmpty())
        } finally {
            harness.close()
        }
    }

    @Test
    fun insufficientSpaceFailsBeforeAnyWrite() {
        val harness = Harness()
        try {
            harness.writeAssets()
            harness.writePins()
            val plane = File(harness.root, "control-plane")
            val bridge = LocalControlPlaneBridge(plane)
            val provisioner = RootPublishingBaselineProvisioner(
                bridge = bridge,
                stagingRoot = File(harness.root, "app-cache"),
                assets = StockAssetSource { path ->
                    val file = File(harness.assetsDir, path.removePrefix("$ASSET_ROOT/"))
                    if (!file.isFile) throw FileNotFoundException(path)
                    ByteArrayInputStream(file.readBytes())
                },
                deviceFacts = { harness.device },
                freeBytes = { 1024L },
                clock = harness.clock,
            )
            failed(provisioner.ensureBaseline(), ModeSwitchCodes.SPACE_INSUFFICIENT)
            assertTrue(planeFingerprint(plane).isEmpty())
            assertFalse(File(harness.root, "app-cache/baseline-import").exists())
        } finally {
            harness.close()
        }
    }

    // ------------------------------------------------------------------ 根脚本桥（解析/失败语义）

    @Test
    fun probeParsesRootScriptOutputAndFailsClosedWithoutMarker() {
        val bridge = RootScriptBaselineBridge(
            runner = dev.maplesu.manager.workmode.superuser.RootScriptRunner { _ ->
                dev.maplesu.manager.workmode.superuser.RootScriptResult(0, "")
            },
        )
        val manifest = """{"id":"bl-a-1","slot":"_a"}"""
        val output = buildString {
            appendLine("ID:bl-a-1")
            appendLine("IMG:boot:${"a".repeat(64)}:4096")
            appendLine("IMG:init_boot:${"b".repeat(64)}:2048")
            appendLine("MSHA:${"c".repeat(64)}")
            appendLine("SHAFILE:${"c".repeat(64)}")
            appendLine("MAN:$manifest")
            appendLine("END:bl-a-1")
            appendLine("LISTED")
        }
        val entries = bridge.parseProbe(output)
        assertNotNull(entries)
        assertEquals(1, entries!!.size)
        val entry = entries.first()
        assertEquals("bl-a-1", entry.id)
        assertEquals(manifest, entry.manifestJson)
        assertEquals(4096L, entry.imageSize["boot"])
        assertEquals("b".repeat(64), entry.imageSha256["init_boot"])
        // 没有 LISTED 标记 = 读不到（不是"没有基线"）：必须返回 null 让调用方显式失败。
        assertNull(bridge.parseProbe("ID:bl-a-1\nMAN:$manifest\nEND:bl-a-1\n"))
        // 脚本失败（无 root）同样不得当成空列表。
        assertEquals(null, RootScriptBaselineBridge(
            dev.maplesu.manager.workmode.superuser.RootScriptRunner { _ ->
                dev.maplesu.manager.workmode.superuser.RootScriptResult(1, "")
            },
        ).probe())
    }

    @Test
    fun nonReusableControlPlaneEntryIsNotTreatedAsReady() {
        // shaFile 与 manifest 实际 sha 不符（manifest 被篡改）⇒ 不得复用（判 CORRUPT）。
        val harness = Harness()
        try {
            harness.writeAssets()
            harness.writePins()
            val plane = File(harness.root, "control-plane")
            val bridge = LocalControlPlaneBridge(plane)
            val provisioner = RootPublishingBaselineProvisioner(
                bridge = bridge,
                stagingRoot = File(harness.root, "app-cache"),
                assets = StockAssetSource { path ->
                    val file = File(harness.assetsDir, path.removePrefix("$ASSET_ROOT/"))
                    if (!file.isFile) throw FileNotFoundException(path)
                    ByteArrayInputStream(file.readBytes())
                },
                deviceFacts = { harness.device },
                freeBytes = { 8L shl 30 },
                clock = harness.clock,
            )
            val first = ready(provisioner.ensureBaseline())
            // 篡改 manifest 的一个字节（sha256 兄弟文件不变）⇒ 必须判 CORRUPT，不可复用。
            val manifest = File(plane, "boot/baseline/${first.id}/manifest.json")
            manifest.writeText(manifest.readText().replace("OEM_PACKAGE", "OEM_PACKAGX"), Charsets.UTF_8)
            val entries = bridge.probe()!!
            val reusable = provisioner.reusable(entries, harness.device)
            assertNull("被篡改的 manifest 不得复用", reusable)
        } finally {
            harness.close()
        }
    }

    // ------------------------------------------------------------------ fakes

    /**
     * 用本地目录模拟"控制面"（root 侧 `cp -a + chown/chmod + mv` 的等价物）：
     * 这样整条生产编排（App 暂存 → 发布 → 从控制面复核）可在主机端到端验证。
     */
    private class LocalControlPlaneBridge(private val plane: File) : BaselineControlPlaneBridge {
        var publishCalls = 0
        var failPublish = false

        override fun probe(): List<BaselineControlPlaneEntry>? {
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

    private fun planeFingerprint(plane: File): Map<String, String> {
        if (!plane.isDirectory) return emptyMap()
        return plane.walkTopDown().filter { it.isFile }.associate { file ->
            file.relativeTo(plane).path.replace('\\', '/') to "${file.length()}:${sha(file.readBytes())}"
        }
    }

    private fun baselineRelative(id: String, name: String): String = "boot/baseline/$id/$name"

    private companion object {
        const val ASSET_ROOT = "boot-stock/PLQ110_16.0.7.201_CN01"
        const val FIRMWARE = "PLQ110_16.0.7.201(CN01)"
        const val KERNEL_RELEASE = "6.6.89-android15-8-g7e1f3c083cc6-abogki467167594-4k"
    }
}
