// SPDX-License-Identifier: GPL-3.0-or-later
package dev.maplesu.manager.installer

import java.io.File
import java.security.MessageDigest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/** `RootPartitionExtractorTest` 与它的假设备共用的一份摘要实现（顶层函数：嵌套类也能用）。 */
private fun sha256Hex(bytes: ByteArray): String =
    MessageDigest.getInstance("SHA-256").digest(bytes)
        .joinToString("") { "%02x".format(it.toInt() and 0xFF) }

/**
 * 「直接安装」时从当前设备提取分区镜像（`RootPartitionExtractor`）。
 *
 * 全部在主机 JVM 上跑：`RootShellRunner` 用假设备替代（记录命令 + 模拟 `dd`/`wc -c`/`sha256sum`），
 * 因此"命令形态 / 槽位拼接 / 回读校验 / 失败码 / 不进入修补"都能被机器证明。
 */
class RootPartitionExtractorTest {

    @get:Rule
    val tmp = TemporaryFolder()

    /**
     * 假设备：只认 [DirectInstallCommands] 造出来的那几种命令形态。
     *
     * `dd` 会把 [imageBytes] 写到命令里的 `of=` 路径（模拟真实拷贝），
     * `wc -c` / `sha256sum` 默认回报真实值，可用 override 造出"回读不一致"。
     */
    private class FakeDevice(
        var slotProperty: String = "_b",
        var existingNodes: Set<String> = setOf("/dev/block/by-name/init_boot_b"),
        var imageBytes: ByteArray = ByteArray(4096) { (it % 251).toByte() },
        var ddExitCode: Int = 0,
        var ddWritesFile: Boolean = true,
        var reportSize: Long? = null,
        var reportDigest: String? = null,
        var sizeExitCode: Int = 0,
    ) : RootShellRunner {

        val commands = mutableListOf<String>()

        override fun run(command: String, timeoutMs: Long): RootShellResult {
            commands += command
            return when {
                command == DirectInstallCommands.SLOT_COMMAND ->
                    RootShellResult(0, listOf(slotProperty))

                command.startsWith("for n in ") -> {
                    val candidates = tokens(command.substringAfter("for n in ").substringBefore("; do"))
                    val found = candidates.firstOrNull { it in existingNodes }
                    RootShellResult(0, listOfNotNull(found))
                }

                command.startsWith("dd if=") -> {
                    if (ddExitCode != 0) {
                        RootShellResult(ddExitCode, emptyList(), listOf("dd: boom"))
                    } else {
                        if (ddWritesFile) {
                            val out = File(tokenValue(command, "of="))
                            out.parentFile?.mkdirs()
                            out.writeBytes(imageBytes)
                        }
                        RootShellResult(0, listOf("1+0 records in"))
                    }
                }

                command.startsWith("wc -c ") -> {
                    val file = File(lastToken(command))
                    val size = reportSize ?: file.length()
                    RootShellResult(sizeExitCode, listOf("$size ${file.absolutePath}"))
                }

                command.startsWith("sha256sum ") -> {
                    val file = File(lastToken(command))
                    val digest = reportDigest ?: sha256Hex(if (file.isFile) file.readBytes() else ByteArray(0))
                    RootShellResult(0, listOf("$digest  ${file.absolutePath}"))
                }

                else -> RootShellResult(127, emptyList(), listOf("unexpected: $command"))
            }
        }

        /** `dd` 里的 `if=<node>`（未加引号，路径不含空白）。 */
        fun ddSourceNode(): String = tokens(commands.last { it.startsWith("dd if=") })
            .first { it.startsWith("if=") }
            .removePrefix("if=")

        private fun tokens(line: String): List<String> =
            line.split(' ').map { it.trim('\'') }.filter { it.isNotEmpty() }

        private fun tokenValue(line: String, prefix: String): String =
            tokens(line).first { it.startsWith(prefix) }.removePrefix(prefix).trim('\'')

        private fun lastToken(line: String): String = tokens(line).last()
    }

    private fun extractor(device: FakeDevice): RootPartitionExtractor =
        RootPartitionExtractor(device, File(tmp.root, "ksu-direct-install"))

    private fun extracted(result: PartitionExtractResult): ExtractedPartitionImage {
        assertTrue("expected Extracted, got $result", result is PartitionExtractResult.Extracted)
        return (result as PartitionExtractResult.Extracted).value
    }

    private fun failed(result: PartitionExtractResult): PartitionExtractResult.Failed {
        assertTrue("expected Failed, got $result", result is PartitionExtractResult.Failed)
        return result as PartitionExtractResult.Failed
    }

    // ── 命令形态 ─────────────────────────────────────────────────────────

    @Test
    fun ddCommandReadsTheByNameNodeOfTheRequestedPartitionAndSlot() {
        val image = File(tmp.root, "init_boot_a.img")
        assertEquals(
            "dd if=/dev/block/by-name/init_boot_a of=${DirectInstallCommands.quote(image.absolutePath)} bs=1M",
            DirectInstallCommands.ddCommand("/dev/block/by-name/init_boot_a", image),
        )
        // 节点路径被钉在 by-name 下，不能被外部字符串带出这个目录。
        val rejected = runCatching {
            DirectInstallCommands.ddCommand("/dev/block/mmcblk0p1", image)
        }.exceptionOrNull()
        assertNotNull("节点不在 by-name 下必须被构造层拒绝", rejected)
    }

    @Test
    fun sizeAndDigestCommandsAreTheOnlyReadbackPaths() {
        val image = File(tmp.root, "boot_a.img")
        val quoted = DirectInstallCommands.quote(image.absolutePath)
        assertEquals("wc -c $quoted", DirectInstallCommands.sizeCommand(image))
        assertEquals("sha256sum $quoted", DirectInstallCommands.digestCommand(image))
    }

    // ── 正例 ─────────────────────────────────────────────────────────────

    @Test
    fun extractsTheCurrentSlotPartitionAndVerifiesIt() {
        val device = FakeDevice(
            slotProperty = "_b",
            existingNodes = setOf("/dev/block/by-name/init_boot_b"),
        )
        val image = extracted(
            extractor(device).extract(InstallPartition.INIT_BOOT, device.slotProperty),
        )

        assertEquals(InstallPartition.INIT_BOOT, image.partition)
        assertEquals("_b", image.slotSuffix)
        assertEquals("/dev/block/by-name/init_boot_b", image.deviceNode)
        assertEquals(4096L, image.size)
        assertEquals(sha256Hex(device.imageBytes), image.sha256)
        assertTrue(image.image.isFile)
        assertEquals(4096L, image.image.length())
        // dd 读的就是拼好的节点。
        assertEquals("/dev/block/by-name/init_boot_b", device.ddSourceNode())
        // 命令顺序：找节点 → dd → wc -c → sha256sum（槽位由上层传入，本类不再查 getprop）。
        assertEquals(4, device.commands.size)
        assertTrue(device.commands[0].startsWith("for n in "))
        assertTrue(device.commands[1].startsWith("dd if="))
        assertTrue(device.commands[2].startsWith("wc -c "))
        assertTrue(device.commands[3].startsWith("sha256sum "))
    }

    @Test
    fun bootPartitionUsesBootNodeWithTheSameSlot() {
        val device = FakeDevice(
            slotProperty = "_a",
            existingNodes = setOf("/dev/block/by-name/boot_a"),
        )
        val image = extracted(
            extractor(device).extract(InstallPartition.BOOT, device.slotProperty),
        )
        assertEquals("boot_a", image.image.nameWithoutExtension)
        assertEquals("/dev/block/by-name/boot_a", image.deviceNode)
        assertEquals(InstallPartition.BOOT, image.partition)
    }

    @Test
    fun missingSlotPropertyFallsBackToSlotA() {
        val device = FakeDevice(
            slotProperty = "",
            existingNodes = setOf("/dev/block/by-name/init_boot_a"),
        )
        val image = extracted(extractor(device).extract(InstallPartition.INIT_BOOT, null))
        assertEquals("_a", image.slotSuffix)
        assertEquals("/dev/block/by-name/init_boot_a", image.deviceNode)
        assertEquals("init_boot_a.img", image.image.name)
    }

    // ── 失败（显式码，且不留下半份镜像）────────────────────────────────────

    @Test
    fun missingDeviceNodeFailsWithoutRunningDd() {
        val device = FakeDevice(existingNodes = emptySet())
        val rejected = failed(extractor(device).extract(InstallPartition.INIT_BOOT, "_a"))
        assertEquals(DirectInstallCodes.DEVICE_NODE_MISSING, rejected.code)
        assertFalse("dd must not run when the node is missing", device.commands.any { it.startsWith("dd ") })
    }

    @Test
    fun ddFailureIsReportedAndNoImageIsKept() {
        val device = FakeDevice(ddExitCode = 1)
        val rejected = failed(extractor(device).extract(InstallPartition.INIT_BOOT, "_b"))
        assertEquals(DirectInstallCodes.EXTRACT_FAILED, rejected.code)
        assertFalse(File(tmp.root, "ksu-direct-install/init_boot_b.img").exists())
    }

    @Test
    fun ddThatWritesNothingIsRejected() {
        val device = FakeDevice(ddWritesFile = false)
        val rejected = failed(extractor(device).extract(InstallPartition.INIT_BOOT, "_b"))
        assertEquals(DirectInstallCodes.EXTRACT_EMPTY, rejected.code)
    }

    @Test
    fun zeroSizeReadbackIsRejected() {
        val device = FakeDevice(reportSize = 0L)
        val rejected = failed(extractor(device).extract(InstallPartition.INIT_BOOT, "_b"))
        assertEquals(DirectInstallCodes.EXTRACT_EMPTY, rejected.code)
    }

    @Test
    fun sizeMismatchBetweenDeviceAndLocalFileIsRejected() {
        val device = FakeDevice(reportSize = 999_999L)
        val rejected = failed(extractor(device).extract(InstallPartition.INIT_BOOT, "_b"))
        assertEquals(DirectInstallCodes.SIZE_MISMATCH, rejected.code)
        assertFalse(File(tmp.root, "ksu-direct-install/init_boot_b.img").exists())
    }

    @Test
    fun digestMismatchIsRejected() {
        val device = FakeDevice(reportDigest = "0".repeat(64))
        val rejected = failed(extractor(device).extract(InstallPartition.INIT_BOOT, "_b"))
        assertEquals(DirectInstallCodes.DIGEST_MISMATCH, rejected.code)
    }

    @Test
    fun unparseableDigestIsRejected() {
        val device = FakeDevice(reportDigest = "not-a-digest")
        val rejected = failed(extractor(device).extract(InstallPartition.INIT_BOOT, "_b"))
        assertEquals(DirectInstallCodes.DIGEST_READBACK_FAILED, rejected.code)
    }

    @Test
    fun oversizedImageIsRejected() {
        val device = FakeDevice(imageBytes = ByteArray(8))
        val extractor = RootPartitionExtractor(
            device,
            File(tmp.root, "ksu-direct-install-small"),
            maxBytes = 4L,
        )
        val rejected = failed(extractor.extract(InstallPartition.INIT_BOOT, "_b"))
        assertEquals(DirectInstallCodes.EXTRACT_TOO_LARGE, rejected.code)
    }
}
