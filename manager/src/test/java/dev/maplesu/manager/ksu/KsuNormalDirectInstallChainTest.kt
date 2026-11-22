// SPDX-License-Identifier: GPL-3.0-or-later
package dev.maplesu.manager.ksu

import dev.maplesu.manager.installer.DirectInstallCodes
import dev.maplesu.manager.installer.InstallPartition
import dev.maplesu.manager.installer.InstallSourceKind
import dev.maplesu.manager.installer.InstallTargetDecision
import dev.maplesu.manager.installer.InstallTargetDispatch
import dev.maplesu.manager.installer.InstallTargetMode
import dev.maplesu.manager.installer.InstallTargetRequest
import dev.maplesu.manager.installer.KsuKmiMatrix
import dev.maplesu.manager.installer.PartitionExtractResult
import dev.maplesu.manager.installer.RootPartitionExtractor
import dev.maplesu.manager.installer.RootShellResult
import dev.maplesu.manager.installer.RootShellRunner
import java.io.File
import java.security.MessageDigest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

private fun sha256Hex(bytes: ByteArray): String =
    MessageDigest.getInstance("SHA-256").digest(bytes)
        .joinToString("") { "%02x".format(it.toInt() and 0xFF) }

/**
 * Normal + **直接安装**的整条链路（不含 Android）：分派 → 策略 → 提取当前分区 → 修补 → 提交。
 *
 * 这一组用例回答用户口径里的三个问题：
 * 1. 「直接安装（推荐）」在 Normal 下**不需要先选文件**：先 root 读当前分区，再修补；
 * 2. 分区选择**真的贯通**：`init_boot`（默认）与 `boot` 分别决定读哪个节点、`ksud boot-patch`
 *    的 `--partition`、以及候选/提交里的 `partition` —— 三者恒等；
 * 3. 提取失败**不进入修补/刷写**（不拿半份镜像去赌）。
 */
class KsuNormalDirectInstallChainTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private val android15Release = "6.6.127-android15-8-4k-g46a034eca005"

    /**
     * 假设备：只认提取器会发的五条命令。
     *
     * @param partitionBytes 当前分区的"真实内容"（合成 stock boot，能过 producer 的 ramdisk 校验）
     */
    private class FakeDevice(
        private val slot: String,
        private val nodes: Set<String>,
        private val partitionBytes: ByteArray,
    ) : RootShellRunner {

        val commands = mutableListOf<String>()

        override fun run(command: String, timeoutMs: Long): RootShellResult {
            commands += command
            return when {
                command == "getprop ro.boot.slot_suffix" -> RootShellResult(0, listOf(slot))

                command.startsWith("for n in ") -> {
                    val candidates = command.substringAfter("for n in ").substringBefore("; do")
                        .split(' ').map { it.trim('\'') }
                    RootShellResult(0, listOfNotNull(candidates.firstOrNull { it in nodes }))
                }

                command.startsWith("dd if=") -> {
                    val out = File(command.split(' ').first { it.startsWith("of=") }
                        .removePrefix("of=").trim('\''))
                    out.parentFile?.mkdirs()
                    out.writeBytes(partitionBytes)
                    RootShellResult(0, listOf("1+0 records in"))
                }

                command.startsWith("wc -c ") -> {
                    val file = File(command.removePrefix("wc -c ").trim('\''))
                    RootShellResult(0, listOf("${file.length()} ${file.absolutePath}"))
                }

                command.startsWith("sha256sum ") -> {
                    val file = File(command.removePrefix("sha256sum ").trim('\''))
                    RootShellResult(0, listOf("${sha256Hex(file.readBytes())}  ${file.absolutePath}"))
                }

                else -> RootShellResult(127, emptyList(), listOf("unexpected: $command"))
            }
        }
    }

    private fun daemon(): File {
        val dir = File(tmp.root, "applib").apply { mkdirs() }
        return KsuImageFixtures.write(dir, "libksud_ksu.so", "ksud".toByteArray())
    }

    private fun ready(
        partition: String? = null,
        source: InstallSourceKind = InstallSourceKind.CURRENT_PARTITION,
    ): InstallTargetDecision.Ready {
        val decision = InstallTargetDispatch.decide(
            InstallTargetRequest(
                target = InstallTargetMode.NORMAL,
                source = source,
                partition = partition,
                kernelRelease = android15Release,
                availableKmis = KsuKmiMatrix.KMIS,
                sdkInt = 35,
            ),
        )
        assertTrue("expected Ready, got $decision", decision is InstallTargetDecision.Ready)
        return decision as InstallTargetDecision.Ready
    }

    /** 与 `KsuInstallGlue` 同序：分派结论 → 策略选项。 */
    private fun options(decision: InstallTargetDecision.Ready, bootUriPresent: Boolean): KsuBootPatchOptions {
        val evaluated = KsuInstallPolicy.evaluate(
            bootUriPresent = bootUriPresent,
            kmi = decision.kmi,
            lkmIsUri = false,
            ota = false,
            partition = decision.partition,
            allowShell = false,
            enableAdb = false,
            forceBackup = false,
            blockModules = "",
            directInstall = !bootUriPresent,
        )
        assertTrue("expected Allowed, got $evaluated", evaluated is KsuInstallDecision.Allowed)
        return (evaluated as KsuInstallDecision.Allowed).options
    }

    private fun producer(
        runner: KsuRootCommandRunner,
        commit: KsuCandidateCommitPort,
    ): KsuInstallProducer = KsuInstallProducer(
        daemonPath = daemon().absolutePath,
        runner = runner,
        workRoot = File(tmp.root, "work").apply { mkdirs() },
        commit = commit,
        switchSession = { "switch-uuid" },
        clock = { 1L },
    )

    // ── 1) 直装 + init_boot（默认）→ 读 init_boot 节点、补 init_boot、提交 init_boot ─────

    @Test
    fun directInstallReadsInitBootAndPatchesTheSamePartition() {
        val device = FakeDevice(
            slot = "_a",
            nodes = setOf("/dev/block/by-name/init_boot_a"),
            partitionBytes = KsuImageFixtures.stockImage(),
        )
        // 页面没传分区 → 默认 init_boot。
        val decision = ready(partition = null)
        assertEquals("init_boot", decision.partition)

        val extractor = RootPartitionExtractor(device, File(tmp.root, "cache"))
        val extracted = extractor.extract(
            requireNotNull(InstallPartition.fromWire(decision.partition)),
            extractor.readSlotSuffix(),
        )
        assertTrue("expected Extracted, got $extracted", extracted is PartitionExtractResult.Extracted)
        val image = (extracted as PartitionExtractResult.Extracted).value
        assertEquals("/dev/block/by-name/init_boot_a", image.deviceNode)

        val patcher = KsuImageFixtures.FakeBootPatchRunner(KsuImageFixtures.ksuImage())
        var committed: KsuProducedCandidate? = null
        val result = producer(patcher, KsuCandidateCommitPort { candidate, _ ->
            committed = candidate
            KsuCommitResult.Committed("switch-uuid", "REBOOT_REQUIRED")
        }).installBoot(image.image, options(decision, bootUriPresent = false))

        assertTrue("expected Committed, got $result", result is KsuInstallResult.Committed)
        val tokens = KsuImageFixtures.splitCommandLine(patcher.commands.single())
        assertTrue(
            "boot-patch must target init_boot, got $tokens",
            tokens.containsAll(listOf("--partition", "init_boot")),
        )
        // 候选与提交里的分区 = 修补分区（不存在"补 init_boot、写 boot"的错位）。
        assertEquals("init_boot", committed!!.partition)
        val provenance = File(tmp.root, "work/staged/${committed!!.sha256}.json")
        assertTrue(provenance.readText().contains("\"partition\":\"init_boot\""))
    }

    // ── 2) 直装 + 用户把分区切成 boot → 读 boot 节点、补 boot、提交 boot ────────────────

    @Test
    fun switchingThePartitionToBootMovesExtractionPatchAndCommitToBoot() {
        val device = FakeDevice(
            slot = "_b",
            nodes = setOf("/dev/block/by-name/boot_b"),
            partitionBytes = KsuImageFixtures.stockImage(),
        )
        val decision = ready(partition = "boot")
        assertEquals("boot", decision.partition)

        val extractor = RootPartitionExtractor(device, File(tmp.root, "cache"))
        val extracted = extractor.extract(
            requireNotNull(InstallPartition.fromWire(decision.partition)),
            extractor.readSlotSuffix(),
        )
        val image = (extracted as PartitionExtractResult.Extracted).value
        assertEquals("/dev/block/by-name/boot_b", image.deviceNode)
        assertEquals("boot_b.img", image.image.name)

        val patcher = KsuImageFixtures.FakeBootPatchRunner(KsuImageFixtures.ksuImage())
        var committed: KsuProducedCandidate? = null
        val result = producer(patcher, KsuCandidateCommitPort { candidate, _ ->
            committed = candidate
            KsuCommitResult.Committed("switch-uuid", "REBOOT_REQUIRED")
        }).installBoot(image.image, options(decision, bootUriPresent = false))

        assertTrue("expected Committed, got $result", result is KsuInstallResult.Committed)
        val tokens = KsuImageFixtures.splitCommandLine(patcher.commands.single())
        assertTrue(
            "boot-patch must target boot, got $tokens",
            tokens.containsAll(listOf("--partition", "boot")),
        )
        assertEquals("boot", committed!!.partition)
        assertTrue(
            "candidate partition must be boot, not init_boot",
            File(tmp.root, "work/staged/${committed!!.sha256}.json")
                .readText().contains("\"partition\":\"boot\""),
        )
    }

    // ── 3) 提取失败 → 不进入修补/刷写 ──────────────────────────────────────────────

    @Test
    fun extractionFailureNeverReachesThePatcherOrTheTransaction() {
        val device = FakeDevice(
            slot = "_a",
            nodes = emptySet(), // 机型没有 / 槽位拼错 → by-name 下找不到节点
            partitionBytes = ByteArray(0),
        )
        val decision = ready(partition = null)
        val extractor = RootPartitionExtractor(device, File(tmp.root, "cache"))
        val extracted = extractor.extract(
            requireNotNull(InstallPartition.fromWire(decision.partition)),
            extractor.readSlotSuffix(),
        )
        assertTrue(extracted is PartitionExtractResult.Failed)
        assertEquals(
            DirectInstallCodes.DEVICE_NODE_MISSING,
            (extracted as PartitionExtractResult.Failed).code,
        )

        // 提取失败 = 链路的终点：既没有 ksud 调用，也没有提交。
        val patcher = KsuImageFixtures.FakeBootPatchRunner(KsuImageFixtures.ksuImage())
        var commitCalls = 0
        val producer = producer(patcher, KsuCandidateCommitPort { _, _ ->
            commitCalls++
            KsuCommitResult.Committed("switch-uuid", "REBOOT_REQUIRED")
        })
        assertTrue(patcher.commands.isEmpty())
        assertEquals(0, commitCalls)
        // producer 本身没有"空源也能跑"的后门。
        val rejected = producer.produceCandidate(
            File(tmp.root, "cache/missing.img"),
            options(decision, bootUriPresent = false),
        )
        assertTrue(rejected is KsuProduceResult.Rejected)
        assertEquals("PRODUCE_SOURCE_MISSING", (rejected as KsuProduceResult.Rejected).code)
        assertTrue(patcher.commands.isEmpty())
        assertEquals(0, commitCalls)
    }

    // ── 4) 用户自带文件：仍然可用，分区同样生效 ─────────────────────────────────────

    @Test
    fun userSuppliedImageStillWorksAndHonoursTheSelectedPartition() {
        val selected = File(tmp.root, "user-init_boot.img").apply {
            writeBytes(KsuImageFixtures.stockImage())
        }
        val decision = ready(partition = "boot", source = InstallSourceKind.IMAGE)
        assertEquals("boot", decision.partition)

        val patcher = KsuImageFixtures.FakeBootPatchRunner(KsuImageFixtures.ksuImage())
        var committed: KsuProducedCandidate? = null
        val result = producer(patcher, KsuCandidateCommitPort { candidate, _ ->
            committed = candidate
            KsuCommitResult.Committed("switch-uuid", "REBOOT_REQUIRED")
        }).installBoot(selected, options(decision, bootUriPresent = true))

        assertTrue("expected Committed, got $result", result is KsuInstallResult.Committed)
        val tokens = KsuImageFixtures.splitCommandLine(patcher.commands.single())
        assertTrue(tokens.containsAll(listOf("--partition", "boot")))
        assertTrue(
            "the user's own file must be the patch input",
            tokens[tokens.indexOf("-b") + 1] == selected.absolutePath,
        )
        assertEquals("boot", committed!!.partition)
        assertTrue("the user's own file must not be deleted by the producer", selected.exists())
    }
}
