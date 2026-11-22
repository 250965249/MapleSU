// SPDX-License-Identifier: GPL-3.0-or-later
package dev.maplesu.manager.ksu

import dev.maplesu.image.RamdiskInspector
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * KSU 候选生产者。
 *
 * 这些用例验证只产候选、已修补输入由 ksud 裁决及返回候选的结构约束：
 * 全部在主机 JVM 上跑，用合成 boot v4 镜像，不接触真机。
 */
class KsuInstallProducerTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private lateinit var workRoot: File
    private lateinit var daemon: File
    private var sequence = 0

    /** 每次调用都用唯一目录：`TemporaryFolder.newFolder(name)` 不允许重名。 */
    private fun producer(
        runner: KsuRootCommandRunner,
        commit: KsuCandidateCommitPort = KsuCandidateCommitPort { _, _ ->
            KsuCommitResult.NoTransaction("SWITCH_NOT_ACTIVE", "no switch")
        },
        switchSession: () -> String? = { null },
        kmiCatalog: Collection<String>? = null,
    ): KsuInstallProducer {
        workRoot = File(tmp.root, "work-${sequence++}").apply { mkdirs() }
        daemon = KsuImageFixtures.write(
            File(tmp.root, "applib-${sequence++}"),
            "libksud_ksu.so",
            "ksud".toByteArray(),
        )
        daemon.setExecutable(true)
        return KsuInstallProducer(
            daemonPath = daemon.absolutePath,
            runner = runner,
            workRoot = workRoot,
            commit = commit,
            switchSession = switchSession,
            clock = { 1000L },
            kmiCatalog = { kmiCatalog },
        )
    }

    private fun source(bytes: ByteArray = KsuImageFixtures.stockImage()): File =
        KsuImageFixtures.write(File(tmp.root, "src-${sequence++}"), "init_boot.img", bytes)

    private fun produced(result: KsuProduceResult): KsuProducedCandidate {
        assertTrue("expected Produced, got $result", result is KsuProduceResult.Produced)
        return (result as KsuProduceResult.Produced).candidate
    }

    private fun rejection(result: KsuProduceResult): KsuProduceResult.Rejected {
        assertTrue("expected Rejected, got $result", result is KsuProduceResult.Rejected)
        return result as KsuProduceResult.Rejected
    }

    // ── 正例：只产候选 ────────────────────────────────────────────────────

    @Test
    fun producesValidatedCandidateOnly() {
        val runner = KsuImageFixtures.FakeBootPatchRunner(KsuImageFixtures.ksuImage())
        val source = source()
        val result = producer(runner).produceCandidate(source, KsuBootPatchOptions(kmi = "android15-6.6"))
        val candidate = produced(result)

        assertTrue(candidate.candidate.isFile)
        assertTrue(candidate.size > 0L)
        assertEquals(KsuInstallProducer.ALLOWED_PARTITION, candidate.partition)
        assertEquals(KsuInstallProducer.sha256(candidate.candidate), candidate.sha256)
        assertEquals(RamdiskInspector.Form.KSU_LKM_COMPATIBLE, candidate.form)
        assertEquals(RamdiskState.COMPATIBLE, candidate.ramdiskState)
        assertEquals(KsuInstallProducer.sha256(source), candidate.sourceSha256)
        assertTrue(candidate.kernelsuKoSha256?.isNotEmpty() == true)
    }

    @Test
    fun commandIsCandidateOnlyAndUsesFixedArguments() {
        val runner = KsuImageFixtures.FakeBootPatchRunner(KsuImageFixtures.ksuImage())
        producer(runner).produceCandidate(source(), KsuBootPatchOptions(kmi = "android15-6.6"))
        assertEquals(1, runner.commands.size)
        val tokens = KsuImageFixtures.splitCommandLine(runner.commands.single())
        assertEquals(daemon.absolutePath, tokens.first())
        assertTrue(tokens.contains("boot-patch"))
        assertTrue(tokens.containsAll(listOf("--partition", "init_boot")))
        assertTrue(tokens.containsAll(listOf("--out-name", "candidate.img")))
        assertTrue(tokens.containsAll(listOf("--kmi", "android15-6.6")))
        listOf("--flash", "-f", "--backup", "--ota", "-u", "--force-foreign", "--no-install",
            "--kernel", "--restore").forEach {
            assertFalse("forbidden token leaked into produced command: $it", tokens.contains(it))
        }
    }

    @Test
    fun commandQuotesPathsWithSpaces() {
        val runner = KsuImageFixtures.FakeBootPatchRunner(KsuImageFixtures.ksuImage())
        workRoot = tmp.newFolder("work dir")
        daemon = KsuImageFixtures.write(tmp.newFolder("lib dir"), "libksud_ksu.so", "ksud".toByteArray())
        val source = KsuImageFixtures.write(tmp.newFolder("src dir"), "init_boot.img",
            KsuImageFixtures.stockImage())
        KsuInstallProducer(
            daemonPath = daemon.absolutePath,
            runner = runner,
            workRoot = workRoot,
            commit = KsuCandidateCommitPort { _, _ -> KsuCommitResult.Accepted },
            switchSession = { null },
            clock = { 1L },
        ).produceCandidate(source, KsuBootPatchOptions())
        val tokens = KsuImageFixtures.splitCommandLine(runner.commands.single())
        assertEquals(source.absolutePath, tokens[tokens.indexOf("-b") + 1])
        assertTrue(tokens[tokens.indexOf("-o") + 1].startsWith(workRoot.absolutePath))
    }

    // ── 候选校验：stock / foreign / 畸形 ─────────────────────────────────

    @Test
    fun rejectsStockCandidate() {
        val runner = KsuImageFixtures.FakeBootPatchRunner(KsuImageFixtures.stockImage())
        val rejected = rejection(producer(runner).produceCandidate(source(), KsuBootPatchOptions()))
        assertTrue(
            "stock candidate must be rejected by the KSU LKM assertion, got ${rejected.code}",
            rejected.code.startsWith("PRODUCE_CANDIDATE_FORM_MISSING"),
        )
    }

    @Test
    fun rejectsForeignSevenkCandidate() {
        val runner = KsuImageFixtures.FakeBootPatchRunner(KsuImageFixtures.foreignImage())
        val rejected = rejection(producer(runner).produceCandidate(source(), KsuBootPatchOptions()))
        assertTrue(
            "foreign sevenk.ko candidate must be rejected, got ${rejected.code}",
            rejected.code.contains("FOREIGN_ARTIFACT"),
        )
    }

    @Test
    fun rejectsMalformedCandidate() {
        val runner = KsuImageFixtures.FakeBootPatchRunner("definitely-not-a-boot-image".toByteArray())
        val rejected = rejection(producer(runner).produceCandidate(source(), KsuBootPatchOptions()))
        assertEquals("PRODUCE_CANDIDATE_MALFORMED", rejected.code)
    }

    // ── 源镜像校验 ────────────────────────────────────────────────────────

    @Test
    fun alreadyPatchedSourceReachesKsudWithoutAnExtraGate() {
        val runner = KsuImageFixtures.FakeBootPatchRunner(KsuImageFixtures.ksuImage())
        val patchedSource = source(KsuImageFixtures.ksuImage())
        val candidate = produced(
            producer(runner).produceCandidate(patchedSource, KsuBootPatchOptions()),
        )
        assertEquals(RamdiskInspector.Form.KSU_LKM_COMPATIBLE, candidate.form)
        assertEquals(1, runner.commands.size)
        val tokens = KsuImageFixtures.splitCommandLine(runner.commands.single())
        assertEquals(patchedSource.absolutePath, tokens[tokens.indexOf("-b") + 1])
    }

    @Test
    fun upstreamKsuRepatchPreservesTheCandidateOnlyCommand() {
        val runner = KsuImageFixtures.FakeBootPatchRunner(KsuImageFixtures.ksuImage(withMaplesuId = true))
        val candidate = produced(producer(runner).produceCandidate(
            source(KsuImageFixtures.ksuImage()), KsuBootPatchOptions()))
        assertEquals(RamdiskInspector.Form.KSU_LKM_OURS, candidate.form)
        assertEquals(1, runner.commands.size)
        val tokens = KsuImageFixtures.splitCommandLine(runner.commands.single())
        assertFalse(tokens.any { it in setOf("--flash", "-f", "--backup", "--restore") })
    }

    private fun generatedWithoutOriginalRamdisk(
        origin: String? = "maplesu_original_ramdisk=empty-v1",
        release: String = "6.6.127-android15-8-gabcdef",
        kmi: String = "android15-6.6",
    ): ByteArray {
        val ramdisk = KsuImageFixtures.cpio(listOf(
            "init" to "ksuinit".toByteArray(), "kernelsu.ko" to "module".toByteArray(),
            "maplesu_id" to "uapi=7".toByteArray(),
            "ksu_config" to listOfNotNull("kmi=$kmi", origin).joinToString(" ").toByteArray(),
        ))
        return ByteArray(16384).apply {
            KsuImageFixtures.bootV4(ramdisk).copyInto(this)
            java.nio.ByteBuffer.wrap(this).order(java.nio.ByteOrder.LITTLE_ENDIAN).putInt(8, 4096)
            fill(0, 4096, size)
            ByteArray(4096) { 42 }.copyInto(this, 4096)
            if (release.isNotEmpty()) "Linux version $release (fixture)\u0000".toByteArray().copyInto(this, 4096 + 64)
            ramdisk.copyInto(this, 8192)
        }
    }

    @Test
    fun bootFileUsesItsOwnKernelKmiInsteadOfTheRunningDeviceDefault() {
        val bytes = generatedWithoutOriginalRamdisk(release = "5.10.252-android13-4-gabcdef", kmi = "android13-5.10")
        val runner = KsuImageFixtures.FakeBootPatchRunner(bytes)
        val candidate = produced(producer(runner, kmiCatalog = setOf("android13-5.10"))
            .produceCandidate(source(bytes), KsuBootPatchOptions(partition = "boot", kmi = "android15-6.6")))
        assertEquals("boot", candidate.partition)
        val tokens = KsuImageFixtures.splitCommandLine(runner.commands.single())
        assertEquals("android13-5.10", tokens[tokens.indexOf("--kmi") + 1])
        assertFalse(tokens.contains("android15-6.6"))
    }

    @Test
    fun unparseableBootKernelDoesNotUseTheRunningDeviceDefault() {
        val bytes = generatedWithoutOriginalRamdisk(release = "")
        val runner = KsuImageFixtures.FakeBootPatchRunner(bytes)
        val result = producer(runner).produceCandidate(source(bytes),
            KsuBootPatchOptions(partition = "boot", kmi = "android15-6.6"))
        assertEquals("PRODUCE_TARGET_KMI_UNAVAILABLE", rejection(result).code)
        assertTrue(runner.commands.isEmpty())
    }

    @Test
    fun ownEmptyRamdiskOriginAllowsRepeatedBootUpdatesWithoutInventingInitReal() {
        val bytes = generatedWithoutOriginalRamdisk()
        repeat(2) {
            val runner = KsuImageFixtures.FakeBootPatchRunner(bytes)
            val candidate = produced(producer(runner).produceCandidate(source(bytes),
                KsuBootPatchOptions(partition = "boot")))
            assertFalse(RamdiskInspector.inspect(candidate.candidate).hasInitReal)
            assertEquals(1, runner.commands.size)
        }
    }

    @Test
    fun anEmptyRamdiskUpdateStillValidatesTheReturnedOrigin() {
        val runner = KsuImageFixtures.FakeBootPatchRunner(generatedWithoutOriginalRamdisk(origin = null))
        val result = producer(runner).produceCandidate(source(generatedWithoutOriginalRamdisk()),
            KsuBootPatchOptions(partition = "boot"))
        assertTrue(rejection(result).code.startsWith("PRODUCE_CANDIDATE_FORM_"))
        assertEquals(1, runner.commands.size)
    }

    @Test
    fun unknownMissingInitRealAndConflictingOriginDoNotBecomeKnownEmptyRamdisks() {
        for (origin in listOf(null, "maplesu_original_ramdisk=unknown",
            "maplesu_original_ramdisk=empty-v1 maplesu_original_ramdisk=present")) {
            val runner = KsuImageFixtures.FakeBootPatchRunner(generatedWithoutOriginalRamdisk())
            val result = producer(runner).produceCandidate(source(generatedWithoutOriginalRamdisk(origin)),
                KsuBootPatchOptions(partition = "boot"))
            assertTrue(rejection(result).code.startsWith("PRODUCE_CANDIDATE_FORM_"))
            assertEquals(1, runner.commands.size)
        }
    }

    @Test
    fun sevenkSourceReachesKsudAndPreservesItsFailure() {
        val runner = KsuImageFixtures.FakeBootPatchRunner(null).apply {
            exitCode = 53
            stderr = "fixture producer rejected sevenk input"
        }
        val errors = mutableListOf<String>()
        val result = producer(runner).produceCandidate(source(KsuImageFixtures.foreignImage()),
            KsuBootPatchOptions(), onStderr = errors::add)
        assertEquals("PRODUCE_KSud_FAILED", rejection(result).code)
        assertEquals(53, rejection(result).exitCode)
        assertEquals(listOf(runner.stderr), errors)
        assertEquals(1, runner.commands.size)
    }

    @Test
    fun mixedMagiskSourceUsesTheActualProducerVerdict() {
        val mixed = KsuImageFixtures.bootV4(KsuImageFixtures.cpio(listOf(
            "init" to "ksuinit".toByteArray(), "init.real" to "stock-init".toByteArray(),
            "kernelsu.ko" to "old-ko".toByteArray(), "ksu_config" to ByteArray(0),
            ".backup/.magisk" to "magisk-config".toByteArray(),
        )))
        val runner = KsuImageFixtures.FakeBootPatchRunner(null).apply {
            exitCode = 17
            stderr = "fixture producer rejected mixed ramdisk"
        }
        val receipts = mutableListOf<KsuPatchCommandReceipt>()
        val result = producer(runner).produceCandidate(source(mixed), KsuBootPatchOptions(),
            onCommand = receipts::add)
        assertEquals("PRODUCE_KSud_FAILED", rejection(result).code)
        assertEquals(17, rejection(result).exitCode)
        assertEquals(17, receipts.single().result.code)
        assertEquals(listOf(runner.stderr), receipts.single().result.err)
        assertEquals(1, runner.commands.size)
    }

    @Test
    fun repatchedSourceStillValidatesTheReturnedCandidate() {
        val runner = KsuImageFixtures.FakeBootPatchRunner(KsuImageFixtures.stockImage())
        val result = producer(runner).produceCandidate(source(KsuImageFixtures.ksuImage()),
            KsuBootPatchOptions())
        assertTrue(rejection(result).code.startsWith("PRODUCE_CANDIDATE_FORM_MISSING"))
        assertEquals(1, runner.commands.size)
    }

    @Test
    fun rejectsMalformedSourceBeforeRunningKsud() {
        val runner = KsuImageFixtures.FakeBootPatchRunner(KsuImageFixtures.ksuImage())
        val broken = source("garbage-not-an-image".toByteArray())
        val rejected = rejection(producer(runner).produceCandidate(broken, KsuBootPatchOptions()))
        assertTrue(
            "malformed source must be rejected, got ${rejected.code}",
            rejected.code.startsWith("PRODUCE_SOURCE_"),
        )
        assertTrue(runner.commands.isEmpty())
    }

    @Test
    fun rejectsMissingSourceAndDaemon() {
        val runner = KsuImageFixtures.FakeBootPatchRunner(KsuImageFixtures.ksuImage())
        val producer = producer(runner)
        assertEquals(
            "PRODUCE_SOURCE_MISSING",
            rejection(producer.produceCandidate(File(tmp.root, "nope.img"), KsuBootPatchOptions())).code,
        )
        // daemon 缺失：直接拒绝，不尝试执行
        val missingDaemonProducer = KsuInstallProducer(
            daemonPath = File(tmp.root, "missing/libksud_ksu.so").absolutePath,
            runner = runner,
            workRoot = workRoot,
            commit = KsuCandidateCommitPort { _, _ -> KsuCommitResult.Accepted },
            switchSession = { null },
            clock = { 1L },
        )
        assertEquals(
            "PRODUCE_DAEMON_MISSING",
            rejection(missingDaemonProducer.produceCandidate(source(), KsuBootPatchOptions())).code,
        )
    }

    @Test
    fun rejectsPartitionOutsideTheWhitelistBeforeRunningKsud() {
        val runner = KsuImageFixtures.FakeBootPatchRunner(KsuImageFixtures.ksuImage())
        val rejected = rejection(
            producer(runner).produceCandidate(source(), KsuBootPatchOptions(partition = "vendor_boot")),
        )
        assertEquals("PRODUCE_PARTITION_UNSUPPORTED", rejected.code)
        assertTrue(runner.commands.isEmpty())
    }

    @Test
    fun producesBootCandidateWhenTheSelectedPartitionIsBoot() {
        // 用户把分区切成 boot：命令参数与候选/提交里的分区都必须变成 boot。
        val kernel = ByteArray(4096) { 42 }.apply {
            "Linux version 6.6.127-android15-8-gabcdef\u0000".toByteArray().copyInto(this, 64)
        }
        fun boot(ramdisk: ByteArray) = ByteArray(16384).apply {
            KsuImageFixtures.bootV4(ramdisk).copyInto(this)
            java.nio.ByteBuffer.wrap(this).order(java.nio.ByteOrder.LITTLE_ENDIAN).putInt(8, kernel.size)
            fill(0, 4096, size)
            kernel.copyInto(this, 4096)
            ramdisk.copyInto(this, 8192)
        }
        val runner = KsuImageFixtures.FakeBootPatchRunner(boot(KsuImageFixtures.ksuRamdisk()))
        var committed: KsuProducedCandidate? = null
        val result = producer(
            runner,
            KsuCandidateCommitPort { candidate, _ ->
                committed = candidate
                KsuCommitResult.Committed("switch-uuid-boot", "REBOOT_REQUIRED")
            },
            switchSession = { "switch-uuid-boot" },
        ).installBoot(source(boot(KsuImageFixtures.stockRamdisk())), KsuBootPatchOptions(partition = "boot"))

        assertTrue("expected Committed, got $result", result is KsuInstallResult.Committed)
        val tokens = KsuImageFixtures.splitCommandLine(runner.commands.single())
        assertTrue("boot-patch must target boot, got $tokens", tokens.containsAll(listOf("--partition", "boot")))
        assertEquals("boot", committed!!.partition)
        // staging provenance 记录的也是 boot（刷写侧读的就是这份）。
        val provenance = File(workRoot, "staged/${committed!!.sha256}.json")
        assertTrue(provenance.readText().contains("\"partition\":\"boot\""))
    }

    @Test
    fun selectedBootWithNoRamdiskCanCreateTheNormalPayloadWithoutAnOriginalInit() {
        val kernel = ByteArray(4096) { 42 }.apply {
            "Linux version 6.6.127-android15-8-gabcdef\u0000".toByteArray().copyInto(this, 64)
        }
        fun boot(ramdisk: ByteArray) = ByteArray(16384).apply {
            KsuImageFixtures.bootV4(ramdisk).copyInto(this)
            java.nio.ByteBuffer.wrap(this).order(java.nio.ByteOrder.LITTLE_ENDIAN).putInt(8, kernel.size)
            fill(0, 4096, size)
            kernel.copyInto(this, 4096)
            ramdisk.copyInto(this, 8192)
        }
        val payload = KsuImageFixtures.cpio(listOf(
            "init" to "ksuinit".toByteArray(), "kernelsu.ko" to "module".toByteArray(),
            "ksu_config" to "kmi=android15-6.6".toByteArray()))
        val runner = KsuImageFixtures.FakeBootPatchRunner(boot(payload))
        val candidate = produced(producer(runner).produceCandidate(source(boot(ByteArray(0))),
            KsuBootPatchOptions(partition = "boot")))
        assertEquals("boot", candidate.partition)
        assertEquals(RamdiskInspector.Form.KSU_LKM_COMPATIBLE, candidate.form)
        assertEquals(RamdiskState.COMPATIBLE, candidate.ramdiskState)
    }

    @Test
    fun rejectsWhenKsudFailsOrWritesNothing() {
        val failing = KsuImageFixtures.FakeBootPatchRunner(KsuImageFixtures.ksuImage()).apply {
            exitCode = 1
            stderr = "boom"
        }
        val failed = rejection(producer(failing).produceCandidate(source(), KsuBootPatchOptions()))
        assertEquals("PRODUCE_KSud_FAILED", failed.code)

        val silent = KsuImageFixtures.FakeBootPatchRunner(null)
        val missing = rejection(producer(silent).produceCandidate(source(), KsuBootPatchOptions()))
        assertEquals("PRODUCE_OUTPUT_MISSING", missing.code)
    }

    // ── 交共用事务 / staging ─────────────────────────────────────────────

    @Test
    fun installBootStagesWithoutSwitchTransaction() {
        val runner = KsuImageFixtures.FakeBootPatchRunner(KsuImageFixtures.ksuImage())
        val result = producer(runner).installBoot(source(), KsuBootPatchOptions())
        assertTrue("expected Staged, got $result", result is KsuInstallResult.Staged)
        val staged = result as KsuInstallResult.Staged
        assertEquals("SWITCH_NOT_ACTIVE", staged.code)
        val stagedFile = File(workRoot, "staged/${staged.candidate.sha256}.img")
        assertTrue("staged candidate missing: ${stagedFile.path}", stagedFile.isFile)
        assertEquals(staged.candidate.sha256, KsuInstallProducer.sha256(stagedFile))
        val provenance = File(workRoot, "staged/${staged.candidate.sha256}.json")
        assertTrue(provenance.isFile)
        val json = provenance.readText()
        assertTrue(json.contains(staged.candidate.sha256))
        assertTrue(json.contains("\"partition\":\"init_boot\""))
        assertTrue(json.contains("\"stagedAt\":1000"))
    }

    @Test
    fun installBootSubmitsCandidateToSharedTransaction() {
        var seenSwitchId: String? = "unset"
        var seenCandidate: KsuProducedCandidate? = null
        val progress = mutableListOf<String>()
        val commit = object : KsuCandidateCommitPort, KsuProgressCommitPort {
            override fun submit(candidate: KsuProducedCandidate, switchId: String?): KsuCommitResult =
                submitWithProgress(candidate, switchId) {}

            override fun submitWithProgress(
                candidate: KsuProducedCandidate,
                switchId: String?,
                onProgress: (String) -> Unit,
            ): KsuCommitResult {
                seenCandidate = candidate
                seenSwitchId = switchId
                onProgress("S4")
                return KsuCommitResult.Committed("switch-uuid-1", "REBOOT_REQUIRED")
            }
        }
        val runner = KsuImageFixtures.FakeBootPatchRunner(KsuImageFixtures.ksuImage())
        val result = producer(runner, commit, switchSession = { "switch-uuid-1" })
            .installBoot(source(), KsuBootPatchOptions(), { progress += it }, {})
        assertTrue("expected Committed, got $result", result is KsuInstallResult.Committed)
        assertEquals("switch-uuid-1", seenSwitchId)
        assertEquals(KsuInstallProducer.sha256(seenCandidate!!.candidate), seenCandidate!!.sha256)
        // 事务 id 必须落到 staging provenance（续跑/取证）；只在 Committed 路径写。
        val provenance = File(workRoot, "staged/${seenCandidate!!.sha256}.json")
        assertTrue(provenance.isFile)
        assertTrue(provenance.readText().contains("\"switchId\":\"switch-uuid-1\""))
        assertTrue("progress must reach the installer console", progress.any { it == "S4" })
    }

    /**
     * P0-1 第 4 项防谎报：事务只"接收"候选（`Accepted`）**不得**映射成安装成功。
     *
     * 这是本波最重要的一条回归：历史上 `Accepted → Committed → code=0/需重启`，
     * 一旦补上 switchId 就会变成"谎报安装成功"。
     */
    @Test
    fun acceptedWithoutCommitIsStagedNotCommitted() {
        val commit = KsuCandidateCommitPort { _, _ -> KsuCommitResult.Accepted }
        val runner = KsuImageFixtures.FakeBootPatchRunner(KsuImageFixtures.ksuImage())
        val result = producer(runner, commit, switchSession = { "switch-uuid-2" })
            .installBoot(source(), KsuBootPatchOptions())
        assertFalse("Accepted must never map to Committed", result is KsuInstallResult.Committed)
        assertTrue("expected Staged, got $result", result is KsuInstallResult.Staged)
        assertEquals(
            KsuInstallProducer.COMMIT_NOT_CONFIRMED_CODE,
            (result as KsuInstallResult.Staged).code,
        )
    }

    @Test
    fun recoveryRequiredIsNotSuccess() {
        val commit = KsuCandidateCommitPort { _, _ ->
            KsuCommitResult.RecoveryRequired("SWITCH_ROLLBACK_FAILED", "init_boot", "switch-uuid-3")
        }
        val runner = KsuImageFixtures.FakeBootPatchRunner(KsuImageFixtures.ksuImage())
        val result = producer(runner, commit, switchSession = { "switch-uuid-3" })
            .installBoot(source(), KsuBootPatchOptions())
        assertFalse(result is KsuInstallResult.Committed)
        assertTrue("expected NeedsRecovery, got $result", result is KsuInstallResult.NeedsRecovery)
        assertEquals("switch-uuid-3", (result as KsuInstallResult.NeedsRecovery).switchId)
    }

    @Test
    fun installBootPropagatesCommitFailureAndDoesNotPretendSuccess() {
        val commit = KsuCandidateCommitPort { _, _ ->
            KsuCommitResult.Failed("SWITCH_SUBMIT_FAILED", "service not ready", rolledBack = true)
        }
        val runner = KsuImageFixtures.FakeBootPatchRunner(KsuImageFixtures.ksuImage())
        val result = producer(runner, commit, switchSession = { "switch-uuid-2" })
            .installBoot(source(), KsuBootPatchOptions())
        assertTrue("expected Failed, got $result", result is KsuInstallResult.Failed)
        assertEquals("SWITCH_SUBMIT_FAILED", (result as KsuInstallResult.Failed).code)
        assertTrue(result.rolledBack)
    }

    @Test
    fun stagingIsContentAddressedAndStable() {
        val runner = KsuImageFixtures.FakeBootPatchRunner(KsuImageFixtures.ksuImage())
        val producer = producer(runner)
        val first = producer.installBoot(source(), KsuBootPatchOptions()) as KsuInstallResult.Staged
        val second = producer.installBoot(source(), KsuBootPatchOptions()) as KsuInstallResult.Staged
        assertEquals(first.candidate.sha256, second.candidate.sha256)
        assertEquals(
            File(workRoot, "staged/${first.candidate.sha256}.img").absolutePath,
            File(workRoot, "staged/${second.candidate.sha256}.img").absolutePath,
        )
        assertNotEquals(
            first.candidate.candidate.absolutePath,
            File(workRoot, "staged/${first.candidate.sha256}.img").absolutePath,
        )
    }
}
