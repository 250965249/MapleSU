// SPDX-License-Identifier: GPL-3.0-or-later
package dev.maplesu.manager.installer

import dev.maplesu.manager.ksu.KsuImageFixtures
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * Normal（KSU / LKM）的**内核系列匹配 + 目标分区**契约（用户口径 2026-11-01）。
 *
 * 三件事在这里被机器证明：
 * 1. KMI 只按「内核 `major.minor` + `androidN`」匹配 —— `6.6.50` 与 `6.6.89` 是同一个 KMI，
 *    patch 段/构建号/后缀从不参与；解析不出的串一律 fail-closed；
 * 2. 绝不跨 KMI 顶替 —— 目录里只有别的 KMI 的 `.ko` 时报"缺产物"，矩阵外报"矩阵外"，
 *    两种失败都点名**设备自己那份**资产，不会悄悄换成邻居；
 * 3. Normal 的目标分区可以是 `init_boot` **或** `boot`；两种目标下 LKM 补丁都只准改
 *    ramdisk —— `boot` 目标的候选 kernel 段必须与源镜像逐字节相同。
 */
class KsuNormalKmiSeriesTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private var sequence = 0

    // ── 1) 六个内核系列：按系列匹配，不按 release ─────────────────────────────

    @Test
    fun sixSeriesMatchBySeriesNotByRelease() {
        // 六个系列都应命中自己的 KMI 和嵌入产物。
        val cases = listOf(
            "6.6.50-android15-8-4k-g46a034eca005" to "android15-6.6",
            "6.6.89-android15-8-g7e1f3c083cc6-abogki467167594-4k" to "android15-6.6",
            "6.1.60-android14-11-gabcdef012345" to "android14-6.1",
            "6.12.30-android16-6-gdeadbeef1234" to "android16-6.12",
            "6.18.21-android17-5-gabcdef" to "android17-6.18",
            "5.15.99-android13-5.15.99_r00-00002-gabcdef" to "android13-5.15",
            "5.10.77-android12-9-00001-g1234567890ab" to "android12-5.10",
        )
        cases.forEach { (release, expected) ->
            val detection = KsuKmiDetector.detect(release)
            assertTrue("${detection.code}: ${detection.detail}", detection.ok)
            assertEquals(release, expected, detection.kmi)
            // 证据保留**真实** release（"按系列匹配"和"记录成 6.6"是两件事）。
            assertTrue(detection.evidence.contains(release))
            // 选择层必须命中同一份产物。
            val selection = KsuKmiSelector.select(detection.kmi, KsuKmiMatrix.KMIS)
            assertTrue("expected Ready for $release, got $selection", selection is KsuKmiSelection.Ready)
            assertEquals(expected, (selection as KsuKmiSelection.Ready).kmi)
            assertEquals("${expected}_kernelsu.ko", selection.artifactName)
        }
    }

    @Test
    fun patchLevelNeverChangesTheKmi() {
        // 同一系列的任意 patch 段都归同一个 KMI（1 / 50 / 89 / 100 都一样）。
        listOf("6.6.1", "6.6.50", "6.6.89", "6.6.100").forEach { release ->
            val detection = KsuKmiDetector.detect("$release-android15-8-gabcdef")
            assertTrue("$release: ${detection.code}", detection.ok)
            assertEquals("android15-6.6", detection.kmi)
            assertEquals("6.6", detection.kernelSeries)
            assertEquals(15, detection.androidMajor)
        }
        // 系列不同就必须是不同 KMI（6.1 不能落到 6.6）。
        assertEquals("android14-6.1", KsuKmiDetector.detect("6.1.166-android14-11-gab").kmi)
        assertEquals("android16-6.12", KsuKmiDetector.detect("6.12.76-android16-6-gab").kmi)
    }

    @Test
    fun android12KeepsNonDirectInstallSemantics() {
        val detection = KsuKmiDetector.detect("5.10.77-android12-9-g1234567890ab")
        assertEquals("android12-5.10", detection.kmi)
        // android12 设备没有独立 init_boot：矩阵里有产物，但语义上不是 directInstall。
        assertFalse(requireNotNull(KsuKmiMatrix.spec("android12-5.10")).directInstall)
        assertTrue(requireNotNull(KsuKmiMatrix.spec("android13-5.15")).directInstall)
        // 直装闸门（`KmiRule.supported`）对 android12-* 仍然是否定的。
        assertFalse(KmiRule.supported("android12-5.10"))
    }

    @Test
    fun seriesWithoutArtifactIsNamedExplicitly() {
        val detection = KsuKmiDetector.detect("6.18.5-android17-4-gabcdef")
        assertTrue(detection.ok)
        assertEquals("android17-6.18", detection.kmi)
        assertEquals("6.18", detection.kernelSeries)
        assertEquals(17, detection.androidMajor)
        assertTrue(KmiRule.supported(requireNotNull(detection.kmi)))
        val selection = KsuKmiSelector.select(detection.kmi, KsuKmiMatrix.KMIS.filter { it != detection.kmi })
        assertTrue(selection is KsuKmiSelection.Missing)
        val missing = selection as KsuKmiSelection.Missing
        assertEquals(KsuKmiSelector.CODE_ARTIFACT_MISSING, missing.code)
        assertTrue(missing.detail, missing.detail.contains("android17-6.18_kernelsu.ko"))
    }

    @Test
    fun kmiRuleParsesAndroid13() {
        assertEquals("android13-5.10", KmiRule.parse("5.10.198-android13-8-test"))
        assertEquals("android14-6.1", KmiRule.parse("6.1.25-android14-11-gabcdef"))
    }

    @Test
    fun kmiRuleRejectsAndroid12AndMalformed() {
        assertTrue(!KmiRule.supported("android12-5.10"))
        assertTrue(KmiRule.supported("android13-5.10"))
        assertTrue(!KmiRule.supported("5.10.198"))
        assertEquals(null, KmiRule.parse("no-android-here"))
    }

    // ── 2) 异常输入：各自明确、fail-closed ───────────────────────────────────

    @Test
    fun anomalousReleasesFailClosed() {
        // 空串 / 格式串 / 只有主版本 / 缺 patch 段 / 缺 androidN 标记 / 纯文本。
        val cases = listOf("", "   ", "%s", "6", "6.6", "6.6.89", "android15", "garbage", "v6.6.1")
        cases.forEach { release ->
            val detection = KsuKmiDetector.detect(release)
            assertFalse("expected failure for '$release'", detection.ok)
            assertEquals("'$release' must be unparseable", KsuKmiDetection.CODE_UNPARSEABLE, detection.code)
            assertNull("'$release' must not yield a KMI", detection.kmi)
            assertTrue(detection.detail.isNotEmpty())
            // 解析不出 → 选择层也绝不能给出一份 .ko。
            assertTrue(KsuKmiSelector.select(detection.kmi, KsuKmiMatrix.KMIS) is KsuKmiSelection.Missing)
        }
        // 只有主版本 / 缺 patch 段的串在**系列前缀**上也会被拒（不是"猜一个 6.6"）。
        assertNull(KsuKmiDetector.parseKernelRelease("6"))
        assertNull(KsuKmiDetector.parseKernelRelease("6.6"))
        // 有 patch 段但缺 androidN → 系列能取到，KMI 仍然判定不出来（没有第二个坐标）。
        assertNull(KsuKmiDetector.parseKernelRelease("6.6.89"))
        // 6.6 系列 + 合法的 androidN 才成立。
        assertEquals("6.6" to 15, KsuKmiDetector.parseKernelRelease("6.6.89-android15-8-gab"))
    }

    // ── 3) 绝不跨 KMI 顶替 ──────────────────────────────────────────────────

    @Test
    fun neverSubstitutesAnotherKmi() {
        val devices = listOf(
            "6.6.89-android15-8-gab" to "android15-6.6",
            "6.1.60-android14-11-gab" to "android14-6.1",
            "6.12.30-android16-6-gab" to "android16-6.12",
            "6.18.21-android17-5-gab" to "android17-6.18",
            "5.15.99-android13-8-gab" to "android13-5.15",
            "5.10.77-android12-9-gab" to "android12-5.10",
        )
        devices.forEach { (release, kmi) ->
            val deviceKmi = requireNotNull(KsuKmiDetector.detect(release).kmi)
            // 目录里"只有别人的 .ko"：必须报缺产物，点名设备自己那份资产。
            val others = KsuKmiMatrix.KMIS.filter { it != deviceKmi }
            val selection = KsuKmiSelector.select(deviceKmi, others)
            assertTrue("expected Missing, got $selection", selection is KsuKmiSelection.Missing)
            val missing = selection as KsuKmiSelection.Missing
            assertEquals(KsuKmiSelector.CODE_ARTIFACT_MISSING, missing.code)
            assertTrue(missing.detail, missing.detail.contains("${deviceKmi}_kernelsu.ko"))
            // 每一份"别的 KMI"都被原样列在目录里 —— 没有一个被当成替代品 Ready。
            others.forEach { other ->
                assertFalse(
                    "detail must not claim $other was selected",
                    missing.detail.contains("selected $other"),
                )
            }
            assertEquals(kmi, deviceKmi)
        }

        // 最直白的一条：目录里只有 6.12 的 .ko，设备要 6.6 → 拒绝（绝不 Ready）。
        val mismatch = KsuKmiSelector.select("android15-6.6", setOf("android16-6.12"))
        assertTrue(mismatch is KsuKmiSelection.Missing)
        assertEquals(
            KsuKmiSelector.CODE_ARTIFACT_MISSING,
            (mismatch as KsuKmiSelection.Missing).code,
        )

        // 未构建的 android15-5.15 不映射到相邻版本。
        val outOfMatrix = KsuKmiSelector.select("android15-5.15", KsuKmiMatrix.KMIS)
        assertTrue(outOfMatrix is KsuKmiSelection.Missing)
        assertEquals(
            KsuKmiSelector.CODE_NOT_IN_MATRIX,
            (outOfMatrix as KsuKmiSelection.Missing).code,
        )

        // 旧装配未上报目录 → Unknown，期望资产名仍是设备 KMI 自己的（不是任何邻居）。
        val unknown = KsuKmiSelector.select("android17-6.18", null)
        assertTrue(unknown is KsuKmiSelection.Unknown)
        assertEquals("android17-6.18_kernelsu.ko", (unknown as KsuKmiSelection.Unknown).artifactName)
    }

    @Test
    fun matrixAuditFindsNoContradiction() {
        val violations = KsuKmiMatrix.audit()
        assertTrue("matrix audit violations: $violations", violations.isEmpty())
    }

    // ── 4) Normal 的目标分区：init_boot 或 boot ────────────────────────────

    @Test
    fun normalAcceptsInitBootOrBootOnly() {
        assertTrue(KsuInstallProducerDefaults.isTarget("init_boot"))
        assertTrue(KsuInstallProducerDefaults.isTarget("boot"))
        assertTrue(KsuInstallProducerDefaults.isTarget(" BOOT "))
        assertFalse(KsuInstallProducerDefaults.isTarget("vendor_boot"))
        assertFalse(KsuInstallProducerDefaults.isTarget("initboot"))
        assertFalse(KsuInstallProducerDefaults.isTarget(""))
        assertFalse(KsuInstallProducerDefaults.isTarget(null))
        assertEquals("init_boot", KsuInstallProducerDefaults.PARTITION)
        assertEquals("boot", KsuInstallProducerDefaults.BOOT_PARTITION)
        assertEquals(setOf("init_boot", "boot"), KsuInstallProducerDefaults.TARGETS)
        assertEquals("boot", KsuInstallProducerDefaults.normalize(" Boot "))
        assertNull(KsuInstallProducerDefaults.normalize("system"))
    }

    @Test
    fun initBootTargetRejectsImagesThatCarryAKernel() {
        // init_boot 镜像里没有 kernel 段：候选带了 kernel 段 = 拿错分区。
        val ksuRamdisk = KsuImageFixtures.ksuRamdisk(withMaplesuId = true)
        val stockRamdisk = KsuImageFixtures.stockRamdisk()
        val withKernel = imageFile("candidate-with-kernel.img",
            bootImage(kernel = ByteArray(2048) { 0x41 }, ramdisk = ksuRamdisk))
        val source = imageFile("source-init_boot.img", bootImage(ByteArray(0), stockRamdisk))

        val verdict = KsuKernelPreservation.check("init_boot", source, withKernel)
        assertTrue(verdict is KsuKernelPreservation.Verdict.Rejected)
        assertEquals(
            KsuKernelPreservation.CODE_KERNEL_UNEXPECTED,
            (verdict as KsuKernelPreservation.Verdict.Rejected).code,
        )
        // 源镜像带 kernel 段（选了 boot 镜像当 init_boot 源）同样拒绝。
        val wrongSource = KsuKernelPreservation.check(
            "init_boot",
            imageFile("source-boot.img", bootImage(ByteArray(4096) { 0x42 }, stockRamdisk)),
            imageFile("candidate-init_boot.img", bootImage(ByteArray(0), ksuRamdisk)),
        )
        assertEquals(
            KsuKernelPreservation.CODE_SOURCE_KERNEL_UNEXPECTED,
            (wrongSource as KsuKernelPreservation.Verdict.Rejected).code,
        )
        // 裸 ramdisk 组件（没有 ANDROID! magic）合法：它本身就没有 kernel 段。
        val bare = imageFile("bare-ramdisk.img", ksuRamdisk)
        assertEquals(
            KsuKernelPreservation.Verdict.Ok,
            KsuKernelPreservation.check("init_boot", null, bare),
        )
    }

    @Test
    fun bootTargetRequiresAByteIdenticalKernel() {
        val kernel = ByteArray(8192) { (it * 31 and 0xFF).toByte() }
        val ramdisk = KsuImageFixtures.ksuRamdisk(withMaplesuId = true)
        val source = imageFile("boot-source.img", bootImage(kernel, KsuImageFixtures.stockRamdisk()))
        // 补丁只改 ramdisk：kernel 段逐字节相同。
        val sameKernel = imageFile("boot-candidate.img", bootImage(kernel, ramdisk))
        assertEquals(
            KsuKernelPreservation.Verdict.Ok,
            KsuKernelPreservation.check("boot", source, sameKernel),
        )
        // kernel 改了 1 个字节 → 拒绝（这就是"改内核"）。
        val mutated = kernel.copyOf().also { it[100] = (it[100] + 1).toByte() }
        val changedKernel = imageFile("boot-candidate-mutated.img", bootImage(mutated, ramdisk))
        val rejected = KsuKernelPreservation.check("boot", source, changedKernel)
        assertEquals(
            KsuKernelPreservation.CODE_KERNEL_CHANGED,
            (rejected as KsuKernelPreservation.Verdict.Rejected).code,
        )
        // kernel 段长度都变了（被替换成另一份内核）→ 拒绝。
        val otherKernel = imageFile(
            "boot-candidate-other.img",
            bootImage(ByteArray(16384) { 0x55 }, ramdisk),
        )
        assertEquals(
            KsuKernelPreservation.CODE_KERNEL_CHANGED,
            (KsuKernelPreservation.check("boot", source, otherKernel)
                as KsuKernelPreservation.Verdict.Rejected).code,
        )
        // 没有源镜像就无法证明 kernel 未变 → fail-closed（不是"放行"）。
        assertEquals(
            KsuKernelPreservation.CODE_KERNEL_UNVERIFIED,
            (KsuKernelPreservation.check("boot", null, sameKernel)
                as KsuKernelPreservation.Verdict.Rejected).code,
        )
        // 裸 ramdisk 当 boot 候选 → 不是 boot 容器 → 同样无法证明。
        assertEquals(
            KsuKernelPreservation.CODE_KERNEL_UNVERIFIED,
            (KsuKernelPreservation.check("boot", source, imageFile("bare.img", ramdisk))
                as KsuKernelPreservation.Verdict.Rejected).code,
        )
    }

    @Test
    fun verifierAcceptsBothNormalTargetsAndStillGatesTheKernel() {
        val verifier = RamdiskCandidateVerifier()
        val kernel = ByteArray(4096) { 0x7e }
        val ramdisk = KsuImageFixtures.ksuRamdisk(withMaplesuId = true)

        // init_boot：普通 boot v4（kernel_size=0）+ KSU LKM ramdisk → Ok。
        val initBoot = imageFile("init_boot-ok.img", bootImage(ByteArray(0), ramdisk))
        val initBootOk = verifier.verify(
            artifact(initBoot, partition = "init_boot"),
            KsuCandidateExpectation(partition = "init_boot", partitionSize = initBoot.length()),
        )
        assertTrue("expected Ok, got $initBootOk", initBootOk is KsuVerifyOutcome.Ok)

        // boot：kernel 段与源镜像一致 → Ok（目标分区 boot 不再是"不支持"）。
        val source = imageFile("boot-src.img", bootImage(kernel, KsuImageFixtures.stockRamdisk()))
        val bootCandidate = imageFile("boot-ok.img", bootImage(kernel, ramdisk))
        val bootOk = verifier.verify(
            artifact(bootCandidate, partition = "boot", source = source),
            KsuCandidateExpectation(partition = "boot", partitionSize = bootCandidate.length()),
        )
        assertTrue("expected Ok for boot, got $bootOk", bootOk is KsuVerifyOutcome.Ok)

        // boot：kernel 被改 → 拒绝（第二层判定也断这一点，不只靠 producer 自述）。
        val mutated = kernel.copyOf().also { it[7] = (it[7] + 1).toByte() }
        val bootChanged = imageFile("boot-bad.img", bootImage(mutated, ramdisk))
        val rejected = verifier.verify(
            artifact(bootChanged, partition = "boot", source = source),
            KsuCandidateExpectation(partition = "boot", partitionSize = bootChanged.length()),
        )
        assertEquals(
            KsuKernelPreservation.CODE_KERNEL_CHANGED,
            (rejected as KsuVerifyOutcome.Rejected).code,
        )

        // boot：没有源镜像 → 无法证明 kernel 未变 → 拒绝。
        val unverified = verifier.verify(
            artifact(bootCandidate, partition = "boot", source = null),
            KsuCandidateExpectation(partition = "boot", partitionSize = bootCandidate.length()),
        )
        assertEquals(
            KsuKernelPreservation.CODE_KERNEL_UNVERIFIED,
            (unverified as KsuVerifyOutcome.Rejected).code,
        )
    }

    // ── helpers ────────────────────────────────────────────────────────────

    private fun artifact(
        candidate: File,
        partition: String,
        source: File? = null,
    ): KsuProducedArtifact = KsuProducedArtifact(
        candidate = candidate,
        size = candidate.length(),
        sha256 = sha256(candidate.readBytes()),
        partition = partition,
        form = null,
        ramdiskState = null,
        sourceSha256 = source?.let { sha256(it.readBytes()) } ?: "0".repeat(64),
        kernelsuKoSha256 = null,
        source = source,
    )

    private fun imageFile(name: String, bytes: ByteArray): File {
        val root = File(tmp.root, "img-${sequence++}").apply { mkdirs() }
        return File(root, name).apply { writeBytes(bytes) }
    }

    private fun sha256(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes)
            .joinToString("") { "%02x".format(it.toInt() and 0xFF) }

    /** 对齐后的 AOSP boot v4 容器；`kernel` 为空 = init_boot 形态（kernel_size=0）。 */
    private fun bootImage(kernel: ByteArray, ramdisk: ByteArray): ByteArray {
        val page = 4096
        val ramdiskOffset = page + alignUp(kernel.size, page)
        val total = alignUp(ramdiskOffset + ramdisk.size, page)
        val image = ByteArray(total)
        val header = ByteBuffer.wrap(image).order(ByteOrder.LITTLE_ENDIAN)
        header.put("ANDROID!".toByteArray(Charsets.US_ASCII))
        header.putInt(8, kernel.size) // kernel_size
        header.putInt(12, ramdisk.size) // ramdisk_size
        header.putInt(20, 1584) // header_size (v4)
        header.putInt(40, 4) // header_version
        System.arraycopy(kernel, 0, image, page, kernel.size)
        System.arraycopy(ramdisk, 0, image, ramdiskOffset, ramdisk.size)
        return image
    }

    private fun alignUp(value: Int, page: Int): Int = (value + page - 1) / page * page
}
