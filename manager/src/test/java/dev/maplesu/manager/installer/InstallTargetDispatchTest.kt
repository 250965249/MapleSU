// SPDX-License-Identifier: GPL-3.0-or-later
package dev.maplesu.manager.installer

import dev.maplesu.manager.workmode.WorkMode
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 目标模式 → 修补路径的分派（纯函数）契约。
 *
 * 重点：Normal 的 **fail-closed**（KMI 矩阵外 / 缺 `kernelsu.ko`）与"绝不静默回退 Ultra"。
 */
class InstallTargetDispatchTest {

    private val android15Release = "6.6.127-android15-8-4k-g46a034eca005"
    private val android14Release = "6.1.166-android14-11-g1234567890ab"

    private fun request(
        target: InstallTargetMode,
        source: InstallSourceKind = InstallSourceKind.CURRENT_PARTITION,
        kernelRelease: String? = android15Release,
        availableKmis: Collection<String>? = KsuKmiMatrix.KMIS,
        partition: String? = null,
        sdkInt: Int = 35,
    ) = InstallTargetRequest(
        target = target,
        source = source,
        partition = partition,
        kernelRelease = kernelRelease,
        availableKmis = availableKmis,
        sdkInt = sdkInt,
    )

    private fun assertBlocked(
        decision: InstallTargetDecision,
        code: String,
        blocker: InstallTargetBlocker,
    ): InstallTargetDecision.Blocked {
        assertTrue("expected Blocked, got $decision", decision is InstallTargetDecision.Blocked)
        val blocked = decision as InstallTargetDecision.Blocked
        assertEquals(code, blocked.code)
        assertEquals(blocker, blocked.blocker)
        assertEquals(InstallTargetMode.NORMAL, blocked.target)
        return blocked
    }

    // ------------------------------------------------------------------ Ultra

    @Test
    fun ultraKeepsTheUltraKernelChainAndNeverBlocks() {
        val decision = InstallTargetDispatch.decide(request(InstallTargetMode.ULTRA))
        assertTrue(decision is InstallTargetDecision.Ready)
        val ready = decision as InstallTargetDecision.Ready
        assertEquals(InstallTargetMode.ULTRA, ready.target)
        assertEquals(InstallPatchPath.ULTRA_ULTRA_KERNEL, ready.path)
        assertEquals(WorkMode.LITE, ready.workMode)
        // Ultra 的分区由管线固定（`InstallPartitionPolicy.ULTRA_FIXED`），用户不能改。
        assertEquals(InstallPartitionPolicy.ULTRA_FIXED.wire, ready.partition)
        assertEquals("boot", ready.partition)
        assertEquals(null, ready.kmi)
        assertEquals(null, ready.kmiArtifact)
    }

    @Test
    fun ultraIsNotAffectedByAnUnknownDeviceKernel() {
        // Ultra 的 release 资产/门禁由 UltraKernelFlow 自己裁决（含 ULTRA_KERNEL_RELEASE_UNSUPPORTED），
        // 分派层不额外拦截，否则会改变既有 Ultra 语义。
        val decision = InstallTargetDispatch.decide(
            request(InstallTargetMode.ULTRA, kernelRelease = null, availableKmis = null, sdkInt = 0),
        )
        assertTrue(decision is InstallTargetDecision.Ready)
        assertEquals(InstallPatchPath.ULTRA_ULTRA_KERNEL, (decision as InstallTargetDecision.Ready).path)
    }

    @Test
    fun ultraRoutesExplicitInitBootWithoutClaimingBridgeAvailability() {
        val decision = InstallTargetDispatch.decide(
            request(InstallTargetMode.ULTRA, partition = "init_boot"),
        ) as InstallTargetDecision.Ready
        assertEquals(InstallTargetMode.ULTRA, decision.target)
        assertEquals("init_boot", decision.partition)
        assertEquals(InstallPatchPath.ULTRA_ULTRA_KERNEL, decision.path)

        // 白名单外的值报"不支持"。
        val unsupported = InstallTargetDispatch.decide(
            request(InstallTargetMode.ULTRA, partition = "vendor_boot"),
        ) as InstallTargetDecision.Blocked
        assertEquals(InstallPartitionPolicy.CODE_UNSUPPORTED, unsupported.code)
        assertEquals(InstallTargetBlocker.PARTITION_UNSUPPORTED, unsupported.blocker)
    }

    // ------------------------------------------------------------------ Normal：结构前提

    @Test
    fun normalDirectInstallIsAllowedBecauseThePartitionIsReadWithRoot() {
        // 用户口径：直接安装不要求先选文件 —— 源镜像由 root 从当前槽的目标分区读出来。
        val decision = InstallTargetDispatch.decide(
            request(
                InstallTargetMode.NORMAL,
                source = InstallSourceKind.CURRENT_PARTITION,
                partition = null,
            ),
        )
        assertTrue("expected Ready, got $decision", decision is InstallTargetDecision.Ready)
        val ready = decision as InstallTargetDecision.Ready
        assertEquals(InstallPatchPath.NORMAL_KSU_LKM, ready.path)
        assertEquals("init_boot", ready.partition)
    }

    @Test
    fun normalAcceptsTheDownloadedImageForItsSelectedPartition() {
        val decision = InstallTargetDispatch.decide(request(InstallTargetMode.NORMAL,
            source = InstallSourceKind.DOWNLOADED_BOOT, partition = "boot"))
        assertTrue("expected Ready, got $decision", decision is InstallTargetDecision.Ready)
        assertEquals("boot", (decision as InstallTargetDecision.Ready).partition)
    }

    @Test
    fun normalHonoursTheSelectedPartitionAndRejectsAnythingElse() {
        // 默认 → init_boot；显式选 boot → boot（修补与刷写都用它）。
        assertEquals(
            "boot",
            (InstallTargetDispatch.decide(
                request(InstallTargetMode.NORMAL, partition = "boot"),
            ) as InstallTargetDecision.Ready).partition,
        )
        assertEquals(
            "init_boot",
            (InstallTargetDispatch.decide(
                request(InstallTargetMode.NORMAL, partition = "init_boot"),
            ) as InstallTargetDecision.Ready).partition,
        )
        // 白名单外 → 明确拒绝（不猜、不静默换成默认值）。
        val blocked = assertBlocked(
            InstallTargetDispatch.decide(request(InstallTargetMode.NORMAL, partition = "vendor_boot")),
            InstallPartitionPolicy.CODE_UNSUPPORTED,
            InstallTargetBlocker.PARTITION_UNSUPPORTED,
        )
        assertTrue(blocked.detail.contains("vendor_boot"))
    }

    // ------------------------------------------------------------------ Normal：KMI/产物

    @Test
    fun normalIsReadyWhenTheKmiArtifactIsPackaged() {
        val decision = InstallTargetDispatch.decide(request(InstallTargetMode.NORMAL))
        assertTrue("expected Ready, got $decision", decision is InstallTargetDecision.Ready)
        val ready = decision as InstallTargetDecision.Ready
        assertEquals(InstallTargetMode.NORMAL, ready.target)
        assertEquals(InstallPatchPath.NORMAL_KSU_LKM, ready.path)
        assertEquals(WorkMode.KSU, ready.workMode)
        // 没选分区 → 默认 init_boot（`InstallPartitionPolicy.NORMAL_DEFAULT`）。
        assertEquals(InstallTargetRequest.NORMAL_PARTITION, "init_boot")
        assertEquals("init_boot", ready.partition)
        assertEquals("android15-6.6", ready.kmi)
        assertEquals("android15-6.6_kernelsu.ko", ready.kmiArtifact)
        assertTrue(ready.kmiCatalogKnown)
    }

    @Test
    fun normalFailsClosedWhenTheKmiArtifactIsMissing() {
        // 目录已知（本次 APK 只打包了 android15-6.6）却要装 android14-6.1 的产物 → 明确失败。
        val blocked = assertBlocked(
            InstallTargetDispatch.decide(
                request(
                    InstallTargetMode.NORMAL,
                    kernelRelease = android14Release,
                    availableKmis = setOf("android15-6.6"),
                    sdkInt = 35,
                ),
            ),
            InstallTargetCodes.KMI_ARTIFACT_MISSING,
            InstallTargetBlocker.KMI_ARTIFACT_MISSING,
        )
        assertEquals("android14-6.1", blocked.kmi)
        assertTrue(blocked.detail.contains("android14-6.1_kernelsu.ko"))
        assertTrue(blocked.detail.contains("android15-6.6"))
    }

    @Test
    fun normalFailsClosedWhenTheKmiIsOutsideTheBuiltMatrix() {
        // 未打包的组合仍报矩阵外，保留原 KMI，不选择相邻产物。
        val blocked = assertBlocked(
            InstallTargetDispatch.decide(
                request(
                    InstallTargetMode.NORMAL,
                    kernelRelease = "5.10.252-android14-4-g1234567890ab",
                    availableKmis = setOf("android14-5.10"),
                    sdkInt = 34,
                ),
            ),
            InstallTargetCodes.KMI_NOT_IN_MATRIX,
            InstallTargetBlocker.KMI_NOT_IN_MATRIX,
        )
        assertEquals("android14-5.10", blocked.kmi)
    }

    @Test
    fun addedNormalKmisReachEveryInstallSourceWithTheirOwnArtifact() {
        val cases = mapOf("5.10.252-android13-4-g1234567890ab" to "android13-5.10",
            "5.15.180-android14-8-g1234567890ab" to "android14-5.15")
        cases.forEach { (release, kmi) ->
            InstallSourceKind.entries.forEach { source ->
                listOf("boot", "init_boot").forEach { partition ->
                    val decision = InstallTargetDispatch.decide(request(InstallTargetMode.NORMAL,
                        source = source, kernelRelease = release, availableKmis = setOf(kmi),
                        partition = partition))
                    assertTrue("$source/$partition $kmi: $decision", decision is InstallTargetDecision.Ready)
                    val ready = decision as InstallTargetDecision.Ready
                    assertEquals(if (source == InstallSourceKind.CURRENT_PARTITION) kmi else null, ready.kmi)
                    assertEquals(if (source == InstallSourceKind.CURRENT_PARTITION) "${kmi}_kernelsu.ko" else null,
                        ready.kmiArtifact)
                    assertEquals(partition, ready.partition)
                }
            }
        }
    }

    @Test
    fun normalFailsClosedWhenTheKernelReleaseIsUnknown() {
        listOf(null, "", "   ").forEach { release ->
            assertBlocked(
                InstallTargetDispatch.decide(request(InstallTargetMode.NORMAL, kernelRelease = release)),
                InstallTargetCodes.KMI_UNPARSEABLE,
                InstallTargetBlocker.KMI_UNPARSEABLE,
            )
        }
        // 有 release 但没有 androidN 标记 / 版本号：同样无法判定。
        assertBlocked(
            InstallTargetDispatch.decide(request(InstallTargetMode.NORMAL, kernelRelease = "6.1.166")),
            InstallTargetCodes.KMI_UNPARSEABLE,
            InstallTargetBlocker.KMI_UNPARSEABLE,
        )
    }

    @Test
    fun normalUsesTheKernelArtifactAfterAnAndroidUpgrade() {
        // Current-partition installs keep the actual kernel KMI after an OS upgrade.
        listOf(InstallSourceKind.CURRENT_PARTITION).forEach { source ->
            listOf("init_boot", "boot").forEach { partition ->
                listOf(0, 35, 36, 37).forEach { sdk ->
                    val decision = InstallTargetDispatch.decide(request(InstallTargetMode.NORMAL,
                        source = source, kernelRelease = android14Release, partition = partition, sdkInt = sdk))
                    assertTrue("$source/$partition SDK $sdk: $decision", decision is InstallTargetDecision.Ready)
                    val ready = decision as InstallTargetDecision.Ready
                    assertEquals(InstallPatchPath.NORMAL_KSU_LKM, ready.path)
                    assertEquals(partition, ready.partition)
                    assertEquals("android14-6.1", ready.kmi)
                    assertEquals("android14-6.1_kernelsu.ko", ready.kmiArtifact)
                    assertTrue(ready.kmiCatalogKnown)
                }
            }
        }
    }

    @Test
    fun fileTargetsDoNotSelectAnArtifactFromTheRunningKernel() {
        listOf(InstallSourceKind.IMAGE, InstallSourceKind.DOWNLOADED_BOOT).forEach { source ->
            listOf(null, "garbage", "5.10.252-android14-4-gabcdef", android15Release).forEach { release ->
                val decision = InstallTargetDispatch.decide(request(InstallTargetMode.NORMAL,
                    source = source, kernelRelease = release, availableKmis = emptyList(), partition = "boot"))
                assertTrue("$source/$release: $decision", decision is InstallTargetDecision.Ready)
                val ready = decision as InstallTargetDecision.Ready
                assertEquals("boot", ready.partition)
                assertEquals(null, ready.kmi)
                assertEquals(null, ready.kmiArtifact)
                assertFalse(ready.kmiCatalogKnown)
            }
        }
    }

    @Test
    fun normalKeepsTheSelectedKmiWhenTheCatalogIsUnknown() {
        // 目录未上报（旧装配）：选中的仍是设备事实推导出的 KMI（不是猜的），
        // 产物是否存在由 ksud 的内嵌资产查找硬失败兜底 —— 仍然不会换用别的 KMI。
        val decision = InstallTargetDispatch.decide(
            request(InstallTargetMode.NORMAL, availableKmis = null),
        )
        assertTrue(decision is InstallTargetDecision.Ready)
        val ready = decision as InstallTargetDecision.Ready
        assertEquals("android15-6.6", ready.kmi)
        assertEquals("android15-6.6_kernelsu.ko", ready.kmiArtifact)
        assertFalse("目录未知 ≠ 全部都有", ready.kmiCatalogKnown)
    }

    // ------------------------------------------------------------------ 绝不回退 Ultra

    @Test
    fun normalNeverFallsBackToTheUltraPath() {
        val blockedInputs = listOf(
            request(InstallTargetMode.NORMAL, source = InstallSourceKind.CURRENT_PARTITION),
            request(InstallTargetMode.NORMAL, source = InstallSourceKind.DOWNLOADED_BOOT),
            request(InstallTargetMode.NORMAL, availableKmis = setOf("android15-6.6")),
            request(InstallTargetMode.NORMAL, kernelRelease = null),
            request(InstallTargetMode.NORMAL, kernelRelease = "5.10.252-android13-4-g1234567890ab", sdkInt = 33),
        )
        blockedInputs.forEach { input ->
            val decision = InstallTargetDispatch.decide(input)
            assertTrue("Normal 的输入必须要么 Ready(NORMAL_KSU_LKM) 要么 Blocked，实际 $decision",
                decision is InstallTargetDecision.Blocked ||
                    (decision as InstallTargetDecision.Ready).path == InstallPatchPath.NORMAL_KSU_LKM)
            assertNotEquals(
                "Normal 绝不能静默回退 Ultra",
                InstallPatchPath.ULTRA_ULTRA_KERNEL,
                (decision as? InstallTargetDecision.Ready)?.path,
            )
            assertEquals(InstallTargetMode.NORMAL, decision.target)
        }
    }

    @Test
    fun normalPartitionConstantMatchesTheKsuContract() {
        // 与 KsuInstallPolicy.ALLOWED_PARTITION / KsuInstallProducer.ALLOWED_PARTITION /
        // KsuInstallProducerDefaults.PARTITION（KsuModeInstallContract.kt）同值。
        // 这里只钉字面量：那几个常量依赖 installer-core，不在本纯 JVM 测试的编译面内。
        assertEquals("init_boot", InstallTargetRequest.NORMAL_PARTITION)
        assertEquals(setOf("init_boot", "boot"), InstallTargetRequest.ALLOWED_PARTITIONS)
        // 没选分区时 Normal 的 Ready 必须落在默认 init_boot。
        val ready = InstallTargetDispatch.decide(request(InstallTargetMode.NORMAL)) as InstallTargetDecision.Ready
        assertEquals("init_boot", ready.partition)
    }
}
