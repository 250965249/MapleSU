// SPDX-License-Identifier: GPL-3.0-or-later
package dev.maplesu.manager.ksu

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * KSU 安装参数策略（W12；03 §3.8.6 / D10）。
 *
 * 策略拒绝的参数：`ota`（--ota/未使用槽）、`forceBackup`（--backup）、
 * 用户 `.ko`（--kernel）、非 init_boot 分区、无源镜像。逐条断言 reason，
 * 不依赖 UI 文案。
 */
class KsuInstallPolicyTest {

    private fun evaluate(
        bootUriPresent: Boolean = true,
        kmi: String? = "android15-6.6",
        lkmIsUri: Boolean = false,
        ota: Boolean = false,
        partition: String? = "init_boot",
        allowShell: Boolean = false,
        enableAdb: Boolean = false,
        forceBackup: Boolean = false,
        blockModules: String = "",
        directInstall: Boolean = false,
    ): KsuInstallDecision = KsuInstallPolicy.evaluate(
        bootUriPresent, kmi, lkmIsUri, ota, partition, allowShell, enableAdb, forceBackup,
        blockModules, directInstall,
    )

    private fun reasonOf(decision: KsuInstallDecision): KsuInstallRejectReason {
        assertTrue("expected Rejected, got $decision", decision is KsuInstallDecision.Rejected)
        return (decision as KsuInstallDecision.Rejected).reason
    }

    @Test
    fun rejectsOtaInstall() {
        assertEquals(KsuInstallRejectReason.OTA_UNSUPPORTED, reasonOf(evaluate(ota = true)))
    }

    @Test
    fun rejectsForceBackup() {
        assertEquals(KsuInstallRejectReason.FORCE_BACKUP_UNSUPPORTED, reasonOf(evaluate(forceBackup = true)))
    }

    @Test
    fun rejectsUserSuppliedKoFile() {
        assertEquals(KsuInstallRejectReason.LKM_URI_UNSUPPORTED, reasonOf(evaluate(lkmIsUri = true)))
    }

    @Test
    fun rejectsPartitionsOutsideTheWhitelist() {
        // 白名单 = init_boot / boot（与 KernelSU 一致）。节点路径与其它分区名一律拒绝。
        assertEquals(
            KsuInstallRejectReason.PARTITION_UNSUPPORTED,
            reasonOf(evaluate(partition = "vendor_boot")),
        )
        assertEquals(
            KsuInstallRejectReason.PARTITION_UNSUPPORTED,
            reasonOf(evaluate(partition = "/dev/block/by-name/init_boot")),
        )
        assertEquals(
            KsuInstallRejectReason.PARTITION_UNSUPPORTED,
            reasonOf(evaluate(partition = "Boot")),
        )
    }

    @Test
    fun allowsBothInitBootAndBoot() {
        val initBoot = evaluate(partition = "init_boot")
        assertTrue(initBoot is KsuInstallDecision.Allowed)
        assertEquals("init_boot", (initBoot as KsuInstallDecision.Allowed).options.partition)

        val boot = evaluate(partition = "boot")
        assertTrue(boot is KsuInstallDecision.Allowed)
        assertEquals("boot", (boot as KsuInstallDecision.Allowed).options.partition)
    }

    @Test
    fun directInstallIsAllowedWithoutAnImageButOnlyWhenTheCallerDeclaresIt() {
        // 直装（不传文件）：调用方声明会去 root 提取当前分区 → 允许。
        val direct = evaluate(bootUriPresent = false, directInstall = true)
        assertTrue("expected Allowed, got $direct", direct is KsuInstallDecision.Allowed)
        assertEquals("init_boot", (direct as KsuInstallDecision.Allowed).options.partition)
        // 没声明直装 = 没有源镜像 → 仍然显式拒绝（不猜、不空跑）。
        assertEquals(
            KsuInstallRejectReason.NO_SOURCE_IMAGE,
            reasonOf(evaluate(bootUriPresent = false, directInstall = false)),
        )
    }

    @Test
    fun directInstallCanTargetBoot() {
        val direct = evaluate(bootUriPresent = false, partition = "boot", directInstall = true)
        assertTrue(direct is KsuInstallDecision.Allowed)
        assertEquals("boot", (direct as KsuInstallDecision.Allowed).options.partition)
    }

    @Test
    fun rejectsMissingSourceImage() {
        assertEquals(KsuInstallRejectReason.NO_SOURCE_IMAGE, reasonOf(evaluate(bootUriPresent = false)))
    }

    @Test
    fun rejectsInvalidBlockModuleList() {
        assertEquals(
            KsuInstallRejectReason.BLOCK_MODULES_INVALID,
            reasonOf(evaluate(blockModules = "bad-name; reboot")),
        )
        assertEquals(
            KsuInstallRejectReason.BLOCK_MODULES_INVALID,
            reasonOf(evaluate(blockModules = "a".repeat(65))),
        )
    }

    @Test
    fun allowsInitBootAndBuildsControlledOptions() {
        val decision = evaluate(
            allowShell = true,
            enableAdb = true,
            blockModules = " mod_a , mod_b ",
        )
        assertTrue(decision is KsuInstallDecision.Allowed)
        val options = (decision as KsuInstallDecision.Allowed).options
        assertEquals("init_boot", options.partition)
        assertEquals("android15-6.6", options.kmi)
        assertTrue(options.allowShell)
        assertTrue(options.enableAdb)
        assertEquals(listOf("mod_a", "mod_b"), options.blockModules)
    }

    @Test
    fun nullPartitionDefaultsToInitBoot() {
        val decision = evaluate(partition = null)
        assertTrue(decision is KsuInstallDecision.Allowed)
        assertEquals("init_boot", (decision as KsuInstallDecision.Allowed).options.partition)
    }

    @Test
    fun blockModuleValidationMatchesUiSemantics() {
        assertTrue(KsuInstallPolicy.isBlockModulesValid(""))
        assertTrue(KsuInstallPolicy.isBlockModulesValid("a,b_c,Module1"))
        assertTrue(!KsuInstallPolicy.isBlockModulesValid("a b"))
        // 单名合法但总长超过内核 256 字节缓冲（join 后 >255）必须拒绝
        val tooLong = (1..5).joinToString(",") { "a".repeat(64) }
        assertTrue(tooLong.length > 255)
        assertTrue(!KsuInstallPolicy.isBlockModulesValid(tooLong))
    }
}
