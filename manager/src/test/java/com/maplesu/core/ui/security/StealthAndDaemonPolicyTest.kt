package com.maplesu.core.ui.security

import com.maplesu.core.ui.util.KsuDaemonPolicy
import dev.maplesu.manager.workmode.ModeCapabilities
import dev.maplesu.manager.workmode.WorkMode
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File

/**
 * P1 隐藏/网页管理器接线修复的 JVM 纯策略测试。
 *
 * 覆盖：隐身密令路径（B=ksu、A=sevenk 不回归、legacy 只读回退、acceptedCodes 并集）、
 * ksud daemon 解析（B=libksud_ksu.so / 非 B=libksud.so / B 缺失不回退）、
 * `getKsuDaemonPath()` 行为未变（源码回归断言）、W18 能力位与动作接线。
 */
class StealthAndDaemonPolicyTest {

    // ── 隐身密令路径 ──────────────────────────────────────────────────────

    @Test
    fun liteKeepsSevenkStealthCodePath() {
        assertEquals("/data/adb/sevenk/stealth_code", StealthPathPolicy.primaryPath(WorkMode.LITE))
        assertEquals("/data/adb/sevenk/stealth_code", StealthPathPolicy.writePath(WorkMode.LITE))
        assertEquals("/data/adb/sevenk", StealthPathPolicy.writeDir(WorkMode.LITE))
    }

    @Test
    fun unresolvedBehavesLikeLiteNoRegression() {
        assertEquals(StealthPathPolicy.primaryPath(WorkMode.LITE), StealthPathPolicy.primaryPath(null))
        assertEquals(StealthPathPolicy.writePath(WorkMode.LITE), StealthPathPolicy.writePath(null))
        assertEquals(
            StealthPathPolicy.acceptedPaths(WorkMode.LITE),
            StealthPathPolicy.acceptedPaths(null),
        )
    }

    @Test
    fun ksuUsesKsuStealthCodePath() {
        assertEquals("/data/adb/ksu/stealth_code", StealthPathPolicy.primaryPath(WorkMode.KSU))
        assertEquals("/data/adb/ksu/stealth_code", StealthPathPolicy.writePath(WorkMode.KSU))
        assertEquals("/data/adb/ksu", StealthPathPolicy.writeDir(WorkMode.KSU))
    }

    @Test
    fun ksuReadsKsuFirstThenLegacySevenkReadOnly() {
        val paths = StealthPathPolicy.readPaths(WorkMode.KSU)
        assertEquals(listOf("/data/adb/ksu/stealth_code", "/data/adb/sevenk/stealth_code"), paths.map { it.path })
        assertTrue("ksu 主路径只读", paths[0].selfHealWriteToPrimary.not())
        assertTrue("sevenk 旧值仅只读兼容（不写回）", paths[1].selfHealWriteToPrimary.not())
    }

    @Test
    fun liteReadOrderKeepsLegacySelfHealSemantics() {
        val paths = StealthPathPolicy.readPaths(WorkMode.LITE)
        assertEquals(listOf("/data/adb/sevenk/stealth_code", "/data/adb/ksu/stealth_code"), paths.map { it.path })
        assertTrue("历史 ksu 软链读到后自愈补写 sevenk（原行为）", paths[1].selfHealWriteToPrimary)
    }

    @Test
    fun acceptedCodesUnionContainsKsuPathFirstInB() {
        val b = StealthPathPolicy.acceptedPaths(WorkMode.KSU)
        assertEquals("/data/adb/ksu/stealth_code", b.first())
        assertTrue(b.contains("/data/adb/sevenk/stealth_code"))
        val a = StealthPathPolicy.acceptedPaths(WorkMode.LITE)
        assertEquals("/data/adb/sevenk/stealth_code", a.first())
        assertTrue(a.contains("/data/adb/ksu/stealth_code"))
    }

    // ── 内核持久化隐身 flag 路径（P1 尾巴修复）──────────────────────────────

    @Test
    fun ksuPersistedFlagUsesKsuPath() {
        assertEquals("/data/adb/ksu/stealth", StealthPathPolicy.flagPrimaryPath(WorkMode.KSU))
        assertEquals("/data/adb/ksu/stealth", StealthPathPolicy.flagPaths(WorkMode.KSU).first())
    }

    @Test
    fun litePersistedFlagKeepsSevenkPath() {
        assertEquals("/data/adb/sevenk/stealth", StealthPathPolicy.flagPrimaryPath(WorkMode.LITE))
        assertEquals("/data/adb/sevenk/stealth", StealthPathPolicy.flagPaths(WorkMode.LITE).first())
    }

    @Test
    fun unresolvedPersistedFlagBehavesLikeLite() {
        assertEquals(
            StealthPathPolicy.flagPrimaryPath(WorkMode.LITE),
            StealthPathPolicy.flagPrimaryPath(null),
        )
        assertEquals(
            StealthPathPolicy.flagPaths(WorkMode.LITE),
            StealthPathPolicy.flagPaths(null),
        )
    }

    @Test
    fun ksuFlagReadOrderIsKsuThenLegacySevenk() {
        assertEquals(
            listOf("/data/adb/ksu/stealth", "/data/adb/sevenk/stealth"),
            StealthPathPolicy.flagPaths(WorkMode.KSU),
        )
        assertTrue(
            "B 下 sevenk 旧 flag 仅只读兼容",
            StealthPathPolicy.flagReadPaths(WorkMode.KSU)[1].selfHealWriteToPrimary.not(),
        )
    }

    @Test
    fun liteFlagReadOrderIsSevenkThenKsuLegacy() {
        assertEquals(
            listOf("/data/adb/sevenk/stealth", "/data/adb/ksu/stealth"),
            StealthPathPolicy.flagPaths(WorkMode.LITE),
        )
    }

    @Test
    fun stealthFlagPathConstantRemainsSevenkForSourceCompatibility() {
        // 外部引用可能直接使用该常量（A 语义）；值必须保持 sevenk（A 现状不变）。
        assertEquals("/data/adb/sevenk/stealth", Stealth.STEALTH_FLAG_PATH)
        assertEquals(StealthPathPolicy.A_FLAG_PATH, Stealth.STEALTH_FLAG_PATH)
        // 当前模式的主路径必须经策略——B 的主路径与常量不同（避免误用常量读 B）。
        assertNotEquals(Stealth.STEALTH_FLAG_PATH, StealthPathPolicy.flagPrimaryPath(WorkMode.KSU))
    }

    @Test
    fun getPersistedStealthFlagUsesModeAwarePolicy() {
        val file = File("src/main/java/com/maplesu/core/ui/util/KsuCli.kt")
        assumeTrue(file.isFile)
        val text = file.readText()
        val start = text.indexOf("internal suspend fun getPersistedStealthFlag()")
        assertTrue("getPersistedStealthFlag() 缺失", start >= 0)
        val body = text.substring(start, minOf(text.length, start + 900))
        assertTrue("必须经 StealthPathPolicy 取模式感知路径", body.contains("StealthPathPolicy.flagPaths"))
        assertTrue("不得再直接 cat STEALTH_FLAG_PATH 常量", !body.contains("cat \${Stealth.STEALTH_FLAG_PATH}"))
    }

    // ── 内核持久化 flag 路径结束 ───────────────────────────────────────────

    // ── ksud daemon 解析 ──────────────────────────────────────────────────

    @Test
    fun ksuDaemonIsLibksudKsuSo() {
        assertEquals("libksud_ksu.so", KsuDaemonPolicy.daemonName(WorkMode.KSU))
        assertEquals("/lib/libksud_ksu.so", KsuDaemonPolicy.daemonPath("/lib", WorkMode.KSU))
    }

    @Test
    fun liteAndUnresolvedKeepLibksudSo() {
        assertEquals("libksud.so", KsuDaemonPolicy.daemonName(WorkMode.LITE))
        assertEquals("libksud.so", KsuDaemonPolicy.daemonName(null))
        assertEquals("/lib/libksud.so", KsuDaemonPolicy.daemonPath("/lib", null))
    }

    @Test
    fun ksuResolveNeverFallsBackToLiteDaemon() {
        val ksuPath = "/lib/libksud_ksu.so"
        assertEquals(
            ksuPath,
            KsuDaemonPolicy.resolve(WorkMode.KSU, "/lib", "/lib/libksud.so") { it == ksuPath },
        )
        assertNull(
            "B 下 libksud_ksu.so 缺失必须显式不可用，不得回退 Lite daemon",
            KsuDaemonPolicy.resolve(WorkMode.KSU, "/lib", "/lib/libksud.so") { false },
        )
    }

    @Test
    fun liteResolveKeepsLegacyPathEvenIfUnavailable() {
        // A 的安装流程依赖 getKsuDaemonPath() 原结果；这里只断言非 B 不使用 ksu 二进制。
        assertEquals(
            "/lib/libksud.so",
            KsuDaemonPolicy.resolve(WorkMode.LITE, "/lib", "/lib/libksud.so") { false },
        )
    }

    @Test
    fun getKsuDaemonPathBehaviourIsUnchanged() {
        val file = File("src/main/java/com/maplesu/core/ui/util/KsuCli.kt")
        assumeTrue(file.isFile)
        val text = file.readText()
        val start = text.indexOf("internal fun getKsuDaemonPath()")
        assertTrue("getKsuDaemonPath() 缺失", start >= 0)
        val body = text.substring(start, minOf(text.length, start + 300))
        assertTrue("Lite 安装路径仍依赖 libksud.so", body.contains("\"libksud.so\""))
        assertTrue("不得把 getKsuDaemonPath 改成 ksu 二进制", !body.contains("libksud_ksu.so"))
    }

    // ── W18 三卡：能力位 + 动作接线 ──────────────────────────────────────

    @Test
    fun ksuCapabilitiesEnableStealthAndWebAdminWhileLiteDisables() {
        val ksu = ModeCapabilities.forMode(WorkMode.KSU)
        assertTrue("B 必须声称支持隐身", ksu.supportsStealth)
        assertTrue("B 必须声称支持网页管理器", ksu.supportsWebAdmin)
        val lite = ModeCapabilities.forMode(WorkMode.LITE)
        assertFalse("A 不支持隐身（Natives 桩）", lite.supportsStealth)
        assertFalse("A 不支持网页管理器", lite.supportsWebAdmin)
    }

    @Test
    fun w18SettingsActionsCallTheRealBackends() {
        val vm = File("src/main/java/com/maplesu/core/ui/viewmodel/SettingsViewModel.kt")
        val cli = File("src/main/java/com/maplesu/core/ui/util/WebAdminCli.kt")
        assumeTrue(vm.isFile && cli.isFile)
        val vmText = vm.readText()
        assertTrue("隐身开关必须落 Natives.stealthSet（经 Stealth.setEnabledReporting）",
            vmText.contains("Stealth.setEnabledReporting("))
        assertTrue("网页管理器开关必须落 WebAdminCli.setEnabled",
            vmText.contains("WebAdminCli.setEnabled("))
        assertTrue("WebAdminCli.run 必须经 KsuDaemonPolicy 选 daemon",
            cli.readText().contains("KsuDaemonPolicy.resolve("))
    }
}
