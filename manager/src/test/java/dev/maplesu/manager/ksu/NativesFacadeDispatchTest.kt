// SPDX-License-Identifier: GPL-3.0-or-later
package dev.maplesu.manager.ksu

import com.maplesu.core.Natives
import com.maplesu.core.Natives.Profile
import dev.maplesu.manager.runtime.MapleSuRuntime
import java.io.File
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 门面分派合同。
 *
 * 三个不变量，每条都有独立断言：
 * 1. **LITE 逐字节等价**：LITE 分支的返回值与改动前表达式完全一致；且一次都不请求 KSU 端口。
 * 2. **KSU 全量路由**：每个成员都路由到 KSU 端口（不是只改了几个高频成员）。
 * 3. **未判定阻断**：返回无能力默认值，不碰 Lite 探测、不碰 JNI（端口请求数 = 0）。
 */
class NativesFacadeDispatchTest {

    private class RecordingPort(
        private val versionValue: Int = 32650,
        private val manager: Boolean = true,
    ) : NativesFacadePort {
        val calls = mutableListOf<String>()
        override val version: Int get() = versionValue.also { calls += "version" }
        override val isSafeMode: Boolean get() = true.also { calls += "isSafeMode" }
        override val isLkmMode: Boolean get() = true.also { calls += "isLkmMode" }
        override val isLkmBundled: Boolean get() = true.also { calls += "isLkmBundled" }
        override val isLateLoadMode: Boolean get() = true.also { calls += "isLateLoadMode" }
        override val isManager: Boolean get() = manager.also { calls += "isManager" }
        override val isPrBuild: Boolean get() = true.also { calls += "isPrBuild" }
        override val kernelUAPIVersion: Int get() = 7.also { calls += "kernelUAPIVersion" }
        override val managerUAPIVersion: Int get() = 7.also { calls += "managerUAPIVersion" }
        override fun uidShouldUmount(uid: Int): Boolean = true.also { calls += "uidShouldUmount" }
        override fun appLockState(): Int = 2.also { calls += "appLockState" }
        override fun appLockAuth(hash: ByteArray): Boolean = true.also { calls += "appLockAuth" }
        override fun appLockSet(hash: ByteArray, disable: Boolean): Boolean =
            true.also { calls += "appLockSet" }
        override fun stealthState(): Int = 1.also { calls += "stealthState" }
        override fun stealthSet(enabled: Boolean): Boolean = true.also { calls += "stealthSet" }
        override fun getAppProfile(key: String?, uid: Int): Profile =
            Profile(key ?: "ksu", uid, allowSu = true).also { calls += "getAppProfile" }
        override fun setAppProfile(profile: Profile?): Boolean = true.also { calls += "setAppProfile" }
        override fun isSuEnabled(): Boolean = true.also { calls += "isSuEnabled" }
        override fun setSuEnabled(enabled: Boolean): Boolean = true.also { calls += "setSuEnabled" }
        override fun isKernelUmountEnabled(): Boolean = true.also { calls += "isKernelUmountEnabled" }
        override fun setKernelUmountEnabled(enabled: Boolean): Boolean =
            true.also { calls += "setKernelUmountEnabled" }
        override fun isSelinuxHideEnabled(): Boolean = true.also { calls += "isSelinuxHideEnabled" }
        override fun setSelinuxHideEnabled(enabled: Boolean): Int =
            0.also { calls += "setSelinuxHideEnabled" }
        override fun getUserName(uid: Int): String? = "ksu-user".also { calls += "getUserName" }
        override fun getSuperuserCount(): Int = 3.also { calls += "getSuperuserCount" }
        override fun setDefaultUmountModules(enabled: Boolean): Boolean =
            true.also { calls += "setDefaultUmountModules" }
        override fun isDefaultUmountModules(): Boolean =
            true.also { calls += "isDefaultUmountModules" }
        override fun isFullFeatured(): Boolean = true.also { calls += "isFullFeatured" }
    }

    private class ThrowingPort : NativesFacadePort {
        private fun boom(): Nothing = throw AssertionError("KSU port must not be touched")
        override val version: Int get() = boom()
        override val isSafeMode: Boolean get() = boom()
        override val isLkmMode: Boolean get() = boom()
        override val isLkmBundled: Boolean get() = boom()
        override val isLateLoadMode: Boolean get() = boom()
        override val isManager: Boolean get() = boom()
        override val isPrBuild: Boolean get() = boom()
        override val kernelUAPIVersion: Int get() = boom()
        override val managerUAPIVersion: Int get() = boom()
        override fun uidShouldUmount(uid: Int): Boolean = boom()
        override fun appLockState(): Int = boom()
        override fun appLockAuth(hash: ByteArray): Boolean = boom()
        override fun appLockSet(hash: ByteArray, disable: Boolean): Boolean = boom()
        override fun stealthState(): Int = boom()
        override fun stealthSet(enabled: Boolean): Boolean = boom()
        override fun getAppProfile(key: String?, uid: Int): Profile = boom()
        override fun setAppProfile(profile: Profile?): Boolean = boom()
        override fun isSuEnabled(): Boolean = boom()
        override fun setSuEnabled(enabled: Boolean): Boolean = boom()
        override fun isKernelUmountEnabled(): Boolean = boom()
        override fun setKernelUmountEnabled(enabled: Boolean): Boolean = boom()
        override fun isSelinuxHideEnabled(): Boolean = boom()
        override fun setSelinuxHideEnabled(enabled: Boolean): Int = boom()
        override fun getUserName(uid: Int): String? = boom()
        override fun getSuperuserCount(): Int = boom()
        override fun setDefaultUmountModules(enabled: Boolean): Boolean = boom()
        override fun isDefaultUmountModules(): Boolean = boom()
        override fun isFullFeatured(): Boolean = boom()
    }

    @After
    fun resetFacade() {
        NativesFacade.resetForTest()
    }

    // Lite authority needs the Application; the host dispatch test deliberately has none.
    private fun <T> withoutApplication(call: () -> T): T? = try {
        call()
    } catch (error: UninitializedPropertyAccessException) {
        assertTrue(error.message.orEmpty().contains("ksuApp"))
        null
    }

    private fun callEveryMember() {
        Natives.MINIMAL_SUPPORTED_KERNEL
        Natives.KERNEL_SU_DOMAIN
        Natives.version
        Natives.isSafeMode
        Natives.isLkmMode
        Natives.isLkmBundled
        Natives.isLateLoadMode
        Natives.isManager
        Natives.isPrBuild
        Natives.kernelUAPIVersion
        Natives.managerUAPIVersion
        Natives.uidShouldUmount(10000)
        Natives.appLockState()
        Natives.appLockAuth(ByteArray(32))
        Natives.appLockSet(ByteArray(32), false)
        Natives.stealthState()
        Natives.stealthSet(true)
        Natives.getAppProfile("pkg", 10000)
        Natives.setAppProfile(Profile("pkg"))
        withoutApplication { Natives.isSuEnabled() }
        withoutApplication { Natives.setSuEnabled(true) }
        Natives.isKernelUmountEnabled()
        Natives.setKernelUmountEnabled(true)
        Natives.isSelinuxHideEnabled()
        Natives.setSelinuxHideEnabled(true)
        Natives.getUserName(10000)
        withoutApplication { Natives.getSuperuserCount() }
        Natives.setDefaultUmountModules(true)
        Natives.isDefaultUmountModules()
        Natives.isFullFeatured()
    }

    @Test
    fun targetIsBlockedWhenUnresolved() {
        NativesFacade.resetForTest()
        assertEquals(NativesFacadeTarget.BLOCKED, NativesFacade.target())
    }

    @Test
    fun targetFollowsExplicitMode() {
        NativesFacade.installForTest(target = NativesFacadeTarget.LITE)
        assertEquals(NativesFacadeTarget.LITE, NativesFacade.target())
        NativesFacade.installForTest(target = NativesFacadeTarget.KSU)
        assertEquals(NativesFacadeTarget.KSU, NativesFacade.target())
        NativesFacade.installForTest(target = NativesFacadeTarget.BLOCKED)
        assertEquals(NativesFacadeTarget.BLOCKED, NativesFacade.target())
    }

    @Test
    fun unresolvedReturnsNoCapabilityDefaults() {
        NativesFacade.installForTest(target = NativesFacadeTarget.BLOCKED)
        assertEquals(1, Natives.MINIMAL_SUPPORTED_KERNEL)
        assertEquals("", Natives.KERNEL_SU_DOMAIN)
        assertEquals(-1, Natives.version)
        assertFalse(Natives.isManager)
        assertEquals(-1, Natives.kernelUAPIVersion)
        assertEquals(-1, Natives.managerUAPIVersion)
        assertEquals(-1, Natives.stealthState())
        assertEquals(-1, Natives.appLockState())
        assertEquals(-1, Natives.getSuperuserCount())
        assertEquals(-1, Natives.setSelinuxHideEnabled(true))
        assertFalse(Natives.setSuEnabled(true))
        assertFalse(Natives.isFullFeatured())
        assertTrue(Natives.isDefaultUmountModules())
        assertNull(Natives.getUserName(10000))
        val profile = Natives.getAppProfile("pkg", 10000)
        assertNotNull(profile)
        assertEquals("pkg", profile!!.name)
        assertEquals(10000, profile.currentUid)
        assertFalse(profile.allowSu)
    }

    @Test
    fun unresolvedNeverRequestsKsuPort() {
        NativesFacade.installForTest(target = NativesFacadeTarget.BLOCKED, ksuPort = ThrowingPort())
        callEveryMember()
        assertEquals(
            "unresolved must not dispatch to the KSU backend",
            0,
            NativesFacade.ksuPortRequests(),
        )
    }

    @Test
    fun litePreservesOriginalExpressions() {
        // 主机 JVM 里 Lite 的探测必然失败（ksuApp 未初始化）→ 原表达式的确定值：
        //   version/kernelUAPIVersion = -1、isManager = false、managerUAPIVersion = MapleSuRuntime.API_VERSION。
        NativesFacade.installForTest(target = NativesFacadeTarget.LITE)
        assertEquals(MapleSuRuntime.API_VERSION, Natives.MINIMAL_SUPPORTED_KERNEL)
        assertEquals("", Natives.KERNEL_SU_DOMAIN)
        assertEquals(-1, Natives.version)
        assertFalse(Natives.isManager)
        assertFalse(Natives.isSafeMode)
        assertFalse(Natives.isLkmMode)
        assertFalse(Natives.isLkmBundled)
        assertFalse(Natives.isLateLoadMode)
        assertFalse(Natives.isPrBuild)
        assertEquals(-1, Natives.kernelUAPIVersion)
        assertEquals(MapleSuRuntime.API_VERSION, Natives.managerUAPIVersion)
        assertFalse(Natives.uidShouldUmount(10000))
        assertEquals(-1, Natives.appLockState())
        assertFalse(Natives.appLockAuth(ByteArray(32)))
        assertFalse(Natives.appLockSet(ByteArray(32), true))
        assertEquals(-1, Natives.stealthState())
        assertFalse(Natives.stealthSet(true))
        assertNull(withoutApplication { Natives.isSuEnabled() })
        assertNull(withoutApplication { Natives.setSuEnabled(true) })
        assertFalse(Natives.isKernelUmountEnabled())
        assertFalse(Natives.setKernelUmountEnabled(true))
        assertFalse(Natives.isSelinuxHideEnabled())
        assertEquals(-1, Natives.setSelinuxHideEnabled(true))
        assertNull(Natives.getUserName(10000))
        assertNull(withoutApplication { Natives.getSuperuserCount() })
        assertFalse(Natives.setDefaultUmountModules(true))
        assertFalse(Natives.isDefaultUmountModules())
        assertFalse(Natives.isFullFeatured())
        // getAppProfile 的 Lite 原实现依赖 Context：JVM 下 runCatching 吞掉后为 null，
        // 这本身就是"原表达式"在该环境下的结果（设备值由仪器测试覆盖）。
        assertNull(Natives.getAppProfile("pkg", 10000))
    }

    @Test
    fun liteNeverRequestsKsuPort() {
        NativesFacade.installForTest(target = NativesFacadeTarget.LITE, ksuPort = ThrowingPort())
        callEveryMember()
        assertEquals(
            "LITE must not load/dispatch to the KSU backend (R5)",
            0,
            NativesFacade.ksuPortRequests(),
        )
    }

    @Test
    fun ksuRoutesEveryMember() {
        val port = RecordingPort()
        NativesFacade.installForTest(target = NativesFacadeTarget.KSU, ksuPort = port)
        callEveryMember()
        val expected = setOf(
            "version", "isSafeMode", "isLkmMode", "isLkmBundled", "isLateLoadMode", "isManager",
            "isPrBuild", "kernelUAPIVersion", "managerUAPIVersion", "uidShouldUmount",
            "appLockState", "appLockAuth", "appLockSet", "stealthState", "stealthSet",
            "getAppProfile", "setAppProfile", "isSuEnabled", "setSuEnabled",
            "isKernelUmountEnabled", "setKernelUmountEnabled", "isSelinuxHideEnabled",
            "setSelinuxHideEnabled", "getUserName", "getSuperuserCount",
            "setDefaultUmountModules", "isDefaultUmountModules", "isFullFeatured",
        )
        assertEquals(expected, port.calls.toSet())
    }

    @Test
    fun ksuReturnsBackendValuesNotLiteConstants() {
        NativesFacade.installForTest(target = NativesFacadeTarget.KSU, ksuPort = RecordingPort())
        assertEquals(32650, Natives.version)
        assertTrue(Natives.isManager)
        assertEquals(7, Natives.kernelUAPIVersion)
        assertEquals(7, Natives.managerUAPIVersion)
        assertEquals(2, Natives.appLockState())
        assertEquals(1, Natives.stealthState())
        assertEquals(3, Natives.getSuperuserCount())
        assertEquals(0, Natives.setSelinuxHideEnabled(true))
        assertEquals("ksu-user", Natives.getUserName(10000))
        assertTrue(Natives.isFullFeatured())
        // 审计要求：这两个旧 FQN 保持 const 静态字段（LITE 字节语义不变），
        // KSU 分支的对应值只经 NativesFacade 访问器/Profile 默认值暴露。
        assertEquals(MapleSuRuntime.API_VERSION, Natives.MINIMAL_SUPPORTED_KERNEL)
        assertEquals("", Natives.KERNEL_SU_DOMAIN)
        assertEquals("u:r:ksu:s0", Profile("pkg").context)
    }

    @Test
    fun profileDefaultContextFollowsMode() {
        NativesFacade.installForTest(target = NativesFacadeTarget.KSU, ksuPort = RecordingPort())
        assertEquals("u:r:ksu:s0", Profile("pkg").context)
        NativesFacade.installForTest(target = NativesFacadeTarget.LITE)
        assertEquals("", Profile("pkg").context)
    }

    @Test
    fun liteDispatchIsObservedForEveryCallAndNeverTouchesKsu() {
        // 行为契约（替代旧的源码字面断言；重构/聚合后源码文本不构成契约）：
        // 1) LITE 下每个公开成员都**真的经过**门面分派（不是绕开门面的旧实现快照）；
        // 2) 所有分派结论都是 LITE，没有任何一次落到 KSU/BLOCKED；
        // 3) KSU 端口一次都没有被请求 —— LITE 仍走原实现且不加载 KSU so（R5）。
        NativesFacade.installForTest(target = NativesFacadeTarget.LITE, ksuPort = ThrowingPort())
        val observed = mutableListOf<NativesFacadeTarget>()
        NativesFacade.observer = { observed += it }
        callEveryMember()
        assertTrue("expected >= 30 dispatches, got ${observed.size}", observed.size >= 30)
        assertEquals(setOf(NativesFacadeTarget.LITE), observed.toSet())
        assertEquals(0, NativesFacade.ksuPortRequests())
    }

    @Test
    fun ksuConstantsMatchAppliedUpstreamSource() {
        // 常量出处：third_party/kernelsu/applied/.../Natives.kt（上游 pin 528bafc + 补丁树）。
        assertEquals(32513, NativesFacade.KSU_MINIMAL_SUPPORTED_KERNEL)
        assertEquals("u:r:ksu:s0", NativesFacade.KSU_KERNEL_SU_DOMAIN)
        val appliedNatives = File(
            KsuTestPaths.applied(),
            "manager/app/src/main/java/me/weishu/kernelsu/Natives.kt",
        )
        assertTrue("applied upstream Natives.kt missing: ${appliedNatives.path}", appliedNatives.isFile)
        val text = appliedNatives.readText()
        assertTrue(
            "applied MINIMAL_SUPPORTED_KERNEL drifted from 32513",
            text.contains("MINIMAL_SUPPORTED_KERNEL = 32513"),
        )
        assertTrue(
            "applied KERNEL_SU_DOMAIN drifted",
            text.contains("KERNEL_SU_DOMAIN = \"u:r:ksu:s0\""),
        )
    }

    @Test
    fun explicitLiteInstallIsAllowedWhenModeUnresolved() {
        // 审计要求：installBoot 是用户在安装页的**显式动作**，未判定不能一律 BLOCKED，
        // 否则 Lite 自装失效。契约 = 显式意图得到 LITE（→ 继续原 Lite 实现体，该体未改），
        // 而同一时刻静默意图仍是 BLOCKED（没有全局翻转、没有默认 Lite）。
        NativesFacade.resetForTest() // 未判定（无 mode override）
        assertEquals(
            "explicit install must continue the original Lite implementation",
            NativesFacadeTarget.LITE,
            KsuInstallDispatch.targetForExplicitInstall(),
        )
        assertEquals(
            "silent tasks at the same instant must stay blocked",
            NativesFacadeTarget.BLOCKED,
            NativesFacade.target(),
        )
        assertTrue(NativesFacade.explicitLiteEscalations() >= 1)
        // 显式放行不等于"当作 Lite 已激活"：门面成员仍返回未判定默认值，KSU 端口零请求。
        assertEquals(-1, Natives.version)
        assertFalse(Natives.isManager)
        assertEquals(0, NativesFacade.ksuPortRequests())
    }

    @Test
    fun silentTasksRemainBlockedWhenModeUnresolved() {
        // 静默后台任务（开机服务/自检/自动部署）走默认 IMPLICIT：未判定 → BLOCKED，
        // 且不触碰 Lite 探测与 KSU 后端。
        NativesFacade.resetForTest()
        val observed = mutableListOf<NativesFacadeTarget>()
        NativesFacade.observer = { observed += it }
        callEveryMember()
        assertTrue("expected >= 30 dispatches, got ${observed.size}", observed.size >= 30)
        assertEquals(setOf(NativesFacadeTarget.BLOCKED), observed.toSet())
        assertEquals(0, NativesFacade.explicitLiteEscalations())
        assertEquals(0, NativesFacade.ksuPortRequests())
    }
}
