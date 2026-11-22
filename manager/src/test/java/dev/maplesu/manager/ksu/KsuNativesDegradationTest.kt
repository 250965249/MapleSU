// SPDX-License-Identifier: GPL-3.0-or-later
package dev.maplesu.manager.ksu

import com.maplesu.core.Natives.Profile
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * native 缺失时的安全降级。
 *
 * 在纯 JVM 单测里 `System.loadLibrary("maplesu_ksu")` 必然失败：这正是要证明的场景——
 * 任何 KSU 后端入口都不得抛异常、不得 crash，只能返回无能力默认值 + 一条日志。
 */
class KsuNativesDegradationTest {

    @Before
    fun resetLoader() {
        KsuNativeLoader.installForTest(null)
        KsuLog.clear()
    }

    @After
    fun cleanup() {
        KsuNativeLoader.installForTest(null)
    }

    @Test
    fun loaderMarksUnavailableAndRemembersError() {
        assertFalse(KsuNativeLoader.ensureLoaded())
        assertEquals(KsuNativeLoader.State.UNAVAILABLE, KsuNativeLoader.state)
        assertTrue(KsuNativeLoader.lastError?.contains("UnsatisfiedLinkError") == true)
    }

    @Test
    fun allGettersDegradeWithoutNative() {
        assertEquals(-1, KsuNativeCalls.version)
        assertFalse(KsuNativeCalls.isManager)
        assertFalse(KsuNativeCalls.isLkmMode)
        assertEquals(-1, KsuNativeCalls.kernelUAPIVersion)
        assertEquals(-1, KsuNativeCalls.managerUAPIVersion)
        assertEquals(-1, KsuNativeCalls.stealthState())
        assertEquals(-1, KsuNativeCalls.appLockState())
        assertEquals(-1, KsuNativeCalls.getSuperuserCount())
        assertEquals(-1, KsuNativeCalls.setSelinuxHideEnabled(true))
        assertFalse(KsuNativeCalls.setSuEnabled(true))
        assertFalse(KsuNativeCalls.stealthSet(true))
        assertFalse(KsuNativeCalls.appLockAuth(ByteArray(32)))
        assertNull(KsuNativeCalls.getAppProfile("pkg", 10000))
        assertFalse(KsuNativeCalls.setAppProfile(Profile("pkg")))
        assertNull(KsuNativeCalls.getUserName(10000))
    }

    @Test
    fun backendUnavailableReturnsDefaultsNotExceptions() {
        val backend = KsuNativesBackend.unavailable("native missing")
        assertFalse(backend.available)
        assertEquals(-1, backend.version)
        assertFalse(backend.isManager)
        assertFalse(backend.isFullFeatured())
        assertEquals(-1, backend.getSuperuserCount())
        assertFalse(backend.setDefaultUmountModules(true))
        assertTrue("7K semantics: default umount = true on failure", backend.isDefaultUmountModules())
        assertNull(backend.getAppProfile("pkg", 1))
    }

    @Test
    fun unavailableIsLogged() {
        KsuLog.clear()
        KsuNativesBackend.unavailable("boom")
        assertTrue(KsuLog.snapshot().any { it.contains("ksu.unavailable") && it.contains("boom") })
    }

    @Test
    fun unavailableSuperuserAdapterNeverWrites() {
        val adapter = UnavailableKsuSuperuserAdapter("no native")
        assertFalse(adapter.available())
        assertEquals(0, adapter.count())
        assertNull(adapter.getProfile("pkg", 10000))
        assertFalse(adapter.setAllow("pkg", 10000, true))
        // Windows 的 File.path 用 '\'；比较规范化的 POSIX 形式，不硬编码分隔符
        assertEquals(
            "/data/adb/ksu/.allowlist",
            adapter.allowListFile().invariantSeparatorsPath,
        )
    }

    @Test
    fun simulatedLoadedLibraryStillDegradesOnMissingSymbol() {
        // 模拟「so 加载成功但符号缺失/结构错误」：loader 成功，raw external 仍会抛
        KsuNativeLoader.installForTest { _ -> /* pretend load succeeded */ }
        assertTrue(KsuNativeLoader.ensureLoaded())
        assertEquals(KsuNativeLoader.State.LOADED, KsuNativeLoader.state)
        // 任何 raw external 调用都会 UnsatisfiedLinkError → 安全层必须吞掉
        assertEquals(-1, KsuNativeCalls.version)
        assertFalse(KsuNativeCalls.isManager)
        assertTrue(KsuLog.snapshot().any { it.contains("ksu.native-error") })
    }

    @Test
    fun wiredBackendsSafelyDegrade() {
        val set = KsuBackends.wireUnavailable("test")
        assertFalse(set.isReady())
        assertTrue(runCatching { set.modules.listJson() }.exceptionOrNull() is KsuModuleListException)
        assertFalse(set.modules.toggle("m", true))
        assertFalse(set.settingsFeature.set(KsuFeature.SULOG, true))
        assertEquals(KsuFeature.STATUS_UNKNOWN, set.settingsFeature.status(KsuFeature.SULOG))
        assertNull(set.settingsFeature.value(KsuFeature.SULOG))
        assertEquals(RamdiskState.UNKNOWN, set.bootInfo.ramdiskState(null))
        assertNull(set.bootInfo.kernelInfo())
    }
}
