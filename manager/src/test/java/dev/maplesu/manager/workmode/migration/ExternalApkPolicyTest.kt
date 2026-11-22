package dev.maplesu.manager.workmode.migration

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** 05 §5.6 / 红线 12：外部 APK 卸载只在 M9 后、且绝不碰自身包名。 */
class ExternalApkPolicyTest {

    private val detected = setOf("me.weishu.kernelsu")
    private val onDevice = setOf("me.weishu.kernelsu", "com.example.app")

    @Test
    fun uninstallBeforeVerifiedIsRejected() {
        val plan = ExternalApkPolicy.plan(
            requested = listOf("me.weishu.kernelsu"),
            detected = detected,
            selfPackages = setOf(MigrationPaths.SELF_PACKAGE),
            onDevice = onDevice,
            verifiedState = false,
        )
        assertTrue(plan.selected.isEmpty())
        assertEquals(MigrationCodes.APK_UNINSTALL_BEFORE_VERIFIED, plan.error)
    }

    @Test
    fun selfPackageAlwaysRefusesWholeRequest() {
        val plan = ExternalApkPolicy.plan(
            requested = listOf("me.weishu.kernelsu", MigrationPaths.SELF_PACKAGE),
            detected = detected,
            selfPackages = setOf(MigrationPaths.SELF_PACKAGE),
            onDevice = onDevice,
            verifiedState = true,
        )
        assertEquals(MigrationCodes.SELF_UNINSTALL_REFUSED, plan.error)
        assertTrue(plan.selected.isEmpty())
    }

    @Test
    fun onlyDetectedAndInstalledPackagesAreSelected() {
        val plan = ExternalApkPolicy.plan(
            requested = listOf("me.weishu.kernelsu", "com.not.detected", "com.example.app", "me.weishu.kernelsu"),
            detected = detected,
            selfPackages = setOf(MigrationPaths.SELF_PACKAGE),
            onDevice = onDevice,
            verifiedState = true,
        )
        assertEquals(listOf("me.weishu.kernelsu"), plan.selected)
        assertTrue(plan.skipped.contains("com.not.detected"))
        assertTrue(plan.skipped.contains("com.example.app"))
        assertEquals("", plan.error)
    }

    @Test
    fun uninstallerOnlyCallsPmForSelectedPackages() {
        val calls = mutableListOf<String>()
        val uninstaller = ExternalPackageUninstaller(
            pm = { packageName ->
                calls += packageName
                0
            },
        )
        val plan = ExternalApkPolicy.plan(
            requested = listOf("me.weishu.kernelsu"),
            detected = detected,
            selfPackages = setOf(MigrationPaths.SELF_PACKAGE),
            onDevice = onDevice,
            verifiedState = true,
        )
        val results = uninstaller.uninstall(plan)
        assertEquals(listOf("me.weishu.kernelsu"), calls)
        assertTrue(results.single().ok)
    }

    @Test
    fun failedPmCallIsReportedNotRetried() {
        val uninstaller = ExternalPackageUninstaller(pm = { 1 })
        val plan = ApkUninstallPlan(selected = listOf("me.weishu.kernelsu"), skipped = emptyList())
        val results = uninstaller.uninstall(plan)
        assertFalse(results.single().ok)
        assertEquals(1, results.single().exitCode)
    }

    @Test
    fun erroredPlanNeverReachesPm() {
        var called = false
        val uninstaller = ExternalPackageUninstaller(pm = { called = true; 0 })
        val results = uninstaller.uninstall(
            ApkUninstallPlan(selected = listOf("me.weishu.kernelsu"), skipped = emptyList(), error = "X"),
        )
        assertTrue(results.isEmpty())
        assertFalse(called)
    }
}
