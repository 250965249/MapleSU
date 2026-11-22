// SPDX-License-Identifier: GPL-3.0-or-later
package dev.maplesu.manager.workmode.storage

import dev.maplesu.manager.modules.LiteModuleModePolicy
import dev.maplesu.manager.modules.ModuleTree
import dev.maplesu.manager.workmode.WorkMode
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Standard executable layout is shared; catalog and configuration remain mode-scoped. */
class ModeModuleRootIsolationTest {

    private val filesDir = "/data/user/0/dev.maplesu.manager/files"

    @Test
    fun compatibleExecutableRootsUseTheStandardKsuLayout() {
        val lite = ModePaths.moduleRoot(WorkMode.LITE, filesDir)
        val ksu = ModePaths.moduleRoot(WorkMode.KSU, filesDir)
        assertNotNull(lite)
        assertNotNull(ksu)
        assertEquals(ModePaths.ModuleOwner.LITE, lite!!.owner)
        assertEquals(ModePaths.ModuleOwner.KSU, ksu!!.owner)
        assertEquals("/data/adb/modules", lite.path)
        assertEquals("/data/adb/modules", ksu.path)
        assertTrue(lite.sharedWithOtherMode)
        assertTrue(ksu.sharedWithOtherMode)
        assertEquals(lite.path, ksu.path)
    }

    @Test
    fun unresolvedModeHasNoModuleRoot() {
        assertNull(ModePaths.moduleRoot(null, filesDir))
        // 未判定 = 两个方向都不允许读（绝不默认 LITE）
        assertFalse(ModePaths.allowsModulePath(null, "/data/adb/modules/x", filesDir))
        assertFalse(ModePaths.allowsModulePath(null, "$filesDir/module-runtime/x", filesDir))
    }

    @Test
    fun ultraMayReadTheStandardTreeAndItsPrivateCatalog() {
        assertTrue(ModePaths.allowsModulePath(WorkMode.LITE, "/data/adb/modules", filesDir))
        assertTrue(ModePaths.allowsModulePath(WorkMode.LITE, "/data/adb/modules/demo", filesDir))
        assertTrue(ModePaths.allowsModulePath(WorkMode.LITE, "$filesDir/module-runtime", filesDir))
        assertTrue(
            ModePaths.allowsModulePath(WorkMode.LITE, "$filesDir/module-runtime/revisions/demo", filesDir),
        )
        assertTrue(ModePaths.allowsModulePath(WorkMode.LITE, "$filesDir/module-catalog", filesDir))
    }

    @Test
    fun ksuMustNotReadTheLiteTree() {
        assertFalse(
            ModePaths.allowsModulePath(WorkMode.KSU, "$filesDir/module-runtime/revisions/demo", filesDir),
        )
        assertFalse(ModePaths.allowsModulePath(WorkMode.KSU, "$filesDir/module-catalog", filesDir))
        assertTrue(ModePaths.allowsModulePath(WorkMode.KSU, "/data/adb/modules", filesDir))
        assertTrue(ModePaths.allowsModulePath(WorkMode.KSU, "/data/adb/modules/demo", filesDir))
    }

    @Test
    fun prefixSiblingIsNotTreatedAsTheModuleRoot() {
        // "…/module-runtime-old" 不是 "…/module-runtime" 的子路径。
        assertFalse(
            ModePaths.allowsModulePath(WorkMode.LITE, "$filesDir/module-runtime-old/x", filesDir),
        )
        assertFalse(ModePaths.allowsModulePath(WorkMode.KSU, "/data/adb/modules-old/x", filesDir))
    }

    @Test
    fun moduleTreePublishIsLiteOnly() {
        assertTrue(ModuleTree.allowsPublish(WorkMode.LITE))
        // Normal 的 /data/adb/modules 是 ksud 的树：Ultra 不得往里发布软链。
        assertFalse(ModuleTree.allowsPublish(WorkMode.KSU))
        assertFalse("未判定绝不默认 LITE", ModuleTree.allowsPublish(null))
        // 单一事实来源：两边必须是同一个路径常量。
        assertEquals(ModePaths.KSU_MODULE_ROOT, ModuleTree.ROOT)
    }

    @Test
    fun liteModuleBootIsLiteOnly() {
        assertTrue(LiteModuleModePolicy.allowsRun(WorkMode.LITE))
        assertFalse(LiteModuleModePolicy.allowsRun(WorkMode.KSU))
        assertFalse("未判定绝不默认 LITE", LiteModuleModePolicy.allowsRun(null))
        assertNull(LiteModuleModePolicy.rejectionReason(WorkMode.LITE))
        assertTrue(LiteModuleModePolicy.rejectionReason(WorkMode.KSU)!!.contains("MODE_KSU"))
        assertTrue(LiteModuleModePolicy.rejectionReason(null)!!.contains("MODE_UNRESOLVED"))
    }

    @Test
    fun moduleRootIsAlsoPartitionedOnDiskForPrefsAndFiles() {
        // 配置层面同样分开（既有语义，回归保护）：B 用 _B 后缀 + filesDir/ksu。
        assertEquals("settings_B", ModePaths.prefsNameFor("settings", WorkMode.KSU))
        assertEquals("settings", ModePaths.prefsNameFor("settings", WorkMode.LITE))
        assertEquals("ksu/module-catalog", ModePaths.filesSubdir("module-catalog", WorkMode.KSU))
        assertEquals("module-catalog", ModePaths.filesSubdir("module-catalog", WorkMode.LITE))
    }
}
