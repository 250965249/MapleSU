package dev.maplesu.manager.workmode.switch

import dev.maplesu.manager.workmode.WorkMode
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 目标分区解析（安装页分区选择 / 切换事务共用）：
 * - Ultra 固定 boot；
 * - Normal 默认 init_boot，允许显式 boot（KernelSU `--partition`）；
 * - 写序：目标与源相同只写一次（KSU 装到 boot 时不再"还原 boot"）。
 */
class ModeSwitchTargetPartitionTest {

    @Test
    fun ultraAllowsExplicitCarriersAndKeepsAutomaticBoot() {
        assertEquals(setOf("boot", "init_boot"), ModeSwitchPreflight.allowedTargets(WorkMode.LITE))
        assertEquals("boot", ModeSwitchPreflight.resolveTarget(WorkMode.LITE, null))
        assertEquals("boot", ModeSwitchPreflight.resolveTarget(WorkMode.LITE, "boot"))
        assertEquals("init_boot", ModeSwitchPreflight.resolveTarget(WorkMode.LITE, "init_boot"))
    }

    @Test
    fun normalDefaultsToInitBootAndAllowsBoot() {
        assertEquals(setOf("init_boot", "boot"), ModeSwitchPreflight.allowedTargets(WorkMode.KSU))
        assertEquals("init_boot", ModeSwitchPreflight.resolveTarget(WorkMode.KSU, null))
        assertEquals("init_boot", ModeSwitchPreflight.resolveTarget(WorkMode.KSU, ""))
        assertEquals("boot", ModeSwitchPreflight.resolveTarget(WorkMode.KSU, "boot"))
        assertNull(ModeSwitchPreflight.resolveTarget(WorkMode.KSU, "vendor_boot"))
    }

    @Test
    fun writeOrderDependsOnResolvedTarget() {
        // KSU 默认写 init_boot：先还原 Ultra 的 boot，再写 init_boot。
        assertEquals(listOf("init_boot", "boot"), ModeSwitchPreflight.writeOrder(WorkMode.KSU))
        // KSU 显式写 boot：boot 就是目标，只写一次（不先还原再覆盖）。
        assertEquals(listOf("boot"), ModeSwitchPreflight.writeOrder(WorkMode.KSU, "boot"))
        // 回到 Ultra：先还原 KSU 的 init_boot，再写 boot。
        assertEquals(listOf("init_boot", "boot"), ModeSwitchPreflight.writeOrder(WorkMode.LITE, "boot"))
        assertEquals(listOf("init_boot"), ModeSwitchPreflight.writeOrder(WorkMode.LITE, "init_boot", "init_boot"))
    }

    @Test
    fun actualSourceControlsTheWriteSetInBothDirections() {
        assertEquals(listOf("boot"), ModeSwitchPreflight.writeOrder(WorkMode.LITE, "boot", "boot"))
        assertEquals(listOf("init_boot", "boot"),
            ModeSwitchPreflight.writeOrder(WorkMode.LITE, "boot", "init_boot"))
        assertEquals(listOf("boot"),
            ModeSwitchPreflight.writeOrder(WorkMode.LITE, "boot", "", setOf("boot")))
        assertEquals("boot", ModeSwitchPreflight.resolveTarget(WorkMode.KSU, null, setOf("boot")))
        assertEquals("boot", ModeSwitchPreflight.resolveTarget(WorkMode.KSU, null,
            setOf("boot", "init_boot"), "android12-5.10"))
        assertEquals("boot", ModeSwitchPreflight.resolveTarget(WorkMode.KSU, "boot",
            setOf("boot", "init_boot"), "android15-6.6"))
    }
}
