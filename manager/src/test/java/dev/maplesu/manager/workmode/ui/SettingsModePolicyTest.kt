package dev.maplesu.manager.workmode.ui

import dev.maplesu.manager.workmode.WorkMode
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 设置页模式矩阵（2026-10-31 可见项独立性）。
 *
 * 纯 JVM：只依赖 [SettingsModePolicy] 与 `WorkMode`，不触碰 Android/Compose。
 */
class SettingsModePolicyTest {

    private val ultra = SettingsModePolicy.forMode(WorkMode.LITE)
    private val normal = SettingsModePolicy.forMode(WorkMode.KSU)
    private val unresolved = SettingsModePolicy.forMode(null)

    @Test
    fun ultraIsCommonPlusUltraOnly() {
        assertEquals(
            SettingsModePolicy.COMMON_SECTIONS + SettingsModePolicy.ULTRA_ONLY_SECTIONS,
            ultra.sections,
        )
        assertEquals(
            SettingsModePolicy.COMMON_ROWS + SettingsModePolicy.ULTRA_ONLY_ROWS,
            ultra.rows,
        )
        assertTrue(ultra.resolved)
        assertEquals(WorkMode.LITE, ultra.mode)
    }

    @Test
    fun normalIsCommonPlusNormalOnly() {
        assertEquals(
            SettingsModePolicy.COMMON_SECTIONS + SettingsModePolicy.NORMAL_ONLY_SECTIONS,
            normal.sections,
        )
        assertEquals(
            SettingsModePolicy.COMMON_ROWS + SettingsModePolicy.NORMAL_ONLY_ROWS,
            normal.rows,
        )
        assertTrue(normal.resolved)
        assertEquals(WorkMode.KSU, normal.mode)
    }

    @Test
    fun intersectionOfBothModesIsExactlyCommon() {
        assertEquals(SettingsModePolicy.COMMON_SECTIONS, ultra.sections intersect normal.sections)
        assertEquals(SettingsModePolicy.COMMON_ROWS, ultra.rows intersect normal.rows)
    }

    @Test
    fun bothModesHaveNonEmptyExclusiveSets() {
        assertTrue(SettingsModePolicy.ULTRA_ONLY_SECTIONS.isNotEmpty())
        assertTrue(SettingsModePolicy.NORMAL_ONLY_SECTIONS.isNotEmpty())
        assertTrue(SettingsModePolicy.ULTRA_ONLY_ROWS.isNotEmpty())
        assertTrue(SettingsModePolicy.NORMAL_ONLY_ROWS.isNotEmpty())
        assertTrue((ultra.sections - normal.sections).isNotEmpty())
        assertTrue((normal.sections - ultra.sections).isNotEmpty())
        assertTrue((ultra.rows - normal.rows).isNotEmpty())
        assertTrue((normal.rows - ultra.rows).isNotEmpty())
        // 两模式的独占集合互不相交（同一行不可能既 A 又 B）。
        assertTrue(SettingsModePolicy.ULTRA_ONLY_ROWS.intersect(SettingsModePolicy.NORMAL_ONLY_ROWS).isEmpty())
    }

    @Test
    fun noModeSpecificRowIsInCommon() {
        assertTrue(
            SettingsModePolicy.COMMON_ROWS
                .intersect(SettingsModePolicy.ULTRA_ONLY_ROWS + SettingsModePolicy.NORMAL_ONLY_ROWS)
                .isEmpty(),
        )
    }

    @Test
    fun unresolvedShowsOnlyCommonRows() {
        assertFalse(unresolved.resolved)
        assertEquals(SettingsModePolicy.COMMON_SECTIONS, unresolved.sections)
        assertEquals(SettingsModePolicy.COMMON_ROWS, unresolved.rows)
        // 未判定：只允许通用项，任何模式专属读取都必须被拒绝。
        assertTrue(unresolved.dataSources.isEmpty())
        SettingsModePolicy.ULTRA_ONLY_ROWS.forEach { assertFalse(unresolved.shows(it)) }
        SettingsModePolicy.NORMAL_ONLY_ROWS.forEach { assertFalse(unresolved.shows(it)) }
        SettingsModePolicy.ULTRA_ONLY_SECTIONS.forEach { assertFalse(unresolved.shows(it)) }
        SettingsModePolicy.NORMAL_ONLY_SECTIONS.forEach { assertFalse(unresolved.shows(it)) }
    }

    @Test
    fun ultraHasNoKsuStealthOrKsuRows() {
        // 用户要求：Ultra 下不得出现任何 KSU stealth / 隐身 / KSU 专属行。
        listOf(
            SettingsSection.KSU_FEATURES,
            SettingsSection.KSU_STEALTH,
            SettingsSection.KSU_APP_LOCK,
            SettingsSection.KSU_WEB_ADMIN,
            SettingsSection.KSU_APP_PROFILE,
            SettingsSection.KSU_KERNEL_MODE,
            SettingsSection.SU_COMPAT,
        ).forEach { assertFalse("Ultra 不得显示 $it", ultra.shows(it)) }

        listOf(
            SettingsRow.KSU_STEALTH,
            SettingsRow.KSU_APP_LOCK,
            SettingsRow.KSU_WEB_ADMIN,
            SettingsRow.SELINUX_HIDE,
            SettingsRow.KERNEL_UMOUNT,
            SettingsRow.SULOG,
            SettingsRow.ADB_ROOT,
            SettingsRow.SHELL_SU_ADB_ONLY,
            SettingsRow.UMOUNT_MODULES_DEFAULT,
            SettingsRow.SU_COMPAT,
            SettingsRow.KSU_APP_PROFILE,
            SettingsRow.KSU_KERNEL_MODE,
        ).forEach { assertFalse("Ultra 不得显示 $it", ultra.shows(it)) }

        // 更关键：不是"隐藏"，而是根本不允许读取。
        listOf(
            SettingsDataSource.KSU_FEATURES,
            SettingsDataSource.KSU_STEALTH,
            SettingsDataSource.KSU_APP_LOCK,
            SettingsDataSource.KSU_WEB_ADMIN,
            SettingsDataSource.SU_COMPAT,
            SettingsDataSource.KSU_KERNEL_MODE,
        ).forEach { assertFalse("Ultra 不得读取 $it", ultra.mayRead(it)) }
    }

    @Test
    fun normalHasNoUltraOrUltraHiddenRows() {
        // 用户要求：Normal 下不得出现 Ultra 环境 / Ultra 修补 / 寄生入口。
        assertFalse(normal.shows(SettingsSection.ULTRA_ULTRA_ENV))
        assertFalse(normal.shows(SettingsSection.ULTRA_HIDDEN))
        assertFalse(normal.shows(SettingsRow.ULTRA_ENVIRONMENT))
        assertFalse(normal.shows(SettingsRow.LITE_HIDDEN))
        assertFalse("Normal 不得读取 Ultra 环境", normal.mayRead(SettingsDataSource.ULTRA_ENVIRONMENT))
        assertFalse("Normal 不得读取 Lite 隐藏", normal.mayRead(SettingsDataSource.LITE_HIDDEN))
    }

    @Test
    fun onlyUltraReadsUltraEnvironmentAndLiteHidden() {
        assertTrue(ultra.mayRead(SettingsDataSource.ULTRA_ENVIRONMENT))
        assertTrue(ultra.mayRead(SettingsDataSource.LITE_HIDDEN))
        assertTrue(SettingsDataSource.ULTRA_ENVIRONMENT in ultra.dataSources)
        assertTrue(SettingsDataSource.LITE_HIDDEN in ultra.dataSources)
    }

    @Test
    fun normalReadsEveryNormalDataSource() {
        listOf(
            SettingsDataSource.KSU_FEATURES,
            SettingsDataSource.KSU_STEALTH,
            SettingsDataSource.KSU_APP_LOCK,
            SettingsDataSource.KSU_WEB_ADMIN,
            SettingsDataSource.SU_COMPAT,
            SettingsDataSource.KSU_KERNEL_MODE,
        ).forEach { assertTrue("Normal 应允许读取 $it", normal.mayRead(it)) }
    }

    @Test
    fun commonSectionsHaveNoModeSpecificDataReads() {
        // 通用 section 不允许携带任何模式专属数据源（防止"通用行偷偷读 KSU/Ultra"）。
        SettingsModePolicy.COMMON_SECTIONS.forEach { section ->
            assertTrue(
                "通用 section $section 不得带模式专属读取：${settingsDataSourcesOf(section)}",
                settingsDataSourcesOf(section).isEmpty(),
            )
        }
    }

    @Test
    fun everySectionMapsToAtLeastOneRowAndEveryRowIsReachable() {
        SettingsSection.entries.forEach { section ->
            assertTrue("$section 没有行", settingsRowsOf(section).isNotEmpty())
        }
        val allMapped = SettingsSection.entries.flatMap { settingsRowsOf(it) }.toSet()
        SettingsRow.entries.forEach { row ->
            assertTrue("$row 未被任何 section 覆盖", row in allMapped)
        }
    }

    @Test
    fun sectionAndRowSetsAreStableAcrossCalls() {
        assertEquals(ultra, SettingsModePolicy.forMode(WorkMode.LITE))
        assertEquals(normal, SettingsModePolicy.forMode(WorkMode.KSU))
        assertEquals(unresolved, SettingsModePolicy.forMode(null))
        assertNotEquals(ultra, normal)
    }

    @Test
    fun onlyExplicitOnIsReportedAsOn() {
        // 明确 ON：operable && enabled。
        assertEquals(
            SettingsStatus.ON,
            settingsStatusOf(BFeatureCard(show = true, operable = true, enabled = true)),
        )
        // 明确 OFF。
        assertEquals(
            SettingsStatus.OFF,
            settingsStatusOf(BFeatureCard(show = true, operable = true, enabled = false)),
        )
        // 读失败 / 内核不支持：即便某个字段被写成 true，也不得报 ON。
        assertEquals(
            SettingsStatus.UNKNOWN,
            settingsStatusOf(BFeatureCard(show = true, operable = false, enabled = false, reasonCode = BFeatureReasons.KERNEL_UNREADABLE)),
        )
        assertEquals(
            SettingsStatus.UNKNOWN,
            settingsStatusOf(BFeatureCard(show = true, operable = false, enabled = true)),
        )
        SettingsStatus.entries.forEach { status ->
            if (status != SettingsStatus.ON) {
                assertNotEquals(
                    "只有明确 ON 才允许映射到 settings_status_on",
                    com.maplesu.core.R.string.settings_status_on,
                    SettingsStatusCopy.statusRes(status),
                )
            }
        }
        assertEquals(
            com.maplesu.core.R.string.settings_status_unknown,
            SettingsStatusCopy.statusRes(SettingsStatus.UNKNOWN),
        )
    }
}
