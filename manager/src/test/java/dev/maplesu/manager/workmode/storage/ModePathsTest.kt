package dev.maplesu.manager.workmode.storage

import dev.maplesu.manager.workmode.WorkMode
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** 01 §8.1 `ModePathsTest`：§3.2 每行一个断言。 */
class ModePathsTest {
    @Test
    fun prefsNameMapping() {
        assertEquals("settings", ModePaths.prefsName("settings", WorkMode.LITE))
        assertEquals("settings_B", ModePaths.prefsName("settings", WorkMode.KSU))
        assertEquals("installer_B", ModePaths.prefsName("installer", WorkMode.KSU))
        assertEquals("maplesu-ultra", ModePaths.prefsName("maplesu-ultra", WorkMode.LITE))
    }

    @Test
    fun filesSubdirMapping() {
        assertEquals("images", ModePaths.filesSubdir("images", WorkMode.LITE))
        assertEquals("ksu/images", ModePaths.filesSubdir("images", WorkMode.KSU))
        assertEquals("ksu/module-catalog", ModePaths.filesSubdir("module-catalog", WorkMode.KSU))
    }

    @Test
    fun fullPrefsFilePaths() {
        assertEquals(
            "/data/user/0/dev.maplesu.manager/shared_prefs/settings.xml",
            ModePaths.prefsFile("/data/user/0/dev.maplesu.manager/shared_prefs", "settings", WorkMode.LITE),
        )
        assertEquals(
            "/data/user/0/dev.maplesu.manager/shared_prefs/settings_B.xml",
            ModePaths.prefsFile("/data/user/0/dev.maplesu.manager/shared_prefs", "settings", WorkMode.KSU),
        )
    }

    @Test
    fun fullFilesDirPaths() {
        assertEquals("/data/user/0/dev.maplesu.manager/files/wallpaper",
            ModePaths.filesDir("/data/user/0/dev.maplesu.manager/files", "wallpaper", WorkMode.LITE))
        assertEquals("/data/user/0/dev.maplesu.manager/files/ksu/wallpaper",
            ModePaths.filesDir("/data/user/0/dev.maplesu.manager/files", "wallpaper", WorkMode.KSU))
    }

    @Test
    fun prefsTableMatchesSpec() {
        assertEquals("settings", ModePaths.prefsNameFor("settings", WorkMode.LITE))
        assertEquals("settings_B", ModePaths.prefsNameFor("settings", WorkMode.KSU))
        // A-only prefs：B 不使用 → null（禁止悄悄落到 A 的名字）。
        assertNull(ModePaths.prefsNameFor("maplesu-ultra", WorkMode.KSU))
        assertNull(ModePaths.prefsNameFor("ultra-auto-setup", WorkMode.KSU))
        assertNull(ModePaths.prefsNameFor("su_entry_mode", WorkMode.KSU))
        assertNull(ModePaths.prefsNameFor("runtime_deployment", WorkMode.KSU))
        assertEquals(listOf("maplesu-ultra", "ultra-auto-setup", "runtime_deployment", "su_entry_mode"),
            ModePaths.A_ONLY_PREFS.sorted())
        assertTrue(ModePaths.NEUTRAL_PREFS_NAMES.contains(ModePaths.NEUTRAL_PREFS))
        assertTrue(ModePaths.NEUTRAL_PREFS_NAMES.contains("migration_notice"))
    }

    @Test
    fun neutralAndNoBackupSetsAreStable() {
        assertEquals("workmode_state", ModePaths.NEUTRAL_PREFS)
        assertEquals("active_mode", ModePaths.KEY_ACTIVE_MODE)
        assertEquals("active_boot_id", ModePaths.KEY_ACTIVE_BOOT_ID)
        assertTrue(ModePaths.A_ONLY_NO_BACKUP.contains("maplesu-credential.bin"))
        assertTrue(ModePaths.FILES_SUBDIRS.contains("module-catalog"))
        assertTrue(ModePaths.NEUTRAL_FILES.contains("last_crash.txt"))
    }
}
