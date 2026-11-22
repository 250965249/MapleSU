package dev.maplesu.manager.workmode.storage

import dev.maplesu.manager.workmode.WorkMode
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.nio.file.Files

/** P0 配置隔离：设置总仓 A/B 路由策略 + A 行为等价 + 模式切换后各读各的。 */
class SettingsPrefsPolicyTest {

    /** 最小 prefs fake：文件名 → (key → value)，用于验证隔离/等价性。 */
    private class FakePrefs {
        private val files = linkedMapOf<String, MutableMap<String, String>>()

        fun write(name: String, key: String, value: String) {
            files.getOrPut(name) { linkedMapOf() }[key] = value
        }

        fun read(name: String, key: String): String? = files[name]?.get(key)

        fun snapshot(): Map<String, Map<String, String>> =
            files.mapValues { it.value.toMap() }
    }

    @Test
    fun activeLiteUsesOriginalFileName() {
        assertEquals("settings", SettingsPrefsPolicy.nameFor(WorkMode.LITE))
        // A 行为逐字节等价：文件名与 key 都不变。
        assertEquals("settings", SettingsPathsAlias.A_NAME)
    }

    @Test
    fun activeKsuUsesSuffixedFileName() {
        assertEquals("settings_B", SettingsPrefsPolicy.nameFor(WorkMode.KSU))
        assertNotEquals(SettingsPrefsPolicy.A_NAME, SettingsPrefsPolicy.nameFor(WorkMode.KSU))
    }

    @Test
    fun unresolvedWithoutHintsIsNullThenFallbacksAreExplicit() {
        assertNull(SettingsPrefsPolicy.nameFor(null))
        assertEquals(
            SettingsPrefsPolicy.A_NAME,
            SettingsPrefsPolicy.unresolvedName(lastKnown = WorkMode.LITE, liteEvidencePresent = false),
        )
        assertEquals(
            SettingsPrefsPolicy.B_NAME,
            SettingsPrefsPolicy.unresolvedName(lastKnown = WorkMode.KSU, liteEvidencePresent = false),
        )
        assertEquals(
            SettingsPrefsPolicy.A_NAME,
            SettingsPrefsPolicy.unresolvedName(lastKnown = null, liteEvidencePresent = true),
        )
    }

    @Test
    fun unresolvedWithoutAnyEvidenceNeverDefaultsToA() {
        val name = SettingsPrefsPolicy.unresolvedName(lastKnown = null, liteEvidencePresent = false)
        assertEquals(ModePaths.NEUTRAL_PREFS, name)
        assertNotEquals(SettingsPrefsPolicy.A_NAME, name)
    }

    @Test
    fun hasLiteEvidenceReadsCredentialFiles() {
        val directory = Files.createTempDirectory("maplesu-settings-evidence-").toFile()
        try {
            assertFalse(SettingsPrefsPolicy.hasLiteEvidence(directory))
            File(directory, "maplesu-credential.bin").writeBytes(byteArrayOf(1))
            assertTrue(SettingsPrefsPolicy.hasLiteEvidence(directory))
            File(directory, "maplesu-credential.bin").delete()
            File(directory, dev.maplesu.manager.compat.StoredInputs.CREDENTIAL_FILE).writeBytes(byteArrayOf(1))
            assertTrue(SettingsPrefsPolicy.hasLiteEvidence(directory))
        } finally {
            directory.deleteRecursively()
        }
    }

    @Test
    fun liteWriteStaysInSettingsFileAndRoundTrips() {
        val prefs = FakePrefs()
        val name = SettingsPrefsPolicy.nameFor(WorkMode.LITE)!!
        prefs.write(name, "ui_mode", "dark")
        assertEquals("dark", prefs.read("settings", "ui_mode"))
        assertTrue(prefs.snapshot().containsKey("settings"))
    }

    @Test
    fun ksuWriteNeverTouchesAFile() {
        val prefs = FakePrefs()
        prefs.write(SettingsPrefsPolicy.nameFor(WorkMode.LITE)!!, "ui_mode", "dark")
        prefs.write(SettingsPrefsPolicy.nameFor(WorkMode.KSU)!!, "ui_mode", "light")
        assertEquals("dark", prefs.read("settings", "ui_mode"))
        assertEquals("light", prefs.read("settings_B", "ui_mode"))
    }

    @Test
    fun switchingActiveModeReadsTheRightFile() {
        val prefs = FakePrefs()
        var active: WorkMode? = WorkMode.LITE
        fun currentName() = SettingsPrefsPolicy.nameFor(active)
            ?: SettingsPrefsPolicy.unresolvedName(null, liteEvidencePresent = true)
        prefs.write(currentName(), "check_update", "true")
        assertTrue(prefs.read("settings", "check_update") == "true")

        active = WorkMode.KSU
        assertEquals("settings_B", currentName())
        assertNull(prefs.read(SettingsPrefsPolicy.nameFor(active)!!, "check_update"))
        prefs.write(currentName(), "check_update", "false")
        assertEquals("true", prefs.read("settings", "check_update"))
        assertEquals("false", prefs.read("settings_B", "check_update"))
    }

    @Test
    fun noWriteEverLandsInAWhenBIsUnresolvedButHintsB() {
        val prefs = FakePrefs()
        val name = SettingsPrefsPolicy.unresolvedName(lastKnown = WorkMode.KSU, liteEvidencePresent = true)
        prefs.write(name, "ui_mode", "light")
        assertNull(prefs.read("settings", "ui_mode"))
        assertEquals("light", prefs.read("settings_B", "ui_mode"))
    }

    /** 常量对照：A 的名字必须等于 01 §3.2 的 `settings`。 */
    private object SettingsPathsAlias {
        const val A_NAME = "settings"
    }
}
