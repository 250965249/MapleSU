package com.maplesu.core.theme

import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

class ThemeCompatibilityTest {
    @Test fun multiBackgroundAccentUsesHomeImageAndTheMasterSwitchGatesVideo() {
        val files = listOf("background.png", "background_home.png", "background_settings.png", "video_background.mp4")
            .associateWith { temporary.newFile(it) }
        val j = JSONObject().put("isBackgroundEnabled",true).put("isMultiBackgroundEnabled",true)
            .put("isVideoBackgroundEnabled",true)
        assertEquals("background_home.png",ThemeDocument.seedImage(j,files)?.name)
        j.put("isMultiBackgroundEnabled",false)
        assertEquals("background.png",ThemeDocument.seedImage(j,files)?.name)
        j.put("isBackgroundEnabled",false)
        assertNull(ThemeDocument.seedImage(j,files))
        assertEquals("none",ThemeDocument.preferenceValues(j,files.values.first().parentFile!!)["wallpaper_kind"])
    }
    @get:Rule val temporary = TemporaryFolder()

    /** Independent producer prevents a symmetric reader/writer bug from passing the test. */
    private fun fixture(vararg entries: Pair<String, ByteArray>): ByteArray {
        val zip = ByteArrayOutputStream()
        ZipOutputStream(zip).use { out -> entries.forEach { (name,data) ->
            out.putNextEntry(ZipEntry(name));out.write(data);out.closeEntry()
        } }
        val iv = ByteArray(16) { it.toByte() }
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(MessageDigest.getInstance("SHA-256")
            .digest("FolkPatchThemeSecretKey2025".toByteArray()),"AES"),IvParameterSpec(iv))
        return iv+cipher.doFinal(zip.toByteArray())
    }

    @Test fun independentFinaContainerRetainsFutureFieldsAndBinaryResources() {
        val raw = JSONObject().put("homeLayoutStyle","focus").put("future",JSONObject().put("v",3))
        val bytes = ByteArray(4096) { (it*17).toByte() }
        val source = fixture("theme.json" to raw.toString().toByteArray(),"future.resource" to bytes)
        val (config,files) = FptContainer.read(ByteArrayInputStream(source),temporary.newFolder())
        assertEquals(3,config.getJSONObject("future").getInt("v"))
        val written = FptContainer.write(config,files)
        val (_,again) = FptContainer.read(ByteArrayInputStream(written),temporary.newFolder())
        assertArrayEquals(bytes,again.getValue("future.resource").readBytes())
    }

    @Test fun traversalTruncationAndInvalidPaddingFailBeforeApply() {
        val traversal = fixture("theme.json" to "{}".toByteArray(),"../outside" to byteArrayOf(1))
        assertThrows(IllegalArgumentException::class.java) { FptContainer.read(ByteArrayInputStream(traversal),temporary.newFolder()) }
        val valid = fixture("theme.json" to "{}".toByteArray())
        assertThrows(Exception::class.java) { FptContainer.read(ByteArrayInputStream(valid.copyOf(valid.size-1)),temporary.newFolder()) }
        valid[valid.lastIndex] = (valid.last().toInt() xor 0x7f).toByte()
        assertThrows(Exception::class.java) { FptContainer.read(ByteArrayInputStream(valid),temporary.newFolder()) }
    }

    @Test fun explicitFalseAndAbsentLocaleRemainDistinct() {
        val raw = JSONObject().put("isBackgroundEnabled",false).put("nightModeEnabled",false)
            .put("nightModeFollowSys",false).put("useSystemDynamicColor",false)
        val (j,_) = ThemeDocument.normalize(raw,emptyMap())
        val prefs = ThemeDocument.preferenceValues(j,temporary.newFolder())
        assertEquals(1,prefs["color_mode"])
        assertEquals(false,prefs["miuix_monet"])
        assertEquals("none",prefs["wallpaper_kind"])
        assertFalse(j.has("appLanguage"))
        assertFalse(raw.has("customColor"))
        assertEquals("",ThemeDocument.normalize(JSONObject().put("appLanguage",""),emptyMap()).first.getString("appLanguage"))
    }

    @Test fun resourceSelectionUsesFinaPriorityAndKeepsOtherFiles() {
        val files = listOf("background.png","background.jpg","font.otf","font.ttf").associateWith { temporary.newFile(it) }
        assertEquals("background.jpg",ThemeResourcePolicy.select("background",files)?.name)
        assertEquals("font.ttf",ThemeResourcePolicy.select("font",files)?.name)
        assertEquals(4,files.size)
        assertFalse(ThemeResourcePolicy.wantsImage(JSONObject().put("hasDashboardCardBg",false),"hasDashboardCardBg",true,true))
    }

    @Test fun focusMasterAndChildrenAreIndependentAndDayNightValuesApply() {
        val j = JSONObject().put("isFocusCardBackgroundEnabled",false).put("hasFocusCardKernelBg",true)
            .put("isFocusCardDualOpacityEnabled",true).put("focusCardBgDayOpacity",.2).put("focusCardBgNightOpacity",.8)
        assertFalse(ThemeSurface.read(j,"focus_card_kernel_bg",false).enabled)
        j.put("isFocusCardBackgroundEnabled",true)
        assertTrue(ThemeSurface.read(j,"focus_card_kernel_bg",false).enabled)
        assertEquals(.2f,ThemeSurface.read(j,"focus_card_kernel_bg",false).opacity,.001f)
        assertEquals(.8f,ThemeSurface.read(j,"focus_card_kernel_bg",true).opacity,.001f)
    }

    @Test fun gridAndDashboardUseTheirRealProtocolNames() {
        val grid = JSONObject().put("isGridWorkingCardBackgroundEnabled",true).put("gridWorkingCardBackgroundOpacity",.3)
        assertTrue(ThemeSurface.read(grid,"grid_working_card_background",false).enabled)
        assertEquals(.3f,ThemeSurface.read(grid,"grid_working_card_background",false).opacity,.001f)
        val dashboard = JSONObject().put("isDashboardCardBackgroundEnabled",true).put("hasDashboardCardBg",false)
        assertFalse(ThemeSurface.read(dashboard,"dashboard_card_bg",false).enabled)
    }

    @Test fun dualOpacitySwitchesAreBooleansRatherThanOpacityNumbers() {
        val keys = listOf("isGridDualOpacityEnabled", "isFocusCardDualOpacityEnabled", "isDashboardCardDualOpacityEnabled")
        for (enabled in listOf(true, false)) {
            val original = JSONObject().apply { keys.forEach { put(it, enabled) } }
            val (normalized, warnings) = ThemeDocument.normalize(original, emptyMap())
            assertTrue(warnings.toString(), warnings.isEmpty())
            keys.forEach { assertEquals(enabled, normalized.getBoolean(it)) }
        }
    }

    @Test fun destinationsNeverMapPluginToModuleByIndex() {
        assertEquals("module",ThemeDocument.destinations["AModule"])
        assertNull(ThemeDocument.destinations["KModule"])
        assertEquals(4,ThemeDocument.destinations.size)
    }

    @Test fun themePreferenceOwnershipExcludesSkinAndBusinessKeys() {
        val j = ThemeDocument.normalize(JSONObject(),emptyMap()).first
        val keys = ThemeDocument.preferenceValues(j,temporary.newFolder()).keys
        assertFalse("ui_mode" in keys)
        assertFalse("theme_store_mode" in keys)
        assertTrue(keys.all { it in ThemeRepository.ownedPreferences })
    }

    @Test fun missingImportedNavigationResetsThePreviousThemeInsteadOfRevivingLegacyIcons() {
        val normalized = ThemeDocument.normalize(JSONObject(),emptyMap()).first
        assertTrue(normalized.has("navIcons"))
        assertEquals(0,normalized.getJSONObject("navIcons").length())
        assertFalse(normalized.getBoolean("navIconCustomEnabled"))
    }

    @Test fun indexUsesStableIdAndIgnoresMalformedEntries() {
        val text = """[{"id":1,"name":"Same","download_url":"https://example.org/a.fpt"},{"id":2,"name":"Same","download_url":"https://example.org/b.fpt"},{"id":3,"download_url":"file:///bad"}]"""
        val entries = ThemeStore.parse(text)
        assertEquals(listOf("1","2"),entries.map { it.id })
        assertTrue(ThemeStore.parse("[]").isEmpty())
        assertThrows(IllegalStateException::class.java) { ThemeStore.parse("[{}]") }
    }

    @Test fun mirrorsRetainTheirOrderAndUseOnlyDistinctHttpsSources() {
        val theme = ThemeStore.parse("""[{"id":7,"name":"Mirrored","download_url":"https://primary.invalid/a.fpt","download_mirrors":["https://primary.invalid/a.fpt","http://folk.mysqil.com/download/themes/7","http://other.invalid/a.fpt","https://mirror.invalid/a.fpt"]}]""").single()
        assertEquals(listOf("https://primary.invalid/a.fpt","https://folk.mysqil.com/download/themes/7","https://mirror.invalid/a.fpt"),theme.downloadSources)
        assertEquals(theme.downloadSources,StoreTheme.read(theme.json()).downloadSources)
    }

    @Test fun amoledExportAndImportRemainDarkRatherThanFollowingTheSystem() {
        val j = JSONObject().put("nightModeFollowSys",false).put("nightModeEnabled",true).put("maplesu.amoled",true)
        assertEquals(6,ThemeDocument.preferenceValues(j,temporary.newFolder())["color_mode"])
        j.put("nightModeEnabled",false)
        assertEquals(1,ThemeDocument.preferenceValues(j,temporary.newFolder())["color_mode"])
    }

    @Test fun legacyStoreOriginsUpgradeToHttpsWithoutAcceptingOtherCleartextHosts() {
        val entries = ThemeStore.parse("""[{"id":1,"name":"Fixture","download_url":"http://folk.mysqil.com/download/themes/1","preview_url":"http://folk.mysqil.com/images/cover.webp"}]""")
        assertEquals("https://folk.mysqil.com/download/themes/1",entries.single().download)
        assertEquals("https://folk.mysqil.com/images/cover.webp",entries.single().preview)
        assertThrows(IllegalStateException::class.java) { ThemeStore.parse("""[{"id":2,"name":"Fixture","download_url":"http://other.invalid/package.fpt"}]""") }
    }
}
