package com.maplesu.core.theme

import android.content.Context
import android.content.ContextWrapper
import android.graphics.Bitmap
import android.net.Uri
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import java.io.File
import java.util.UUID

/** Real filesystem/preferences/MediaStore, isolated from the installed manager's appearance. */
class ThemeRepositoryDeviceTest {
    private lateinit var context: Context
    private lateinit var prefs: android.content.SharedPreferences
    private lateinit var directory: File
    private lateinit var repository: ThemeRepository
    private val exported = mutableListOf<Uri>()
    @Before fun setup() {
        val base = InstrumentationRegistry.getInstrumentation().targetContext
        directory = File(base.cacheDir,"theme-test-${UUID.randomUUID()}").apply { mkdirs() }
        context = object : ContextWrapper(base) {
            override fun getApplicationContext(): Context = this
            override fun getFilesDir(): File = directory
        }
        prefs = base.getSharedPreferences("isolated-theme-${directory.name}",0)
        repository = ThemeRepository(context,prefs)
        prefs.edit().putString("ui_mode","material").putString("work_mode","fixture")
            .putString("theme_store_mode","compat").commit()
    }
    @After fun cleanup() {
        exported.forEach { context.contentResolver.delete(it,null,null) }
        prefs.edit().clear().commit(); directory.deleteRecursively()
    }
    private fun packageFile(name: String, j: JSONObject): File {
        val image = File(directory,"$name.png")
        Bitmap.createBitmap(16,16,Bitmap.Config.ARGB_8888).apply { eraseColor(if (name == "A") android.graphics.Color.RED else android.graphics.Color.BLUE) }
            .let { bitmap -> image.outputStream().use { bitmap.compress(Bitmap.CompressFormat.PNG,100,it) }; bitmap.recycle() }
        val resources = mapOf("background.png" to image,"background_kernel.png" to image,"nav_icon_Home.png" to image)
        j.put("meta_name",name).put("futureField",JSONObject().put("keep",true))
        return File(directory,"$name.fpt").also { out -> out.outputStream().use { FptContainer.write(j,resources,it) } }
    }

    @Test fun prepareCancelApplySwitchResetAndExportPreserveOwnership() = runBlocking {
        val a = packageFile("A",JSONObject().put("isBackgroundEnabled",true).put("navIconCustomEnabled",false)
            .put("navIcons",JSONObject().put("Home","nav_icon_Home.png").put("KModule","background_kernel.png")))
        val before = prefs.all.toMap()
        val prepared = repository.prepare(Uri.fromFile(a))
        assertEquals(before,prefs.all)
        repository.discard(prepared)
        assertFalse(File(prepared.path).exists())
        repository.apply(repository.prepare(Uri.fromFile(a)))
        assertEquals("material",prefs.getString("ui_mode",""))
        assertEquals("fixture",prefs.getString("work_mode",""))
        assertEquals("compat",prefs.getString("theme_store_mode",""))
        val generationA = ThemeRuntime.generation(context,prefs)!!
        assertTrue(File(generationA,"assets/background.png").isFile)
        val originalBackground = File(generationA,"assets/background.png").readBytes()
        val b = packageFile("B",JSONObject().put("isBackgroundEnabled",false))
        repository.apply(repository.prepare(Uri.fromFile(b)))
        assertEquals("none",prefs.getString("wallpaper_kind",""))
        repository.apply(repository.prepare(Uri.fromFile(a)))
        val uri = repository.export(ThemeMetadata(name="MapleSU-device-roundtrip")); exported += uri
        val out = File(directory,"exported")
        val (raw,files) = context.contentResolver.openInputStream(uri)!!.use { FptContainer.read(it,out) }
        assertTrue(raw.getJSONObject("futureField").getBoolean("keep"))
        assertEquals("background_kernel.png",raw.getJSONObject("navIcons").getString("KModule"))
        assertEquals("nav_icon_Home.png",raw.getJSONObject("navIcons").getString("Home"))
        assertFalse(raw.getBoolean("navIconCustomEnabled"))
        assertArrayEquals(originalBackground,files.getValue("background.png").readBytes())
        val displayName = context.contentResolver.query(uri,arrayOf(android.provider.OpenableColumns.DISPLAY_NAME),null,null,null)!!.use { it.moveToFirst(); it.getString(0) }
        assertTrue(displayName.endsWith(".fpt")); assertFalse(displayName.endsWith(".bin"))
        repository.reset()
        assertEquals("material",prefs.getString("ui_mode",""))
        assertEquals("fixture",prefs.getString("work_mode",""))
        assertEquals("compat",prefs.getString("theme_store_mode",""))
        assertNull(ThemeRuntime.generation(context,prefs))
    }

    @Test fun interruptedResourceCommitRecoversWithoutTouchingBusinessState() = runBlocking {
        val a = packageFile("A",JSONObject().put("isBackgroundEnabled",true))
        repository.apply(repository.prepare(Uri.fromFile(a)))
        val old = prefs.all.toMap()
        val pending = UUID.randomUUID().toString()
        val root = File(directory,"themes")
        File(root,"generations/$pending/assets").mkdirs()
        File(root,"transaction.json").writeText(JSONObject().put("generation",pending).toString())
        ThemeRepository(context,prefs).recover()
        assertEquals(old,prefs.all)
        assertFalse(File(root,"generations/$pending").exists())
        val committed = prefs.getString("theme_generation","")!!
        File(root,"transaction.json").writeText(JSONObject().put("generation",committed).toString())
        ThemeRepository(context,prefs).recover()
        assertTrue(File(root,"generations/$committed/assets/background.png").isFile)
    }

    @Test fun failedCommitRestoresThePreviousThemeAndDiscardsItsResources() = runBlocking {
        repository.apply(repository.prepare(Uri.fromFile(packageFile("A",JSONObject().put("isBackgroundEnabled",true)))))
        val before = prefs.all.toMap()
        val failing = ThemeRepository(context, failingCommits(1))
        val prepared = failing.prepare(Uri.fromFile(packageFile("B",JSONObject().put("isBackgroundEnabled",false))))
        assertTrue(runCatching { failing.apply(prepared) }.isFailure)
        assertEquals(before,prefs.all)
        assertFalse(File(directory,"themes/transaction.json").exists())
        assertEquals(listOf(before["theme_generation"]),File(directory,"themes/generations").listFiles()!!.map { it.name })
        assertTrue(File(ThemeRuntime.generation(context,prefs),"assets/background.png").isFile)
    }

    @Test fun failedRollbackIsRetriedOnRestartAndPreservesLaterBusinessChanges() = runBlocking {
        repository.apply(repository.prepare(Uri.fromFile(packageFile("A",JSONObject().put("isBackgroundEnabled",true)))))
        val before = prefs.all.toMap()
        val failing = ThemeRepository(context, failingCommits(2))
        val prepared = failing.prepare(Uri.fromFile(packageFile("B",JSONObject().put("isBackgroundEnabled",false))))
        assertTrue(runCatching { failing.apply(prepared) }.isFailure)
        assertTrue(File(directory,"themes/transaction.json").isFile)
        prefs.edit().putString("work_mode","later-business-value").commit()
        ThemeRepository(context,prefs).recover()
        assertEquals(before + ("work_mode" to "later-business-value"),prefs.all)
        assertFalse(File(directory,"themes/transaction.json").exists())
        assertEquals(listOf(before["theme_generation"]),File(directory,"themes/generations").listFiles()!!.map { it.name })
    }

    @Test fun editingAnImportedResourceExportsItsCurrentSwitchAndOriginalFutureFields() = runBlocking {
        val original = packageFile("A",JSONObject().put("isBackgroundEnabled",false).put("homeLayoutStyle","future-layout"))
        repository.apply(repository.prepare(Uri.fromFile(original)))
        repository.setAsset("background",Uri.fromFile(File(directory,"A.png")),"png",mapOf("isBackgroundEnabled" to true))
        val uri = repository.export(ThemeMetadata(name="MapleSU-edited-roundtrip")); exported += uri
        val (raw,files) = context.contentResolver.openInputStream(uri)!!.use { FptContainer.read(it,File(directory,"edited-export")) }
        assertTrue(raw.getBoolean("isBackgroundEnabled"))
        assertEquals("future-layout",raw.getString("homeLayoutStyle"))
        assertTrue(raw.getJSONObject("futureField").getBoolean("keep"))
        assertArrayEquals(File(directory,"A.png").readBytes(),files.getValue("background.png").readBytes())
        repository.edit(mapOf("homeLayoutStyle" to "focus"))
        val second = repository.export(ThemeMetadata(name="MapleSU-layout-roundtrip")); exported += second
        val changed = context.contentResolver.openInputStream(second)!!.use { FptContainer.read(it,File(directory,"layout-export")) }.first
        assertEquals("focus",changed.getString("homeLayoutStyle"))
    }

    @Test fun audioWithAnImportedFilenameCanBeRemovedWithoutDeletingOtherResources() = runBlocking {
        val audio = File(directory,"music.original.v2.wav").apply { writeBytes(byteArrayOf(1,2,3,4)) }
        val untouched = File(directory,"future.resource").apply { writeText("preserved") }
        val input = File(directory,"audio.fpt")
        input.outputStream().use { FptContainer.write(JSONObject().put("musicFilename",audio.name).put("isMusicEnabled",true),
            mapOf(audio.name to audio,untouched.name to untouched),it) }
        repository.apply(repository.prepare(Uri.fromFile(input)))
        assertEquals(audio.name,ThemeRuntime.file(context,"theme_music",prefs)?.name)
        repository.setAsset("theme_music",null,"wav",mapOf("isMusicEnabled" to false))
        assertNull(ThemeRuntime.file(context,"theme_music",prefs))
        val generation = ThemeRuntime.generation(context,prefs)!!
        assertFalse(File(generation,"assets/${audio.name}").exists())
        assertTrue(File(generation,"assets/${untouched.name}").isFile)
        assertEquals("",ThemeRuntime.document(context,prefs).getString("musicFilename"))
    }

    @Test fun editingBackgroundControlsUpdatesTheSameSnapshotThatExportUses() = runBlocking {
        repository.apply(repository.prepare(Uri.fromFile(packageFile("A",JSONObject().put("isBackgroundEnabled",true)))))
        assertNotEquals(0,prefs.getInt("wallpaper_seed_color",0))
        repository.edit(mapOf("backgroundBlur" to 7f,"backgroundDim" to .4f,"backgroundOpacity" to .6f))
        assertEquals(7f,prefs.getFloat("wallpaper_blur",0f),.001f)
        assertEquals(.4f,prefs.getFloat("wallpaper_dim",0f),.001f)
        assertEquals(.6f,prefs.getFloat("ui_translucent_alpha",0f),.001f)
        assertEquals(.6,ThemeRuntime.document(context,prefs).getDouble("backgroundOpacity"),.001)
        assertTrue(prefs.getBoolean("theme_modified",false))
        repository.edit(mapOf("nightModeFollowSys" to false,"nightModeEnabled" to true,"maplesu.amoled" to true))
        assertEquals(6,prefs.getInt("color_mode",0))
        val uri = repository.export(ThemeMetadata(name="MapleSU-amoled-roundtrip")); exported += uri
        val (raw,_) = context.contentResolver.openInputStream(uri)!!.use { FptContainer.read(it,File(directory,"amoled-export")) }
        assertFalse(raw.getBoolean("nightModeFollowSys")); assertTrue(raw.getBoolean("nightModeEnabled"))
        assertTrue(raw.getBoolean("maplesu.amoled"))
    }

    @Test fun generatedMediaPackageDecodesAndHomeSeedSurvivesVideoAndPageSwitches() = runBlocking {
        val fixture = File(directory,"media.fpt")
        InstrumentationRegistry.getInstrumentation().context.assets.open("theme/media.fpt").use { input -> fixture.outputStream().use(input::copyTo) }
        val prepared = repository.prepare(Uri.fromFile(fixture))
        assertTrue(prepared.warnings.toString(),prepared.warnings.isEmpty())
        repository.apply(prepared)
        val generation = ThemeRuntime.generation(context,prefs)!!
        val home = File(generation,"assets/background_home.png")
        val seed = com.maplesu.core.ui.util.extractSeedColor(home)
        assertNotEquals(0,seed)
        assertEquals(seed,prefs.getInt("wallpaper_seed_color",0))
        assertEquals("music.original.v2.wav",ThemeRuntime.file(context,"theme_music",prefs)?.name)
        ThemeAssetValidation.validateSelected("video_background",File(generation,"assets/video_background.mp4"))
        ThemeAssetValidation.validateSelected("theme_music",ThemeRuntime.file(context,"theme_music",prefs)!!)
        repository.edit(mapOf("isVideoBackgroundEnabled" to true))
        assertEquals(seed,prefs.getInt("wallpaper_seed_color",0))
        repository.edit(mapOf("isBackgroundEnabled" to false))
        assertEquals("none",prefs.getString("wallpaper_kind",""))
        assertEquals(0,prefs.getInt("wallpaper_seed_color",-1))
        repository.edit(mapOf("isBackgroundEnabled" to true,"useSystemDynamicColor" to false,
            "finasu_keyColor" to 0xff006876.toInt(),"colorStyle" to "TONAL_SPOT","colorStandard" to "M3E_2025"))
        assertEquals(0xff006876.toInt(),prefs.getInt("key_color",0))
        assertFalse(prefs.getBoolean("miuix_monet",true))
        assertEquals("TonalSpot",prefs.getString("color_style",""))
        assertEquals("SPEC_2025",prefs.getString("color_spec",""))
        val output = repository.export(ThemeMetadata(name="MapleSU-media-roundtrip")); exported += output
        val (raw,resources) = context.contentResolver.openInputStream(output)!!.use { FptContainer.read(it,File(directory,"media-export")) }
        assertTrue(raw.getJSONObject("futureField").getBoolean("retained"))
        assertArrayEquals(File(generation,"assets/music.original.v2.wav").readBytes(),resources.getValue("music.original.v2.wav").readBytes())
    }

    @Test fun manualWallpaperExportPreservesTheMasterSwitchAndReplacesAllOldVariants() = runBlocking {
        repository.apply(repository.prepare(Uri.fromFile(packageFile("A",JSONObject().put("isBackgroundEnabled",true)))))
        val manual = File(directory,"manual.jpg")
        Bitmap.createBitmap(16,16,Bitmap.Config.ARGB_8888).let { bitmap ->
            bitmap.eraseColor(android.graphics.Color.GREEN)
            manual.outputStream().use { bitmap.compress(Bitmap.CompressFormat.JPEG,100,it) }
            bitmap.recycle()
        }
        prefs.edit().putString("wallpaper_path",manual.absolutePath).putString("wallpaper_kind","image")
            .putInt("wallpaper_seed_color",12345).commit()
        for (enabled in listOf(false,true)) {
            repository.edit(mapOf("isBackgroundEnabled" to enabled,"isMultiBackgroundEnabled" to false,"isVideoBackgroundEnabled" to false))
            assertEquals(manual.absolutePath,prefs.getString("wallpaper_path",""))
            assertEquals(12345,prefs.getInt("wallpaper_seed_color",0))
            val uri = repository.export(ThemeMetadata(name="MapleSU-manual-$enabled")); exported += uri
            val (raw,resources) = context.contentResolver.openInputStream(uri)!!.use { FptContainer.read(it,File(directory,"manual-export-$enabled")) }
            assertEquals(enabled,raw.getBoolean("isBackgroundEnabled"))
            assertFalse(raw.getBoolean("isMultiBackgroundEnabled"))
            assertFalse(raw.getBoolean("isVideoBackgroundEnabled"))
            assertFalse(resources.containsKey("background.png"))
            assertArrayEquals(manual.readBytes(),resources.getValue("background.jpg").readBytes())
            assertTrue(raw.getJSONObject("futureField").getBoolean("keep"))
        }
    }

    @Test fun importingEveryUpstreamLayoutKeepsArrangementAndFullResetRestoresInitialLayout() = runBlocking {
        for (layout in ThemeHomeLayout.entries) {
            repository.homeLayout(layout)
            val before = prefs.all.filterKeys { it in setOf("home_card_layout","home_large_card","ui_mode","work_mode","theme_store_mode") }
            for (source in ThemeDocument.layouts) {
                repository.apply(repository.prepare(Uri.fromFile(packageFile("Layout",JSONObject().put("homeLayoutStyle",source)))))
                assertEquals(source,ThemeRuntime.document(context,prefs).getString("homeLayoutStyle"))
                assertEquals(before,prefs.all.filterKeys { it in before.keys })
            }
            repository.reset()
            assertFalse(prefs.contains("home_card_layout"))
            assertFalse(prefs.getBoolean("home_large_card",true))
            assertEquals(before.filterKeys { it !in setOf("home_card_layout","home_large_card") },
                prefs.all.filterKeys { it in before.keys && it !in setOf("home_card_layout","home_large_card") })
        }
    }

    @Test fun restoringDefaultsClearsAllAppearanceButKeepsSkinAndBusinessChoices() = runBlocking {
        prefs.edit().putString("home_card_layout", "three").putBoolean("home_large_card", true)
            .putString("status_decoration_source", "comic").putBoolean("snow_enabled", true)
            .putBoolean("troll_rain_enabled", true).putFloat("page_scale", 1.25f)
            .putBoolean("enable_floating_bottom_bar", true).putBoolean("appearance_intro_complete_v1", true)
            .putString(ThemeStoreSource.PREFERENCE, "finasu").commit()
        repository.reset()
        assertEquals("material", prefs.getString("ui_mode", ""))
        assertEquals("fixture", prefs.getString("work_mode", ""))
        assertEquals("finasu", prefs.getString(ThemeStoreSource.PREFERENCE, ""))
        assertTrue(prefs.getBoolean("appearance_intro_complete_v1", false))
        assertFalse("The default preset must restore the plain initial card", prefs.getBoolean("home_large_card", true))
        assertEquals("check", prefs.getString("status_decoration_source", ""))
        assertFalse(prefs.getBoolean("snow_enabled", true))
        assertFalse(prefs.getBoolean("troll_rain_enabled", true))
        assertEquals(1f, prefs.getFloat("page_scale", 1f))
        assertFalse(prefs.getBoolean("enable_floating_bottom_bar", true))
        assertFalse(prefs.contains("home_card_layout"))
    }

    @Test fun comicAndStandardRestoresUseTheInitialPresetAndKeepLibraryAndSkin() = runBlocking {
        val library = File(directory,"themes/store/local/retained.fpt").apply { parentFile!!.mkdirs(); writeText("keep") }
        for (comic in listOf(true,false,true)) {
            repository.homeLayout(ThemeHomeLayout.Three)
            prefs.edit().putFloat("wallpaper_blur",90f).putString("theme_document","{\"isMusicEnabled\":true}")
                .putFloat("status_decoration_zoom",3f).putFloat("snow_speed",2f).commit()
            repository.reset(comic)
            com.maplesu.core.ui.util.AppearancePrefsPolicy.comicPreset(comic).forEach { (key,value) -> assertEquals(key,value,prefs.all[key]) }
            assertFalse(prefs.contains("home_card_layout"))
            assertFalse(prefs.contains("wallpaper_blur"))
            assertFalse(prefs.contains("snow_speed"))
            assertTrue(ThemeRuntime.document(context,prefs).length() == 0)
            assertEquals("material",prefs.getString("ui_mode",""))
            assertEquals("fixture",prefs.getString("work_mode",""))
            assertEquals("keep",library.readText())
        }
    }

    @Test fun failedFullResetAndRestartRollbackRestoreAllAppearanceAndKeepLaterBusinessChanges() = runBlocking {
        repository.apply(repository.prepare(Uri.fromFile(packageFile("A",JSONObject().put("isBackgroundEnabled",true)))))
        for (failures in listOf(1,2)) {
            prefs.edit().putString("home_card_layout","three").putFloat("page_scale",1.08f)
                .putBoolean("snow_enabled",false).putBoolean("appearance_intro_comic",false)
                .putString("status_decoration_source","custom").commit()
            val before=prefs.all.toMap()
            assertTrue(runCatching { ThemeRepository(context,failingCommits(failures)).reset(true) }.isFailure)
            assertEquals(before,prefs.all)
            prefs.edit().putString("work_mode","later-business").putString("theme_store_mode","builtin").commit()
            ThemeRepository(context,prefs).recover()
            assertEquals(before + mapOf("work_mode" to "later-business","theme_store_mode" to "builtin"),prefs.all)
            assertFalse(File(directory,"themes/transaction.json").exists())
            assertTrue(File(ThemeRuntime.generation(context,prefs),"assets/background.png").isFile)
        }
    }

    @Test fun mapleCatalogPackagesPreserveBothSkinsAndEveryHomeArrangement() = runBlocking {
        val assets = InstrumentationRegistry.getInstrumentation().context.assets
        for (skin in listOf("miuix","material")) for (layout in ThemeHomeLayout.entries) {
            prefs.edit().putString("ui_mode",skin).commit()
            repository.homeLayout(layout)
            for (name in listOf("default","comic")) {
                val input = File(directory,"maplesu-$name.fpt")
                assets.open("theme/maplesu-$name.fpt").use { source -> input.outputStream().use(source::copyTo) }
                val prepared = repository.prepare(Uri.fromFile(input))
                assertTrue(prepared.warnings.toString(),prepared.warnings.isEmpty())
                repository.apply(prepared)
                assertEquals(skin,prefs.getString("ui_mode",""))
                assertEquals(layout.value,prefs.getString(ThemeHomeLayout.PREFERENCE,""))
                val document = ThemeRuntime.document(context,prefs)
                val photo = ThemeRuntime.file(context,ThemeHomeLayout.statusResource(document),prefs)
                assertEquals(name == "comic",photo != null)
                if (photo != null) {
                    val drawable = context.resources.openRawResource(com.maplesu.core.R.drawable.art_default).use { it.readBytes() }
                    assertArrayEquals(drawable,photo.readBytes())
                }
            }
        }
    }

    /** A failed commit still changes the in-memory map on Android. */
    private fun failingCommits(count: Int): android.content.SharedPreferences {
        var remaining = count
        return object : android.content.SharedPreferences by prefs {
            override fun edit(): android.content.SharedPreferences.Editor {
                val editor = prefs.edit()
                return object : android.content.SharedPreferences.Editor by editor {
                    override fun putString(key: String?, value: String?) = apply { editor.putString(key,value) }
                    override fun putStringSet(key: String?, values: Set<String>?) = apply { editor.putStringSet(key,values) }
                    override fun putInt(key: String?, value: Int) = apply { editor.putInt(key,value) }
                    override fun putLong(key: String?, value: Long) = apply { editor.putLong(key,value) }
                    override fun putFloat(key: String?, value: Float) = apply { editor.putFloat(key,value) }
                    override fun putBoolean(key: String?, value: Boolean) = apply { editor.putBoolean(key,value) }
                    override fun remove(key: String?) = apply { editor.remove(key) }
                    override fun clear() = apply { editor.clear() }
                    override fun commit(): Boolean {
                        val written = editor.commit()
                        return if (remaining-- > 0) false else written
                    }
                }
            }
        }
    }
}
