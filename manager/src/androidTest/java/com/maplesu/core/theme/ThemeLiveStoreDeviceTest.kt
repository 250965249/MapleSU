package com.maplesu.core.theme

import android.content.Context
import android.content.ContextWrapper
import android.net.Uri
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File
import java.security.MessageDigest
import java.util.UUID

/** Explicit opt-in: the normal suite stays independent of the public store's availability. */
class ThemeLiveStoreDeviceTest {
    @Test fun realStoreDownloadAppliesAndExportsOnAndroid() = runBlocking {
        assumeTrue(InstrumentationRegistry.getArguments().getString("themeLiveStore") == "true")
        val base = InstrumentationRegistry.getInstrumentation().targetContext
        assertTrue(base.packageName.endsWith(".themetest"))
        val directory = File(base.cacheDir,"live-theme-${UUID.randomUUID()}").apply { mkdirs() }
        val context = object : ContextWrapper(base) {
            override fun getApplicationContext(): Context = this
            override fun getFilesDir(): File = directory
        }
        val prefs = base.getSharedPreferences(directory.name,0)
        val evidence = File(base.getExternalFilesDir(null),"theme-network-evidence").apply { mkdirs() }
        var exported: Uri? = null
        try {
            prefs.edit().putString("ui_mode","miuix").putString("work_mode","fixture").commit()
            val store = ThemeStore(context)
            val themes = store.index()
            val theme = requireNotNull(themes.find { it.id == "374" }) { "Store fixture id 374 missing" }
            val downloaded = store.download(theme) { _,_ -> }
            assertTrue(downloaded.length() > 0)
            assertEquals(theme,store.local().single())
            val repository = ThemeRepository(context,prefs)
            val prepared = repository.prepare(Uri.fromFile(downloaded))
            repository.apply(prepared,store.identity(theme))
            assertEquals("miuix",prefs.getString("ui_mode",""))
            assertEquals("fixture",prefs.getString("work_mode",""))
            assertEquals("kernelsu",ThemeRuntime.document(context,prefs).getString("homeLayoutStyle"))
            exported = repository.export(prepared.metadata)
            val output = File(evidence,"device-roundtrip.fpt")
            context.contentResolver.openInputStream(exported)!!.use { input -> output.outputStream().use { input.copyTo(it) } }
            val original = downloaded.inputStream().use { FptContainer.read(it,File(directory,"original")) }
            val roundtrip = output.inputStream().use { FptContainer.read(it,File(directory,"roundtrip")) }
            original.second.forEach { (name,file) -> assertArrayEquals(name,file.readBytes(),roundtrip.second.getValue(name).readBytes()) }
            assertEquals(prepared.metadata,ThemeMetadata.read(roundtrip.first))
            val reimport = repository.prepare(Uri.fromFile(output))
            repository.apply(reimport)
            assertEquals("kernelsu",ThemeRuntime.document(context,prefs).getString("homeLayoutStyle"))
            File(evidence,"live-store.json").writeText(JSONObject().put("indexCount",themes.size)
                .put("theme",theme.json()).put("bytes",downloaded.length())
                .put("sha256",MessageDigest.getInstance("SHA-256").digest(downloaded.readBytes()).joinToString("") { "%02x".format(it) })
                .put("resourceCount",roundtrip.second.size).put("result","download-apply-export-reimport passed").toString(2))
        } finally {
            exported?.let { context.contentResolver.delete(it,null,null) }
            prefs.edit().clear().commit()
            directory.deleteRecursively()
        }
    }
}
