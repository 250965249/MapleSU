package com.maplesu.core.theme

import android.content.Context
import android.content.ContextWrapper
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.runBlocking
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.Response
import okhttp3.ResponseBody.Companion.toResponseBody
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import java.io.File
import java.security.MessageDigest
import java.util.UUID

/** Real download/cache/import pipeline; HTTP responses are controlled, not live server state. */
class ThemeStoreDeviceTest {
    private lateinit var directory: File
    private lateinit var context: Context
    private lateinit var payload: ByteArray
    private val requests = mutableListOf<Request>()
    private val theme = StoreTheme("stable-id","Same name","Fixture","1","","phone","","","https://fixture.invalid/theme.fpt")

    @Before fun setup() {
        val base = InstrumentationRegistry.getInstrumentation().targetContext
        directory = File(base.cacheDir,"store-test-${UUID.randomUUID()}").apply { mkdirs() }
        context = object : ContextWrapper(base) {
            override fun getApplicationContext(): Context = this
            override fun getFilesDir(): File = directory
        }
        val resource = File(directory,"future.resource").apply {
            writeBytes(ByteArray(256*1024).also { java.util.Random(42).nextBytes(it) })
        }
        payload = FptContainer.write(JSONObject().put("meta_name","Fixture"),mapOf(resource.name to resource))
    }

    @After fun cleanup() { directory.deleteRecursively() }

    private fun store(respond: (Request) -> Response): ThemeStore = ThemeStore(context,
        OkHttpClient.Builder().addInterceptor { chain -> requests += chain.request(); respond(chain.request()) }.build())

    private fun response(request: Request, code: Int, bytes: ByteArray, range: String? = null, etag: String = "\"v1\""): Response =
        Response.Builder().request(request).protocol(Protocol.HTTP_1_1).code(code).message("Fixture")
            .header("ETag",etag).apply { range?.let { header("Content-Range",it) } }.body(bytes.toResponseBody()).build()

    @Test fun interruptedDownloadResumesWithRangeAndPublishesAnOfflineLibraryWithoutApplying() = runBlocking {
        val repo = store { request ->
            val offset = request.header("Range")?.removePrefix("bytes=")?.removeSuffix("-")?.toInt() ?: 0
            if (offset == 0) response(request,200,payload)
            else response(request,206,payload.copyOfRange(offset,payload.size),"bytes $offset-${payload.lastIndex}/${payload.size}")
        }
        val checked = theme.copy(sha256=MessageDigest.getInstance("SHA-256").digest(payload).joinToString("") { "%02x".format(it) })
        val before = com.maplesu.core.ui.util.AppearancePreferences.prefs(context).all.toMap()
        assertTrue(runCatching { repo.download(checked) { _,_ -> throw CancellationException("pause fixture") } }.isFailure)
        assertTrue(repo.local().isEmpty())
        assertFalse(repo.packageFile(checked).exists())
        val partial = File(directory,"themes/store").listFiles()!!.single { it.extension == "part" }
        val offset = partial.length()
        assertTrue(offset in 1 until payload.size.toLong())
        assertEquals(checked,repo.paused())
        val completed = repo.download(checked) { _,_ -> }
        assertEquals("bytes=$offset-",requests.last().header("Range"))
        assertEquals("\"v1\"",requests.last().header("If-Range"))
        assertArrayEquals(payload,completed.readBytes())
        assertEquals(listOf(checked.id),repo.local().map { it.id })
        assertEquals(before,com.maplesu.core.ui.util.AppearancePreferences.prefs(context).all)
        assertFalse(partial.exists())
        assertNull(repo.paused())
        repo.delete(checked)
        assertTrue(repo.local().isEmpty())
    }

    @Test fun mismatchedRangeDiscardsPartialAndRetryStartsFromZero() = runBlocking {
        var wrong = true
        val repo = store { request ->
            if (request.header("Range") == null) response(request,200,payload)
            else if (wrong) response(request,206,payload,"bytes 0-${payload.lastIndex}/${payload.size}")
            else error("Retry must start without a Range header")
        }
        runCatching { repo.download(theme) { _,_ -> throw CancellationException("pause fixture") } }
        assertTrue(runCatching { repo.download(theme) { _,_ -> } }.isFailure)
        assertTrue(File(directory,"themes/store").listFiles()!!.none { it.extension == "part" || it.name.endsWith(".partial.json") })
        wrong = false
        assertArrayEquals(payload,repo.download(theme) { _,_ -> }.readBytes())
        assertNull(requests.last().header("Range"))
    }

    @Test fun fullResponseOnResumeRestartsAndBadDigestNeverPublishes() = runBlocking {
        val repo = store { response(it,200,payload) }
        runCatching { repo.download(theme) { _,_ -> throw CancellationException("pause fixture") } }
        assertArrayEquals(payload,repo.download(theme) { _,_ -> }.readBytes())
        val bad = theme.copy(id="bad-digest",sha256="0".repeat(64))
        assertTrue(runCatching { repo.download(bad) { _,_ -> } }.isFailure)
        assertFalse(repo.packageFile(bad).exists())
        assertEquals(listOf(theme.id),repo.local().map { it.id })
        assertFalse(repo.samePackage(theme,theme.copy(id="another-id")))
    }

    @Test fun failedPrimaryUsesMirrorAndPersistsTheOriginalIdentity() = runBlocking {
        val mirrored = theme.copy(mirrors=listOf("https://mirror.invalid/theme.fpt"))
        val repo = store { if (it.url.host == "fixture.invalid") response(it,503,byteArrayOf()) else response(it,200,payload) }
        assertArrayEquals(payload,repo.download(mirrored) { _,_ -> }.readBytes())
        assertEquals(listOf("fixture.invalid","mirror.invalid"),requests.map { it.url.host })
        assertEquals(mirrored,repo.local().single())
        assertTrue(repo.samePackage(theme,mirrored))
    }

    @Test fun switchingCatalogsKeepsTheirCachesSeparateAndTheDownloadedLibraryShared() = runBlocking {
        val first = ThemeStoreSource.custom("https://first.invalid/catalog.json")
        val second = ThemeStoreSource.custom("https://second.invalid/catalog.json")
        var offline = false
        val repo = store { request ->
            if (offline) throw java.io.IOException("offline fixture")
            if (request.url.encodedPath.endsWith(".fpt")) response(request,200,payload)
            else response(request,200,"""[{"id":1,"name":"${request.url.host}","version":"1","download_url":"theme.fpt"}]""".toByteArray())
        }
        val a = repo.index(source=first).single()
        val b = repo.index(source=second).single()
        assertNotEquals(a.download,b.download)
        repo.download(a) { _,_ -> }
        offline = true
        assertTrue(runCatching { repo.index(source=second) }.isFailure)
        assertEquals(listOf(a),repo.index(false,first))
        assertEquals(listOf(b),repo.index(false,second))
        assertEquals(listOf(a),repo.local())
        assertTrue(repo.index(false,ThemeStoreSource.Maple).isEmpty())
    }

    @Test fun redirectedCatalogResolvesRelativeResourcesFromItsFinalHttpsLocation() = runBlocking {
        val source = ThemeStoreSource.custom("https://alias.invalid/catalog.json")
        val repo = store { request ->
            val redirected = request.newBuilder().url("https://static.invalid/themes/index.json").build()
            response(redirected,200,"""[{"id":1,"name":"Fixture","download_url":"packages/one.fpt","preview_url":"previews/one.png"}]""".toByteArray())
        }
        val entry = repo.index(source=source).single()
        assertEquals("https://static.invalid/themes/packages/one.fpt",entry.download)
        assertEquals("https://static.invalid/themes/previews/one.png",entry.preview)
        assertEquals(listOf(entry),repo.index(false,source))
    }
}
