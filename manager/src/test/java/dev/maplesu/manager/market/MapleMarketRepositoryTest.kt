package dev.maplesu.manager.market

import java.io.File
import java.io.IOException
import java.nio.file.Files
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.async
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import me.weishu.kernelsu.data.registry.RegistryDownloadStore
import me.weishu.kernelsu.data.registry.verifyFile
import okhttp3.Interceptor
import okhttp3.MediaType
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.Response
import okhttp3.ResponseBody
import okhttp3.ResponseBody.Companion.toResponseBody
import okio.Buffer
import okio.BufferedSource
import okio.Source
import okio.Timeout
import okio.buffer
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test

class MapleMarketRepositoryTest {
    private lateinit var root: File
    private lateinit var fixture: MarketFixture
    private lateinit var selectedSource: MarketSource
    private lateinit var server: FixtureServer
    private lateinit var repository: MapleMarketRepository

    @Before fun setup() {
        root = Files.createTempDirectory("maplesu-market-test").toFile()
        fixture = MarketFixture()
        selectedSource = fixture.source
        server = FixtureServer()
        repository = newRepository()
        serveCatalog(fixture.module())
    }

    @After fun cleanup() { root.deleteRecursively() }

    @Test fun liveVerifiedCatalogPersistsForOfflineStartup() = runBlocking {
        val live = repository.loadCatalog()
        assertNull(live.error)
        assertFalse(live.stale)
        assertEquals(1, live.modules.size)
        server.routes.clear()
        val offline = newRepository().loadCatalog()
        assertTrue(offline.stale)
        assertNotNull(offline.error)
        assertEquals(live.modules, offline.modules)
    }

    @Test fun offlineWithoutACacheIsAnExplicitError() = runBlocking {
        server.routes.clear()
        val result = repository.loadCatalog()
        assertTrue(result.modules.isEmpty())
        assertEquals(MarketErrorCode.NETWORK, (result.error as MarketException).code)
    }

    @Test fun pinnedOfficialBackupVerifiesTheRealCatalogAndCachesIt() = runBlocking {
        selectedSource = MapleMarketRepository.officialSource()
        server.routes.clear()
        val file = listOf(File("../maplesu-module-market/market.json"), File("maplesu-module-market/market.json")).first { it.isFile }
        server.bytes(MarketCatalogCodec.OFFICIAL_BACKUP_URL, file.readBytes())
        server.bytes(MarketCatalogCodec.signatureUrl(MarketCatalogCodec.OFFICIAL_BACKUP_URL),
            File(file.parentFile, "market.json.sig").readBytes())
        val result = repository.loadCatalog()
        assertNull(result.error)
        assertFalse(result.stale)
        assertEquals(org.json.JSONObject(file.readText()).getJSONArray("module_list").length(), result.modules.size)
        assertEquals(MarketCatalogCodec.OFFICIAL_URL, server.requests.first())
        assertTrue(server.requests.indexOf(MarketCatalogCodec.OFFICIAL_BACKUP_URL) > 0)
        assertTrue(result.modules.all { it.downloadUrls.first().startsWith("https://raw.githubusercontent.com/FengQiuFQ/maplesu-module-market/main/") })
        server.routes.clear()
        val offline = newRepository().loadCatalog()
        assertTrue(offline.stale)
        assertEquals(result.modules.map { it.id }, offline.modules.map { it.id })
    }

    @Test fun downloadsKsuArchiveWithInstallerIntegrityMetadata() = runBlocking {
        serveCatalog(fixture.module().put("type", "KERNEL_SU"))
        val module = repository.loadCatalog().modules.single()
        server.bytes(module.downloadUrls.single(), fixture.packageBytes)
        val archive = repository.download(module) {}
        val expected = RegistryDownloadStore.expectedFor(File(root, "files/${RegistryDownloadStore.DIR_NAME}"), archive)
        assertNotNull(expected)
        val staged = File(root, "installer.zip")
        archive.inputStream().use { me.weishu.kernelsu.data.registry.copyForInstall(it, staged, expected) }
        val report = dev.maplesu.manager.ModuleArchiveInspector.inspect(staged)
        assertEquals(module.id, report.id)
        assertEquals(module.sha256, report.sha256)
        assertEquals(dev.maplesu.manager.ModuleArchiveInspector.ModuleType.KERNEL_SU, report.type)
    }

    @Test fun aModifiedDiskCacheIsReverifiedAndRejected() = runBlocking {
        repository.loadCatalog()
        val cache = File(root, "cache").walkTopDown().first { it.name == "catalog.bin" }
        val bytes = cache.readBytes()
        bytes[12] = (bytes[12].toInt() xor 1).toByte()
        cache.writeBytes(bytes)
        server.routes.clear()
        val result = newRepository().loadCatalog()
        assertTrue(result.modules.isEmpty())
        assertNotNull(result.error)
    }

    @Test fun changingTheUrlOrKeyNeverReusesAnOldSourcesCache() = runBlocking {
        repository.loadCatalog()
        server.routes.clear()
        selectedSource = selectedSource.copy(key = MarketFixture().key)
        assertTrue(newRepository().loadCatalog().modules.isEmpty())
        selectedSource = fixture.source.copy(url = "https://another.example.test/modules/market.json")
        assertTrue(newRepository().loadCatalog().modules.isEmpty())
    }

    @Test fun anInvalidOnlineSignatureKeepsOnlyTheVerifiedOfflineCatalog() = runBlocking {
        val original = repository.loadCatalog()
        server.bytes(MarketCatalogCodec.signatureUrl(selectedSource.url), "not base64".toByteArray())
        val result = repository.loadCatalog()
        assertTrue(result.stale)
        assertEquals(original.modules, result.modules)
        assertEquals(MarketErrorCode.SIGNATURE_INVALID, (result.error as MarketException).code)
    }

    @Test fun verifiesDownloadAndKeepsTheExistingInstallersIntegrityMetadata() = runBlocking {
        val module = repository.loadCatalog().modules.single()
        server.bytes(module.downloadUrls.single(), fixture.packageBytes)
        val progress = mutableListOf<Float>()
        val file = repository.download(module) { progress += it }
        assertArrayEquals(fixture.packageBytes, file.readBytes())
        val expected = RegistryDownloadStore.expectedFor(File(root, "files/${RegistryDownloadStore.DIR_NAME}"), file)
        assertNotNull(expected)
        assertEquals(module.sha256, expected!!.sha256)
        verifyFile(file, expected)
        assertEquals(0f, progress.first())
        assertEquals(1f, progress.last())
    }

    @Test fun downloadAutomaticallyRetriesTheSignedBackupResource() = runBlocking {
        val entry = fixture.module().put("mirrors", JSONObject().put("primary", "packages/module.zip").put("backup", "packages/backup.zip"))
        serveCatalog(entry)
        val module = repository.loadCatalog().modules.single()
        assertEquals(2, module.downloadUrls.size)
        server.bytes(module.downloadUrls.last(), fixture.packageBytes)
        val file = repository.download(module) {}
        assertArrayEquals(fixture.packageBytes, file.readBytes())
        assertTrue(server.requests.indexOf(module.downloadUrls.first()) < server.requests.indexOf(module.downloadUrls.last()))
    }

    @Test fun wrongHashAndSizeNeverProduceAnInstallableFile() = runBlocking {
        val module = repository.loadCatalog().modules.single()
        server.bytes(module.downloadUrls.single(), fixture.packageBytes.copyOf().apply { this[0] = (this[0].toInt() xor 1).toByte() })
        rejectsSuspend(MarketErrorCode.DOWNLOAD_INTEGRITY) { repository.download(module) {} }
        assertTrue(File(root, "files").walkTopDown().none { it.isFile })
        server.bytes(module.downloadUrls.single(), byteArrayOf(1))
        rejectsSuspend(MarketErrorCode.DOWNLOAD_INTEGRITY) { repository.download(module) {} }
        assertTrue(File(root, "files").walkTopDown().none { it.isFile })
    }

    @Test fun aBadPrimaryPackageMayOnlyFallBackToBytesWithTheSameSignedHash() = runBlocking {
        serveCatalog(fixture.module().put("mirrors", JSONObject().put("primary", "packages/module.zip").put("backup", "packages/backup.zip")))
        val module = repository.loadCatalog().modules.single()
        server.bytes(module.downloadUrls.first(), fixture.packageBytes.copyOf().apply { this[0] = 0 })
        server.bytes(module.downloadUrls.last(), fixture.packageBytes)
        assertArrayEquals(fixture.packageBytes, repository.download(module) {}.readBytes())
        assertEquals(1, File(root, "files").walkTopDown().count { it.isFile })
    }

    @Test fun aForgedOrPreviouslySelectedModuleIsRejectedBeforeDownload() = runBlocking {
        val module = repository.loadCatalog().modules.single()
        val requestCount = server.requests.size
        rejectsSuspend(MarketErrorCode.MODULE_UNAVAILABLE) { repository.download(module.copy(size = module.size + 1)) {} }
        selectedSource = selectedSource.copy(url = "https://new.example.test/modules/market.json")
        rejectsSuspend(MarketErrorCode.MODULE_UNAVAILABLE) { repository.download(module) {} }
        assertEquals(requestCount, server.requests.size)
    }

    @Test fun bannedAndNormalOnlyModulesKeepTheirRowsWithoutDownloading() = runBlocking {
        serveCatalog(fixture.module().put("ban", true))
        val banned = repository.loadCatalog().modules.single()
        assertFalse(banned.installable)
        rejectsSuspend(MarketErrorCode.MODULE_UNAVAILABLE) { repository.download(banned) {} }
        assertTrue(server.requests.none { it.endsWith(".zip") })
    }

    @Test fun changelogUsesTheResolvedSourceAndAnEmptyOptionalFieldReturnsEmptyText() = runBlocking {
        val module = repository.loadCatalog().modules.single()
        server.bytes(module.changelogUrl, "# 1.2.3\n优化体验".toByteArray())
        assertEquals("# 1.2.3\n优化体验", repository.changelog(module))
        val noChangelog = fixture.module().apply { remove("changelog_url") }
        serveCatalog(noChangelog)
        assertEquals("", repository.changelog(repository.loadCatalog().modules.single()))
    }

    @Test fun catalogCancellationCancelsTheActualOkHttpCallAndDoesNotBecomeAnOfflineResult() = runBlocking {
        val entered = CountDownLatch(1)
        val cancelled = CountDownLatch(1)
        server.routes[selectedSource.url] = { chain ->
            entered.countDown()
            while (!chain.call().isCanceled()) Thread.sleep(2)
            cancelled.countDown()
            throw IOException("cancelled")
        }
        val task = async { repository.loadCatalog() }
        withTimeout(3000) {
            while (entered.count > 0) kotlinx.coroutines.delay(5)
            task.cancelAndJoin()
        }
        assertTrue(task.isCancelled)
        assertTrue(cancelled.await(2, TimeUnit.SECONDS))
        assertTrue(File(root, "cache").walkTopDown().none { it.isFile })
    }

    @Test fun downloadCancellationClosesTheBodyAndDeletesItsPartialFile() = runBlocking {
        val module = repository.loadCatalog().modules.single()
        val entered = CountDownLatch(1)
        val bodyClosed = AtomicBoolean(false)
        val callCancelled = AtomicBoolean(false)
        server.routes[module.downloadUrls.single()] = { chain ->
            val body = object : ResponseBody() {
                override fun contentType(): MediaType? = null
                override fun contentLength(): Long = module.size
                override fun source(): BufferedSource = object : Source {
                    override fun timeout(): Timeout = Timeout.NONE
                    override fun close() { bodyClosed.set(true) }
                    override fun read(sink: Buffer, byteCount: Long): Long {
                        entered.countDown()
                        while (!chain.call().isCanceled()) Thread.sleep(2)
                        callCancelled.set(true)
                        throw IOException("cancelled read")
                    }
                }.buffer()
            }
            response(chain.request(), body)
        }
        val task = async { repository.download(module) {} }
        withTimeout(3000) {
            while (entered.count > 0) kotlinx.coroutines.delay(5)
            task.cancelAndJoin()
        }
        assertTrue(task.isCancelled)
        repeat(100) {
            if (bodyClosed.get()) return@repeat
            Thread.sleep(5)
        }
        assertTrue(callCancelled.get())
        assertTrue(bodyClosed.get())
        assertTrue(File(root, "files").walkTopDown().none { it.isFile })
    }

    @Test fun rejectsAHttpOrCrossDirectoryRedirectBeforeFollowingIt() = runBlocking {
        server.routes[selectedSource.url] = { chain -> response(chain.request(), byteArrayOf().toResponseBody(), 302)
            .newBuilder().header("Location", "http://untrusted.example.test/catalog.json").build() }
        val result = repository.loadCatalog()
        assertTrue(result.modules.isEmpty())
        assertEquals(MarketErrorCode.NETWORK, (result.error as MarketException).code)
        assertEquals(listOf(selectedSource.url), server.requests.toList())
    }

    @Test fun supportsBoundedHttpsRedirectsWithinTheSameResourceDirectory() = runBlocking {
        val redirected = selectedSource.url.replace("market.json", "current.json")
        val catalog = fixture.catalog(fixture.module())
        server.bytes(redirected, catalog)
        server.routes[selectedSource.url] = { chain -> response(chain.request(), byteArrayOf().toResponseBody(), 302)
            .newBuilder().header("Location", "current.json").build() }
        assertEquals(1, repository.loadCatalog().modules.size)
        assertTrue(redirected in server.requests)
    }

    @Test fun rejectsAnOversizedHttpCatalogBeforeParsingOrCaching() = runBlocking {
        server.bytes(selectedSource.url, ByteArray(MarketCatalogCodec.MAX_CATALOG_BYTES + 1))
        val result = repository.loadCatalog()
        assertTrue(result.modules.isEmpty())
        assertEquals(MarketErrorCode.CATALOG_INVALID, (result.error as MarketException).code)
        assertTrue(File(root, "cache").walkTopDown().none { it.isFile })
    }

    @Test fun validatesSourceChangesAndResetsToThePinnedOfficialIdentity() {
        repository.saveSource("https://new.example.test/market.json", fixture.key)
        assertEquals("https://new.example.test/market.json", repository.source().url)
        assertFalse(repository.source().isOfficial)
        repository.resetSource()
        assertEquals(MapleMarketRepository.officialSource(), repository.source())
    }

    private fun serveCatalog(module: JSONObject) {
        val bytes = fixture.catalog(module)
        server.bytes(selectedSource.url, bytes)
        server.bytes(MarketCatalogCodec.signatureUrl(selectedSource.url), fixture.sign(bytes))
    }

    private fun newRepository() = MapleMarketRepository(File(root, "files"), File(root, "cache"),
        readSource = { selectedSource }, writeSource = { selectedSource = it ?: MapleMarketRepository.officialSource() },
        client = OkHttpClient.Builder().addInterceptor(server).build())

    private suspend fun rejectsSuspend(code: MarketErrorCode, block: suspend () -> Unit) {
        try { block(); fail("Expected $code") }
        catch (error: MarketException) { assertEquals(error.message, code, error.code) }
    }

    private class FixtureServer : Interceptor {
        val routes = ConcurrentHashMap<String, (Interceptor.Chain) -> Response>()
        val requests = CopyOnWriteArrayList<String>()
        fun bytes(url: String, bytes: ByteArray) { routes[url] = { chain -> response(chain.request(), bytes.toResponseBody()) } }
        override fun intercept(chain: Interceptor.Chain): Response {
            val url = chain.request().url.toString()
            requests += url
            return routes[url]?.invoke(chain) ?: throw IOException("Offline fixture: $url")
        }
    }

    companion object {
        private fun response(request: Request, body: ResponseBody, code: Int = 200): Response = Response.Builder()
            .request(request).protocol(Protocol.HTTP_1_1).code(code).message("fixture").body(body).build()
    }
}
