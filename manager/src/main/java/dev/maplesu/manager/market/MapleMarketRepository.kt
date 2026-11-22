package dev.maplesu.manager.market

import android.content.Context
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.util.UUID
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import me.weishu.kernelsu.data.registry.DownloadVerificationException
import me.weishu.kernelsu.data.registry.ExpectedFile
import me.weishu.kernelsu.data.registry.RegistryDownloadStore
import okhttp3.Call
import okhttp3.Callback
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response

class MapleMarketRepository internal constructor(
    private val filesDir: File,
    private val cacheDir: File,
    private val readSource: () -> MarketSource,
    private val writeSource: (MarketSource?) -> Unit,
    client: OkHttpClient = OkHttpClient.Builder().connectTimeout(15, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS).build(),
) {
    constructor(context: Context) : this(
        context.applicationContext.filesDir,
        File(context.applicationContext.cacheDir, "maplesu-market"),
        sourceReader(context.applicationContext),
        sourceWriter(context.applicationContext),
    )

    private val client = client.newBuilder().followRedirects(false).followSslRedirects(false).build()
    @Volatile private var verifiedCatalog: Pair<String, List<MarketModule>>? = null

    fun source(): MarketSource = readSource()

    fun saveSource(url: String, key: String) {
        writeSource(MarketCatalogCodec.source(url, key))
        verifiedCatalog = null
    }

    fun resetSource() {
        writeSource(null)
        verifiedCatalog = null
    }

    suspend fun loadCatalog(): MarketCatalog = withContext(Dispatchers.IO) {
        val source = try {
            val current = source()
            MarketCatalogCodec.source(current.url, current.key, current.isOfficial)
        } catch (error: Exception) {
            return@withContext MarketCatalog(emptyList(), error = error)
        }
        val failures = mutableListOf<Throwable>()
        for (url in MarketCatalogCodec.endpoints(source)) {
            currentCoroutineContext().ensureActive()
            try {
                val bytes = bytes(url, MarketCatalogCodec.MAX_CATALOG_BYTES, MarketErrorCode.CATALOG_INVALID)
                val signature = bytes(MarketCatalogCodec.signatureUrl(url),
                    MarketCatalogCodec.MAX_SIGNATURE_BYTES, MarketErrorCode.SIGNATURE_INVALID)
                val modules = MarketCatalogCodec.parseVerified(bytes, signature, source, url)
                currentCoroutineContext().ensureActive()
                requireCurrentSource(source)
                // A cache write failure does not discard an already verified live catalog.
                val cacheError = try { writeCache(source, bytes, signature); null } catch (error: IOException) { error }
                verifiedCatalog = MarketCatalogCodec.identity(source) to modules
                return@withContext MarketCatalog(modules, error = cacheError)
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (error: Exception) {
                currentCoroutineContext().ensureActive()
                failures += error
            }
        }
        val failure = combinedFailure(failures)
        try {
            val modules = cachedModules(source)
            requireCurrentSource(source)
            verifiedCatalog = MarketCatalogCodec.identity(source) to modules
            MarketCatalog(modules, stale = true, error = failure)
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (error: Exception) {
            failure.addSuppressed(error)
            MarketCatalog(emptyList(), error = failure)
        }
    }

    suspend fun changelog(module: MarketModule): String = withContext(Dispatchers.IO) {
        val source = source()
        val trusted = trustedModule(source, module)
        val urls = trusted.changelogUrls.ifEmpty { listOfNotNull(trusted.changelogUrl.takeIf(String::isNotEmpty)) }
        if (urls.isEmpty()) return@withContext ""
        attemptUrls(urls) { url ->
            MarketCatalogCodec.utf8(bytes(url, MarketCatalogCodec.MAX_CHANGELOG_BYTES, MarketErrorCode.CATALOG_INVALID))
        }
    }

    suspend fun download(module: MarketModule, onProgress: (Float) -> Unit): File = withContext(Dispatchers.IO) {
        val source = source()
        val trusted = trustedModule(source, module)
        if (!trusted.installable) throw MarketException(MarketErrorCode.MODULE_UNAVAILABLE, "此模块暂不开放安装")
        val store = File(filesDir, RegistryDownloadStore.DIR_NAME)
        val expected = ExpectedFile(trusted.size, trusted.sha256)
        val fileName = RegistryDownloadStore.sanitizeFileName("${trusted.id}-${trusted.version}-${UUID.randomUUID()}.zip")
        attemptUrls(trusted.downloadUrls) { url ->
            requireCurrentSource(source)
            onProgress(0f)
            request(url, discard = { file -> RegistryDownloadStore.delete(store, file) }) { response, checkActive ->
                val length = response.body.contentLength()
                if (length >= 0 && length != trusted.size)
                    throw MarketException(MarketErrorCode.DOWNLOAD_INTEGRITY, "模块包大小与已验证清单不一致")
                try {
                    RegistryDownloadStore.download(
                        response.body.byteStream(), store, expected, fileName,
                        onProgress = { downloaded -> onProgress((downloaded.toDouble() / trusted.size).toFloat().coerceIn(0f, 1f)) },
                        checkActive = checkActive,
                    ).also { file ->
                        try {
                            checkActive()
                            requireCurrentSource(source)
                        } catch (error: Throwable) {
                            RegistryDownloadStore.delete(store, file)
                            throw error
                        }
                    }
                } catch (error: DownloadVerificationException) {
                    throw MarketException(MarketErrorCode.DOWNLOAD_INTEGRITY, "模块包摘要或大小校验失败", error)
                }
            }
        }
    }

    private fun trustedModule(source: MarketSource, module: MarketModule): MarketModule {
        val identity = MarketCatalogCodec.identity(source)
        if (module.catalogIdentity != identity)
            throw MarketException(MarketErrorCode.MODULE_UNAVAILABLE, "市场来源已变更，请重新选择模块")
        val modules = verifiedCatalog?.takeIf { it.first == identity }?.second ?: cachedModules(source)
        return modules.firstOrNull { it == module }
            ?: throw MarketException(MarketErrorCode.MODULE_UNAVAILABLE, "请从已验证的市场清单选择模块")
    }

    private fun requireCurrentSource(expected: MarketSource) {
        if (MarketCatalogCodec.identity(source()) != MarketCatalogCodec.identity(expected))
            throw MarketException(MarketErrorCode.INVALID_SOURCE, "市场来源已变更，请重新加载")
    }

    private suspend fun bytes(url: String, limit: Int, code: MarketErrorCode): ByteArray = request(url) { response, checkActive ->
        if (response.body.contentLength() > limit) throw MarketException(code, "市场资源超出大小限制")
        response.body.byteStream().use { input ->
            val output = ByteArrayOutputStream()
            val buffer = ByteArray(8192)
            while (true) {
                checkActive()
                val read = input.read(buffer)
                if (read == -1) break
                if (read > limit - output.size()) throw MarketException(code, "市场资源超出大小限制")
                output.write(buffer, 0, read)
            }
            output.toByteArray()
        }
    }

    private class Redirect(val url: String) : IOException()

    private suspend fun <T> request(
        url: String,
        discard: (T) -> Unit = {},
        read: (Response, () -> Unit) -> T,
    ): T {
        var current = url
        repeat(4) { hop ->
            try { return requestOnce(current, discard, read) }
            catch (redirect: Redirect) {
                if (hop == 3) throw MarketException(MarketErrorCode.NETWORK, "市场地址重定向次数过多")
                current = redirect.url
            }
        }
        throw MarketException(MarketErrorCode.NETWORK, "市场资源读取失败")
    }

    private suspend fun <T> requestOnce(
        url: String,
        discard: (T) -> Unit,
        read: (Response, () -> Unit) -> T,
    ): T = suspendCancellableCoroutine { continuation ->
        val requested = MarketCatalogCodec.httpsUrl(url)
        if (!MarketCatalogCodec.allowedResource(url, MarketCatalogCodec.endpoints(source()))) {
            continuation.resumeWith(Result.failure(MarketException(MarketErrorCode.INVALID_SOURCE, "资源地址不属于当前市场来源")))
            return@suspendCancellableCoroutine
        }
        val call = client.newCall(Request.Builder().url(requested).build())
        continuation.invokeOnCancellation { call.cancel() }
        call.enqueue(object : Callback {
            override fun onFailure(call: Call, error: IOException) {
                if (continuation.isActive) continuation.resumeWith(Result.failure(
                    MarketException(MarketErrorCode.NETWORK, "市场网络请求失败", error)))
            }

            override fun onResponse(call: Call, response: Response) {
                try {
                    val value = response.use {
                        if (!continuation.isActive) throw CancellationException("Market request cancelled")
                        if (response.code in setOf(301, 302, 303, 307, 308)) {
                            val target = response.header("Location")?.let(requested::resolve)
                            if (target == null || target.resolve("./") != requested.resolve("./") ||
                                !MarketCatalogCodec.allowedResource(target.toString(), MarketCatalogCodec.endpoints(source())))
                                throw MarketException(MarketErrorCode.NETWORK, "市场地址重定向超出可信来源目录")
                            throw Redirect(target.toString())
                        }
                        if (!response.isSuccessful) throw MarketException(MarketErrorCode.NETWORK, "市场请求返回 HTTP ${response.code}")
                        read(response) {
                            if (!continuation.isActive) throw CancellationException("Market request cancelled")
                        }
                    }
                    continuation.resume(value, onCancellation = { _, discarded, _ -> discard(discarded) })
                } catch (error: Exception) {
                    if (continuation.isActive) continuation.resumeWith(Result.failure(error))
                }
            }
        })
    }

    private suspend fun <T> attemptUrls(urls: List<String>, action: suspend (String) -> T): T {
        val failures = mutableListOf<Throwable>()
        for (url in urls.distinct()) {
            currentCoroutineContext().ensureActive()
            try { return action(url) }
            catch (cancelled: CancellationException) { throw cancelled }
            catch (error: IOException) {
                currentCoroutineContext().ensureActive()
                failures += error
            }
        }
        throw combinedFailure(failures)
    }

    private fun combinedFailure(failures: List<Throwable>): MarketException {
        val decisive = failures.firstOrNull { it is MarketException && it.code != MarketErrorCode.NETWORK }
            ?: failures.firstOrNull()
        return MarketException((decisive as? MarketException)?.code ?: MarketErrorCode.NETWORK,
            decisive?.message ?: "市场资源暂时不可用，请稍后重试", decisive).also { combined ->
            failures.filter { it !== decisive }.forEach(combined::addSuppressed)
        }
    }

    private fun cacheFile(source: MarketSource): File = File(File(cacheDir, MarketCatalogCodec.identity(source)), "catalog.bin")

    private fun cachedModules(source: MarketSource): List<MarketModule> {
        val file = cacheFile(source)
        if (!file.isFile || file.length() > MarketCatalogCodec.MAX_CATALOG_BYTES + MarketCatalogCodec.MAX_SIGNATURE_BYTES + 8L)
            throw MarketException(MarketErrorCode.CACHE_INVALID, "此市场暂无可用的离线清单")
        return DataInputStream(file.inputStream()).use { input ->
            val catalogSize = input.readInt()
            val signatureSize = input.readInt()
            if (catalogSize !in 1..MarketCatalogCodec.MAX_CATALOG_BYTES || signatureSize !in 1..MarketCatalogCodec.MAX_SIGNATURE_BYTES)
                throw MarketException(MarketErrorCode.CACHE_INVALID, "离线市场清单格式异常")
            val bytes = ByteArray(catalogSize).also(input::readFully)
            val signature = ByteArray(signatureSize).also(input::readFully)
            if (input.read() != -1) throw MarketException(MarketErrorCode.CACHE_INVALID, "离线市场清单格式异常")
            MarketCatalogCodec.parseVerified(bytes, signature, source, source.url)
        }
    }

    private fun writeCache(source: MarketSource, bytes: ByteArray, signature: ByteArray) {
        val target = cacheFile(source)
        val directory = target.parentFile!!
        if (!directory.isDirectory && !directory.mkdirs()) throw IOException("创建市场缓存失败")
        val temporary = File.createTempFile("catalog-", ".part", directory)
        try {
            FileOutputStream(temporary).use { stream ->
                val output = DataOutputStream(stream)
                output.writeInt(bytes.size)
                output.writeInt(signature.size)
                output.write(bytes)
                output.write(signature)
                output.flush()
                stream.fd.sync()
            }
            Files.move(temporary.toPath(), target.toPath(), StandardCopyOption.REPLACE_EXISTING)
        } finally { temporary.delete() }
    }

    companion object {
        fun officialSource(): MarketSource = MarketSource(MarketCatalogCodec.OFFICIAL_URL, MarketCatalogCodec.OFFICIAL_KEY, true)

        private fun sourceReader(context: Context): () -> MarketSource {
            val prefs = context.getSharedPreferences("maplesu-market", Context.MODE_PRIVATE)
            return {
                val url = prefs.getString("url", null)
                if (url == null) officialSource() else MarketSource(url, prefs.getString("key", "").orEmpty(), false)
            }
        }

        private fun sourceWriter(context: Context): (MarketSource?) -> Unit {
            val prefs = context.getSharedPreferences("maplesu-market", Context.MODE_PRIVATE)
            return { source ->
                prefs.edit().apply {
                    if (source == null) { remove("url"); remove("key") }
                    else { putString("url", source.url); putString("key", source.key) }
                }.apply()
            }
        }
    }
}
