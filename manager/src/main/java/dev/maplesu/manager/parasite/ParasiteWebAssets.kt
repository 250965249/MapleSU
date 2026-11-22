package dev.maplesu.manager.parasite

import dev.maplesu.manager.workmode.Hashes
import java.io.File

data class WebAssetEntry(
    val path: String,
    val mime: String,
    val size: Long,
    val sha256: String,
)

data class WebAssetManifest(
    val version: Int = 1,
    val bundleName: String,
    val bundleFormat: String,
    val entries: List<WebAssetEntry>,
    val routes: List<String>,
)

data class WebAssetVerification(
    val ok: Boolean,
    val missing: List<String> = emptyList(),
    val manifest: WebAssetManifest? = null,
)

/** 打包产物绑定接口：Ultra 侧实现（读取 generated header / ZIP 字节）；当前不可用。 */
interface ParasiteWebBundle {
    val bundleName: String
    val bundleFormat: String
    /** 原始 ZIP 字节（未补齐前的长度由实现解释）；不可用返回 null。 */
    fun bytes(): ByteArray?

    fun size(): Int
}

/** 当前没有可用的 web 资源打包产物（Ultra SDK 侧未生成/未链接）。 */
object UnavailableParasiteWebBundle : ParasiteWebBundle {
    override val bundleName: String = ParasiteWebAssets.BUNDLE_NAME
    override val bundleFormat: String = ParasiteWebAssets.BUNDLE_FORMAT
    override fun bytes(): ByteArray? = null
    override fun size(): Int = 0
}

object ParasiteWebAssets {
    /** 与 `build_parasite_web_assets.ps1` 的常量一致。 */
    const val BUNDLE_NAME = "parasite_web_assets"
    const val BUNDLE_FORMAT = "zip"
    const val GENERATED_HEADER = "parasite_web_assets_bundle.generated.h"
    const val SOURCE_DIR = "runtime/maplesu-sdk/include/maplesu_sdk/parasite_app/web_assets/src"

    /** 最低页面路由（规格 §4.5 的"至少包含"）。 */
    val REQUIRED_ROUTES: List<String> = listOf(
        "status",
        "authorizations",
        "backup",
        "restore",
        "detach",
    )

    val REQUIRED_FILES: List<String> = listOf("index.html", "app.js", "styles.css")

    private val MIME = mapOf(
        "html" to "text/html",
        "js" to "text/javascript",
        "css" to "text/css",
        "json" to "application/json",
        "svg" to "image/svg+xml",
        "png" to "image/png",
        "ico" to "image/x-icon",
        "woff2" to "font/woff2",
        "map" to "application/json",
    )

    /** 期望清单（未读取实际产物时的声明；用于基线检查与文档）。 */
    fun expectedManifest(): WebAssetManifest = WebAssetManifest(
        bundleName = BUNDLE_NAME,
        bundleFormat = BUNDLE_FORMAT,
        entries = REQUIRED_FILES.map { path ->
            WebAssetEntry(path, mimeOf(path), size = 0, sha256 = "")
        },
        routes = REQUIRED_ROUTES,
    )

    /** 从实际资源目录读取清单（主机测试/打包校验用；只读，不生成二进制）。 */
    fun readFromDirectory(root: File): WebAssetManifest {
        val entries = root.walkTopDown()
            .filter { it.isFile }
            .map { file ->
                val relative = file.relativeTo(root).invariantSeparatorsPath
                val bytes = file.readBytes()
                WebAssetEntry(relative, mimeOf(relative), bytes.size.toLong(), Hashes.sha256(bytes))
            }
            .sortedBy { it.path }
            .toList()
        return WebAssetManifest(
            bundleName = BUNDLE_NAME,
            bundleFormat = BUNDLE_FORMAT,
            entries = entries,
            routes = REQUIRED_ROUTES,
        )
    }

    /** 校验资源目录是否具备最低可用集合（缺文件 → ok=false + missing）。 */
    fun verifyDirectory(root: File): WebAssetVerification {
        val manifest = readFromDirectory(root)
        val present = manifest.entries.map { it.path }.toSet()
        val missing = REQUIRED_FILES.filterNot { it in present }
        return WebAssetVerification(
            ok = missing.isEmpty() && root.isDirectory,
            missing = missing,
            manifest = manifest,
        )
    }

    fun mimeOf(path: String): String = MIME[path.substringAfterLast('.', "").lowercase()]
        ?: "application/octet-stream"
}
