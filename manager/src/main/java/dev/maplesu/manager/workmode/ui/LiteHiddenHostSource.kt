package dev.maplesu.manager.workmode.ui

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.drawable.Drawable
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import dev.maplesu.manager.litehidden.HiddenFailure
import dev.maplesu.manager.litehidden.HiddenHostPolicy
import dev.maplesu.manager.litehidden.HostAppFacts
import dev.maplesu.manager.litehidden.HostCandidate
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

/**
 * 宿主候选扫描结果。失败时**不**用空列表假装"没有可用应用"：
 * [failure]/[code] 必须是非空原因，UI 直接显示短句。
 */
data class HostCandidateResult(
    val candidates: List<HostCandidate> = emptyList(),
    /** 包名 → 图标（只在内存；不落盘）。 */
    val icons: Map<String, ImageBitmap> = emptyMap(),
    val failure: HiddenFailure? = null,
    val code: String = "",
) {
    val ok: Boolean get() = failure == null
}

/** 宿主候选来源（可注入 fake；生产实现见 [PackageManagerHostSource]）。 */
interface HostCandidateSource {
    suspend fun load(): HostCandidateResult
}

/** 可注入装配点：测试/预览可替换，不阻塞 UI。 */
object LiteHiddenHostSources {
    @Volatile
    var current: HostCandidateSource? = null

    fun forContext(context: Context): HostCandidateSource = PackageManagerHostSource(context.applicationContext)
}

/**
 * PackageManager 扫描：只读应用列表与图标，筛选规则全在 [HiddenHostPolicy]（纯 Kotlin）。
 *
 * 事实来源（不猜）：
 * - 系统应用 = `FLAG_SYSTEM` / `FLAG_UPDATED_SYSTEM_APP`；
 * - ABI = `primaryCpuAbi` + `nativeLibraryDir` 末段（设备上目录名是 `arm64` 而非 `arm64-v8a`，需归一）；
 * - 有 native 库 = nativeLibraryDir 下确实存在 `.so` 文件（不是"目录存在"）。
 */
class PackageManagerHostSource(private val context: Context) : HostCandidateSource {

    override suspend fun load(): HostCandidateResult = withContext(Dispatchers.IO) {
        runCatching {
            val pm = context.packageManager
            val self = setOf(context.packageName) + HiddenHostPolicy.SELF_PACKAGES
            val facts = pm.getInstalledApplications(0).map { it.toFacts(pm) }
            val candidates = HiddenHostPolicy.candidates(facts, self)
            val icons = buildMap {
                candidates.forEach { candidate ->
                    iconOf(pm, candidate.packageName)?.let { put(candidate.packageName, it) }
                }
            }
            HostCandidateResult(candidates = candidates, icons = icons)
        }.getOrElse {
            HostCandidateResult(
                failure = HiddenFailure.HOST_SCAN_FAILED,
                code = HiddenFailure.HOST_SCAN_FAILED.wire,
            )
        }
    }

    private fun ApplicationInfo.toFacts(pm: PackageManager): HostAppFacts {
        // `primaryCpuAbi` 不在公开 SDK 里；ABI 直接取自 nativeLibraryDir 末段
        // （设备上目录名是 `arm64` / `arm`，由 [abiOfDirectory] 归一成官方 ABI 名）。
        val nativeDir = nativeLibraryDir?.takeIf { it.isNotBlank() }
        val abis = listOfNotNull(
            nativeDir?.let { abiOfDirectory(File(it).name) }?.takeIf { it.isNotBlank() },
        )
        val hasNativeLib = nativeDir
            ?.let { dir -> File(dir).listFiles()?.any { it.isFile && it.name.endsWith(".so") } == true }
            ?: false
        val label = runCatching { pm.getApplicationLabel(this).toString() }.getOrDefault("")
        return HostAppFacts(
            packageName = packageName,
            label = label,
            isSystem = (flags and (ApplicationInfo.FLAG_SYSTEM or ApplicationInfo.FLAG_UPDATED_SYSTEM_APP)) != 0,
            abis = abis,
            hasNativeLib = hasNativeLib,
        )
    }

    private fun abiOfDirectory(name: String): String = when (name) {
        "arm64" -> HiddenHostPolicy.ARM64
        "arm" -> "armeabi-v7a"
        else -> name
    }

    private fun iconOf(pm: PackageManager, packageName: String): ImageBitmap? = runCatching {
        pm.getApplicationIcon(packageName).toImageBitmap(ICON_SIZE)
    }.getOrNull()

    private fun Drawable.toImageBitmap(size: Int): ImageBitmap {
        val bitmap = Bitmap.createBitmap(size, size, Bitmap.Config.ARGB_8888)
        setBounds(0, 0, size, size)
        draw(Canvas(bitmap))
        return bitmap.asImageBitmap()
    }

    private companion object {
        const val ICON_SIZE = 96
    }
}
