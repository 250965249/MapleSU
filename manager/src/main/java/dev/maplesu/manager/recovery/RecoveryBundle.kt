package dev.maplesu.manager.recovery

import dev.maplesu.manager.workmode.Hashes
import java.io.File

/**
 * 真实卸载前的私有恢复备份（P0 安全升级）。
 *
 * 目录 `/data/adb/maplesu/recovery`（0700，文件 0600）：APK、webui.conf、web 资源、native 库与
 * manifest；每个文件**逐项 sha256 读回验证**，任何一项失败 → 禁止卸载（fail-closed）。
 * 逻辑通过 [RecoveryFs] 抽象，主机测试用 [LocalRecoveryFs]（临时目录）。
 */
object RecoveryPaths {
    const val DIR = "/data/adb/maplesu/recovery"
    const val MANIFEST = "$DIR/manifest.json"
    const val APK = "$DIR/manager.apk"
    const val ASSETS_DIR = "$DIR/assets/liteweb"
    const val LIB_DIR = "$DIR/lib"
    const val WEBUI_CONFIG = "$DIR/webui.conf"
    const val HIDDEN_STATE = "/data/adb/maplesu/lite_hidden"
    const val DAEMON_CONFIG = WEBUI_CONFIG

    fun isSecureDir(path: String): Boolean = path.startsWith("/data/adb/")
}

/** 可注入文件系统：设备侧由 root 脚本实现；主机测试用本地 tmp。 */
interface RecoveryFs {
    fun ensureDirectory(path: String, mode: Int): Boolean
    fun exists(path: String): Boolean
    fun copy(source: String, destination: String, mode: Int): Boolean
    fun write(path: String, bytes: ByteArray, mode: Int): Boolean
    fun read(path: String): ByteArray?
    fun sha256(path: String): String?
    fun size(path: String): Long?
    fun deleteRecursively(path: String)
}

/** 主机测试 / root 已就绪场景的本地文件系统实现（mode 仅记录，不 chmod）。 */
class LocalRecoveryFs : RecoveryFs {
    override fun ensureDirectory(path: String, mode: Int): Boolean =
        runCatching { File(path).isDirectory || File(path).mkdirs() }.getOrDefault(false)

    override fun exists(path: String): Boolean = File(path).exists()

    override fun copy(source: String, destination: String, mode: Int): Boolean = runCatching {
        val target = File(destination)
        target.parentFile?.mkdirs()
        File(source).copyTo(target, overwrite = true)
        target.isFile
    }.getOrDefault(false)

    override fun write(path: String, bytes: ByteArray, mode: Int): Boolean = runCatching {
        val target = File(path)
        target.parentFile?.mkdirs()
        target.writeBytes(bytes)
        target.isFile && target.length() == bytes.size.toLong()
    }.getOrDefault(false)

    override fun read(path: String): ByteArray? = runCatching { File(path).readBytes() }.getOrNull()

    override fun sha256(path: String): String? = runCatching {
        val file = File(path)
        if (!file.isFile) null else Hashes.sha256(file.readBytes())
    }.getOrNull()

    override fun size(path: String): Long? =
        runCatching { File(path).takeIf { it.isFile }?.length() }.getOrNull()

    override fun deleteRecursively(path: String) {
        runCatching { File(path).deleteRecursively() }
    }
}

data class RecoverySource(
    val role: String,
    val sourcePath: String,
    val relativePath: String,
    val mode: Int = 0x180,
)

@kotlinx.serialization.Serializable
data class RecoveryItem(
    val role: String,
    val relativePath: String,
    val size: Long,
    val sha256: String,
    val mode: Int,
)

@kotlinx.serialization.Serializable
data class RecoveryManifest(
    val schema: Int = SCHEMA,
    val packageName: String,
    val versionCode: Long,
    val createdAt: Long,
    val apkSha256: String,
    val apkSize: Long,
    val items: List<RecoveryItem>,
    val integritySha256: String = "",
) {
    companion object { const val SCHEMA = 1 }
}

sealed interface RecoveryPrepareResult {
    data class Ok(val manifest: RecoveryManifest) : RecoveryPrepareResult
    data class Failed(val code: String, val detail: String = "") : RecoveryPrepareResult
}

data class RecoveryVerification(
    val ok: Boolean,
    val code: String = "",
    val manifest: RecoveryManifest? = null,
    val problems: List<String> = emptyList(),
)

object RecoveryCodes {
    const val LOCATION_INSECURE = "RECOVERY_LOCATION_INSECURE"
    const val PREPARE_FAILED = "RECOVERY_PREPARE_FAILED"
    const val SOURCE_UNREADABLE = "RECOVERY_SOURCE_UNREADABLE"
    const val COPY_FAILED = "RECOVERY_COPY_FAILED"
    const val SHA_READBACK_FAILED = "RECOVERY_SHA_READBACK_FAILED"
    const val MANIFEST_WRITE_FAILED = "RECOVERY_MANIFEST_WRITE_FAILED"
    const val MANIFEST_CORRUPT = "RECOVERY_MANIFEST_CORRUPT"
    const val MANIFEST_MISSING = "RECOVERY_MANIFEST_MISSING"
    const val VERIFY_FAILED = "RECOVERY_VERIFY_FAILED"
}

class RecoveryBundle(
    private val fs: RecoveryFs,
    private val directory: String = RecoveryPaths.DIR,
    private val clock: () -> Long = { System.currentTimeMillis() },
    private val locationPolicy: (String) -> Boolean = RecoveryPaths::isSecureDir,
) {
    private val json = kotlinx.serialization.json.Json {
        encodeDefaults = true
        ignoreUnknownKeys = true
    }
    private val serializer = RecoveryManifest.serializer()

    fun prepare(
        packageName: String,
        versionCode: Long,
        apkSourcePath: String,
        extras: List<RecoverySource> = emptyList(),
        webuiConfig: ByteArray? = null,
    ): RecoveryPrepareResult {
        if (!locationPolicy(directory)) return RecoveryPrepareResult.Failed(RecoveryCodes.LOCATION_INSECURE)
        fs.deleteRecursively(directory)
        if (!fs.ensureDirectory(directory, DIR_MODE)) {
            return RecoveryPrepareResult.Failed(RecoveryCodes.PREPARE_FAILED, "mkdir")
        }
        val sources = buildList {
            add(RecoverySource("APK", apkSourcePath, "manager.apk", FILE_MODE))
            addAll(extras)
        }
        val items = mutableListOf<RecoveryItem>()
        for (source in sources) {
            val sourceSha = fs.sha256(source.sourcePath)
                ?: return fail(RecoveryCodes.SOURCE_UNREADABLE, source.sourcePath)
            val destination = "$directory/${source.relativePath}"
            if (!fs.copy(source.sourcePath, destination, source.mode)) {
                return fail(RecoveryCodes.COPY_FAILED, source.relativePath)
            }
            val readbackSha = fs.sha256(destination)
            val readbackSize = fs.size(destination)
            if (readbackSha != sourceSha || readbackSize == null) {
                return fail(RecoveryCodes.SHA_READBACK_FAILED, source.relativePath)
            }
            items += RecoveryItem(source.role, source.relativePath, readbackSize, readbackSha, source.mode)
        }
        if (webuiConfig != null) {
            val path = "$directory/webui.conf"
            if (!fs.write(path, webuiConfig, FILE_MODE) || fs.sha256(path) == null) {
                return fail(RecoveryCodes.MANIFEST_WRITE_FAILED, "webui.conf")
            }
            items += RecoveryItem(
                "WEBUI_CONFIG", "webui.conf", webuiConfig.size.toLong(), fs.sha256(path)!!, FILE_MODE,
            )
        }
        val apkItem = items.first { it.role == "APK" }
        val manifest = RecoveryManifest(
            packageName = packageName,
            versionCode = versionCode,
            createdAt = clock(),
            apkSha256 = apkItem.sha256,
            apkSize = apkItem.size,
            items = items.sortedBy { it.role + it.relativePath },
        )
        val sealed = manifest.copy(integritySha256 = integrity(manifest))
        val bytes = json.encodeToString(serializer, sealed).toByteArray(Charsets.UTF_8)
        val manifestPath = "$directory/manifest.json"
        if (!fs.write(manifestPath, bytes, FILE_MODE)) {
            return fail(RecoveryCodes.MANIFEST_WRITE_FAILED, "manifest")
        }
        // 清单也必须读回校验（掉电一致性/损坏检测）。
        val readBack = fs.read(manifestPath)
        val decoded = readBack?.let { runCatching { json.decodeFromString(serializer, it.toString(Charsets.UTF_8)) }.getOrNull() }
        if (decoded == null || decoded.integritySha256 != integrity(decoded)) {
            return fail(RecoveryCodes.MANIFEST_WRITE_FAILED, "manifest readback")
        }
        return RecoveryPrepareResult.Ok(decoded)
    }

    fun verify(): RecoveryVerification {
        if (!locationPolicy(directory)) {
            return RecoveryVerification(false, RecoveryCodes.LOCATION_INSECURE)
        }
        val manifestBytes = fs.read("$directory/manifest.json")
            ?: return RecoveryVerification(false, RecoveryCodes.MANIFEST_MISSING)
        val manifest = runCatching {
            json.decodeFromString(serializer, manifestBytes.toString(Charsets.UTF_8))
        }.getOrNull() ?: return RecoveryVerification(false, RecoveryCodes.MANIFEST_CORRUPT)
        if (manifest.schema > RecoveryManifest.SCHEMA) {
            return RecoveryVerification(false, RecoveryCodes.MANIFEST_CORRUPT, manifest, listOf("schema"))
        }
        if (manifest.integritySha256 != integrity(manifest)) {
            return RecoveryVerification(false, RecoveryCodes.MANIFEST_CORRUPT, manifest, listOf("integrity"))
        }
        val problems = mutableListOf<String>()
        for (item in manifest.items) {
            val path = "$directory/${item.relativePath}"
            val size = fs.size(path)
            val sha = fs.sha256(path)
            if (size == null || sha == null) {
                problems += "missing:${item.relativePath}"
                continue
            }
            if (size != item.size) problems += "size:${item.relativePath}"
            if (sha != item.sha256) problems += "sha:${item.relativePath}"
        }
        if (problems.isEmpty()) return RecoveryVerification(true, manifest = manifest)
        return RecoveryVerification(false, RecoveryCodes.VERIFY_FAILED, manifest, problems)
    }

    fun integrity(manifest: RecoveryManifest): String =
        Hashes.sha256(json.encodeToString(serializer, manifest.copy(integritySha256 = "")).toByteArray())

    private fun fail(code: String, detail: String): RecoveryPrepareResult.Failed {
        fs.deleteRecursively(directory)
        return RecoveryPrepareResult.Failed(code, detail)
    }

    private companion object {
        const val DIR_MODE = 0x1C0
        const val FILE_MODE = 0x180
    }
}
