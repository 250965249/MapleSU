package dev.maplesu.manager.parasite

import dev.maplesu.manager.workmode.Hashes
import dev.maplesu.manager.workmode.control.AtomicControlFile
import dev.maplesu.manager.workmode.control.ControlJsonCodec
import dev.maplesu.manager.workmode.control.ShaCheck
import dev.maplesu.manager.workmode.detect.BootIdSource
import dev.maplesu.manager.workmode.detect.Clock
import dev.maplesu.manager.workmode.detect.ProcBootIdSource
import dev.maplesu.manager.workmode.detect.WallClock
import kotlinx.serialization.Serializable
import java.io.File

/**
 * 私有恢复备份（规格 §4.7–§4.10 / 本轮任务 3）。
 *
 * 边界（访问控制目标）：备份放在**控制面** `/data/adb/maplesu-workmode/parasite/recovery`
 * （0700 root，普通 App/其他用户不可读）；主机测试用注入目录 + [locationPolicy]。
 * 只备份"可迁移的既有资料"，不写明文口令/管理凭据；清单最后写（掉电一致性：
 * 新备份未完成读回前，上一份已验证恢复点保持不动）。
 *
 * 恢复动作**只从备份还原**，且先做完整性预检：manifest 缺失/损坏/逐文件 sha 不符
 * → 阻断（`RECOVERY_VERIFICATION_FAILED`），绝不"尽力而为"地当成功。
 */
@Serializable
data class ParasiteRecoveryManifest(
    val schema: Int = SCHEMA,
    val backupId: String,
    val registrationId: String,
    val hostPackage: String,
    val createdAt: Long,
    val bootId: String,
    val sourceVersion: String,
    val files: List<RecoveryFileEntry>,
    /** canonical manifest（自身字段置空后）的 sha256。 */
    val integritySha256: String = "",
) {
    companion object { const val SCHEMA = 1 }
}

@Serializable
data class RecoveryFileEntry(
    /** "APK" | "SPLIT" | "CONFIG" | "AUTHORIZATION" | "RUNTIME_ORIGIN" | "USER_RECOVERY"。 */
    val role: String,
    /** 原始路径（审计用；不参与恢复目标解析）。 */
    val sourcePath: String,
    /** 相对备份根的路径（恢复时只解析它，防目录穿越由 store 校验）。 */
    val relativePath: String,
    val size: Long,
    val sha256: String,
    val mode: Int = 0,
    val uid: Int = 0,
    val gid: Int = 0,
    val selinux: String? = null,
)

/** 备份输入（设备侧 source 读权限由 root 适配器保证；host 用普通文件）。 */
data class RecoverySource(
    val role: String,
    val sourceFile: File,
    val relativePath: String,
    val mode: Int = 0,
    val uid: Int = 0,
    val gid: Int = 0,
    val selinux: String? = null,
)

/** 可注入文件操作：真机可换成 root 会话实现；主机测试可注入失败。 */
interface RecoveryFileOps {
    fun read(file: File): ByteArray?
    fun write(file: File, bytes: ByteArray): Boolean
    fun deleteRecursively(file: File)
}

class RealRecoveryFileOps : RecoveryFileOps {
    override fun read(file: File): ByteArray? = runCatching { file.readBytes() }.getOrNull()

    override fun write(file: File, bytes: ByteArray): Boolean = runCatching {
        file.parentFile?.let { if (!it.exists()) it.mkdirs() }
        file.writeBytes(bytes)
        file.isFile && file.length() == bytes.size.toLong()
    }.getOrDefault(false)

    override fun deleteRecursively(file: File) {
        runCatching { file.deleteRecursively() }
    }
}

sealed interface RecoveryBackupResult {
    data class Ok(val manifest: ParasiteRecoveryManifest) : RecoveryBackupResult
    data class Failed(val code: String, val detail: String = "") : RecoveryBackupResult
}

data class RecoveryVerification(
    val ok: Boolean,
    val code: String = "",
    val manifest: ParasiteRecoveryManifest? = null,
    val problems: List<String> = emptyList(),
)

data class RecoveryRestoreResult(
    val ok: Boolean,
    val code: String = "",
    val restored: List<String> = emptyList(),
    val failed: List<String> = emptyList(),
    val problems: List<String> = emptyList(),
)

class ParasiteRecoveryStore(
    private val root: File = File(ParasitePaths.RECOVERY),
    private val ops: RecoveryFileOps = RealRecoveryFileOps(),
    private val clock: Clock = WallClock,
    private val bootIdSource: BootIdSource = ProcBootIdSource,
    private val locationPolicy: (File) -> Boolean = ParasitePaths::isControlPlanePath,
) {
    fun backup(
        registrationId: String,
        hostPackage: String,
        sourceVersion: String,
        sources: List<RecoverySource>,
        backupId: String = "bk-${clock.nowMillis()}",
    ): RecoveryBackupResult {
        if (!locationPolicy(root)) {
            return RecoveryBackupResult.Failed(CODES.LOCATION_INSECURE, "recovery root must be control plane")
        }
        if (sources.isEmpty()) {
            return RecoveryBackupResult.Failed(CODES.BACKUP_EMPTY, "no sources")
        }
        val backupDirectory = File(root, backupId)
        val entries = mutableListOf<RecoveryFileEntry>()
        try {
            for (source in sources) {
                val relative = sanitizeRelative(source.relativePath)
                    ?: return failAndCleanup(backupDirectory, CODES.RELATIVE_PATH_INVALID, source.relativePath)
                val payload = File(backupDirectory, "files/$relative")
                val bytes = ops.read(source.sourceFile)
                    ?: return failAndCleanup(
                        backupDirectory, CODES.SOURCE_UNREADABLE, source.sourceFile.absolutePath,
                    )
                if (!ops.write(payload, bytes)) {
                    return failAndCleanup(backupDirectory, CODES.BACKUP_WRITE_FAILED, source.relativePath)
                }
                val readBack = ops.read(payload)
                if (readBack == null || readBack.size != bytes.size ||
                    Hashes.sha256(readBack) != Hashes.sha256(bytes)
                ) {
                    return failAndCleanup(backupDirectory, CODES.BACKUP_READBACK_FAILED, source.relativePath)
                }
                entries += RecoveryFileEntry(
                    role = source.role,
                    sourcePath = source.sourceFile.absolutePath,
                    relativePath = relative,
                    size = bytes.size.toLong(),
                    sha256 = Hashes.sha256(bytes),
                    mode = source.mode,
                    uid = source.uid,
                    gid = source.gid,
                    selinux = source.selinux,
                )
            }
            // 清单最后写（掉电时半备份不可用，上一份已验证恢复点保持不变）。
            val draft = ParasiteRecoveryManifest(
                backupId = backupId,
                registrationId = registrationId,
                hostPackage = hostPackage,
                createdAt = clock.nowMillis(),
                bootId = bootIdSource.read(),
                sourceVersion = sourceVersion,
                files = entries.sortedBy { it.role + it.relativePath },
            )
            val manifest = draft.copy(integritySha256 = computeIntegrity(draft))
            val manifestFile = File(backupDirectory, MANIFEST_NAME)
            AtomicControlFile.writeJson(
                manifestFile,
                ControlJsonCodec.encode(manifest, ParasiteRecoveryManifest.serializer()),
            )
            // 清单读回校验（掉电一致性：只有读回通过才算备份完成）。
            val readBack = runCatching { manifestFile.readText(Charsets.UTF_8) }.getOrNull()
            val decoded = readBack?.let {
                ControlJsonCodec.decodeOrNull(it, ParasiteRecoveryManifest.serializer())
            }
            if (decoded == null || decoded.integritySha256 != computeIntegrity(decoded)) {
                return failAndCleanup(backupDirectory, CODES.BACKUP_READBACK_FAILED, "manifest")
            }
            return RecoveryBackupResult.Ok(decoded)
        } catch (error: Throwable) {
            return failAndCleanup(backupDirectory, CODES.BACKUP_WRITE_FAILED, error.javaClass.simpleName)
        }
    }

    /** 完整性预检：manifest 存在/可解析/sha 校验/自身 integrity 重算一致/逐文件 size+sha。 */
    fun verify(backupId: String): RecoveryVerification {
        val backupDirectory = File(root, backupId)
        val manifestFile = File(backupDirectory, MANIFEST_NAME)
        if (!manifestFile.isFile) {
            return RecoveryVerification(false, CODES.RECOVERY_MISSING)
        }
        if (AtomicControlFile.verifySha(manifestFile) == ShaCheck.MISMATCH) {
            return RecoveryVerification(false, CODES.MANIFEST_CORRUPT, problems = listOf("manifest sha mismatch"))
        }
        val manifest = runCatching { manifestFile.readText(Charsets.UTF_8) }.getOrNull()
            ?.let { ControlJsonCodec.decodeOrNull(it, ParasiteRecoveryManifest.serializer()) }
            ?: return RecoveryVerification(false, CODES.MANIFEST_CORRUPT, problems = listOf("parse failed"))
        if (manifest.schema > ParasiteRecoveryManifest.SCHEMA) {
            return RecoveryVerification(false, CODES.MANIFEST_CORRUPT, manifest, listOf("schema too new"))
        }
        if (manifest.integritySha256 != computeIntegrity(manifest)) {
            return RecoveryVerification(false, CODES.MANIFEST_CORRUPT, manifest, listOf("integrity mismatch"))
        }
        val problems = mutableListOf<String>()
        for (entry in manifest.files) {
            val payload = File(backupDirectory, "files/${sanitizeRelative(entry.relativePath) ?: entry.relativePath}")
            val bytes = ops.read(payload)
            if (bytes == null) {
                problems += "missing:${entry.relativePath}"
                continue
            }
            if (bytes.size.toLong() != entry.size) problems += "size:${entry.relativePath}"
            if (Hashes.sha256(bytes) != entry.sha256) problems += "sha:${entry.relativePath}"
        }
        return if (problems.isEmpty()) {
            RecoveryVerification(true, manifest = manifest)
        } else {
            RecoveryVerification(false, CODES.SHA_MISMATCH, manifest, problems)
        }
    }

    /** 只从备份还原：先 verify；失败 → 阻断（不写任何目标文件）。 */
    fun restore(backupId: String, targetRoot: File): RecoveryRestoreResult {
        val verification = verify(backupId)
        if (!verification.ok) {
            return RecoveryRestoreResult(
                ok = false,
                code = CODES.RECOVERY_VERIFICATION_FAILED,
                problems = verification.problems.ifEmpty { listOf(verification.code) },
            )
        }
        val manifest = verification.manifest!!
        val backupDirectory = File(root, backupId)
        val restored = mutableListOf<String>()
        val failed = mutableListOf<String>()
        val problems = mutableListOf<String>()
        for (entry in manifest.files) {
            val relative = sanitizeRelative(entry.relativePath)
            if (relative == null) {
                failed += entry.relativePath
                problems += "unsafe:${entry.relativePath}"
                continue
            }
            val bytes = ops.read(File(backupDirectory, "files/$relative"))
            if (bytes == null || Hashes.sha256(bytes) != entry.sha256) {
                failed += entry.relativePath
                problems += "payload:${entry.relativePath}"
                continue
            }
            val target = File(targetRoot, relative)
            // 防目录穿越：目标必须落在 targetRoot 下。
            if (!target.canonicalPath.startsWith(targetRoot.canonicalPath + File.separator) &&
                target.canonicalPath != targetRoot.canonicalPath
            ) {
                failed += entry.relativePath
                problems += "traversal:${entry.relativePath}"
                continue
            }
            if (!ops.write(target, bytes)) {
                failed += entry.relativePath
                problems += "write:${entry.relativePath}"
                continue
            }
            val readBack = ops.read(target)
            if (readBack == null || Hashes.sha256(readBack) != entry.sha256) {
                failed += entry.relativePath
                problems += "readback:${entry.relativePath}"
                continue
            }
            restored += relative
        }
        return if (failed.isEmpty()) {
            RecoveryRestoreResult(true, restored = restored)
        } else {
            RecoveryRestoreResult(false, CODES.RESTORE_FAILED, restored, failed, problems)
        }
    }

    fun list(): List<ParasiteRecoveryManifest> {
        if (!locationPolicy(root)) return emptyList()
        val directories = root.listFiles { file -> file.isDirectory }?.toList() ?: return emptyList()
        return directories.mapNotNull { directory ->
            val manifestFile = File(directory, MANIFEST_NAME)
            runCatching { manifestFile.readText(Charsets.UTF_8) }.getOrNull()
                ?.let { ControlJsonCodec.decodeOrNull(it, ParasiteRecoveryManifest.serializer()) }
        }.sortedBy { it.createdAt }
    }

    /** canonical（integrity 字段置空）sha256；字段变化即校验失败。 */
    fun computeIntegrity(manifest: ParasiteRecoveryManifest): String = Hashes.sha256Hex(
        ControlJsonCodec.encode(
            manifest.copy(integritySha256 = ""),
            ParasiteRecoveryManifest.serializer(),
        ),
    )

    private fun failAndCleanup(directory: File, code: String, detail: String): RecoveryBackupResult {
        ops.deleteRecursively(directory)
        return RecoveryBackupResult.Failed(code, detail)
    }

    private fun sanitizeRelative(relativePath: String): String? {
        val normalized = relativePath.replace('\\', '/').trimStart('/')
        if (normalized.isEmpty()) return null
        if (normalized.split('/').any { it.isEmpty() || it == ".." || it == "." }) return null
        return normalized
    }

    companion object {
        const val MANIFEST_NAME = "manifest.json"

        object CODES {
            const val LOCATION_INSECURE = "PARASITE_RECOVERY_LOCATION_INSECURE"
            const val BACKUP_EMPTY = "PARASITE_RECOVERY_BACKUP_EMPTY"
            const val BACKUP_WRITE_FAILED = "PARASITE_RECOVERY_BACKUP_WRITE_FAILED"
            const val BACKUP_READBACK_FAILED = "PARASITE_RECOVERY_BACKUP_READBACK_FAILED"
            const val SOURCE_UNREADABLE = "PARASITE_RECOVERY_SOURCE_UNREADABLE"
            const val RELATIVE_PATH_INVALID = "PARASITE_RECOVERY_PATH_INVALID"
            const val RECOVERY_MISSING = "PARASITE_RECOVERY_MISSING"
            const val MANIFEST_CORRUPT = "PARASITE_RECOVERY_MANIFEST_CORRUPT"
            const val SHA_MISMATCH = "PARASITE_RECOVERY_SHA_MISMATCH"
            const val RECOVERY_VERIFICATION_FAILED = "PARASITE_RECOVERY_VERIFICATION_FAILED"
            const val RESTORE_FAILED = "PARASITE_RECOVERY_RESTORE_FAILED"
        }
    }
}

/** 公开错误码（与内部 [ParasiteRecoveryStore.CODES] 同值；供 UI/测试/诊断引用）。 */
object ParasiteRecoveryCodes {
    const val LOCATION_INSECURE = "PARASITE_RECOVERY_LOCATION_INSECURE"
    const val BACKUP_EMPTY = "PARASITE_RECOVERY_BACKUP_EMPTY"
    const val BACKUP_WRITE_FAILED = "PARASITE_RECOVERY_BACKUP_WRITE_FAILED"
    const val BACKUP_READBACK_FAILED = "PARASITE_RECOVERY_BACKUP_READBACK_FAILED"
    const val SOURCE_UNREADABLE = "PARASITE_RECOVERY_SOURCE_UNREADABLE"
    const val RELATIVE_PATH_INVALID = "PARASITE_RECOVERY_PATH_INVALID"
    const val RECOVERY_MISSING = "PARASITE_RECOVERY_MISSING"
    const val MANIFEST_CORRUPT = "PARASITE_RECOVERY_MANIFEST_CORRUPT"
    const val SHA_MISMATCH = "PARASITE_RECOVERY_SHA_MISMATCH"
    const val RECOVERY_VERIFICATION_FAILED = "PARASITE_RECOVERY_VERIFICATION_FAILED"
    const val RESTORE_FAILED = "PARASITE_RECOVERY_RESTORE_FAILED"
}
