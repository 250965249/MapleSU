package dev.maplesu.manager.workmode.migration

import dev.maplesu.manager.workmode.control.AtomicControlFile
import dev.maplesu.manager.workmode.control.ControlJsonCodec
import dev.maplesu.manager.workmode.control.ControlPermissions
import dev.maplesu.manager.workmode.detect.BootIdSource
import dev.maplesu.manager.workmode.detect.Clock
import dev.maplesu.manager.workmode.detect.ProcBootIdSource
import dev.maplesu.manager.workmode.detect.WallClock
import kotlinx.serialization.Serializable
import java.io.File
import java.io.IOException

/**
 * 迁移备份（05 §2）：`migrations/<id>/backup/` 目录 + `manifest.json`（schema 1，字段级）。
 *
 * 硬规则：
 * - 先备份、后任何破坏性动作（主文档:1231）；
 * - 每个对象写后必须重读 SHA-256 校验（`readBack=true`）；
 * - 读不到的东西必须登记 `unreadable[]`，**不允许静默跳过**（主文档:1238 "无遗漏"）；
 * - manifest 自身原子发布（复用 [AtomicControlFile] 的 tmp→fsync→ATOMIC_MOVE→读回语义）。
 */
@Serializable
data class BackupObject(
    val id: String,
    /** PARTITION_IMAGE / EXTERNAL_STOCK_BACKUP / AUTH_ALLOWLIST / AUTH_DB / PACKAGES /
     *  MODULE_INDEX / MODULE_TAR / MANAGER_APK / CANDIDATE / USERLAND_TAR / EXTERNAL_DATA_TAR */
    val kind: String,
    val label: String,
    /** backup/ 内相对路径。 */
    val path: String,
    val size: Long,
    val sha256: String,
    val sourceKind: String = "EXTERNAL_FILE",
    val sourcePath: String = "",
    val partition: String = "",
    /** 写盘后 readAll + sha256 一致才 true。 */
    val readBack: Boolean = false,
    /** 分区副本要求两遍读取一致。 */
    val twiceRead: Boolean = false,
    /** KSU: 记录 sha1 是否被交叉校验。 */
    val sha1MatchesRecorded: Boolean = false,
)

@Serializable
data class BackupDevice(
    val kernelRelease: String = "",
    val firmware: String = "",
    val slotSuffix: String = "",
    val selinux: String = "Enforcing",
    val managerUid: Int = 0,
)

@Serializable
data class BackupDetect(
    val family: String = "",
    val version: String = "",
    val uapi: Int? = null,
    val managerPackages: List<String> = emptyList(),
    val restoreStrategy: String = "",
    val patchedPartitions: List<String> = emptyList(),
    val detectSha256: String = "",
)

@Serializable
data class UnreadableEntry(val path: String, val reason: String)

@Serializable
data class BackupManifest(
    val schema: Int = SCHEMA,
    val migrationId: String,
    val createdAtEpochMs: Long = 0,
    val createdBootId: String = "",
    val device: BackupDevice = BackupDevice(),
    val detect: BackupDetect = BackupDetect(),
    val targetMode: String = "",
    val restoreSet: List<String> = emptyList(),
    val objects: List<BackupObject> = emptyList(),
    val unreadable: List<UnreadableEntry> = emptyList(),
    val verified: Boolean = false,
    val verifiedAtEpochMs: Long = 0,
    val spaceRequiredBytes: Long = 0,
    val spaceFreeBytes: Long = 0,
) {
    companion object {
        const val SCHEMA = 1
    }

    fun objectOrNull(id: String): BackupObject? = objects.firstOrNull { it.id == id }

    /** canonical 形态：集合排序 + 对象按 id 排序（manifest sha 稳定）。 */
    fun normalized(): BackupManifest = copy(
        detect = detect.copy(
            managerPackages = detect.managerPackages.sorted(),
            patchedPartitions = detect.patchedPartitions.sorted(),
        ),
        restoreSet = restoreSet.sorted(),
        objects = objects.sortedBy { it.id },
        unreadable = unreadable.sortedWith(compareBy({ it.path }, { it.reason })),
    )
}

/** 读回校验结果（§2.5：M1 的完成判据）。 */
data class BackupVerification(
    val ok: Boolean,
    val checked: Int,
    val missing: List<String>,
    val mismatched: List<String>,
) {
    val failed: Boolean get() = !ok
}

@Serializable
data class RetentionFile(
    val schema: Int = SCHEMA,
    val migrationId: String,
    val createdAtEpochMs: Long = 0,
    val pinned: Boolean = true,
    val keepUntilEpochMs: Long,
    val readyToPurge: Boolean = false,
) {
    companion object {
        const val SCHEMA = 1
        const val DEFAULT_KEEP_DAYS = 7L
    }
}

/**
 * 备份管理器。`root` 在设备上 = `/data/adb/maplesu-workmode`，主机单测 = 临时目录。
 */
class MigrationBackup(
    private val root: File,
    private val clock: Clock = WallClock,
    private val bootIdSource: BootIdSource = ProcBootIdSource,
) {

    fun migrationDir(migrationId: String): File = MigrationPaths.migrationDir(root, migrationId)

    fun backupDir(migrationId: String): File = MigrationPaths.backupDir(root, migrationId)

    /** 建 `<root>/`、`backup/`、`backup/<子目录>/`、`secrets/`（0700 尽力）。 */
    fun ensureLayout(migrationId: String): File {
        MigrationPaths.requireCanonicalId(migrationId)
        val migration = migrationDir(migrationId)
        ControlPermissions.ensureDir(migration)
        ControlPermissions.ensureDir(secretsDir(migrationId))
        val backup = backupDir(migrationId)
        ControlPermissions.ensureDir(backup)
        MigrationPaths.BACKUP_SUBDIRS.forEach { sub ->
            ControlPermissions.ensureDir(File(backup, sub))
        }
        return backup
    }

    fun secretsDir(migrationId: String): File = MigrationPaths.secretsDir(root, migrationId)

    fun objectFile(migrationId: String, relativePath: String): File {
        val safe = MigrationPaths.requireSafeRelativePath(relativePath)
        return File(backupDir(migrationId), safe)
    }

    /** 复制一个普通文件进备份并返回带 SHA-256 的对象（写后重读校验）。 */
    fun captureFile(
        migrationId: String,
        source: File,
        relativePath: String,
        kind: String,
        label: String,
        sourceKind: String = "EXTERNAL_FILE",
        sourcePath: String = source.path,
        partition: String = "",
    ): BackupObject {
        MigrationFailure.require(
            source.isFile && !java.nio.file.Files.isSymbolicLink(source.toPath()),
            MigrationCodes.BACKUP_SOURCE_MISSING,
            source.path,
        )
        val destination = objectFile(migrationId, relativePath)
        destination.parentFile?.let { ControlPermissions.ensureDir(it) }
        source.copyTo(destination, overwrite = true)
        val expectedSize = source.length()
        return finishObject(
            destination = destination,
            relativePath = relativePath,
            kind = kind,
            label = label,
            sourceKind = sourceKind,
            sourcePath = sourcePath,
            partition = partition,
            expectedSize = expectedSize,
        )
    }

    /** 写入一组字节（per-module.json / detect.json 副本等小对象）。 */
    fun captureBytes(
        migrationId: String,
        bytes: ByteArray,
        relativePath: String,
        kind: String,
        label: String,
        sourceKind: String = "GENERATED",
        sourcePath: String = "",
        partition: String = "",
    ): BackupObject {
        val destination = objectFile(migrationId, relativePath)
        destination.parentFile?.let { ControlPermissions.ensureDir(it) }
        destination.writeBytes(bytes)
        return finishObject(
            destination = destination,
            relativePath = relativePath,
            kind = kind,
            label = label,
            sourceKind = sourceKind,
            sourcePath = sourcePath,
            partition = partition,
            expectedSize = bytes.size.toLong(),
        )
    }

    private fun finishObject(
        destination: File,
        relativePath: String,
        kind: String,
        label: String,
        sourceKind: String,
        sourcePath: String,
        partition: String,
        expectedSize: Long,
    ): BackupObject {
        val actualSize = destination.length()
        val sha = MigrationHashes.sha256(destination)
        MigrationFailure.require(
            actualSize == expectedSize && MigrationHashes.isHash(sha),
            MigrationCodes.BACKUP_VERIFY_FAILED,
            relativePath,
        )
        return BackupObject(
            id = "$kind.${label.ifBlank { relativePath }}",
            kind = kind,
            label = label,
            path = relativePath,
            size = actualSize,
            sha256 = sha,
            sourceKind = sourceKind,
            sourcePath = sourcePath,
            partition = partition,
            readBack = true,
        )
    }

    /** 原子写 manifest（canonical normalized）。 */
    fun writeManifest(manifest: BackupManifest): BackupManifest {
        MigrationPaths.requireCanonicalId(manifest.migrationId)
        val normalized = manifest.normalized()
        val file = MigrationPaths.manifest(root, manifest.migrationId)
        file.parentFile?.let { ControlPermissions.ensureDir(it) }
        val json = ControlJsonCodec.encode(normalized)
        AtomicControlFile.writeJson(file, json)
        return normalized
    }

    /** 读 manifest；缺失返回 null；schema/id 不符 → `MIGRATION_MANIFEST_INVALID`。 */
    fun readManifest(migrationId: String): BackupManifest? {
        val file = MigrationPaths.manifest(root, migrationId)
        if (!file.isFile) return null
        val raw = AtomicControlFile.readUtf8(file)
            ?: throw MigrationFailure(MigrationCodes.MANIFEST_INVALID, "unreadable")
        val manifest = ControlJsonCodec.decodeOrNull<BackupManifest>(raw)
            ?: throw MigrationFailure(MigrationCodes.MANIFEST_INVALID, "parse")
        if (manifest.schema != BackupManifest.SCHEMA) {
            throw MigrationFailure(MigrationCodes.MANIFEST_INVALID, "schema=${manifest.schema}")
        }
        if (manifest.migrationId != migrationId) {
            throw MigrationFailure(MigrationCodes.MANIFEST_INVALID, "migrationId")
        }
        return manifest
    }

    /** M1 完成判据：逐对象重读校验（§2.5）。 */
    fun verify(migrationId: String, manifest: BackupManifest): BackupVerification {
        val missing = mutableListOf<String>()
        val mismatched = mutableListOf<String>()
        var checked = 0
        for (obj in manifest.objects) {
            checked++
            val file = runCatching { objectFile(migrationId, obj.path) }.getOrNull()
            if (file == null || !file.isFile) {
                missing += obj.id
                continue
            }
            if (file.length() != obj.size || MigrationHashes.sha256(file) != obj.sha256) {
                mismatched += obj.id
            }
        }
        return BackupVerification(
            ok = missing.isEmpty() && mismatched.isEmpty(),
            checked = checked,
            missing = missing,
            mismatched = mismatched,
        )
    }

    /** 校验通过则标记 verified 并原子落盘；否则抛 `MIGRATION_BACKUP_VERIFY_FAILED:<id>`。 */
    fun markVerified(migrationId: String, manifest: BackupManifest): BackupManifest {
        val verification = verify(migrationId, manifest)
        MigrationFailure.require(
            verification.ok,
            MigrationCodes.BACKUP_VERIFY_FAILED,
            (verification.missing + verification.mismatched).joinToString(","),
        )
        return writeManifest(
            manifest.copy(verified = true, verifiedAtEpochMs = clock.nowMillis()),
        )
    }

    /** 硬门禁：未 verified 的 manifest 不允许进入 M2/commit（红线 11）。 */
    fun requireVerified(manifest: BackupManifest?) {
        MigrationFailure.require(
            manifest != null && manifest.verified,
            MigrationCodes.BACKUP_NOT_VERIFIED,
            "manifest",
        )
    }

    fun writeRetention(migrationId: String, keepUntilEpochMs: Long, readyToPurge: Boolean = false): RetentionFile {
        val file = RetentionFile(
            migrationId = migrationId,
            createdAtEpochMs = clock.nowMillis(),
            keepUntilEpochMs = keepUntilEpochMs,
            readyToPurge = readyToPurge,
        )
        val target = MigrationPaths.retention(root, migrationId)
        target.parentFile?.let { ControlPermissions.ensureDir(it) }
        AtomicControlFile.writeJson(target, ControlJsonCodec.encode(file))
        return file
    }

    fun readRetention(migrationId: String): RetentionFile? {
        val file = MigrationPaths.retention(root, migrationId)
        if (!file.isFile) return null
        val raw = AtomicControlFile.readUtf8(file) ?: return null
        return ControlJsonCodec.decodeOrNull<RetentionFile>(raw)
    }

    /** M9 成功后置 `readyToPurge=true`（保留期从创建时算 7 天）。 */
    fun markReadyToPurge(migrationId: String, keepDays: Long = RetentionFile.DEFAULT_KEEP_DAYS): RetentionFile {
        val existing = readRetention(migrationId)
        val keepUntil = existing?.keepUntilEpochMs
            ?: (clock.nowMillis() + keepDays * 24L * 60L * 60L * 1000L)
        return writeRetention(migrationId, keepUntil, readyToPurge = true)
    }

    /**
     * 清理判据（§2.6）：必须 readyToPurge + 已过保留期 + 用户显式确认；
     * 外部备份材料**绝不早于 M9**（主文档:1305）。
     */
    fun canPurge(migrationId: String, nowEpochMs: Long = clock.nowMillis(), userConfirmed: Boolean): Boolean {
        if (!userConfirmed) return false
        val retention = readRetention(migrationId) ?: return false
        return retention.readyToPurge && nowEpochMs >= retention.keepUntilEpochMs
    }

    /** 只删可重产的候选；backup/ 必须保留（回滚证据）。 */
    fun deleteCandidateArtifacts(migrationId: String) {
        File(backupDir(migrationId), "our").listFiles()?.forEach { candidate ->
            if (candidate.isDirectory) candidate.deleteRecursively() else candidate.delete()
        }
    }
}

/** 空间核算（05 §2.7）：不足即阻断，**禁止**降级为"无备份迁移"（主文档:1234）。 */
object SpaceEstimator {
    private const val TAR_OVERHEAD_FACTOR = 1.1
    private const val SAFETY_BYTES = 64L * 1024 * 1024

    fun estimate(
        partitionSizes: Map<String, Long>,
        restoreSet: Set<String>,
        targetSet: Set<String>,
        externalDataBytes: Long,
        apkBytes: Long,
        freeBytesOnData: Long,
    ): SpaceEstimate {
        val touched = (restoreSet + targetSet).mapNotNull { partitionSizes[it] }
        val partitionBytes = touched.sum()
        val backupEstimate = (partitionBytes * TAR_OVERHEAD_FACTOR).toLong() +
            externalDataBytes + apkBytes + SAFETY_BYTES
        val required = backupEstimate + 2 * partitionBytes
        return SpaceEstimate(
            backupEstimateBytes = backupEstimate,
            partitionBytes = partitionBytes,
            requiredBytes = required,
            freeBytesOnData = freeBytesOnData,
            adequate = freeBytesOnData >= required,
        )
    }
}
