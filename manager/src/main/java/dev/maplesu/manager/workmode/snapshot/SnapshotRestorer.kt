package dev.maplesu.manager.workmode.snapshot

import dev.maplesu.manager.workmode.Hashes
import dev.maplesu.manager.workmode.WorkMode
import dev.maplesu.manager.workmode.control.AtomicControlFile
import dev.maplesu.manager.workmode.control.schema.SnapshotEntry
import dev.maplesu.manager.workmode.control.schema.SnapshotManifest
import dev.maplesu.manager.workmode.detect.Clock
import dev.maplesu.manager.workmode.detect.WallClock
import java.io.File
import java.io.IOException
import java.nio.file.Files

/**
 * 清数据后的恢复：固定顺序
 * ① App 实体 → ② root 模块软链 → ③ 设置 merge；顺序违反会导致悬空引用。
 *
 * 宿主可测（appDir/storeRoot 用临时目录）；root 软链重建只消费 manifest 计数，
 * 真正重建需 root 会话（W05/W07 接线），此处明确返回 NO_ROOT blocker，绝不伪造成功。
 */
class FileSnapshotRestorer(
    private val appDir: File,
    private val storeRoot: File,
    private val clock: Clock = WallClock,
) {
    companion object {
        /** 恢复顺序（测试断言）：App 实体 → root 模块软链 → 设置。 */
        val RESTORE_ORDER: List<String> = listOf("APP", "MODULES", "SETTINGS")
    }

    data class RestoreOutcome(
        val result: RestoreResult,
        /** 需要写入本地设置的键 → 值（调用方经 ModeStorage/prefs 落盘）。 */
        val settingsToApply: Map<String, String>,
        val requiresConfirmation: List<String>,
        val manifest: SnapshotManifest?,
    )

    fun restore(
        request: RestoreRequest,
        localSettings: Map<String, String> = emptyMap(),
        mirrorSettings: Map<String, String> = emptyMap(),
        mirrorRevision: Long = 0,
        localRevision: Long = 0,
    ): RestoreOutcome {
        val snapshotDir = resolveSnapshot(request.mode, request.revision)
            ?: return blocked(listOf(SnapshotErrors.SNAPSHOT_NOT_FOUND))
        val manifestFile = File(snapshotDir, "manifest.json")
        if (AtomicControlFile.verifySha(manifestFile) == dev.maplesu.manager.workmode.control.ShaCheck.MISMATCH) {
            return blocked(listOf(SnapshotErrors.SNAPSHOT_CORRUPT), manifest = null)
        }
        val raw = runCatching { manifestFile.readText(Charsets.UTF_8) }.getOrNull()
        val manifest = raw?.let { SnapshotManifests.decode(it) }
            ?: return blocked(listOf(SnapshotErrors.SNAPSHOT_CORRUPT))
        if (!SnapshotManifests.verify(manifest)) {
            // 镜像损坏/缺 sha → 不静默用默认值覆盖（05:389）。
            return blocked(listOf(SnapshotErrors.SNAPSHOT_CORRUPT), manifest = manifest)
        }

        val payloadRoot = File(snapshotDir, "payload")
        var filesRestored = 0
        var settings = SettingsMirror.MergeResult(emptyMap(), emptyMap(), emptyList(), null)
        val blockers = mutableListOf<String>()
        try {
            filesRestored = restoreAppFiles(payloadRoot, manifest, request.allowOverwrite)
        } catch (error: IOException) {
            blockers += SnapshotErrors.SNAPSHOT_CORRUPT
        }

        val rootEntries = manifest.entries.filter {
            it.kind == SnapshotScope.KIND_ROOT_SYMLINK || it.kind == SnapshotScope.KIND_ROOT_TREE
        }
        if (rootEntries.isNotEmpty()) {
            // 无 root 会话：不伪造"已重建"。
            blockers += SnapshotErrors.NO_ROOT
        }

        settings = SettingsMirror.merge(
            local = localSettings,
            mirror = mirrorSettings,
            mirrorRevision = mirrorRevision,
            localRevision = localRevision,
            allowOverwrite = request.allowOverwrite,
        )
        settings.blocker?.let { blockers += it }

        return RestoreOutcome(
            result = RestoreResult(
                settingsRestored = settings.restored.size,
                settingsSkipped = settings.skipped.size,
                secretsRestored = false,
                moduleLinksRebuilt = 0,
                superuserApplied = false,
                blockers = blockers.distinct(),
            ),
            settingsToApply = settings.restored,
            requiresConfirmation = settings.requiresConfirmation,
            manifest = manifest,
        )
    }

    /** 找 snapshot 目录：优先精确 revision，否则取最新。 */
    fun resolveSnapshot(mode: WorkMode, revision: Long? = null): File? {
        val modeRoot = File(storeRoot, "snapshots/${mode.suffix}")
        if (!modeRoot.isDirectory) return null
        val directories = modeRoot.listFiles { file -> file.isDirectory }?.toList() ?: return null
        val decoded = directories.mapNotNull { dir ->
            val raw = runCatching { File(dir, "manifest.json").readText(Charsets.UTF_8) }.getOrNull()
            raw?.let { SnapshotManifests.decode(it) }?.let { it to dir }
        }
        if (decoded.isEmpty()) return null
        return if (revision != null) {
            decoded.firstOrNull { it.first.revision == revision }?.second
        } else {
            decoded.maxByOrNull { it.first.revision }?.second
        }
    }

    /** merge 语义：本地非空只补缺；allowOverwrite 才覆盖（文件级同义）。 */
    private fun restoreAppFiles(payloadRoot: File, manifest: SnapshotManifest, allowOverwrite: Boolean): Int {
        var restored = 0
        for (entry in manifest.entries) {
            when (entry.type) {
                SnapshotScope.TYPE_FILE -> {
                    val local = File(appDir, entry.livePath)
                    if (local.exists() && !allowOverwrite) continue
                    val source = File(payloadRoot, entry.storePath)
                    if (!source.isFile) throw IOException(SnapshotErrors.SNAPSHOT_CORRUPT)
                    if (Hashes.sha256(source.readBytes()) != entry.sha256) {
                        throw IOException(SnapshotErrors.SNAPSHOT_CORRUPT)
                    }
                    local.parentFile?.let { if (!it.exists()) it.mkdirs() }
                    local.writeBytes(source.readBytes())
                    restored++
                }
                SnapshotScope.TYPE_DIR -> {
                    val local = File(appDir, entry.livePath)
                    if (!local.exists()) local.mkdirs()
                }
                SnapshotScope.TYPE_SYMLINK -> {
                    val local = File(appDir, entry.livePath)
                    if (local.exists() && !allowOverwrite) continue
                    local.parentFile?.let { if (!it.exists()) it.mkdirs() }
                    runCatching {
                        if (local.exists()) local.delete()
                        Files.createSymbolicLink(local.toPath(), java.nio.file.Path.of(entry.linkTarget ?: ""))
                        restored++
                    }
                }
            }
        }
        return restored
    }

    private fun blocked(blockers: List<String>, manifest: SnapshotManifest? = null): RestoreOutcome =
        RestoreOutcome(
            result = RestoreResult(0, 0, false, 0, false, blockers),
            settingsToApply = emptyMap(),
            requiresConfirmation = emptyList(),
            manifest = manifest,
        )
}
