package dev.maplesu.manager.workmode.snapshot

import dev.maplesu.manager.workmode.Hashes
import dev.maplesu.manager.workmode.WorkMode
import dev.maplesu.manager.workmode.control.AtomicControlFile
import dev.maplesu.manager.workmode.control.schema.AppSnapshotFacts
import dev.maplesu.manager.workmode.control.schema.ExcludedEntry
import dev.maplesu.manager.workmode.control.schema.SnapshotEntry
import dev.maplesu.manager.workmode.control.schema.SnapshotManifest
import dev.maplesu.manager.workmode.control.schema.canonicalized
import dev.maplesu.manager.workmode.detect.BootIdSource
import dev.maplesu.manager.workmode.detect.Clock
import dev.maplesu.manager.workmode.detect.ProcBootIdSource
import dev.maplesu.manager.workmode.detect.WallClock
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.nio.file.Files
import java.nio.file.Path

/**
 * 快照生成。
 *
 * 步骤：枚举白名单 → 先写 payload（每个文件 copy → fsync → 读回 sha）→ 最后写 manifest.json
 * （+manifest.sha256）。**没有 manifest = 快照不可用**；失败即整体失败并清理半快照目录。
 *
 * 宿主可测：appDir 用测试临时目录，storeRoot 用临时目录。
 */
class FileSnapshotWriter(
    private val appDir: File,
    private val storeRoot: File,
    private val clock: Clock = WallClock,
    private val bootIdSource: BootIdSource = ProcBootIdSource,
    private val maxBytes: Long = SnapshotScope.MAX_SNAPSHOT_BYTES,
) {
    fun create(
        mode: WorkMode,
        revision: Long,
        appFacts: AppSnapshotFacts,
        reason: SnapshotReason = SnapshotReason.MANUAL,
    ): SnapshotResult {
        val id = "rev-$revision-${mode.suffix}"
        val snapshotDir = File(storeRoot, "snapshots/${mode.suffix}/$id")
        val payloadRoot = File(snapshotDir, "payload")
        return try {
            if (snapshotDir.exists()) deleteRecursively(snapshotDir)
            if (!payloadRoot.mkdirs() && !payloadRoot.isDirectory) {
                return SnapshotResult.Failed(SnapshotErrors.SNAPSHOT_COPY_FAILED, "payload dir")
            }
            val collected = collect()
            if (collected.totalBytes > maxBytes) {
                deleteRecursively(snapshotDir)
                return SnapshotResult.Failed(
                    SnapshotErrors.SNAPSHOT_TOO_LARGE,
                    "bytes=${collected.totalBytes} limit=$maxBytes",
                )
            }
            collected.entries.forEach { entry ->
                if (entry.type != SnapshotScope.TYPE_DIR) copyEntry(payloadRoot, entry)
            }
            val manifest = SnapshotManifests.withIntegrity(
                SnapshotManifest(
                    schema = SnapshotManifest.SCHEMA,
                    id = id,
                    revision = revision,
                    mode = mode.suffix,
                    createdAt = clock.nowMillis(),
                    bootId = bootIdSource.read(),
                    app = appFacts,
                    entries = collected.entries,
                    excluded = collected.excluded,
                    totals = SnapshotManifests.totals(collected.entries),
                    integrity = dev.maplesu.manager.workmode.control.schema.Integrity(""),
                ),
            )
            // 回读校验：随机抽 3 个文件 + 全部 SYMLINK。
            verify(payloadRoot, manifest)
            ControlPermissionsForSnapshot.ensureDir(snapshotDir)
            AtomicControlFile.writeJson(File(snapshotDir, "manifest.json"), SnapshotManifests.encode(manifest))
            SnapshotResult.Ok(manifest, snapshotDir.path)
        } catch (error: Exception) {
            runCatching { deleteRecursively(snapshotDir) }
            SnapshotResult.Failed(
                (error.message ?: SnapshotErrors.SNAPSHOT_COPY_FAILED)
                    .takeIf { it.matches(Regex("[A-Z_]+")) } ?: SnapshotErrors.SNAPSHOT_COPY_FAILED,
                error.message.orEmpty(),
            )
        }
    }

    class Collected(
        val entries: List<SnapshotEntry>,
        val excluded: List<ExcludedEntry>,
        val totalBytes: Long,
    )

    private fun collect(): Collected {
        val entries = mutableListOf<SnapshotEntry>()
        val excluded = mutableListOf<ExcludedEntry>()
        var total = 0L
        for (tree in SnapshotScope.APP_TREES) {
            collectRoot(File(appDir, tree), tree, SnapshotScope.KIND_APP_TREE, entries, excluded) { size ->
                total += size
            }
        }
        for (item in SnapshotScope.APP_FILES) {
            collectRoot(File(appDir, item), item, SnapshotScope.KIND_APP_FILE, entries, excluded) { size ->
                total += size
            }
        }
        val dirs = mutableListOf<SnapshotEntry>()
        entries.forEach { entry ->
            if (entry.type != SnapshotScope.TYPE_DIR) return@forEach
            val children = entries.filter {
                it.storePath.startsWith("${entry.storePath}/") && it.type != SnapshotScope.TYPE_DIR
            }
            dirs += entry.copy(sha256 = SnapshotManifests.directoryAggregateSha(children))
        }
        val finalEntries = entries.map { entry ->
            dirs.firstOrNull { it.storePath == entry.storePath } ?: entry
        }.sortedWith(compareBy({ it.storePath }, { it.type }))
        return Collected(finalEntries, excluded.sortedWith(compareBy({ it.livePath }, { it.reason })), total)
    }

    private fun collectRoot(
        root: File,
        rootRelative: String,
        kind: String,
        entries: MutableList<SnapshotEntry>,
        excluded: MutableList<ExcludedEntry>,
        addBytes: (Long) -> Unit,
    ) {
        if (!root.exists()) return
        entries += SnapshotEntry(
            kind = kind,
            livePath = rootRelative,
            storePath = "app/$rootRelative",
            type = SnapshotScope.TYPE_DIR,
            size = 0,
            sha256 = "",
            mode = 0x1c0,
            uid = -1,
            gid = -1,
            origin = originFor(rootRelative),
        )
        val rootPath = root.toPath()
        Files.walk(rootPath).use { stream ->
            val iterator = stream.iterator()
            while (iterator.hasNext()) {
                val path = iterator.next()
                if (path == rootPath) continue
                val relative = rootPath.relativize(path).toString().replace(File.separatorChar, '/')
                val livePath = "$rootRelative/$relative"
                if (SnapshotScope.classify(livePath) == null) {
                    excluded += ExcludedEntry(livePath, SnapshotScope.ExcludedEntryReasons.UNREGISTERED)
                    continue
                }
                val exclusion = SnapshotScope.exclusionFor(livePath)
                if (exclusion != null) {
                    excluded += exclusion
                    continue
                }
                when {
                    Files.isSymbolicLink(path) -> {
                        val target = Files.readSymbolicLink(path).toString()
                        entries += SnapshotEntry(
                            kind = kind,
                            livePath = livePath,
                            storePath = "app/$livePath",
                            type = SnapshotScope.TYPE_SYMLINK,
                            size = 0,
                            sha256 = SnapshotManifests.symlinkSha(target),
                            linkTarget = target,
                            mode = 0,
                            uid = -1,
                            gid = -1,
                            origin = originFor(rootRelative),
                        )
                    }
                    Files.isRegularFile(path) -> {
                        val size = Files.size(path)
                        addBytes(size)
                        val sha = Hashes.sha256(Files.readAllBytes(path))
                        entries += SnapshotEntry(
                            kind = kind,
                            livePath = livePath,
                            storePath = "app/$livePath",
                            type = SnapshotScope.TYPE_FILE,
                            size = size,
                            sha256 = sha,
                            mode = 0x1a4,
                            uid = -1,
                            gid = -1,
                            origin = originFor(rootRelative),
                        )
                    }
                    Files.isDirectory(path) -> {
                        entries += SnapshotEntry(
                            kind = kind,
                            livePath = livePath,
                            storePath = "app/$livePath",
                            type = SnapshotScope.TYPE_DIR,
                            size = 0,
                            sha256 = "",
                            mode = 0x1c0,
                            uid = -1,
                            gid = -1,
                            origin = originFor(rootRelative),
                        )
                    }
                    else -> excluded += ExcludedEntry(livePath, SnapshotScope.ExcludedEntryReasons.UNREGISTERED)
                }
            }
        }
    }

    private fun originFor(rootRelative: String): String =
        if (rootRelative in SnapshotScope.APP_FILES || rootRelative in SnapshotScope.APP_TREES) {
            SnapshotScope.ORIGIN_NEUTRAL
        } else {
            SnapshotScope.ORIGIN_A
        }

    private fun copyEntry(payloadRoot: File, entry: SnapshotEntry) {
        val target = File(payloadRoot, entry.storePath)
        when (entry.type) {
            SnapshotScope.TYPE_FILE -> {
                val source = File(appDir, entry.livePath)
                target.parentFile?.let { parent ->
                    if (!parent.exists() && !parent.mkdirs() && !parent.isDirectory) {
                        throw IOException(SnapshotErrors.SNAPSHOT_COPY_FAILED)
                    }
                }
                FileOutputStream(target).use { output ->
                    source.inputStream().use { it.copyTo(output) }
                    output.flush()
                    output.fd.sync()
                }
                val sha = Hashes.sha256(target.readBytes())
                if (sha != entry.sha256) throw IOException(SnapshotErrors.SNAPSHOT_COPY_FAILED)
            }
            SnapshotScope.TYPE_SYMLINK -> {
                target.parentFile?.mkdirs()
                Files.createSymbolicLink(target.toPath(), Path.of(entry.linkTarget ?: ""))
            }
            else -> Unit
        }
    }

    private fun verify(payloadRoot: File, manifest: SnapshotManifest) {
        val files = manifest.entries.filter { it.type == SnapshotScope.TYPE_FILE }
        val sample = if (files.size <= 3) files else listOf(files.first(), files[files.size / 2], files.last())
        sample.forEach { entry ->
            val copied = File(payloadRoot, entry.storePath)
            if (!copied.isFile) throw IOException(SnapshotErrors.SNAPSHOT_COPY_FAILED)
            if (Hashes.sha256(copied.readBytes()) != entry.sha256) {
                throw IOException(SnapshotErrors.SNAPSHOT_COPY_FAILED)
            }
        }
        manifest.entries.filter { it.type == SnapshotScope.TYPE_SYMLINK }.forEach { entry ->
            val copied = File(payloadRoot, entry.storePath)
            if (!Files.isSymbolicLink(copied.toPath())) throw IOException(SnapshotErrors.SNAPSHOT_COPY_FAILED)
            val target = Files.readSymbolicLink(copied.toPath()).toString()
            if (SnapshotManifests.symlinkSha(target) != entry.sha256) {
                throw IOException(SnapshotErrors.SNAPSHOT_COPY_FAILED)
            }
        }
    }

    private fun deleteRecursively(file: File) {
        if (!file.exists()) return
        Files.walk(file.toPath()).use { stream ->
            stream.sorted(Comparator.reverseOrder()).forEach { path ->
                runCatching { Files.deleteIfExists(path) }
            }
        }
    }

    /** 只建目录（权限/属主由控制面适配器统一处理）。 */
    private object ControlPermissionsForSnapshot {
        fun ensureDir(dir: File) {
            if (!dir.exists() && !dir.mkdirs() && !dir.isDirectory) {
                throw IOException(SnapshotErrors.SNAPSHOT_COPY_FAILED)
            }
        }
    }
}
