package dev.maplesu.manager.workmode.snapshot

import dev.maplesu.manager.workmode.Hashes
import dev.maplesu.manager.workmode.control.ControlJsonCodec
import dev.maplesu.manager.workmode.control.schema.Integrity
import dev.maplesu.manager.workmode.control.schema.SnapshotEntry
import dev.maplesu.manager.workmode.control.schema.SnapshotManifest
import dev.maplesu.manager.workmode.control.schema.canonicalized
import dev.maplesu.manager.workmode.control.schema.SnapshotManifest.Companion.SCHEMA
import kotlinx.serialization.KSerializer

/**
 * 快照 manifest 的 canonical 计算与校验。
 *
 * `integrity.canonicalSha256` = canonical JSON（integrity.canonicalSha256 置空）的 sha256。
 * 这样 integrity 字段不含自身，计算可复现；任何 entries/excluded/totals 变化都会被发现。
 */
object SnapshotManifests {
    private val serializer: KSerializer<SnapshotManifest> = SnapshotManifest.serializer()

    fun computeIntegrity(manifest: SnapshotManifest): Integrity {
        val canonical = manifest.canonicalized().copy(integrity = Integrity(""))
        return Integrity(Hashes.sha256Hex(ControlJsonCodec.encode(canonical, serializer)))
    }

    fun withIntegrity(manifest: SnapshotManifest): SnapshotManifest =
        manifest.copy(integrity = computeIntegrity(manifest))

    fun verify(manifest: SnapshotManifest): Boolean =
        manifest.schema == SCHEMA &&
            manifest.integrity.canonicalSha256.matches(Regex("[0-9a-f]{64}")) &&
            manifest.integrity.canonicalSha256 == computeIntegrity(manifest).canonicalSha256

    fun encode(manifest: SnapshotManifest): String =
        ControlJsonCodec.encode(manifest.canonicalized(), serializer)

    fun decode(raw: String): SnapshotManifest? = ControlJsonCodec.decodeOrNull(raw, serializer)

    /**
     * DIR 的聚合 sha：子项（排序后）`storePath:sha256\n` 拼接的 sha256。
     * 只用于快速判定"目录是否变化"，不替代逐文件校验。
     */
    fun directoryAggregateSha(children: List<SnapshotEntry>): String {
        val canonical = children
            .sortedWith(compareBy({ it.storePath }, { it.type }))
            .joinToString(separator = "") { "${it.storePath}:${it.sha256}\n" }
        return Hashes.sha256Hex(canonical)
    }

    /** SYMLINK 的 sha256 = sha256(linkTarget)，恢复时必须同时校验 readlink。 */
    fun symlinkSha(linkTarget: String): String = Hashes.sha256Hex(linkTarget)

    fun totals(entries: List<SnapshotEntry>): dev.maplesu.manager.workmode.control.schema.Totals {
        val files = entries.count { it.type != SnapshotScope.TYPE_DIR }
        val bytes = entries.filter { it.type == SnapshotScope.TYPE_FILE }.sumOf { it.size }
        return dev.maplesu.manager.workmode.control.schema.Totals(
            entryCount = entries.size,
            fileCount = files,
            bytes = bytes,
        )
    }
}
