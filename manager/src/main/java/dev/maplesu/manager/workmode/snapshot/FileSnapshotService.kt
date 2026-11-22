package dev.maplesu.manager.workmode.snapshot

import dev.maplesu.manager.workmode.WorkMode
import dev.maplesu.manager.workmode.control.AtomicControlFile
import dev.maplesu.manager.workmode.control.schema.AppSnapshotFacts
import dev.maplesu.manager.workmode.detect.BootIdSource
import dev.maplesu.manager.workmode.detect.Clock
import dev.maplesu.manager.workmode.detect.ProcBootIdSource
import dev.maplesu.manager.workmode.detect.WallClock
import java.io.File

/**
 * 快照服务的真实文件系统编排（W04b/W16a）：
 * `create` = 生成 manifest/payload；`restore` = App 实体 → settings merge。
 *
 * **fail-closed**：控制面在 `/data/adb`（0700）且 `secrets/` 需要独立 root 通道。
 * 调用方未确认 root 通道可用（[rootAvailable] 为 false）时：
 * - `create` → `Skipped(NO_ROOT)`，绝不写半快照；
 * - `restore` → `blockers=[NO_ROOT]`，绝不静默用默认值覆盖本地；
 * - `includeSecrets=true` 时 → `Skipped(SECRETS_REQUIRES_ROOT_CHANNEL)`（05 §5.5：
 *   明文凭据只能经 Ultra/KSU 通道写入，本层不伪造成功）。
 *
 * 主机可测：appDir/storeRoot 用临时目录，rootAvailable 注入 true；
 * 真机上由 W05/W07 的 root 适配器判定 [rootAvailable] 并把 storeRoot 指向控制面。
 */
class FileSnapshotService(
    private val appDir: File,
    private val storeRoot: File,
    private val rootAvailable: () -> Boolean,
    private val appFactsProvider: () -> AppSnapshotFacts? = { null },
    private val settingsProvider: () -> Map<String, String> = { emptyMap() },
    private val mirrorSettingsProvider: () -> Map<String, String> = { emptyMap() },
    private val mirrorRevisionProvider: () -> Long = { 0L },
    private val localRevisionProvider: () -> Long = { 0L },
    private val clock: Clock = WallClock,
    private val bootIdSource: BootIdSource = ProcBootIdSource,
) : SnapshotService {

    override suspend fun create(request: SnapshotRequest): SnapshotResult {
        if (!isRootAvailable()) return SnapshotResult.Skipped(SnapshotErrors.NO_ROOT)
        if (request.includeSecrets) return SnapshotResult.Skipped(SECRETS_REQUIRES_ROOT_CHANNEL)
        val facts = runCatching { appFactsProvider() }.getOrNull()
            ?: return SnapshotResult.Skipped(APP_FACTS_UNKNOWN)
        val revision = runCatching { nextRevision(request.mode) }.getOrElse {
            return SnapshotResult.Failed(SnapshotErrors.SNAPSHOT_MANIFEST_FAILED, it.message.orEmpty())
        }
        return FileSnapshotWriter(appDir, storeRoot, clock, bootIdSource)
            .create(request.mode, revision, facts, request.reason)
    }

    override suspend fun restore(request: RestoreRequest): RestoreResult {
        if (!isRootAvailable()) {
            return RestoreResult(0, 0, false, 0, false, listOf(SnapshotErrors.NO_ROOT))
        }
        val outcome = FileSnapshotRestorer(appDir, storeRoot, clock).restore(
            request = request,
            localSettings = safeSettings(settingsProvider),
            mirrorSettings = safeSettings(mirrorSettingsProvider),
            mirrorRevision = safeLong(mirrorRevisionProvider),
            localRevision = safeLong(localRevisionProvider),
        )
        // secrets / superuser 的兑现由 W19/W14 的专用通道负责；这里如实返回未处理，
        // 不把"未处理"写成成功（发布红线 8）。
        return outcome.result.copy(secretsRestored = false, superuserApplied = false)
    }

    /** 下一个 revision（按该模式已有快照的最大 revision + 1）。 */
    fun nextRevision(mode: WorkMode): Long {
        val modeRoot = File(storeRoot, "snapshots/${mode.suffix}")
        val maximum = modeRoot.listFiles { file -> file.isDirectory }?.toList().orEmpty()
            .mapNotNull { directory ->
                val raw = runCatching { File(directory, "manifest.json").readText(Charsets.UTF_8) }.getOrNull()
                raw?.let { SnapshotManifests.decode(it) }?.revision
            }
            .maxOrNull() ?: 0L
        return maximum + 1
    }

    private fun isRootAvailable(): Boolean = runCatching { rootAvailable() }.getOrDefault(false)

    private fun safeSettings(provider: () -> Map<String, String>): Map<String, String> =
        runCatching { provider() }.getOrDefault(emptyMap())

    private fun safeLong(provider: () -> Long): Long = runCatching { provider() }.getOrDefault(0L)

    companion object {
        const val SECRETS_REQUIRES_ROOT_CHANNEL = "SECRETS_REQUIRES_ROOT_CHANNEL"
        const val APP_FACTS_UNKNOWN = "APP_FACTS_UNKNOWN"
    }
}
