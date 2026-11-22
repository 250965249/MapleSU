package dev.maplesu.manager.workmode.snapshot

import android.content.Context
import android.content.pm.PackageManager
import dev.maplesu.manager.workmode.Hashes
import dev.maplesu.manager.workmode.WorkMode
import dev.maplesu.manager.workmode.control.ControlPaths
import dev.maplesu.manager.workmode.control.schema.AppSnapshotFacts
import dev.maplesu.manager.workmode.detect.BootIdSource
import dev.maplesu.manager.workmode.detect.Clock
import dev.maplesu.manager.workmode.detect.ProcBootIdSource
import dev.maplesu.manager.workmode.detect.WallClock
import dev.maplesu.manager.workmode.superuser.DirectRootScriptRunner
import dev.maplesu.manager.workmode.superuser.LiteImplantScripts
import dev.maplesu.manager.workmode.superuser.RootScriptRunner
import dev.maplesu.manager.workmode.switch.GatewayOutcome
import dev.maplesu.manager.workmode.switch.ModeSwitchCodes
import dev.maplesu.manager.workmode.switch.ModeSwitchRequest
import dev.maplesu.manager.workmode.switch.ModeSwitchSnapshots
import java.io.File

/**
 * 回滚恢复 API（B）：供 r3 在 `ModeSwitchBindings.restoreAfterRollback` 接线。
 * 失败必须体现为 [RestoreResult.blockers] 非空（调用方映射 `SNAPSHOT_RESTORE_FAILED`），
 * 绝不允许"假成功"。
 */
interface SwitchSnapshotsRestorer {
    /** 恢复 `mode` 最近一次（或指定 revision）快照；缺快照/损坏/部分失败进 blockers。 */
    suspend fun restoreForRollback(mode: WorkMode, revision: Long? = null): RestoreResult
}

/**
 * 控制面快照桥（root 侧文件操作）：App 只写自己的私有 staging，再由 root 脚本
 * `cp -a + chown/chmod + mv` 发布到 `/data/adb/maplesu-workmode/snapshots`。
 * 主机测试注入本地 fake（temp dir copy）即可验证整条编排。
 */
interface ControlPlaneSnapshotBridge {
    fun controlPlaneAvailable(): Boolean

    /** 该模式下控制面已有快照的 revision 列表；读不到 → null（调用方 fail-closed）。 */
    fun listSnapshotRevisions(mode: WorkMode): List<Long>?

    /** 把本地快照目录发布到控制面 [destination]（测试/真机都要求 manifest sha 校验通过）。 */
    fun publishSnapshot(localSnapshotDir: File, destination: String, expectedManifestSha256: String): Boolean

    /** 把控制面快照 [source] 物化到本地 staging 目录（restore 读本地副本）。 */
    fun materializeSnapshot(source: String, localSnapshotDir: File): Boolean
}

/**
 * 真机实现（root 脚本）：发布走 tmp → chown/chmod → sha 读回 → mv（原子替换）；
 * 读取先 `test -f manifest.json` 再复制，失败返回 false（不静默回落到 filesDir）。
 */
class RootScriptSnapshotBridge(
    private val runner: RootScriptRunner,
    private val snapshotsRoot: String = ControlPaths.SNAPSHOTS,
    private val controlRoot: String = ControlPaths.ROOT,
) : ControlPlaneSnapshotBridge {

    private fun quote(value: String): String = LiteImplantScripts.quote(value)

    override fun controlPlaneAvailable(): Boolean = runCatching {
        runner.run(
            "set -eu\n" +
                "test -d ${quote(controlRoot)}\n" +
                "test -w ${quote(controlRoot)}\n" +
                "/system/bin/printf 'OK\\n'\n",
        ).code == 0
    }.getOrDefault(false)

    override fun listSnapshotRevisions(mode: WorkMode): List<Long>? = runCatching {
        val directory = "$snapshotsRoot/${mode.suffix}"
        val result = runner.run(
            "set -u\n" +
                "if [ -d ${quote(directory)} ]; then /system/bin/ls -1 ${quote(directory)}; fi\n" +
                "/system/bin/printf 'LISTED\\n'\n",
        )
        if (result.code != 0 || !result.out.contains("LISTED")) return null
        result.out.lineSequence()
            .mapNotNull { line -> Regex("^rev-(\\d+)-${mode.suffix}$").find(line.trim()) }
            .mapNotNull { it.groupValues[1].toLongOrNull() }
            .toList()
    }.getOrNull()

    override fun publishSnapshot(
        localSnapshotDir: File,
        destination: String,
        expectedManifestSha256: String,
    ): Boolean = runCatching {
        val temporary = "$snapshotsRoot/.tmp-${System.nanoTime()}"
        val script = buildString {
            appendLine("set -eu")
            appendLine("TMP=${quote(temporary)}")
            appendLine("DST=${quote(destination)}")
            appendLine("OUT=${quote("$snapshotsRoot/.out")}")
            appendLine("/system/bin/mkdir -p ${quote(snapshotsRoot)}")
            appendLine("TMP=\$(/system/bin/mktemp -d ${quote("$snapshotsRoot/.tmp-XXXXXX")})")
            appendLine("/system/bin/cp -a ${quote(localSnapshotDir.absolutePath)}/. \"\$TMP/\"")
            appendLine("/system/bin/chown -R 0:0 \"\$TMP\"")
            appendLine("/system/bin/find \"\$TMP\" -type d -exec /system/bin/chmod 0700 {} +")
            appendLine("/system/bin/find \"\$TMP\" -type f -exec /system/bin/chmod 0600 {} +")
            appendLine("SHA=\$(/system/bin/sha256sum \"\$TMP/manifest.json\" | /system/bin/cut -d' ' -f1)")
            appendLine("if [ \"\$SHA\" != ${quote(expectedManifestSha256)} ]; then /system/bin/rm -rf \"\$TMP\"; exit 5; fi")
            appendLine("/system/bin/rm -rf \"\$DST\"")
            appendLine("/system/bin/mkdir -p \"\$(/system/bin/dirname \"\$DST\")\"")
            appendLine("/system/bin/mv \"\$TMP\" \"\$DST\"")
            appendLine("/system/bin/printf 'PUBLISHED:%s\\n' \"\$SHA\"")
        }
        val result = runner.run(script)
        result.code == 0 && result.out.contains("PUBLISHED:$expectedManifestSha256")
    }.getOrDefault(false)

    override fun materializeSnapshot(source: String, localSnapshotDir: File): Boolean = runCatching {
        val script = buildString {
            appendLine("set -eu")
            appendLine("test -f ${quote("$source/manifest.json")}")
            appendLine("/system/bin/rm -rf ${quote(localSnapshotDir.absolutePath)}")
            appendLine("/system/bin/mkdir -p ${quote(localSnapshotDir.absolutePath)}")
            appendLine("/system/bin/cp -a ${quote(source)}/. ${quote(localSnapshotDir.absolutePath)}/")
            appendLine("/system/bin/printf 'MATERIALIZED\\n'")
        }
        val result = runner.run(script)
        result.code == 0 && result.out.contains("MATERIALIZED")
    }.getOrDefault(false)

    companion object {
        fun snapshotDirectory(mode: WorkMode, revision: Long): String =
            "${ControlPaths.SNAPSHOTS}/${mode.suffix}/rev-$revision-${mode.suffix}"
    }
}

/**
 * A+B：把 S1 快照**发布到控制面**（`/data/adb/maplesu-workmode/snapshots`，清数据不丢），
 * 并提供真实的回滚恢复（`restoreAfterRollback` 不再返回 DEFERRED）。
 *
 * 流程：
 * - S1：控制面不可用 → `SNAPSHOT_FAILED`（**不**静默退 filesDir）；本地 staging 生成
 *   manifest/payload → root 脚本发布（sha 读回校验）→ 成功才返回 ok；
 * - 回滚：控制面快照 → 本地 staging → `FileSnapshotService.restore`（merge 语义/顺序）→
 *   缺快照/损坏 → `SNAPSHOT_RESTORE_FAILED`（不假装成功）。
 */
class ControlPlaneModeSwitchSnapshots(
    private val appDir: File,
    private val stagingRoot: File,
    private val bridge: ControlPlaneSnapshotBridge,
    private val appFactsProvider: () -> AppSnapshotFacts?,
    private val clock: Clock = WallClock,
    private val bootIdSource: BootIdSource = ProcBootIdSource,
) : ModeSwitchSnapshots, SwitchSnapshotsRestorer {

    override suspend fun preSwitchSnapshot(request: ModeSwitchRequest): GatewayOutcome {
        if (!runCatching { bridge.controlPlaneAvailable() }.getOrDefault(false)) {
            return failed(ModeSwitchCodes.SNAPSHOT_FAILED, "CONTROL_PLANE_UNAVAILABLE")
        }
        val facts = runCatching { appFactsProvider() }.getOrNull()
            ?: return failed(ModeSwitchCodes.SNAPSHOT_FAILED, "APP_FACTS_UNKNOWN")
        val revisions = runCatching { bridge.listSnapshotRevisions(request.fromMode) }.getOrNull()
            ?: return failed(ModeSwitchCodes.SNAPSHOT_FAILED, "CONTROL_PLANE_UNREADABLE")
        val revision = (revisions.maxOrNull() ?: 0L) + 1
        val staging = File(stagingRoot, "switch-${request.switchId}")
        // 用显式 revision（控制面已有快照数 +1）写入 staging，发布后同一 revision 永不复用。
        val created = FileSnapshotWriter(appDir, staging, clock, bootIdSource)
            .create(request.fromMode, revision, facts, SnapshotReason.PRE_SWITCH)
        if (created !is SnapshotResult.Ok) {
            val detail = when (created) {
                is SnapshotResult.Skipped -> "SNAPSHOT_SKIPPED:${created.reason}"
                is SnapshotResult.Failed -> created.code.ifEmpty { ModeSwitchCodes.SNAPSHOT_FAILED }
                else -> ModeSwitchCodes.SNAPSHOT_FAILED
            }
            runCatching { staging.deleteRecursively() }
            return failed(ModeSwitchCodes.SNAPSHOT_FAILED, detail)
        }
        val manifestFile = File(created.storePath, "manifest.json")
        val manifestSha = runCatching { Hashes.sha256(manifestFile.readBytes()) }.getOrNull()
            ?: return failed(ModeSwitchCodes.SNAPSHOT_FAILED, "MANIFEST_UNREADABLE")
        val destination = "${ControlPaths.SNAPSHOTS}/${request.fromMode.suffix}/${created.manifest.id}"
        val published = runCatching {
            bridge.publishSnapshot(File(created.storePath), destination, manifestSha)
        }.getOrDefault(false)
        runCatching { staging.deleteRecursively() }
        return if (published) GatewayOutcome(true, "", detail = destination)
        else failed(ModeSwitchCodes.SNAPSHOT_FAILED, "CONTROL_PLANE_PUBLISH_FAILED")
    }

    override suspend fun restoreAfterRollback(request: ModeSwitchRequest): GatewayOutcome {
        val result = restoreForRollback(request.fromMode)
        return if (result.blockers.any { it in FATAL_BLOCKERS }) {
            failed(SNAPSHOT_RESTORE_FAILED, result.blockers.joinToString(","))
        } else {
            GatewayOutcome(true, "", detail = result.blockers.joinToString(","))
        }
    }

    override suspend fun restoreForRollback(mode: WorkMode, revision: Long?): RestoreResult {
        if (!runCatching { bridge.controlPlaneAvailable() }.getOrDefault(false)) {
            return restoreFailure("CONTROL_PLANE_UNAVAILABLE")
        }
        val revisions = runCatching { bridge.listSnapshotRevisions(mode) }.getOrNull()
            ?: return restoreFailure("CONTROL_PLANE_UNREADABLE")
        val chosen = revision ?: revisions.maxOrNull()
            ?: return restoreFailure(SnapshotErrors.SNAPSHOT_NOT_FOUND)
        if (chosen !in revisions) return restoreFailure(SnapshotErrors.SNAPSHOT_NOT_FOUND)

        val directoryName = "rev-$chosen-${mode.suffix}"
        val localSnapshot = File(stagingRoot, "snapshots/${mode.suffix}/$directoryName")
        val materialized = runCatching {
            bridge.materializeSnapshot(
                "${ControlPaths.SNAPSHOTS}/${mode.suffix}/$directoryName",
                localSnapshot,
            )
        }.getOrDefault(false)
        if (!materialized) return restoreFailure(SNAPSHOT_RESTORE_FAILED)

        val service = FileSnapshotService(
            appDir = appDir,
            storeRoot = stagingRoot,
            rootAvailable = { true },
            appFactsProvider = { null },
            clock = clock,
            bootIdSource = bootIdSource,
        )
        return service.restore(
            RestoreRequest(
                mode = mode,
                allowOverwrite = false,
                reason = RestoreReason.SWITCH_COMMITTED,
                revision = chosen,
            ),
        )
    }

    private fun failed(code: String, detail: String): GatewayOutcome =
        GatewayOutcome(false, "", code, detail)

    private fun restoreFailure(code: String): RestoreResult =
        RestoreResult(0, 0, false, 0, false, listOf(code))

    companion object {
        /** 部分失败/缺快照/损坏都算失败（不得当成功）。NO_ROOT/CONFIRM_REQUIRED 记 detail。 */
        const val SNAPSHOT_RESTORE_FAILED = "SNAPSHOT_RESTORE_FAILED"
        val FATAL_BLOCKERS: Set<String> = setOf(
            SnapshotErrors.SNAPSHOT_NOT_FOUND,
            SnapshotErrors.SNAPSHOT_CORRUPT,
            SNAPSHOT_RESTORE_FAILED,
            "CONTROL_PLANE_UNAVAILABLE",
            "CONTROL_PLANE_UNREADABLE",
        )
    }
}

/**
 * 生产装配（Application 启动接线）：
 * `ModeSwitchRuntime.initialize(this, hooks = w19Hooks,
 *   snapshots = controlPlaneModeSwitchSnapshots(this))`
 */
fun controlPlaneModeSwitchSnapshots(context: Context): ModeSwitchSnapshots {
    val appContext = context.applicationContext
    return ControlPlaneModeSwitchSnapshots(
        appDir = appContext.filesDir,
        stagingRoot = File(appContext.filesDir, "workmode/snapshot-staging"),
        bridge = RootScriptSnapshotBridge(DirectRootScriptRunner(appContext)),
        appFactsProvider = { appSnapshotFacts(appContext) },
    )
}

@Suppress("UnusedReceiverParameter")
private fun appSnapshotFacts(context: Context): AppSnapshotFacts? = runCatching {
    val packageName = context.packageName
    val info = context.packageManager.getPackageInfo(
        packageName, PackageManager.GET_SIGNING_CERTIFICATES,
    )
    val signers = info.signingInfo?.apkContentsSigners.orEmpty().map { signature ->
        Hashes.sha256(signature.toByteArray())
    }
    val apk = File(context.applicationInfo.sourceDir)
    AppSnapshotFacts(
        packageName = packageName,
        versionCode = info.longVersionCode,
        apkSha256 = Hashes.sha256(apk.readBytes()),
        signerSha256 = signers,
        settingsRevision = 0,
        appPrefsRevision = 0,
    )
}.getOrNull()
