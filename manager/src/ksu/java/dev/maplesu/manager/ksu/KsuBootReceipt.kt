// SPDX-License-Identifier: GPL-3.0-or-later
package dev.maplesu.manager.ksu

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * **启动链回执与自检**（开发文档 T3：`KsuBootReceipt.kt` + `KsuBootReceiptProbe.kt` 的合并落位）。
 *
 * 要回答的唯一问题：**「KSU 启动链到底跑没跑」**——并且必须能给出"没跑"的**具名理由**，
 * 而不是把"没证据"当成"正常"（审计 §2.2-2：`init_event.rs` 里早先连回执都没有）。
 *
 * ## 判据集（每条一个具名 code，逐条对应开发文档 §6 T3 表）
 * | 判据 | 含义 | 证据 | 失败 code |
 * |---|---|---|---|
 * | P1 | post-fs-data 越过 `catch_bootlog` | `ksu/log/logcat.log` mtime | [CODE_BOOT_LOG_NOT_REFRESHED] |
 * | P2 | 同上（dmesg） | `ksu/log/dmesg.log` mtime | [CODE_BOOT_DMESG_NOT_REFRESHED] |
 * | P3 | 版本配对 | `ksud debug info` × 内核侧 `Natives` | [CODE_KSUD_VERSION_MISMATCH] |
 * | P4 | 列表可用 | `ksud module list` 可解析 | [CODE_MODULE_LIST_UNAVAILABLE] |
 * | P5 | 模块脚本真跑 | logcat 含 `ksud::module: exec /data/adb/modules/` | [CODE_MODULE_SCRIPTS_NOT_EXECUTED] |
 * | P6 | 已启用（且有开机脚本）的模块都跑过 | 集合比较 | [CODE_MODULE_EXEC_PARTIAL] |
 * | P7 | preinit 已生成 | `ksu/preinit_status` mtime | [CODE_PREINIT_NOT_GENERATED] |
 * | P8 | （条件）有 metamodule 则挂载存在 | `/proc/mounts` 的 lowerdir/upperdir 或 metamodule 自报 | [CODE_METAMODULE_NOT_MOUNTED] |
 * | P9 | （条件）有 zygisksu 则 `zn-daemon` 在 | `pgrep -f zn-daemon` | [CODE_ZYGISK_DAEMON_ABSENT] |
 * | P10 | busybox 可用 | `busybox true` rc=0 | [CODE_BUSYBOX_UNUSABLE] |
 *
 * ## 两条硬规则
 * 1. **禁止静默成功**：任何一条判据拿不到证据 → [KsuRuntimeState.Unknown]（或对应 code），
 *    **绝不**默认 PASS。
 * 2. **P8 不照抄文档的 `grep ' KSU ' /proc/mounts`**：T0 现场（`evidence/normal-ksu-parity-20261102/
 *    T0-verdict.md` §7）证明 `mountify` 这类 metamodule 的挂载源是 `overlay`/`mountify`，
 *    `grep ' KSU '` **恒为 0**。因此挂载判定改为「任一 `/proc/mounts` 行的
 *    `lowerdir=`/`upperdir=` 指向 `/data/adb/modules` 或 `/data/adb/metamodule`」，
 *    或 metamodule 自己的状态文件/输出；`grep ' KSU '` 只作为**正向**补充证据，
 *    计数为 0 **不能**判失败。
 *
 * ## 时钟
 * `bootEpoch = now - elapsedRealtime`；设备开机前 25 s RTC 是错的，所以判据侧有
 * [TOLERANCE_MS]（±90 s，开发文档 §3.7）容差。时钟与 `bootEpoch` 都**注入**
 * （[clock] / [bootEpochMs]），本文件不引用 `android.os.SystemClock`，主机单测可完全离线。
 *
 * 本类只读**只增**的证据（文件 mtime / 命令输出），不做任何写操作、不修任何东西：
 * 修复是 T1（重装 ksud）+ 用户点重启（C9）。
 */

/** ksud 的开机阶段（T4 的 `.boot_stage` 回执形状；T3 只定义契约）。 */
enum class KsuBootStage { POST_FS_DATA, SERVICES, BOOT_COMPLETED }

/**
 * 一条开机阶段回执（T4 `boot_receipt.rs` 写 `/data/adb/ksu/log/.boot_stage`）。
 *
 * T3 的判据**不依赖**它（当前 ksud 还不写），它是 T4 落地后的**强判据**：
 * `state=fail` 时 [error] 与两侧 UAPI 一并暴露，避免"静默 `Ok(())`"再次发生。
 */
data class KsuBootStageRecord(
    val stage: KsuBootStage,
    val state: String,
    val atEpochMs: Long,
    val elapsedMs: Long,
    val kernelVersion: Int?,
    val kernelUapi: Int?,
    val ksudUapi: Int?,
    val error: String?,
)

/**
 * UI 可见的运行时状态（**纯数据**，UI 层可直接持有；不含 `Context`/Compose）。
 *
 * 状态机（开发文档 §6 T3）：`Unknown → Ready | StagesNotRun | VersionMismatch |
 * KsudMissing | Broken`；修复成功 → `PENDING_REBOOT`（T1/T2 的持久化状态）→ 重启后 `Ready`。
 *
 * 与模式的对应：
 * - `mode == LITE` → [NotApplicable]（**零**探针调用，§9.4 断言 3）；
 * - 未接线 / 证据不足 → [Unknown]（**不得**是 [Ready]，§9.4 断言 4）。
 */
sealed interface KsuRuntimeState {
    /** LITE（Ultra）模式：KSU 启动链不适用。 */
    data object NotApplicable : KsuRuntimeState

    /** 证据不足（未接线、内核侧读不到、探针异常）：**不等于**正常。 */
    data object Unknown : KsuRuntimeState

    /** 启动链跑完且所有判据通过。 */
    data object Ready : KsuRuntimeState

    /** 启动阶段没跑（P1/P2/P5/P6/P7 之一失败）；[failedCodes] 是具名 code 列表。 */
    data class StagesNotRun(val failedCodes: List<String>) : KsuRuntimeState

    /** ksud 与内核版本/UAPI 不配对（P3）。 */
    data class VersionMismatch(
        val kernelVersion: Int?,
        val ksudVersion: Int?,
        val kernelUapi: Int?,
        val ksudUapi: Int?,
    ) : KsuRuntimeState

    /** 部署的 `ksud` 不可用（`debug info` 读不到）：T1 的修复目标。 */
    data object KsudMissing : KsuRuntimeState

    /** 非阶段性的单点故障（P4/P8/P9/P10）；[detail] 里带全部同时失败的判据。 */
    data class Broken(val code: String, val detail: String) : KsuRuntimeState
}

/**
 * 证据探针：**只读**。生产实现 = 已认证 root shell（`/data/adb` 是 0700 root，app uid 读不到）；
 * 主机单测注入 fake。
 *
 * 前 9 个方法**逐字**对应开发文档 §9.3 的签名草案（字段名不可改，UI/诊断已按此对齐）；
 * 末尾两个带默认实现的方法是 T3 落地必需的**扩展**（P6 的"应跑集合"与 P8 的"自报"），
 * 默认 `null` = 拿不到证据（于是判 UNKNOWN，不会被当成 PASS）。
 */
interface KsuBootReceiptProbe {
    /** 文件 mtime（epoch ms）；`null` = 不存在/不可读（**不是** 0）。 */
    fun statMtime(path: String): Long?

    /** 读取整个文本；`null` = 不存在/不可读。 */
    fun readText(path: String): String?

    /** `ksud debug info`；`null` = ksud 不可用/输出不可解析。 */
    fun versionInfo(): KsuVersionInfo?

    /** `ksud module list` 的模块 id 列表；`null` = 列表命令失败/输出不可解析。 */
    fun moduleIds(): List<String>?

    /** logcat 里 `ksud::module: exec /data/adb/modules/<id>/…` 抽出的模块 id；`null` = logcat 不可读。 */
    fun executedModuleIds(): List<String>?

    /** `pgrep -f` 的进程名行；`null` = pgrep 本身失败。 */
    fun processNames(): List<String>?

    /** `path` 是否存在且是符号链接；`null` = 无法判定。 */
    fun isSymlink(path: String): Boolean?

    /** `grep -c ' KSU ' /proc/mounts`；`null` = 读不到。**只作正向证据**（见类注释 P8）。 */
    fun ksuMountCount(): Int?

    /** `busybox true` 是否 rc=0；`null` = 探针本身失败。 */
    fun busyboxOk(): Boolean?

    /**
     * **已启用且声明了开机脚本**（`post-fs-data.sh` / `service.sh`）的模块 id。
     *
     * 为什么不是"全部已启用模块"：P6 要比较"应跑"与"真跑了"，而**没有**开机脚本的模块
     * 本来就不会出现在 `ksud::module: exec` 里（T0 现场：29 个模块目录 / 18 个启用 /
     * 30 条 exec 行）。拿全量已启用集合去比会 100% 误报。`null` = 拿不到（判 UNKNOWN）。
     */
    fun enabledModuleIds(): List<String>? = null

    /**
     * metamodule 自己的挂载状态/输出（P8 的自报通道，例如 `mountify.log` 的内容）。
     * `null`/空白 = 拿不到（不构成功劳，也不构成失败证据）。
     */
    fun metamoduleSelfReport(): String? = null
}

/**
 * T3 判据实现（纯逻辑，可完全离线单测）。
 *
 * @param probe 只读证据探针（生产 = [RootShellBootReceiptProbe]）。
 * @param kernelVersion 内核侧版本（`Natives.version`）；`null` = 读不到。
 * @param kernelUapi 内核侧 UAPI（`Natives.kernelUAPIVersion`）；`null` = 读不到。
 * @param bootEpochMs 本次开机时刻（`now - elapsedRealtime`）；`<= 0` 视为未知。
 * @param clock 当前时刻（只用于日志/证据文本，不参与判定）。
 */
class KsuBootReceipt(
    private val probe: KsuBootReceiptProbe,
    private val kernelVersion: () -> Int?,
    private val kernelUapi: () -> Int?,
    private val bootEpochMs: () -> Long,
    private val clock: () -> Long = { System.currentTimeMillis() },
) {

    /**
     * 跑一遍 P1–P10 并给出状态。**幂等、只读**；不抛异常（探针异常 → UNKNOWN）。
     *
     * 判定顺序（先致命、后局部）：
     * 1. `ksud debug info` 读不到 → [KsuRuntimeState.KsudMissing]；
     * 2. 内核侧读不到 → [KsuRuntimeState.Unknown]；UAPI/版本不一致 → [KsuRuntimeState.VersionMismatch]；
     * 3. 阶段类失败（P1/P2/P5/P6/P7）→ [KsuRuntimeState.StagesNotRun]；
     * 4. 单点失败（P4/P8/P9/P10）→ [KsuRuntimeState.Broken]；
     * 5. 仍有拿不到的证据 → [KsuRuntimeState.Unknown]；
     * 6. 全过 → [KsuRuntimeState.Ready]。
     */
    fun evaluate(): KsuRuntimeState {
        // ── P3 前置：ksud 侧版本 ─────────────────────────────────────────
        val ksud = guarded("P3.versionInfo") { probe.versionInfo() }
        if (ksud == null) {
            note("state=KSUD_MISSING", "ksud debug info unreadable")
            return KsuRuntimeState.KsudMissing
        }

        // ── P3：版本配对（内核侧读不到 = UNKNOWN，绝不当 PASS）─────────────
        val kernelV = guarded("P3.kernelVersion") { kernelVersion() }
        val kernelU = guarded("P3.kernelUapi") { kernelUapi() }
        if (kernelV == null || kernelU == null) {
            note(
                "state=UNKNOWN",
                "P3 kernel side unreadable: kernelVersion=$kernelV kernelUapi=$kernelU",
            )
            return KsuRuntimeState.Unknown
        }
        if (!ksud.matchesBuild || kernelU != KsuVersionInfo.REQUIRED_UAPI_VERSION || ksud.version != kernelV) {
            note(
                "state=VERSION_MISMATCH",
                "kernel=$kernelV/$kernelU ksud=${ksud.version}/${ksud.uapiVersion}",
            )
            return KsuRuntimeState.VersionMismatch(
                kernelVersion = kernelV,
                ksudVersion = ksud.version,
                kernelUapi = kernelU,
                ksudUapi = ksud.uapiVersion,
            )
        }

        val epoch = guarded("bootEpoch") { bootEpochMs() } ?: -1L
        val now = guarded("clock") { clock() } ?: 0L

        val stageFails = LinkedHashMap<String, String>()
        val otherFails = LinkedHashMap<String, String>()
        val unresolved = LinkedHashMap<String, String>()

        fun record(judge: Judge) {
            when (judge) {
                is Judge.Pass -> Unit
                is Judge.Unresolved -> unresolved[judge.code] = judge.detail
                is Judge.Fail ->
                    if (judge.stage) {
                        stageFails[judge.code] = judge.detail
                    } else {
                        otherFails[judge.code] = judge.detail
                    }
            }
        }

        // ── P1 / P2 / P7：本 boot 的日志与 preinit ──────────────────────
        record(freshness(LOG_CAT, CODE_BOOT_LOG_NOT_REFRESHED, epoch, now))
        record(freshness(DMESG_LOG, CODE_BOOT_DMESG_NOT_REFRESHED, epoch, now))
        record(freshness(PREINIT_STATUS, CODE_PREINIT_NOT_GENERATED, epoch, now))

        // ── P5：模块脚本真跑（logcat 的 exec 标记）───────────────────────
        val executed = guarded("P5.executedModuleIds") { probe.executedModuleIds() }
        when {
            executed == null -> record(
                Judge.Fail(
                    CODE_MODULE_SCRIPTS_NOT_EXECUTED,
                    "$LOG_CAT unreadable: no proof any module script ran",
                    stage = true,
                ),
            )

            executed.isEmpty() -> record(
                Judge.Fail(
                    CODE_MODULE_SCRIPTS_NOT_EXECUTED,
                    "no '$EXEC_MARKER' line in $LOG_CAT",
                    stage = true,
                ),
            )

            else -> Unit
        }

        // ── P6：应跑集合 ⊆ 已跑集合（P5 已失败时不再叠加噪音）───────────
        if (!executed.isNullOrEmpty()) {
            val enabled = guarded("P6.enabledModuleIds") { probe.enabledModuleIds() }
            if (enabled == null) {
                record(
                    Judge.Unresolved(
                        CODE_EVIDENCE_UNAVAILABLE,
                        "P6 enabled-module list unreadable",
                    ),
                )
            } else {
                val execSet = executed.toSet()
                val missing = enabled.filter { it !in execSet }
                if (missing.isNotEmpty()) {
                    record(
                        Judge.Fail(
                            CODE_MODULE_EXEC_PARTIAL,
                            "enabled but not executed: $missing",
                            stage = true,
                        ),
                    )
                }
            }
        }

        // ── P4：列表可用（拿到 ksud 的回答，且是模块数组）───────────────
        val modules = guarded("P4.moduleIds") { probe.moduleIds() }
        if (modules == null) {
            record(
                Judge.Fail(
                    CODE_MODULE_LIST_UNAVAILABLE,
                    "`ksud module list` failed or returned unparseable output",
                    stage = false,
                ),
            )
        }

        // ── P8：metamodule 挂载（条件判据；不照抄 `grep ' KSU '`）────────
        record(metamodule())

        // ── P9：zygisksu 守护（条件判据）────────────────────────────────
        record(zygisk(modules))

        // ── P10：busybox ────────────────────────────────────────────────
        when (val busybox = guarded("P10.busybox") { probe.busyboxOk() }) {
            null -> record(
                Judge.Unresolved(CODE_EVIDENCE_UNAVAILABLE, "P10 busybox probe unreadable"),
            )

            false -> record(
                Judge.Fail(CODE_BUSYBOX_UNUSABLE, "`busybox true` returned non-zero", stage = false),
            )

            true -> Unit
        }

        val state = when {
            stageFails.isNotEmpty() -> KsuRuntimeState.StagesNotRun(stageFails.keys.toList())
            otherFails.isNotEmpty() -> KsuRuntimeState.Broken(
                code = otherFails.keys.first(),
                detail = otherFails.entries.joinToString("; ") { "${it.key}: ${it.value}" },
            )

            unresolved.isNotEmpty() -> KsuRuntimeState.Unknown
            else -> KsuRuntimeState.Ready
        }
        note(
            "state=${state.toString().substringBefore('(')}",
            "stage=${stageFails.keys} other=${otherFails.keys} unresolved=${unresolved.keys} " +
                "bootEpoch=$epoch now=$now",
        )
        return state
    }

    // ── 单条判据 ────────────────────────────────────────────────────────

    /** P1/P2/P7：`mtime` 落在本次开机之后（含 ±[TOLERANCE_MS] 时钟容差）。 */
    private fun freshness(path: String, failureCode: String, epochMs: Long, nowMs: Long): Judge {
        if (epochMs <= 0L) {
            return Judge.Unresolved(CODE_EVIDENCE_UNAVAILABLE, "$path: bootEpoch unknown")
        }
        val mtime = guarded("stat:$path") { probe.statMtime(path) }
            ?: return Judge.Fail(failureCode, "$path: mtime unavailable (missing or unreadable)", true)
        if (mtime <= 0L) {
            return Judge.Fail(failureCode, "$path: nonsensical mtime=$mtime", true)
        }
        // 只判下界：`mtime` 只要不早于 bootEpoch 就是本 boot 写的。
        // 上界不放宽是因为"文件时间在未来"仍说明它被（某个时钟下的）写入过。
        if (mtime + TOLERANCE_MS >= epochMs) return Judge.Pass
        return Judge.Fail(
            failureCode,
            "$path mtime=$mtime < bootEpoch=$epochMs (now=$nowMs, tolerance=${TOLERANCE_MS}ms)",
            true,
        )
    }

    /**
     * P8：metamodule 挂载。
     *
     * 判定（按 T0 现场形态，`mountify` 为典型）：
     * 1. `/data/adb/metamodule` 指针不存在 → 条件不成立（跳过，不算失败）；
     * 2. `/proc/mounts` 任一行 `lowerdir=`/`upperdir=` 指向 `/data/adb/modules`
     *    或 `/data/adb/metamodule` → 已挂载；
     * 3. `grep ' KSU '` 计数 > 0 → 已挂载（**仅正向**：mountify 的源是 `overlay`/`mountify`，
     *    计数恒为 0，不能据此判负）；
     * 4. metamodule 自报（状态文件/输出）非空 → 已挂载；
     * 5. 以上都拿不到 → [CODE_METAMODULE_NOT_MOUNTED]。
     */
    private fun metamodule(): Judge {
        val link = guarded("P8.isSymlink") { probe.isSymlink(METAMODULE_POINTER) }
        val pointerMtime = guarded("P8.statMetamodule") { probe.statMtime(METAMODULE_POINTER) }
        if (link == null && pointerMtime == null) {
            return Judge.Unresolved(
                CODE_EVIDENCE_UNAVAILABLE,
                "P8 $METAMODULE_POINTER unreadable",
            )
        }
        // 指针存在（符号链接，或历史版本的实体目录）才需要判挂载。
        if (link != true && pointerMtime == null) return Judge.Pass

        val mounts = guarded("P8.procMounts") { probe.readText(PROC_MOUNTS) }
        if (mounts != null && hasModuleMount(mounts)) {
            return Judge.Pass
        }
        val ksuMounts = guarded("P8.ksuMountCount") { probe.ksuMountCount() }
        if (ksuMounts != null && ksuMounts > 0) return Judge.Pass
        val selfReport = guarded("P8.selfReport") { probe.metamoduleSelfReport() }
        if (!selfReport.isNullOrBlank()) return Judge.Pass

        val evidence = buildString {
            append("no module mount in ")
            append(PROC_MOUNTS)
            append(" (lowerdir/upperdir -> ")
            append(MODULE_MOUNT_ROOTS.joinToString("|"))
            append(')')
            append(", ksuMounts=")
            append(ksuMounts ?: "unreadable")
            append(", mountsReadable=")
            append(mounts != null)
            append(", selfReport=none")
        }
        return Judge.Fail(CODE_METAMODULE_NOT_MOUNTED, evidence, false)
    }

    /**
     * P9：装了（且启用）`zygisksu` 就必须有 `zn-daemon`。
     *
     * 条件用"已启用且有开机脚本"的集合（[KsuBootReceiptProbe.enabledModuleIds]），
     * 拿不到时退回全量列表；两者都拿不到 → UNKNOWN（`zygisksu` 是否在都判不了）。
     */
    private fun zygisk(modules: List<String>?): Judge {
        val enabled = guarded("P9.enabledModuleIds") { probe.enabledModuleIds() }
        val candidates = enabled ?: modules
            ?: return Judge.Unresolved(
                CODE_EVIDENCE_UNAVAILABLE,
                "P9 module list unreadable: cannot tell whether $ZYGISK_MODULE is installed",
            )
        if (candidates.none { it == ZYGISK_MODULE }) return Judge.Pass

        val processes = guarded("P9.processNames") { probe.processNames() }
            ?: return Judge.Unresolved(
                CODE_EVIDENCE_UNAVAILABLE,
                "P9 pgrep unreadable: cannot confirm $ZYGISK_DAEMON",
            )
        if (processes.any { it.contains(ZYGISK_DAEMON) }) return Judge.Pass
        return Judge.Fail(
            CODE_ZYGISK_DAEMON_ABSENT,
            "$ZYGISK_MODULE enabled but no '$ZYGISK_DAEMON' process",
            false,
        )
    }

    private fun note(state: String, detail: String) {
        runCatching { KsuLog.record("boot-receipt", "$state $detail") }
    }

    private inline fun <T> guarded(label: String, block: () -> T?): T? =
        runCatching { block() }.getOrElse { error ->
            note("probe-exception", "$label: ${error.javaClass.simpleName}: ${error.message}")
            null
        }

    /** 一条判据的结果（内部；`code` 具名，便于 UI/日志逐条定位）。 */
    private sealed interface Judge {
        data object Pass : Judge

        data class Fail(val code: String, val detail: String, val stage: Boolean) : Judge

        data class Unresolved(val code: String, val detail: String) : Judge
    }

    companion object {
        // ── 证据路径（全部只读；`/data/adb` 0700 root，只能经 root shell）──────
        const val LOG_CAT = "/data/adb/ksu/log/logcat.log"
        const val DMESG_LOG = "/data/adb/ksu/log/dmesg.log"
        const val PREINIT_STATUS = "/data/adb/ksu/preinit_status"
        const val METAMODULE_POINTER = "/data/adb/metamodule"
        const val MODULES_DIR = "/data/adb/modules"
        const val PROC_MOUNTS = "/proc/mounts"
        const val DEPLOYED_KSUD = KsuCommands.DEPLOYED_DAEMON
        const val BUSYBOX = "/data/adb/ksu/bin/busybox"

        /** metamodule 自报状态文件的候选（相对 [METAMODULE_POINTER]；指针即模块目录）。 */
        val METAMODULE_SELF_REPORT_FILES: List<String> = listOf(
            "$METAMODULE_POINTER/mountify.log",
            "$METAMODULE_POINTER/mount.log",
            "$METAMODULE_POINTER/metamount.log",
        )

        /** P8 认的"模块挂载根"：overlay 的 lower/upper 指向这里就算挂上了。 */
        val MODULE_MOUNT_ROOTS: List<String> = listOf(MODULES_DIR, METAMODULE_POINTER)

        /** logcat 里"模块脚本被执行"的标记（`ksud::module: exec /data/adb/modules/<id>/…`）。 */
        const val EXEC_MARKER = "ksud::module: exec /data/adb/modules/"

        /** Zygisk Next 的模块 id 与守护进程名（T0 §6 现场值）。 */
        const val ZYGISK_MODULE = "zygisksu"
        const val ZYGISK_DAEMON = "zn-daemon"

        /** 时钟容差：±90 s（开发文档 §3.7；开机前 25 s RTC 是错的）。 */
        const val TOLERANCE_MS = 90_000L

        // ── 失败 code（每条判据一个；UI 直接展示，日志可直接 grep）────────────
        const val CODE_BOOT_LOG_NOT_REFRESHED = "BOOT_LOG_NOT_REFRESHED"
        const val CODE_BOOT_DMESG_NOT_REFRESHED = "BOOT_DMESG_NOT_REFRESHED"
        const val CODE_KSUD_VERSION_MISMATCH = "KSUD_VERSION_MISMATCH"
        const val CODE_MODULE_LIST_UNAVAILABLE = "MODULE_LIST_UNAVAILABLE"
        const val CODE_MODULE_SCRIPTS_NOT_EXECUTED = "MODULE_SCRIPTS_NOT_EXECUTED"
        const val CODE_MODULE_EXEC_PARTIAL = "MODULE_EXEC_PARTIAL"
        const val CODE_PREINIT_NOT_GENERATED = "PREINIT_NOT_GENERATED"
        const val CODE_METAMODULE_NOT_MOUNTED = "METAMODULE_NOT_MOUNTED"
        const val CODE_ZYGISK_DAEMON_ABSENT = "ZYGISK_DAEMON_ABSENT"
        const val CODE_BUSYBOX_UNUSABLE = "BUSYBOX_UNUSABLE"

        /** 拿不到证据（→ [KsuRuntimeState.Unknown]，**不是** PASS）。 */
        const val CODE_EVIDENCE_UNAVAILABLE = "EVIDENCE_UNAVAILABLE"

        /**
         * 从 logcat 原文抽取"真跑过的模块 id"（[EXEC_MARKER] 之后的第一段路径）。
         *
         * 只认 `/data/adb/modules/<id>/…`：`/data/adb/post-fs-data.d/` 下的一次性脚本
         * **不**算任何模块（T0 §5：30 条 exec 里含它们，直接数数会得错误结论）。
         */
        fun parseExecutedModuleIds(logcatText: String): List<String> {
            val ids = LinkedHashSet<String>()
            for (line in logcatText.lineSequence()) {
                val at = line.indexOf(EXEC_MARKER)
                if (at < 0) continue
                val rest = line.substring(at + EXEC_MARKER.length)
                val id = rest.substringBefore('/', missingDelimiterValue = "").trim()
                if (id.isNotEmpty() && MODULE_ID.matches(id)) ids += id
            }
            return ids.toList()
        }

        /**
         * `/proc/mounts` 是否已有模块挂载（overlay 的 `lowerdir=`/`upperdir=` 指向
         * `/data/adb/modules` 或 `/data/adb/metamodule`）。
         *
         * 只看**选项字段**（第 5 字段起），避免把"挂载点恰好在 `/data/adb/modules` 下"
         * 的无关挂载误判成模块挂载。`lowerdir` 是冒号分隔的多路径。
         */
        fun hasModuleMount(mountsText: String): Boolean {
            for (line in mountsText.lineSequence()) {
                if (line.isBlank()) continue
                // `/proc/mounts`：`<device> <mountpoint> <fstype> <options> <dump> <pass>`
                val fields = line.trim().split(WHITESPACE)
                if (fields.size < 4) continue
                val options = fields.drop(3).joinToString(" ")
                if (options.isEmpty()) continue
                val dirs = options.split(',')
                    .filter { it.startsWith("lowerdir=") || it.startsWith("upperdir=") }
                if (dirs.isEmpty()) continue
                val values = dirs.flatMap { it.substringAfter('=').split(':') }
                if (values.any { value -> MODULE_MOUNT_ROOTS.any { isUnder(value, it) } }) return true
            }
            return false
        }

        /** `ksud module list` 的 JSON 原文 → 模块 id；不可解析 → `null`（不伪造空列表）。 */
        fun parseModuleIds(ksudListJson: String): List<String>? =
            parseModuleRows(ksudListJson, enabledOnly = false)

        /** 同上，但只取 `enabled == "true"` 的行（ksud 的值是字符串）。 */
        fun parseEnabledModuleIds(ksudListJson: String): List<String>? =
            parseModuleRows(ksudListJson, enabledOnly = true)

        private fun parseModuleRows(ksudListJson: String, enabledOnly: Boolean): List<String>? {
            if (ksudListJson.isBlank()) return null
            val root = runCatching { JSON.parseToJsonElement(ksudListJson) }.getOrNull() ?: return null
            val array = root as? JsonArray ?: return null
            val ids = LinkedHashSet<String>()
            for (element in array) {
                val obj = element as? JsonObject ?: continue
                val id = (obj["id"] as? JsonPrimitive)
                    ?.takeIf { it.isString }?.content?.trim().orEmpty()
                if (!MODULE_ID.matches(id)) continue
                if (enabledOnly) {
                    val enabled = (obj["enabled"] as? JsonPrimitive)
                        ?.content?.trim().orEmpty()
                    if (!enabled.equals("true", ignoreCase = true) && enabled != "1") continue
                }
                ids += id
            }
            return ids.toList()
        }

        private fun isUnder(value: String, root: String): Boolean {
            val path = value.trim().trim('"')
            return path == root || path.startsWith("$root/")
        }

        private val MODULE_ID = Regex("^[A-Za-z0-9._-]{1,128}$")
        private val WHITESPACE = Regex("\\s+")
        private val JSON = Json { ignoreUnknownKeys = true; isLenient = true }
    }
}

/**
 * **生产探针**：把每个只读证据落到**已认证 root shell**（[KsuRootShellExecutor]）上。
 *
 * 为什么必须走 root shell：`/data/adb` 是 0700 root，app uid 连 `stat` 都不行；用本地
 * `File` 判定会把"已正确部署"的 ksud 判成"不存在"（审计 §8、`KsuRootShell.kt` 头注释）。
 *
 * 三条实现约束：
 * 1. **全部只读**：`stat` / `cat` / `head -c` / `grep` / `pgrep` / `test` / `busybox true`，
 *    没有任何写操作、不装不修（修复是 T1 + 用户点重启）。
 * 2. **区分"没有"与"没读到"**：每条命令都追加 `echo RC=$?` 与哨兵行；哨兵缺失 = shell
 *    没跑起来（返回 `null`），避免"未接线"被当成"判据失败/通过"。
 * 3. `/proc/mounts` 走 **global-mnt** shell（`debug su -g`）：模块 overlay 挂在 init 的
 *    命名空间里，普通 root shell 看到的是管理器自己的视图（上游 `withNewRootShell(true)`）。
 */
class RootShellBootReceiptProbe(
    private val shell: KsuRootShellExecutor,
) : KsuBootReceiptProbe {

    /** `ksud module list` 在一次评估里会被 P4/P6/P9 各问一次，这里做实例内记忆。 */
    @Volatile
    private var moduleListCache: String? = null

    @Volatile
    private var moduleListQueried: Boolean = false

    override fun statMtime(path: String): Long? {
        val invocation = run("stat -c %Y ${quote(path)}") ?: return null
        if (invocation.rc != 0) return null
        val seconds = invocation.lines.firstNotNullOfOrNull { it.trim().toLongOrNull() } ?: return null
        return seconds * 1000L
    }

    override fun readText(path: String): String? {
        // `/proc/mounts` 必须读 global-mnt 命名空间（见类注释第 3 条）。
        val invocation = run(
            "head -c $MAX_TEXT_BYTES ${quote(path)}",
            globalMnt = path == KsuBootReceipt.PROC_MOUNTS,
        ) ?: return null
        if (invocation.rc != 0) return null
        return invocation.lines.joinToString("\n")
    }

    override fun versionInfo(): KsuVersionInfo? {
        val invocation = run("${quote(KsuBootReceipt.DEPLOYED_KSUD)} debug info") ?: return null
        if (invocation.rc != 0) return null
        return KsuVersionInfo.parse(invocation.lines.joinToString("\n"))
    }

    override fun moduleIds(): List<String>? {
        val json = moduleList() ?: return null
        return KsuBootReceipt.parseModuleIds(json)
    }

    override fun enabledModuleIds(): List<String>? {
        val json = moduleList() ?: return null
        val enabled = KsuBootReceipt.parseEnabledModuleIds(json) ?: return null
        if (enabled.isEmpty()) return emptyList()
        // P6 的口径：只比"声明了开机脚本"的模块（没有脚本的模块本来就不会 exec）。
        val withScripts = scriptModuleIds() ?: return null
        return enabled.filter { it in withScripts }
    }

    override fun executedModuleIds(): List<String>? {
        val invocation = run(
            "grep -F -e ${quote(KsuBootReceipt.EXEC_MARKER)} ${quote(KsuBootReceipt.LOG_CAT)}",
        ) ?: return null
        // grep: 0 = 有匹配，1 = 无匹配（文件读得到），>=2 = 读不到/出错。
        if (invocation.rc > 1) return null
        return KsuBootReceipt.parseExecutedModuleIds(invocation.lines.joinToString("\n"))
    }

    override fun processNames(): List<String>? {
        val invocation = run(
            "pgrep -f -l ${quote(KsuBootReceipt.ZYGISK_DAEMON)}",
        ) ?: return null
        if (invocation.rc > 1) return null
        return invocation.lines.map { it.trim() }.filter { it.isNotEmpty() }
    }

    override fun isSymlink(path: String): Boolean? {
        val invocation = run(
            "/system/bin/test -L ${quote(path)} && echo $IS_SYMLINK_MARKER",
        ) ?: return null
        return invocation.lines.any { it.trim() == IS_SYMLINK_MARKER }
    }

    override fun ksuMountCount(): Int? {
        val invocation = run("grep -c -F -e ' KSU ' ${quote(KsuBootReceipt.PROC_MOUNTS)}") ?: return null
        // `grep -c` 无匹配时 rc=1 但仍打印 `0`：只信输出里的数字。
        return invocation.lines.firstNotNullOfOrNull { it.trim().toIntOrNull() }
    }

    override fun busyboxOk(): Boolean? {
        val invocation = run("${quote(KsuBootReceipt.BUSYBOX)} true") ?: return null
        return invocation.rc == 0
    }

    override fun metamoduleSelfReport(): String? {
        val command = KsuBootReceipt.METAMODULE_SELF_REPORT_FILES
            .joinToString(" ") { quote(it) }
        val invocation = run("cat $command") ?: return null
        val text = invocation.lines.joinToString("\n").trim()
        return text.ifEmpty { null }
    }

    // ── 内部 ────────────────────────────────────────────────────────────

    /** 一次 root shell 的解析结果：真实退出码 + 哨兵之前的输出行。 */
    private class Invocation(val rc: Int, val lines: List<String>)

    /**
     * 跑一条只读命令。
     *
     * 形态：`<command>; echo RC=$?; echo <SENTINEL>`。
     * - 哨兵缺失 ⇒ shell 根本没执行（未接线/异常）→ `null`；
     * - 否则 `rc` 是被测命令自身的退出码（不是整行的）。
     */
    private fun run(commandLine: String, globalMnt: Boolean = false): Invocation? {
        val line = "$commandLine; echo \"$RC_TAG=\$?\"; echo $SENTINEL"
        val result = runCatching {
            if (globalMnt) shell.execInGlobalMount(line) else shell.exec(line)
        }.getOrNull() ?: return null
        val trimmed = result.out.map { it.trim() }
        if (SENTINEL !in trimmed) return null
        val body = result.out.filterIndexed { index, _ -> trimmed[index] != SENTINEL }
        val rcLine = body.lastOrNull { it.trim().startsWith("$RC_TAG=") } ?: return null
        val rc = rcLine.trim().substringAfter('=').trim().toIntOrNull() ?: return null
        return Invocation(rc, body.filter { !it.trim().startsWith("$RC_TAG=") })
    }

    private fun moduleList(): String? {
        if (moduleListQueried) return moduleListCache
        val invocation = run("${quote(KsuBootReceipt.DEPLOYED_KSUD)} module list")
        val json = invocation?.takeIf { it.rc == 0 }?.lines?.joinToString("\n")
        moduleListCache = json
        moduleListQueried = true
        return json
    }

    private fun scriptModuleIds(): List<String>? {
        val invocation = run(
            "ls $MODULES_SCRIPTS_GLOB",
        ) ?: return null
        // 某个 glob 没匹配时 ls 返回 2，但仍会列出匹配项：有输出就采信。
        if (invocation.rc != 0 && invocation.lines.isEmpty()) return null
        return invocation.lines.mapNotNull { line ->
            val path = line.trim()
            val prefix = "${KsuBootReceipt.MODULES_DIR}/"
            if (!path.startsWith(prefix)) return@mapNotNull null
            val id = path.removePrefix(prefix).substringBefore('/')
            id.ifEmpty { null }
        }.distinct()
    }

    private fun quote(value: String): String = "'" + value.replace("'", "'\\''") + "'"

    private companion object {
        /** 单文件读取上限（logcat 可能几 MB，回执只需要头部证据）。 */
        const val MAX_TEXT_BYTES = 262_144

        /** root shell 没执行时哨兵不会出现（与 `rootShellPathProbe` 同一套路）。 */
        const val SENTINEL = "MAPLESU_RECEIPT_OK"
        const val RC_TAG = "MAPLESU_RC"
        const val IS_SYMLINK_MARKER = "MAPLESU_IS_SYMLINK"

        /** 只列"会触发开机脚本"的两个文件名（`system/` 挂载不在这里判，见 P8）。 */
        const val MODULES_SCRIPTS_GLOB =
            "/data/adb/modules/*/post-fs-data.sh /data/adb/modules/*/service.sh"
    }
}
