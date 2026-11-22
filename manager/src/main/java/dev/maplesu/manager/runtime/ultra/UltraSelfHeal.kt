// SPDX-License-Identifier: GPL-3.0-or-later
package dev.maplesu.manager.runtime.ultra

import dev.maplesu.manager.compat.ultraPreferences

import android.content.Context
import android.util.Log
import dev.maplesu.manager.modules.UltraRootKeyStore
import dev.maplesu.manager.workmode.ModeRuntime
import dev.maplesu.manager.workmode.WorkMode
import dev.maplesu.manager.workmode.superuser.LiteImplantQuiesceGate
import java.util.concurrent.atomic.AtomicBoolean

/**
 * 「重装管理器后不认主」的启动自愈结果。
 *
 * <p>可安全打印：只有机器码/状态名/计数，**永远不含 rootKey、密文或备份内容**。
 */
data class UltraSelfHealOutcome(
    val attempted: Boolean,
    val action: String,
    val modeSource: ModeSource = ModeSource.NONE,
    val keySource: KeySource? = null,
    val keyRestored: Boolean = false,
    val environment: String? = null,
    val whitelist: String? = null,
    val backup: String? = null,
    val failure: String? = null,
    val detail: String? = null,
) {
    val summary: String
        get() = "attempted=$attempted action=$action mode=$modeSource" +
            (keySource?.let { " keySource=$it" } ?: "") +
            " keyRestored=$keyRestored" +
            (environment?.let { " env=$it" } ?: "") +
            (whitelist?.let { " whitelist[$it]" } ?: "") +
            (backup?.let { " backup[$it]" } ?: "") +
            (failure?.let { " failure=$it" } ?: "") +
            (detail?.let { " detail=$it" } ?: "")
}

/**
 * 自愈编排器（可注入 [Ports]，主机测试无需 Android）。
 *
 * <p>执行序：
 *
 * ```
 * 前置：attempted/模式/静默/暂停/限频/根通道   ← UltraSelfHealPolicy.preflight
 *   ├─ 读本地 key 状态                         ← 无 key 才去读 root 备份
 *   ├─ 决策                                    ← UltraSelfHealPolicy.decide
 *   └─ 执行
 *        RECOVER_FROM_BACKUP:
 *          SDK 用候选 key 探一次状态（证明 key 被接受）
 *          → 写回 UltraRootKeyStore（Running 时走 UltraKeyProvisioning.pair）
 *          → 环境 NotInstalled 时补装（经 UltraEnvironmentInstaller，自带白名单+备份）
 *          → 自白名单（幂等）→ 刷新 root 备份 → 探针回读
 *        ENSURE_WHITELIST_AND_BACKUP:
 *          自白名单（幂等）→ 刷新 root 备份 → 探针回读
 * ```
 *
 * <p>任何一步抛异常都收敛成 [UltraSelfHealOutcome.failure]，绝不外抛（启动路径不得被打断）。
 */
class UltraSelfHealEngine(
    private val ports: Ports,
    private val clock: () -> Long = { System.currentTimeMillis() },
) {

    /** 一份 root 备份的读数；[key] 只在 [state] == OK 时非空。 */
    data class BackupSnapshot(val state: BackupState, val key: String? = null)

    interface Ports {
        fun mode(): WorkMode?
        fun liteSignals(suRootUid: Int?): UltraLiteEvidence.Signals
        fun quiescing(): Boolean
        fun suspended(): Boolean
        fun attemptedThisProcess(): Boolean
        fun markAttempted()
        fun rootUid(): Int?
        fun storedKey(): String?
        fun backup(): BackupSnapshot
        fun environmentState(key: String): String?
        fun storeRecoveredKey(key: String, running: Boolean): Boolean
        fun installEnvironment(key: String): UltraEnvironmentInstaller.Outcome
        fun ensureWhitelisted(key: String, force: Boolean): UltraSelfWhitelist.Result
        fun ensureBackup(key: String): UltraRecoveryKeyStore.BackupOutcome?
        fun probeEnvironment(): String?
        fun limitedUntilMillis(nowMillis: Long): Long
        fun recordAttempt(nowMillis: Long)
        fun recordSuccess(nowMillis: Long, code: String)
        fun recordFailure(nowMillis: Long, code: String)
        fun log(message: String)
    }

    fun runOnce(): UltraSelfHealOutcome {
        val now = clock()
        val mode = guard("MODE") { ports.mode() }
        val initial = UltraSelfHealPolicy.Facts(
            mode = mode,
            liteEvidence = UltraLiteEvidence.Result.NONE,
            quiescing = guard("QUIESCING") { ports.quiescing() } ?: false,
            suspended = guard("SUSPENDED") { ports.suspended() } ?: false,
            attemptedThisProcess = guard("ATTEMPTED") { ports.attemptedThisProcess() } ?: false,
            nowMillis = now,
            limitedUntilMillis = guard("RATE_LIMIT") { ports.limitedUntilMillis(now) } ?: 0L,
        )
        // Known modes and an already attempted process need no root probe to skip.
        if (mode != null || initial.attemptedThisProcess) {
            UltraSelfHealPolicy.preflight(initial).skip?.let {
                return skipped(it, UltraLiteEvidence.Result.NONE)
            }
        }
        val rootUid = guard("SU") { ports.rootUid() }
        val signals = if (mode == null) {
            guard("LITE_SIGNALS") { ports.liteSignals(rootUid) }
                ?: UltraLiteEvidence.Signals(suRootUid = rootUid)
        } else {
            UltraLiteEvidence.Signals(suRootUid = rootUid)
        }
        val evidence = UltraLiteEvidence.evaluate(signals)
        val base = initial.copy(liteEvidence = evidence, rootUid = rootUid)
        UltraSelfHealPolicy.preflight(base).skip?.let { return skipped(it, evidence) }

        val storedKey = guard("STORED_KEY") { ports.storedKey() }
        val storedState = when {
            storedKey == null -> StoredKeyState.ABSENT
            UltraRecoveryKey.isValidKeyFormat(storedKey) -> StoredKeyState.OK
            else -> StoredKeyState.MALFORMED
        }
        val backup = when {
            storedState == StoredKeyState.OK -> BackupSnapshot(BackupState.ABSENT)
            // 没有免 key 的根通道时读备份只会白跑一次 su；直接让 decide 给 NO_ROOT。
            rootUid != 0 -> BackupSnapshot(BackupState.UNREADABLE)
            else -> guard("BACKUP") { ports.backup() } ?: BackupSnapshot(BackupState.UNREADABLE)
        }

        val facts = base.copy(storedKeyState = storedState, backup = backup.state)
        when (val decision = UltraSelfHealPolicy.decide(facts)) {
            is SelfHealDecision.Skip -> return skipped(decision, evidence)
            is SelfHealDecision.Proceed -> {
                guard("MARK_ATTEMPTED") { ports.markAttempted() }
                guard("RECORD_ATTEMPT") { ports.recordAttempt(now) }
                return try {
                    // 设备实测：重装会换 UID，su_auth 里「包名还在」但内核不认（su 失败）。
                    // 根通道不可用时强制 remove+add 刷新 Ultra 的映射。
                    val forceReadd = rootUid != 0
                    when (decision.action) {
                        SelfHealAction.RECOVER_FROM_BACKUP ->
                            recover(decision, backup.key, now, forceReadd)

                        SelfHealAction.ENSURE_WHITELIST_AND_BACKUP ->
                            ensureOnly(decision, storedKey, now, forceReadd)
                    }
                } catch (error: Throwable) {
                    val code = "EXCEPTION:${error.javaClass.simpleName}"
                    guard("RECORD_FAILURE") { ports.recordFailure(now, code) }
                    finish(
                        UltraSelfHealOutcome(
                            attempted = true,
                            action = decision.action.name,
                            modeSource = decision.modeSource,
                            keySource = decision.keySource,
                            failure = code,
                        ),
                    )
                }
            }
        }
    }

    private fun recover(
        decision: SelfHealDecision.Proceed,
        backupKey: String?,
        now: Long,
        forceReadd: Boolean,
    ): UltraSelfHealOutcome {
        val candidate = backupKey
            ?: return fail(decision, now, "BACKUP_KEY_MISSING")
        // 1) 先证明 SDK 接受这个 key（Running/NotInstalled 都算接受；失败 = key 不对）。
        val state = guard("ENV_STATE") { ports.environmentState(candidate) }
            ?: return fail(decision, now, "BACKUP_KEY_REJECTED")
        if (state != "Running" && state != "NotInstalled") {
            return fail(decision, now, "ENVIRONMENT_$state", environment = state)
        }
        // 2) Running 走 pair()；否则仅恢复 key，并保留同一 key 已验证过的配对记录。
        val stored = guard("STORE_KEY") { ports.storeRecoveredKey(candidate, state == "Running") }
        if (stored != true) return fail(decision, now, "KEY_STORE_FAILED", environment = state)

        var environment = state
        var installSummary: String? = null
        if (state == "NotInstalled" && decision.installEnvironmentIfMissing) {
            val install = guard("INSTALL") { ports.installEnvironment(candidate) }
            if (install != null) {
                installSummary = "ok=${install.ok} sdkError=${install.sdkError}"
                guard("PROBE") { ports.probeEnvironment() }?.let { environment = it }
            } else {
                installSummary = "EXCEPTION"
            }
        } else if (state == "NotInstalled") {
            installSummary = "SKIPPED"
        }

        if (environment != "Running" && environment != "NotInstalled") {
            return fail(decision, now, "ENVIRONMENT_$environment", environment = environment,
                keyRestored = true, detail = installSummary)
        }

        val whitelist = guard("WHITELIST") { ports.ensureWhitelisted(candidate, forceReadd) }
        val backup = guard("BACKUP_WRITE") { ports.ensureBackup(candidate) }
        guard("PROBE") { ports.probeEnvironment() }?.let { environment = it }

        val ok = whitelist?.succeeded == true
        val code = when {
            ok -> "RECOVERED"
            else -> "WHITELIST_FAILED"
        }
        if (ok) {
            guard("RECORD_SUCCESS") { ports.recordSuccess(now, code) }
        } else {
            guard("RECORD_FAILURE") { ports.recordFailure(now, code) }
        }
        return finish(
            UltraSelfHealOutcome(
                attempted = true,
                action = decision.action.name,
                modeSource = decision.modeSource,
                keySource = decision.keySource,
                keyRestored = true,
                environment = environment,
                whitelist = whitelist?.summary,
                backup = backup?.reason,
                failure = if (ok) null else "WHITELIST_FAILED",
                detail = installSummary,
            ),
        )
    }

    private fun ensureOnly(
        decision: SelfHealDecision.Proceed,
        storedKey: String?,
        now: Long,
        forceReadd: Boolean,
    ): UltraSelfHealOutcome {
        val key = storedKey ?: return fail(decision, now, "KEY_VANISHED")
        var environment = guard("ENV_STATE") { ports.environmentState(key) }
        // A saved key does not override boot protection or a failed observation.
        // Only the explicit repair path may write through a protected environment.
        if (environment != "Running" && environment != "NotInstalled") {
            return fail(decision, now, "ENVIRONMENT_${environment ?: "UNKNOWN"}", environment = environment)
        }
        val whitelist = guard("WHITELIST") { ports.ensureWhitelisted(key, forceReadd) }
        val backup = guard("BACKUP_WRITE") { ports.ensureBackup(key) }
        guard("PROBE") { ports.probeEnvironment() }?.let { environment = it }
        val ok = whitelist?.succeeded == true
        val code = if (ok) "WHITELIST_ENSURED" else "WHITELIST_FAILED"
        if (ok) {
            guard("RECORD_SUCCESS") { ports.recordSuccess(now, code) }
        } else {
            guard("RECORD_FAILURE") { ports.recordFailure(now, code) }
        }
        return finish(
            UltraSelfHealOutcome(
                attempted = true,
                action = decision.action.name,
                modeSource = decision.modeSource,
                keySource = decision.keySource,
                keyRestored = false,
                environment = environment,
                whitelist = whitelist?.summary,
                backup = backup?.reason,
                failure = if (ok) null else "WHITELIST_FAILED",
            ),
        )
    }

    private fun skipped(
        skip: SelfHealDecision.Skip,
        evidence: UltraLiteEvidence.Result,
    ): UltraSelfHealOutcome {
        val outcome = UltraSelfHealOutcome(
            attempted = false,
            action = "SKIP:${skip.reason.name}",
            failure = skip.reason.name,
            detail = skip.detail.ifEmpty { evidence.reasons.joinToString(",") },
        )
        // 跳过也要留一行日志：真机上「为什么没修」必须可回答。
        guard("LOG") { ports.log(outcome.summary) }
        return outcome
    }

    private fun fail(
        decision: SelfHealDecision.Proceed,
        now: Long,
        code: String,
        environment: String? = null,
        keyRestored: Boolean = false,
        detail: String? = null,
    ): UltraSelfHealOutcome {
        guard("RECORD_FAILURE") { ports.recordFailure(now, code) }
        return finish(
            UltraSelfHealOutcome(
                attempted = true,
                action = decision.action.name,
                modeSource = decision.modeSource,
                keySource = decision.keySource,
                keyRestored = keyRestored,
                environment = environment,
                failure = code,
                detail = detail,
            ),
        )
    }

    private fun finish(outcome: UltraSelfHealOutcome): UltraSelfHealOutcome {
        guard("LOG") { ports.log(outcome.summary) }
        return outcome
    }

    private inline fun <T> guard(code: String, block: () -> T): T? = try {
        block()
    } catch (error: Throwable) {
        runCatching { ports.log("step=$code threw ${error.javaClass.simpleName}") }
        null
    }
}

/**
 * 启动自愈的接线点（`KernelSUApplication` 的 Ultra 预热段之后、独立守护线程里跑）。
 *
 * <p>三条硬约束：
 *  - **不阻塞 UI**：整个流程在自己的 daemon 线程里，且先等模式判定（最多
 *    [MODE_WAIT_MILLIS]），主线程/首帧完全不受影响；
 *  - **失败不打断启动**：任何异常都只写一行 logcat（[TAG]）；
 *  - **每次冷启动最多一次**：进程内 [attempted] 标记 + 文件里的失败退避
 *    （[UltraSelfHealBackoff]）。
 */
object UltraSelfHeal {

    const val TAG = "MapleSUUltraSelfHeal"
    const val PREFS = "maplesu-ultra-selfheal"
    const val KEY_LAST_FAILURE_AT = "lastFailureAtMillis"
    const val KEY_FAILURE_COUNT = "failureCount"
    const val KEY_LAST_OUTCOME = "lastOutcome"
    const val KEY_LAST_OUTCOME_AT = "lastOutcomeAtMillis"

    const val MODE_WAIT_MILLIS = 12_000L
    private const val MODE_POLL_MILLIS = 200L

    private val attempted = AtomicBoolean(false)

    @Volatile
    var lastOutcome: UltraSelfHealOutcome? = null
        private set

    /** 生产入口：起一条守护线程，等模式判定后跑一次；永不抛、永不阻塞调用方。 */
    fun runOnStartup(context: Context, modeWaitMillis: Long = MODE_WAIT_MILLIS) {
        val appContext = context.applicationContext
        runCatching {
            Thread {
                runCatching {
                    val mode = awaitModeResolved(modeWaitMillis)
                    Log.i(TAG, "self-heal start mode=${mode ?: "UNRESOLVED"}")
                    val outcome = UltraSelfHealEngine(AndroidPorts(appContext)).runOnce()
                    lastOutcome = outcome
                    Log.i(TAG, "self-heal outcome ${outcome.summary}")
                }.onFailure { error ->
                    Log.w(TAG, "self-heal failed (ignored): ${error.javaClass.simpleName}")
                }
            }.apply {
                name = "maplesu-ultra-selfheal"
                isDaemon = true
            }.start()
        }.onFailure { Log.w(TAG, "self-heal thread unavailable (ignored)") }
    }

    /** 等 `ModeRuntime` 判定（未判定时返回 null；**超时绝不默认 LITE**）。 */
    fun awaitModeResolved(
        timeoutMillis: Long,
        pollMillis: Long = MODE_POLL_MILLIS,
        sleeper: (Long) -> Unit = { Thread.sleep(it) },
        modeProvider: () -> WorkMode? = { ModeRuntime.active },
    ): WorkMode? {
        val deadline = System.currentTimeMillis() + timeoutMillis.coerceAtLeast(0L)
        var resolved = runCatching { modeProvider() }.getOrNull()
        while (resolved == null && System.currentTimeMillis() < deadline) {
            runCatching { sleeper(pollMillis) }.onFailure { return null }
            resolved = runCatching { modeProvider() }.getOrNull()
        }
        return resolved
    }

    /** 测试/诊断：清掉进程内「已尝试」标记（生产不调用）。 */
    internal fun resetForTest() {
        attempted.set(false)
        lastOutcome = null
    }

    /**
     * Android 端口实现：所有 Android/JNI/su 细节都在这里，引擎本身保持纯逻辑。
     */
    private class AndroidPorts(context: Context) : UltraSelfHealEngine.Ports {
        private val app = context.applicationContext
        private val prefs = app.ultraPreferences(PREFS, Context.MODE_PRIVATE)
        private val su = UltraSuChannel()
        private val root = RootScriptRunner { script -> su.runRoot(script) }

        override fun mode(): WorkMode? = ModeRuntime.active

        override fun liteSignals(suRootUid: Int?): UltraLiteEvidence.Signals {
            if (suRootUid != 0) return UltraLiteEvidence.Signals(suRootUid = suRootUid)
            val output = su.runRoot(UltraLiteEvidence.SIGNAL_SCRIPT)?.output
            return UltraLiteEvidence.parseSignals(output, suRootUid)
        }

        override fun quiescing(): Boolean = LiteImplantQuiesceGate.isBlocked()

        override fun suspended(): Boolean = UltraRootKeyStore.isSuspended(app)

        override fun attemptedThisProcess(): Boolean = attempted.get()

        override fun markAttempted() {
            attempted.set(true)
        }

        override fun rootUid(): Int? = su.rootUid()

        override fun storedKey(): String? = UltraRootKeyStore.read(app)

        override fun backup(): UltraSelfHealEngine.BackupSnapshot {
            val outcome = UltraRecoveryKeyStore.restore(app, root)
            val state = when (outcome.reason) {
                UltraRecoveryKeyStore.REASON_OK -> BackupState.OK
                UltraRecoveryKeyStore.REASON_ABSENT -> BackupState.ABSENT
                UltraRecoveryKeyStore.REASON_NOT_OURS,
                UltraRecoveryKeyStore.REASON_DECRYPT_FAILED,
                -> BackupState.INVALID

                else -> BackupState.UNREADABLE
            }
            return UltraSelfHealEngine.BackupSnapshot(state, outcome.key)
        }

        override fun environmentState(key: String): String? {
            val receipt = UltraRuntimeClient { key }.environmentState()
            return if (receipt.succeeded) receipt.string("state") else null
        }

        override fun storeRecoveredKey(key: String, running: Boolean): Boolean {
            if (!running) {
                UltraKeyPairedStore.storeRecoveredKey(app, key)
                return true
            }
            return UltraKeyProvisioning(app).pair(key).ok
        }

        override fun installEnvironment(key: String): UltraEnvironmentInstaller.Outcome =
            UltraEnvironmentInstaller.install(app, UltraRuntimeClient { key })

        override fun ensureWhitelisted(key: String, force: Boolean): UltraSelfWhitelist.Result =
            UltraSelfWhitelist.ensureCurrentAuthority(app, UltraRuntimeClient { key })

        override fun ensureBackup(key: String): UltraRecoveryKeyStore.BackupOutcome? =
            UltraEnvironmentInstaller.backupKey(app, key)

        override fun probeEnvironment(): String? =
            runCatching { UltraEnvironmentProbe.refresh(app).name }.getOrNull()

        override fun limitedUntilMillis(nowMillis: Long): Long = UltraSelfHealBackoff.limitedUntilMillis(
            prefs.getLong(KEY_LAST_FAILURE_AT, 0L),
            prefs.getInt(KEY_FAILURE_COUNT, 0),
        )

        override fun recordAttempt(nowMillis: Long) {
            prefs.edit().putLong(KEY_LAST_OUTCOME_AT, nowMillis).apply()
        }

        override fun recordSuccess(nowMillis: Long, code: String) {
            prefs.edit()
                .putInt(KEY_FAILURE_COUNT, 0)
                .putLong(KEY_LAST_FAILURE_AT, 0L)
                .putString(KEY_LAST_OUTCOME, code)
                .putLong(KEY_LAST_OUTCOME_AT, nowMillis)
                .apply()
        }

        override fun recordFailure(nowMillis: Long, code: String) {
            val failures = prefs.getInt(KEY_FAILURE_COUNT, 0) + 1
            prefs.edit()
                .putInt(KEY_FAILURE_COUNT, failures)
                .putLong(KEY_LAST_FAILURE_AT, nowMillis)
                .putString(KEY_LAST_OUTCOME, code)
                .putLong(KEY_LAST_OUTCOME_AT, nowMillis)
                .apply()
        }

        override fun log(message: String) {
            Log.i(TAG, message)
        }
    }
}
