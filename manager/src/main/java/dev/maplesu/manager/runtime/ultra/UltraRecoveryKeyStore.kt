// SPDX-License-Identifier: GPL-3.0-or-later
package dev.maplesu.manager.runtime.ultra

import android.content.Context
import android.os.Process
import android.provider.Settings
import android.util.Log
import dev.maplesu.manager.litehidden.ParasitePaths
import dev.maplesu.manager.litehidden.RecoveryIdentity
import dev.maplesu.manager.runtime.authorization.ContextPackageSnapshotSource
import dev.maplesu.manager.runtime.authorization.PackageIdentityReader

/** 执行一段 root 脚本；[UltraSuChannel] 的生产适配是 `{ script -> channel.runRoot(script) }`。 */
fun interface RootScriptRunner {
    fun run(script: String): SuExecResult?
}

/**
 * rootKey 的**受控恢复备份**：`/data/adb/maplesu/recovery/rootkey`（目录 0700、文件 0600、
 * owner 0:0）。
 *
 * <p>为什么放 `/data/adb`：普通卸载（`adb uninstall` / 系统卸载）只清 App 数据目录，
 * `/data/adb/maplesu` 会留下 —— 这正是「重装管理器后不认主」唯一能自救的地方。写/读都
 * 只能通过 root（[RootScriptRunner]），因此备份内容对普通 App 不可读。
 *
 * <p>安全纪律（全部有对应的主机测试）：
 *  - 只备份**格式合法**的 48 字符 key；不做「先写再校验」。
 *  - 加密由 [UltraRecoveryKey] 负责（AES-256-GCM，密钥绑定 androidId + 包名）。
 *  - 备份与身份材料都必须 `600` 且 uid `0`，目录必须 `700` 且 uid `0`；拒绝符号链接。
 *  - 替换前校验现有身份；两份临时文件都验过权限才提交，普通提交失败回滚原件。
 *  - 幂等：已有备份解出同一个 key 且身份一致 → 不重写（`ALREADY_BACKED_UP`）。
 *  - 任何日志/返回值都不得包含 key 或密文。
 */
object UltraRecoveryKeyStore {

    private const val TAG = "MapleSUUltraRecovery"

    const val DIRECTORY = "/data/adb/maplesu/recovery"
    const val PATH = "$DIRECTORY/rootkey"
    private const val TEMP_PATH = "$PATH.tmp"
    private const val IDENTITY_PATH = ParasitePaths.IDENTITY_FILE
    private const val IDENTITY_TEMP = "$IDENTITY_PATH.tmp"

    /** 备份结果；[reason] 是机器码，可直接进日志/文档。 */
    data class BackupOutcome(val ok: Boolean, val skipped: Boolean, val reason: String,
                             val sdkError: String? = null, val sdkErrorCode: Int? = null,
                             val detail: String? = null,
                             /** Current SDK/restorer readback is separate from the optional key backup. */
                             val identityPrepared: Boolean = false) {
        val code: String get() = reason
    }

    /** 读回结果；[key] 只在 [reason] == [REASON_OK] 时非空。 */
    data class RestoreOutcome(val key: String?, val reason: String) {
        val ok: Boolean get() = key != null
    }

    const val REASON_OK = "OK"
    const val REASON_ALREADY = "ALREADY_BACKED_UP"
    const val REASON_KEY_INVALID = "KEY_INVALID"
    const val REASON_SEAL_FAILED = "SEAL_FAILED"
    const val REASON_NO_ROOT = "NO_ROOT_CHANNEL"
    const val REASON_WRITE_FAILED = "WRITE_FAILED"
    const val REASON_READBACK_FAILED = "READBACK_FAILED"
    const val REASON_MODE_UNVERIFIED = "MODE_UNVERIFIED"
    const val REASON_ABSENT = "ABSENT"
    const val REASON_UNREADABLE = "UNREADABLE"
    const val REASON_NOT_OURS = "NOT_OURS"
    const val REASON_DECRYPT_FAILED = "DECRYPT_FAILED"
    const val REASON_IDENTITY_INVALID = "IDENTITY_INVALID"
    const val REASON_IDENTITY_CONFLICT = "IDENTITY_CONFLICT"
    const val REASON_TRUST_UNVERIFIED = "SIGNATURE_TRUST_UNVERIFIED"

    /**
     * 核心写入逻辑（不依赖 Android/Context，主机可测）。
     *
     * @param key 明文 rootKey；为 null / 格式非法直接拒绝（不产生垃圾备份）。
     * @param uid 当前管理器真实 App uid，与密文对应的身份一起保存；不用于获取 Root。
     */
    @Synchronized
    fun backup(
        root: RootScriptRunner,
        key: String?,
        androidId: String?,
        packageName: String,
        uid: Int,
    ): BackupOutcome {
        if (!UltraRecoveryKey.isValidKeyFormat(key)) {
            return BackupOutcome(false, skipped = true, reason = REASON_KEY_INVALID)
        }
        val identity = RecoveryIdentity.of(androidId, packageName, uid)
            ?: return BackupOutcome(false, skipped = true, reason = REASON_IDENTITY_INVALID)
        val sealed = UltraRecoveryKey.seal(key, identity.androidId, identity.packageName)
            ?: return BackupOutcome(false, skipped = false, reason = REASON_SEAL_FAILED)

        val existing = readRaw(root)
        readFailure(existing.state)?.let { return BackupOutcome(false, skipped = true, reason = it) }
        val savedMaterial = readRaw(root, IDENTITY_PATH)
        readFailure(savedMaterial.state)?.let { return BackupOutcome(false, skipped = true, reason = it) }
        val savedIdentity = if (savedMaterial.state == RawState.PRESENT) {
            RecoveryIdentity.parse(savedMaterial.payload)
                ?: return BackupOutcome(false, skipped = true, reason = REASON_IDENTITY_INVALID)
        } else null
        if (savedIdentity != null && savedIdentity.packageName != packageName) {
            return BackupOutcome(false, skipped = true, reason = REASON_IDENTITY_CONFLICT)
        }
        if (existing.state == RawState.PRESENT) {
            val decoded = UltraRecoveryKey.open(existing.payload, androidId, packageName)
            if (decoded == key && savedIdentity == identity && UltraRecoveryKey.isCurrentPayload(existing.payload)) {
                return BackupOutcome(true, skipped = true, reason = REASON_ALREADY)
            }
        }

        val result = root.run(writeScript(sealed, identity))
        if (result == null) return BackupOutcome(false, skipped = false, reason = REASON_NO_ROOT)
        val output = result.output
        if (output.lineSequence().any { it.trim() == MARK_UNSAFE }) {
            return BackupOutcome(false, skipped = false, reason = REASON_MODE_UNVERIFIED)
        }
        if (!result.ok || !output.contains(MARK_WROTE) || !output.contains(MARK_IDENTITY_WROTE)) {
            logWarn("recovery backup write failed exit=${result.exitCode} timedOut=${result.timedOut}")
            return BackupOutcome(false, skipped = false, reason = REASON_WRITE_FAILED)
        }
        if (parsePermissions(output.substringAfter(MARK_WROTE).substringBefore(MARK_IDENTITY_WROTE)) != true ||
            parsePermissions(output.substringAfter(MARK_IDENTITY_WROTE)) != true
        ) {
            return BackupOutcome(false, skipped = false, reason = REASON_MODE_UNVERIFIED)
        }
        // A successful shell/rename is not proof that the current key and identity
        // are both recoverable. Verify the same path a clean reinstall will read.
        if (restore(root, androidId, packageName).key != key || readIdentity(root, IDENTITY_PATH) != identity) {
            return BackupOutcome(false, skipped = false, reason = REASON_READBACK_FAILED)
        }
        logInfo("recovery backup written path=$PATH mode=600 owner=0")
        return BackupOutcome(true, skipped = false, reason = REASON_OK)
    }

    /** Android 入口：读取已有 key、App 作用域 androidId 与当前进程真实 uid。 */
    fun ensureBackup(
        context: Context,
        root: RootScriptRunner,
        key: String? = null,
        androidId: String? = androidId(context),
        packageName: String = context.packageName,
    ): BackupOutcome = backup(
        root = root,
        key = key ?: dev.maplesu.manager.modules.UltraRootKeyStore.read(context),
        androidId = androidId,
        packageName = packageName,
        uid = Process.myUid(),
    )

    /** 读回并解密（核心，无 Context）；[REASON_ABSENT] 与「有文件但解不开」严格区分。 */
    fun restore(
        root: RootScriptRunner,
        androidId: String?,
        packageName: String,
    ): RestoreOutcome {
        val raw = readRaw(root)
        return when (raw.state) {
            RawState.ABSENT -> RestoreOutcome(null, REASON_ABSENT)
            RawState.NO_ROOT, RawState.UNREADABLE -> RestoreOutcome(null, REASON_UNREADABLE)
            RawState.UNSAFE -> RestoreOutcome(null, REASON_MODE_UNVERIFIED)
            RawState.PRESENT -> {
                val payload = raw.payload
                if (!UltraRecoveryKey.looksLikeRecoveryPayload(payload)) {
                    RestoreOutcome(null, REASON_NOT_OURS)
                } else {
                    val key = UltraRecoveryKey.open(payload, androidId, packageName)
                        ?: readIdentity(root, IDENTITY_PATH)
                            ?.takeIf { it.packageName == packageName }
                            ?.let { UltraRecoveryKey.open(payload, it.androidId, it.packageName) }
                    if (key != null) {
                        RestoreOutcome(key, REASON_OK)
                    } else {
                        RestoreOutcome(null, REASON_DECRYPT_FAILED)
                    }
                }
            }
        }
    }

    /** A no-key SU channel does not replace the environment's pinned signer identity. */
    fun restore(
        context: Context,
        root: RootScriptRunner,
        androidId: String? = androidId(context),
        packageName: String = context.packageName,
    ): RestoreOutcome {
        val material = root.run(trustReadScript())
        val source = ContextPackageSnapshotSource(context)
        val trust = if (material?.ok == true) UltraReinstallTrust.fromConfig(material.output.trim())
            ?.withSigningLineage(UltraSigningLineage(source)::read) else null
        val reader = PackageIdentityReader(source)
        return UltraManagerSignatureAuthorization.recover(trust, { reader.read(Process.myUid()) }) {
            restore(root, androidId, packageName)
        } ?: RestoreOutcome(null, REASON_TRUST_UNVERIFIED)
    }

    internal fun trustReadScript(): String = """
        [ "${'$'}(id -u)" = 0 ] || exit 2
        D='${UltraIdentityBroker.DIRECTORY}'
        [ ! -e "${'$'}D/disabled" ] || exit 3
        for p in /data/adb /data/adb/maplesu "${'$'}D"; do
            [ ! -L "${'$'}p" ] && [ -d "${'$'}p" ] && [ "${'$'}(stat -c %u "${'$'}p")" = 0 ] || exit 3
            M=${'$'}(stat -c %a "${'$'}p"); [ "${'$'}((8#${'$'}M & 8#22))" -eq 0 ] || exit 3
        done
        P="${'$'}D/identity.json"
        [ ! -L "${'$'}P" ] && [ -f "${'$'}P" ] && [ "${'$'}(stat -c '%a %u %h' "${'$'}P")" = '600 0 1' ] || exit 3
        N=${'$'}(stat -c %s "${'$'}P"); [ "${'$'}N" -gt 0 ] && [ "${'$'}N" -le 8192 ] || exit 3
        cat "${'$'}P"
    """.trimIndent()

    /** 只读原始密文行（**不**按格式过滤：要能区分「没有文件」「读不了」「不是我们写的」）。 */
    private fun readRaw(root: RootScriptRunner, path: String = PATH): RawRead {
        val result = root.run(readScript(path)) ?: return RawRead(RawState.NO_ROOT)
        if (result.timedOut || result.failure != null) return RawRead(RawState.UNREADABLE)
        val lines = result.output.lineSequence()
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .toList()
        if (lines.any { it == MARK_UNSAFE }) return RawRead(RawState.UNSAFE)
        if (!result.ok) return RawRead(RawState.UNREADABLE)
        if (lines.any { it == MARK_ABSENT }) return RawRead(RawState.ABSENT)
        if (lines.any { it == MARK_UNREADABLE }) return RawRead(RawState.UNREADABLE)
        if (parsePermissions(lines.firstOrNull()) != true) return RawRead(RawState.UNREADABLE)
        // PRESENT 也包含「文件存在但为空」：交给 [UltraRecoveryKey.looksLikeRecoveryPayload] 判 NOT_OURS。
        return RawRead(RawState.PRESENT, lines.drop(1).joinToString("\n"))
    }

    private fun readIdentity(root: RootScriptRunner, path: String): RecoveryIdentity? {
        val raw = readRaw(root, path)
        return if (raw.state == RawState.PRESENT) RecoveryIdentity.parse(raw.payload) else null
    }

    private fun readFailure(state: RawState): String? = when (state) {
        RawState.NO_ROOT -> REASON_NO_ROOT
        RawState.UNREADABLE -> REASON_UNREADABLE
        RawState.UNSAFE -> REASON_MODE_UNVERIFIED
        else -> null
    }

    /**
     * 解析 `stat -c '%a %u'`（优先）或 `ls -ln`（兜底）的输出：
     * 返回 true = 0600 且 uid 0；false = 明确不是；null = 没有任何可解析回读。
     */
    fun parsePermissions(output: String?): Boolean? {
        if (output.isNullOrBlank()) return null
        for (line in output.lineSequence()) {
            val text = line.trim()
            if (text.isEmpty()) continue
            STAT_MATCH.find(text)?.let { match ->
                val mode = match.groupValues[1]
                val uid = match.groupValues[2]
                return mode == "600" && uid == "0"
            }
            LS_MATCH.find(text)?.let { match ->
                val perms = match.groupValues[1]
                val uid = match.groupValues[2]
                return perms == "-rw-------" && uid == "0"
            }
        }
        return null
    }

    fun androidId(context: Context): String? = runCatching {
        Settings.Secure.getString(context.contentResolver, Settings.Secure.ANDROID_ID)
    }.getOrNull()

    private const val MARK_WROTE = "MAPLESU_RK_WROTE"
    private const val MARK_ABSENT = "MAPLESU_RK_ABSENT"
    private const val MARK_UNREADABLE = "MAPLESU_RK_UNREADABLE"
    private const val MARK_UNSAFE = "MAPLESU_RK_UNSAFE"
    private const val MARK_IDENTITY_WROTE = "MAPLESU_RK_IDENTITY_WROTE"

    /** 禁止把「读不了」或「权限不安全」当成「不存在」。 */
    private enum class RawState { PRESENT, ABSENT, UNREADABLE, NO_ROOT, UNSAFE }

    private data class RawRead(val state: RawState, val payload: String? = null)

    /**
     * JVM 安全的日志（`android.util.Log` 在主机单测里是 stub，会抛异常）。
     * 生产仍然打印；单测里静默，绝不让「写一行日志」改变备份结论。
     */
    private fun logInfo(message: String) {
        runCatching { Log.println(Log.INFO, TAG, UltraSdkLogging.redact(message)) }
    }

    private fun logWarn(message: String) {
        runCatching { Log.println(Log.WARN, TAG, UltraSdkLogging.redact(message)) }
    }

    /** 每个 rename 原子；失败 trap 回滚两份原件，不声称跨断电的双文件原子性。 */
    private fun writeScript(payload: String, identity: RecoveryIdentity): String = buildString {
        // payload 只含 base64 字母表（[UltraRecoveryKey.seal] 保证），单引号内无转义风险。
        appendLine("umask 077")
        appendLine("[ \"\$(id -u)\" = 0 ] || exit 2")
        appendLine("safe_file() { [ ! -L \"\$1\" ] && { [ ! -e \"\$1\" ] || { [ -f \"\$1\" ] && [ \"\$(stat -c '%a %u' \"\$1\" 2>/dev/null)\" = '600 0' ]; }; }; }")
        appendLine("if [ -L '$DIRECTORY' ] || { [ -e '$DIRECTORY' ] && [ \"\$(stat -c '%a %u' '$DIRECTORY' 2>/dev/null)\" != '700 0' ]; } || ! safe_file '$PATH' || ! safe_file '$IDENTITY_PATH'; then echo $MARK_UNSAFE; exit 3; fi")
        appendLine("mkdir -p '$DIRECTORY' 2>/dev/null && chmod 700 '$DIRECTORY' || exit 4")
        appendLine("had_key=0; had_identity=0; committing=0")
        appendLine("cleanup() { rm -f '$TEMP_PATH' '$IDENTITY_TEMP' '$PATH.rollback' '$IDENTITY_PATH.rollback' 2>/dev/null; }")
        appendLine("rollback() { restored=1; if [ \"\$had_key\" = 1 ]; then mv -f '$PATH.rollback' '$PATH' || restored=0; else rm -f '$PATH' || restored=0; fi; if [ \"\$had_identity\" = 1 ]; then mv -f '$IDENTITY_PATH.rollback' '$IDENTITY_PATH' || restored=0; else rm -f '$IDENTITY_PATH' || restored=0; fi; [ \"\$restored\" = 1 ]; }")
        appendLine("trap 'status=\$?; if [ \"\$status\" -ne 0 ] && [ \"\$committing\" = 1 ]; then rollback || { echo MAPLESU_RK_ROLLBACK_FAILED; exit 9; }; fi; cleanup' EXIT")
        appendLine("trap 'exit 8' HUP INT TERM")
        appendLine("cleanup")
        appendLine("printf %s '$payload' > '$TEMP_PATH' || exit 5")
        appendLine("printf %s '${identity.toJson()}' > '$IDENTITY_TEMP' || exit 5")
        appendLine("chmod 600 '$TEMP_PATH' '$IDENTITY_TEMP' || exit 6")
        appendLine("if [ \"\$(stat -c '%a %u' '$TEMP_PATH' 2>/dev/null)\" != '600 0' ] || [ \"\$(stat -c '%a %u' '$IDENTITY_TEMP' 2>/dev/null)\" != '600 0' ]; then echo $MARK_UNSAFE; exit 6; fi")
        appendLine("if [ -f '$PATH' ]; then cp -p '$PATH' '$PATH.rollback' || exit 7; had_key=1; fi")
        appendLine("if [ -f '$IDENTITY_PATH' ]; then cp -p '$IDENTITY_PATH' '$IDENTITY_PATH.rollback' || exit 7; had_identity=1; fi")
        appendLine("committing=1")
        appendLine("mv -f '$TEMP_PATH' '$PATH' || exit 7")
        appendLine("mv -f '$IDENTITY_TEMP' '$IDENTITY_PATH' || exit 7")
        appendLine("if [ \"\$(stat -c '%a %u' '$PATH' 2>/dev/null)\" != '600 0' ] || [ \"\$(stat -c '%a %u' '$IDENTITY_PATH' 2>/dev/null)\" != '600 0' ]; then echo $MARK_UNSAFE; exit 6; fi")
        appendLine("sync || exit 7")
        appendLine("echo $MARK_WROTE; stat -c '%a %u' '$PATH'")
        appendLine("echo $MARK_IDENTITY_WROTE; stat -c '%a %u' '$IDENTITY_PATH'")
    }

    private fun readScript(path: String): String =
        "if [ \"\$(id -u)\" != 0 ]; then echo $MARK_UNREADABLE; " +
            "elif [ -L '$DIRECTORY' ] || { [ -e '$DIRECTORY' ] && [ \"\$(stat -c '%a %u' '$DIRECTORY' 2>/dev/null)\" != '700 0' ]; } || [ -L '$path' ]; then echo $MARK_UNSAFE; " +
            "elif [ -f '$path' ]; then " +
            "M=\$(stat -c '%a %u' '$path' 2>/dev/null); " +
            "if [ \"\$M\" != '600 0' ]; then echo $MARK_UNSAFE; " +
            "else echo \"\$M\"; cat '$path' 2>/dev/null || echo $MARK_UNREADABLE; fi; " +
            "elif [ -e '$path' ]; then echo $MARK_UNSAFE; else echo $MARK_ABSENT; fi"

    private val STAT_MATCH = Regex("""^([0-7]{3})\s+(\d+)$""")
    private val LS_MATCH = Regex("""^([-rwxst]{10})\s+\d+\s+(\d+)\s+""")
}
