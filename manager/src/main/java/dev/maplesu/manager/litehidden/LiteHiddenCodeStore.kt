package dev.maplesu.manager.litehidden

import dev.maplesu.manager.runtime.RootExec
import dev.maplesu.manager.runtime.RootExecResult

/**
 * 自定义拨号密令的 root 存储（`/data/adb/maplesu/lite_hidden_code`，0600）：
 * 读取/写入都经 [RootExec]（LITE 下 Ultra 环境优先）；写入后回读校验。
 * 同时尽量同步到 `webui.conf`（daemon 可读取新密令；失败不影响 App 侧密令生效）。
 */
class LiteHiddenCodeStore(
    private val run: (String) -> RootExecResult = { script -> RootExec.execute(script) },
    private val codePath: String = LiteHiddenPaths.CODE_PATH,
    private val webuiConfigPath: String = "/data/adb/maplesu/webadmin.conf",
) {
    /** 磁盘密令（不存在/读失败 → null；调用方再退 prefs/默认值）。 */
    fun read(): String? {
        val result = runCatching { run("cat '$codePath' 2>/dev/null") }.getOrNull() ?: return null
        if (!result.ok) return null
        return LiteHiddenCodePolicy.sanitize(result.output)
    }

    /** 生效密令：磁盘 → [LiteHiddenCodePolicy.DEFAULT_CODE]（默认 70707）。 */
    fun effective(): String = read() ?: LiteHiddenCodePolicy.DEFAULT_CODE

    /** 写自定义密令：3–12 位数字（超长/非数字拒绝）→ root 0600 → 回读校验。 */
    fun write(code: String?): Boolean {
        val normalized = LiteHiddenCodePolicy.normalizeUserCode(code) ?: return false
        val result = runCatching {
            run(
                "mkdir -p '${LiteHiddenPaths.DATA_DIR}' 2>/dev/null; " +
                    "printf '%s' '$normalized' > '$codePath' && " +
                    "chmod 600 '$codePath' && printf 'LITE_OK'",
            )
        }.getOrNull() ?: return false
        if (!result.ok || !result.output.contains("LITE_OK")) return false
        return read() == normalized
    }

    /** 同步 webui.conf（保留 token/port，只更新/追加 lite_hidden_code 行；尽力而为）。 */
    fun syncWebuiConfig(code: String?): Boolean {
        val normalized = LiteHiddenCodePolicy.normalizeUserCode(code) ?: return false
        val conf = webuiConfigPath
        val script = buildString {
            append("if [ -f '$conf' ]; then ")
            append("grep -v '^lite_hidden_code=' '$conf' > '$conf.tmp' 2>/dev/null; ")
            append("else : > '$conf.tmp'; fi; ")
            append("printf 'lite_hidden_code=%s\\n' '$normalized' >> '$conf.tmp' && ")
            append("chmod 600 '$conf.tmp' && mv '$conf.tmp' '$conf' && printf 'LITE_OK'")
        }
        val result = runCatching { run(script) }.getOrNull() ?: return false
        return result.ok && result.output.contains("LITE_OK")
    }

    /** 设置页保存：写密令 + 同步 webui.conf；密令写成功即成功（sync 失败仅记 reason）。 */
    fun save(code: String?): CodeSaveResult {
        val normalized = LiteHiddenCodePolicy.normalizeUserCode(code)
            ?: return CodeSaveResult(false, "CODE_INVALID")
        if (!write(normalized)) return CodeSaveResult(false, "CODE_WRITE_FAILED")
        val synced = syncWebuiConfig(normalized)
        return CodeSaveResult(true, if (synced) "" else "WEBUI_CONFIG_SYNC_FAILED")
    }
}

data class CodeSaveResult(val ok: Boolean, val reason: String = "")
