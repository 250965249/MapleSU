package dev.maplesu.manager.workmode.gating

/**
 * `mode.gating` 日志的**纯格式化**部分。
 *
 * 不 import 任何 Android 类 → 可在主机 JVM 上直接单测（T4 `ModeGateFormatTest`）。
 * 字段白名单：`v/component/action/mode/state/boot/pid/uid/reason/[k=v]…`；
 * **禁止**路径、包名、模块 id、token、凭据、IP（review 断言 G9）。
 */
object ModeGateFormat {

    const val VERSION = 1
    const val MAX_LENGTH = 512

    /** action 三态：allow=执行、deny=策略禁止、skip=当前模式不需要。 */
    enum class Action(val wire: String) {
        ALLOW("allow"),
        DENY("deny"),
        SKIP("skip"),
    }

    /** reason 枚举；新增值必须先加到本枚举（04 §1.9 表格）。 */
    enum class Reason {
        UNDETERMINED,
        LITE,
        KSU,
        STEALTH_MASKED,
        PENDING_SWITCH,
        PROBE_FAILED,
        USER_CANCELLED,
        COMPONENT_DISABLED,
        NOT_APPLICABLE,
        ;

        val wire: String get() = name
    }

    data class Event(
        val component: String,
        val action: Action,
        /** `lite` / `ksu` / `none`（未判定）。 */
        val mode: String,
        /** `ModeState.name` 或 `UNKNOWN`。 */
        val state: String,
        /** bootId 前 8 位小写十六进制；未知为空串。 */
        val boot: String,
        val pid: Int,
        val uid: Int,
        val reason: Reason,
        /** 只允许计数/布尔，键名不得含空格/等号。 */
        val extras: Map<String, String> = emptyMap(),
    )

    fun format(event: Event): String {
        val sb = StringBuilder(160)
        sb.append("mode.gating v=").append(VERSION)
            .append(" component=").append(sanitize(event.component))
            .append(" action=").append(event.action.wire)
            .append(" mode=").append(event.mode)
            .append(" state=").append(sanitize(event.state))
            .append(" boot=").append(sanitize(event.boot))
            .append(" pid=").append(event.pid)
            .append(" uid=").append(event.uid)
            .append(" reason=").append(event.reason.wire)
        for ((key, value) in event.extras) {
            if (key.isBlank() || key.length > 24 || key.any { it == '=' || it.isWhitespace() }) continue
            sb.append(' ').append(key).append('=').append(sanitize(value))
        }
        val text = sb.toString()
        return if (text.length <= MAX_LENGTH) text else text.take(MAX_LENGTH - 1) + "\u2026"
    }

    private fun sanitize(value: String): String {
        val cleaned = buildString(value.length) {
            value.forEach { ch ->
                when {
                    ch == ' ' || ch == '\n' || ch == '\t' || ch == '=' || ch == '"' -> append('_')
                    ch.isISOControl() -> append('_')
                    else -> append(ch)
                }
            }
        }
        return if (cleaned.length <= 64) cleaned else cleaned.take(64)
    }
}
