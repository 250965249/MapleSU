package dev.maplesu.manager.litehidden

import java.util.Locale

/**
 * Lite 隐藏模式的拨号密令策略（纯函数，主机可测）。
 *
 * 恢复密令 = `/data/adb/maplesu/lite_hidden_code` ∪ App prefs 的并集（与 KSU 同思路：
 * 两份不一致时任意一份都能开锁，避免写盘失败导致锁死）；两边都没配才用默认 `70707`。
 * **默认值不会作为"万能兜底"塞进并集** —— 只有全部来源为空时才启用。
 */
object LiteHiddenCodePolicy {
    const val DEFAULT_CODE = "70707"
    const val MAX_CODE_LENGTH = 12

    fun sanitize(raw: String?): String? =
        raw?.trim()?.filter { it.isDigit() }?.take(MAX_CODE_LENGTH)?.takeIf { it.isNotBlank() }

    /** 接受集合：磁盘 ∪ prefs；都无 → {DEFAULT_CODE}。 */
    fun acceptedCodes(diskCode: String?, prefCode: String?): Set<String> {
        val codes = LinkedHashSet<String>()
        sanitize(diskCode)?.let { codes.add(it) }
        sanitize(prefCode)?.let { codes.add(it) }
        return if (codes.isEmpty()) setOf(DEFAULT_CODE) else codes
    }

    /** 拨号串（`*#*#<code>#*#*` 的 host 部分）是否命中。 */
    fun matches(dialed: String?, diskCode: String?, prefCode: String?): Boolean {
        val d = sanitize(dialed) ?: return false
        return d in acceptedCodes(diskCode, prefCode)
    }

    /** 恢复失败四态文案键（资源名，UI 由 `LiteHiddenCopy` 映射）。 */
    fun outcomeFor(
        liteMode: Boolean,
        hiddenEffectiveOn: Boolean,
        dialed: String?,
        diskCode: String?,
        prefCode: String?,
        writeSucceeded: Boolean = true,
    ): LiteHiddenOutcome = when {
        !liteMode -> LiteHiddenOutcome.NOT_SUPPORTED
        !hiddenEffectiveOn -> LiteHiddenOutcome.NOT_SUPPORTED
        !matches(dialed, diskCode, prefCode) -> LiteHiddenOutcome.NOT_AUTHORIZED
        !writeSucceeded -> LiteHiddenOutcome.FAILED
        else -> LiteHiddenOutcome.SUCCESS
    }

    /** 文案键（供 res 映射与测试锁定）。 */
    fun messageKey(outcome: LiteHiddenOutcome): String = when (outcome) {
        LiteHiddenOutcome.SUCCESS -> "lite_hidden_restore_ok"
        LiteHiddenOutcome.NOT_SUPPORTED -> "lite_hidden_restore_not_supported"
        LiteHiddenOutcome.NOT_AUTHORIZED -> "lite_hidden_restore_not_authorized"
        LiteHiddenOutcome.FAILED -> "lite_hidden_restore_failed"
    }

    /** 规范化用户输入（设置页改密令）：只留数字；**原始数字长度必须在 3–12**，超出即拒绝（不截断）。 */
    fun normalizeUserCode(raw: String?): String? {
        val digits = raw?.trim()?.filter { it.isDigit() } ?: return null
        return digits.takeIf { it.length in 3..MAX_CODE_LENGTH }
    }

    fun codeHint(code: String): String =
        String.format(Locale.US, "*#*#%s#*#*", sanitize(code) ?: DEFAULT_CODE)
}

/**
 * 恢复密令限流（与 KSU 同规则：连续失败 N 次 → 冷却窗口）。
 * 纯内存、注入时钟；进程重启即清（与现有 StealthReceiver 行为一致）。
 */
class LiteHiddenRateLimiter(
    private val maxFailures: Int = MAX_FAILURES,
    private val blockMillis: Long = BLOCK_MILLIS,
    private val clock: () -> Long = { System.currentTimeMillis() },
) {
    private var failures = 0
    private var blockedUntil = 0L

    fun isBlocked(): Boolean = clock() < blockedUntil

    fun recordFailure(): Boolean {
        if (isBlocked()) return true
        failures += 1
        if (failures >= maxFailures) {
            blockedUntil = clock() + blockMillis
            failures = 0
        }
        return isBlocked()
    }

    fun recordSuccess() {
        failures = 0
        blockedUntil = 0L
    }

    internal fun failureCount(): Int = failures

    companion object {
        const val MAX_FAILURES = 5
        /** 与 KSU 实现保持同一量级（1 分钟冷却），避免暴力猜默认 70707。 */
        const val BLOCK_MILLIS = 60_000L
    }
}
