package dev.maplesu.ghostlock.extract

/**
 * The OTA paste flow's user-visible state machine (no Android, no Compose, so it
 * is unit-testable).
 *
 * Copy rules (product decision, 2026-10-31):
 * - the field only appears when this device has no matching profile at all;
 * - success allows an attempt immediately (no "unverified"/"candidate" wording);
 * - failure is one short human sentence and never silently allows an attempt.
 */
enum class OtaFailure {
    EMPTY_URL,
    INVALID_URL,
    DOWNLOAD_FAILED,
    NOT_AN_IMAGE,
    NO_KERNEL,
    KERNEL_MISMATCH,
    INCOMPLETE_PROFILE,
    KALLSYMS_FAILED,
    ROUTE_UNSUPPORTED,
    KERNEL_FIXED,
    ALREADY_PRESENT,
    INTERNAL,
}

sealed interface OtaParseState {
    /** Nothing typed and nothing running. */
    data object Idle : OtaParseState

    /** A parse is in flight. */
    data object Parsing : OtaParseState

    /** Parsed, validated and exactly this device's kernel. */
    data class Succeeded(val release: String) : OtaParseState

    /** Failed or unusable; [reason] drives the one-line message. */
    data class Failed(val reason: OtaFailure) : OtaParseState
}

/** The exact user-visible strings this flow owns. */
object OtaCopy {
    const val MISSING_PROFILE =
        "当前机型没有内置 Ghostlock 配置。粘贴系统更新包直链，解析成功后即可尝试。"
    const val FIELD_HINT = "粘贴系统更新包直链"
    const val ACTION = "解析"
    const val PARSING = "正在解析…"
    const val SUCCESS = "解析成功，可以尝试 Ghostlock。"
    const val PICK_LOCAL = "选择 boot.img 和辅助镜像"
    const val OVERWRITE_QUESTION = "已存在该内核的配置，是否替换？"
    const val OVERWRITE_CONFIRM = "替换"
    const val OVERWRITE_CANCEL = "取消"
    private const val FAILURE_PREFIX = "解析失败："

    fun failureLine(reason: OtaFailure): String = FAILURE_PREFIX + when (reason) {
        OtaFailure.EMPTY_URL -> "请先粘贴更新包直链"
        OtaFailure.INVALID_URL -> "链接无效"
        OtaFailure.DOWNLOAD_FAILED -> "无法下载更新包"
        OtaFailure.NOT_AN_IMAGE -> "无法识别的更新包"
        OtaFailure.NO_KERNEL -> "包里找不到内核"
        OtaFailure.KERNEL_MISMATCH -> "内核版本与本机不一致"
        OtaFailure.INCOMPLETE_PROFILE -> "配置不完整，缺少必要参数"
        OtaFailure.KALLSYMS_FAILED -> "无法从内核读取符号表"
        OtaFailure.ROUTE_UNSUPPORTED -> "内核不支持当前利用方式"
        OtaFailure.KERNEL_FIXED -> "此内核已修复该漏洞"
        OtaFailure.ALREADY_PRESENT -> "已存在该内核的配置"
        OtaFailure.INTERNAL -> "解析出错，请重试"
    }

    /** The line shown for a state, or null when the flow shows nothing yet. */
    fun lineFor(state: OtaParseState): String? = when (state) {
        OtaParseState.Idle -> null
        OtaParseState.Parsing -> PARSING
        is OtaParseState.Succeeded -> SUCCESS
        is OtaParseState.Failed -> failureLine(state.reason)
    }
}

/**
 * Drives [OtaParseState] for one device.
 *
 * The transitions are intentionally small and complete:
 *
 * ```
 * Idle --start(url)--> Parsing
 * Parsing --finish(outcome)--> Succeeded | Failed
 * * --reset()--> Idle
 * ```
 *
 * `start` validates the URL before any network work; `finish` maps an
 * [ExtractionOutcome] to success only when a *complete* profile carries exactly
 * this device's release. Any other outcome is a [OtaParseState.Failed] - never a
 * silent pass.
 */
class GhostlockOtaFlow(private val deviceRelease: String) {
    var state: OtaParseState = OtaParseState.Idle
        private set

    /** Begin parsing [rawUrl]; returns the new state (never leaves [OtaParseState.Idle]). */
    fun start(rawUrl: String): OtaParseState {
        val url = rawUrl.trim()
        state = when {
            url.isEmpty() -> OtaParseState.Failed(OtaFailure.EMPTY_URL)
            !HttpRangeSource.isSupported(url) -> OtaParseState.Failed(OtaFailure.INVALID_URL)
            else -> OtaParseState.Parsing
        }
        return state
    }

    /** Complete a parse; the returned [ExtractionOutcome] decides success. */
    fun finish(outcome: ExtractionOutcome): OtaParseState {
        state = evaluate(outcome, deviceRelease)
        return state
    }

    fun reset() {
        state = OtaParseState.Idle
    }

    /** The refusal reason a failure maps to, for logs; null when it succeeded. */
    fun failureOf(outcome: ExtractionOutcome): OtaFailure? = when (val evaluated = evaluate(outcome, deviceRelease)) {
        is OtaParseState.Failed -> evaluated.reason
        else -> null
    }

    companion object {
        fun evaluate(outcome: ExtractionOutcome, deviceRelease: String): OtaParseState =
            when (outcome) {
                is ExtractionOutcome.Failure -> OtaParseState.Failed(classify(outcome))
                ExtractionOutcome.AlreadyPresent -> OtaParseState.Failed(OtaFailure.ALREADY_PRESENT)
                is ExtractionOutcome.NeedsOverwrite -> evaluate(ExtractionOutcome.Generated(
                    outcome.profiles), deviceRelease)
                is ExtractionOutcome.Generated -> {
                    val exact = outcome.profiles.firstOrNull { it.release == deviceRelease }
                    when {
                        exact == null -> OtaParseState.Failed(OtaFailure.KERNEL_MISMATCH)
                        !exact.complete -> OtaParseState.Failed(OtaFailure.INCOMPLETE_PROFILE)
                        else -> OtaParseState.Succeeded(deviceRelease)
                    }
                }
            }

        private fun classify(failure: ExtractionOutcome.Failure): OtaFailure {
            val message = failure.message.lowercase()
            return when {
                message.contains("not an http") -> OtaFailure.INVALID_URL
                message.contains("not an android boot image") ||
                    message.contains("arm64 image") -> OtaFailure.NOT_AN_IMAGE
                message.contains("no kernel release") -> OtaFailure.NO_KERNEL
                failure.kind == FailureKind.KALLSYMS -> OtaFailure.KALLSYMS_FAILED
                failure.kind == FailureKind.UNSUPPORTED -> OtaFailure.INCOMPLETE_PROFILE
                failure.kind == FailureKind.INFEASIBLE -> OtaFailure.ROUTE_UNSUPPORTED
                failure.kind == FailureKind.ALREADY_FIXED -> OtaFailure.KERNEL_FIXED
                message.contains("payload") || message.contains("remote") ||
                    message.contains("download") || message.contains("zip") ||
                    message.contains("length") || message.contains("failed to read") ->
                    OtaFailure.DOWNLOAD_FAILED
                else -> OtaFailure.INTERNAL
            }
        }
    }
}
