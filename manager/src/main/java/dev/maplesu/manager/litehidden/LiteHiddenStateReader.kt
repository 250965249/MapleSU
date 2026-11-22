package dev.maplesu.manager.litehidden

import dev.maplesu.manager.runtime.RootExecResult

internal data class LiteHiddenStateRead(val state: LiteHiddenState, val failure: String? = null)

/** Only this read-only query may retry admission failures; mutations never pass here. */
internal object LiteHiddenStateReader {
    private const val MAX_ATTEMPTS = 4
    private val admissionFailures = setOf("ROOT_EXECUTION_BUSY", "ULTRA_ROOT_FAILED:MAPLESU_SDK_BUSY")

    fun read(
        execute: (String) -> RootExecResult,
        pause: (Long) -> Unit = { Thread.sleep(it) },
    ): LiteHiddenStateRead {
        repeat(MAX_ATTEMPTS) { attempt ->
            if (Thread.currentThread().isInterrupted) return interrupted()
            val result = try {
                execute(LiteHiddenPaths.stateReadScript())
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                return interrupted()
            } catch (error: Exception) {
                return LiteHiddenStateRead(LiteHiddenState.UNKNOWN, "ROOT_EXEC_EXCEPTION:${error.javaClass.simpleName}")
            }
            if (result.ok) {
                val state = parse(result.output)
                return LiteHiddenStateRead(state, if (state == LiteHiddenState.UNKNOWN) "HIDDEN_STATE_INVALID" else null)
            }
            val failure = result.detail.ifEmpty { "${result.backend}:code=${result.code}" }
            if (failure !in admissionFailures || attempt == MAX_ATTEMPTS - 1) {
                return LiteHiddenStateRead(LiteHiddenState.UNKNOWN, failure)
            }
            try {
                pause(150L * (attempt + 1))
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                return interrupted()
            }
        }
        error("unreachable")
    }

    fun parse(raw: String?): LiteHiddenState = when (
        raw?.lineSequence()?.map { it.trim() }?.lastOrNull { it.isNotEmpty() }
    ) {
        "LITE_MISSING", "0" -> LiteHiddenState.OFF
        "1" -> LiteHiddenState.ON
        else -> LiteHiddenState.UNKNOWN
    }

    private fun interrupted() = LiteHiddenStateRead(LiteHiddenState.UNKNOWN, "ROOT_EXECUTION_INTERRUPTED")
}
