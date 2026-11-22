package dev.maplesu.manager.runtime

/** Root-service startup is separate from runtime pairing and from the service's mutations. */
internal object RootServiceBootstrap {
    internal data class Result(val code: Int, val output: String, val detail: String = "") {
        val ok: Boolean get() = code == 0
        constructor(result: RootExecResult) : this(
            if (result.ok) 0 else result.code.takeUnless { it == 0 } ?: -1, result.output, result.detail)
    }
    internal data class Candidate(val source: String, val run: (String) -> Result)

    private const val READY = "MAPLESU_ROOT_SERVICE_READY"
    private const val PROBE = "/system/bin/service check activity | /system/bin/grep -q ': found' || exit 14; " +
        "printf '$READY\\n'"

    // UID 0 in the kernel domain cannot look up framework Binder services. Transition only
    // that child; Magisk/KSU and other already working root domains keep their own policy.
    fun command(script: String): String = """
        [ "${'$'}(/system/bin/id -u)" = 0 ] || exit 13
        case "${'$'}(/system/bin/cat /proc/self/attr/current 2>/dev/null)" in
            u:r:kernel:s0) exec /system/bin/toybox runcon u:r:shell:s0 /system/bin/sh -c ${quote(script)} ;;
            *) exec /system/bin/sh -c ${quote(script)} ;;
        esac
    """.trimIndent()

    /** Try every read-only probe. Dispatch the official launch once, through the verified source. */
    fun launch(script: String, candidates: List<Candidate>,
               onAttempt: (String, String, Result) -> Unit = { _, _, _ -> }): Result {
        var frameworkUnavailable = false
        for (candidate in candidates) {
            if (Thread.currentThread().isInterrupted) return interrupted()
            val probe = run(candidate, PROBE)
            if (probe.code == 14) frameworkUnavailable = true
            onAttempt(candidate.source, "probe", probe)
            if (Thread.currentThread().isInterrupted) return interrupted()
            if (!probe.ok || probe.output.lineSequence().lastOrNull { it.isNotBlank() }?.trim() != READY) continue
            return run(candidate, script).also { onAttempt(candidate.source, "launch", it) }
        }
        return Result(-1, "", if (frameworkUnavailable) "INSTALLER_SERVICE_FRAMEWORK_UNAVAILABLE"
            else "INSTALLER_ROOT_SOURCES_EXHAUSTED")
    }

    private fun run(candidate: Candidate, script: String): Result = try {
        candidate.run(command(script))
    } catch (error: Exception) {
        if (error is InterruptedException) Thread.currentThread().interrupt()
        Result(-1, "", "ROOT_SERVICE_SOURCE_FAILED:${error.javaClass.simpleName}")
    }

    private fun interrupted() = Result(-1, "", "ROOT_EXECUTION_INTERRUPTED")

    private fun quote(script: String) = "'" + script.replace("'", "'\\''") + "'"
}
