package dev.maplesu.manager.runtime

import android.os.Bundle
import java.io.File
import java.util.concurrent.atomic.AtomicBoolean

/**
 * The user-space half of the L3 su gate (ABI v1, 2026-10-31).
 *
 * <p>**What runs where.** Kotlin never issues the magic `prctl`. This object forks
 * once per command through [run] (JNI, `manager/src/main/cpp/maplesu_su.c`); the
 * *child* arms itself with the ABI's magic `prctl` option - the numeric value exists
 * only in that native source, and a host test asserts that - proves `getuid() == 0`
 * and then `execv`s the caller's argv. The ART process that called in keeps its own
 * credentials untouched, which is the structural half of "ART must not be root".
 *
 * <p>**Fail-closed.** [execute] dispatches nothing at all unless
 * [SuGate.Gate.armed] holds: a missing token, an `suGate` that is not `ARMED`, or a
 * record bound to another attempt/boot returns `{code:126, out:"",
 * err:"SU_GATE_NOT_ARMED"}` and never reaches the native layer. There is no branch
 * here that turns an absent gate into a successful command.
 *
 * <p>**Test seam.** [inject] replaces the JNI dispatch with a fake [Runner]. Unit
 * tests use it so they never load the `.so`; production code never calls it.
 */
object NativeSu {
    /**
     * The JNI shim. Deliberately **not** `maplesu_su`: `manager/build.gradle.kts`
     * publishes the runtime's `maplesu-su` executable under `libmaplesu_su.so`, and
     * loading an executable instead of a shared object always fails. A distinct
     * name lets both entries coexist in the same APK.
     */
    const val LIBRARY = "maplesu_l3_su"

    /** `su -c` semantics: the child becomes root and execs this. */
    const val SHELL = "/system/bin/sh"

    /**
     * Reserved in-app client (ABI v1 keeps the slot): `<filesDir>/maplesu-su`.
     * Retried only when the native side reports that the *exec itself* failed.
     */
    const val FALLBACK_NAME = "maplesu-su"

    const val DEFAULT_TIMEOUT_MILLIS = 30_000

    /** The child refused: gate denied or `getuid()` was not 0 after the prctl. */
    const val EXIT_GATE_DENIED = 126

    /** `execv` returned in the child, i.e. the program could not be started. */
    const val EXIT_EXEC_FAILED = 127

    /** The session outlived its absolute lifetime and was SIGKILLed (design §4.3). */
    const val EXIT_TIMEOUT = 124

    /** One finished command; `code` is the child's exit status (or 124 on timeout). */
    data class SuResult(val code: Int, val out: String, val err: String)

    /** The dispatch seam: production is JNI, tests inject a fake. */
    fun interface Runner {
        fun run(token: Long, argv: Array<String>, timeoutMillis: Int): SuResult
    }

    /**
     * The streaming seam (design §4.2).
     *
     * <p>[start] forks a child that is **blocked on a control pipe and has not armed
     * anything**: its only credentials are the caller's. [commit] writes the one byte
     * that lets it arm the gate and exec; [abort] closes the pipe so it exits 126
     * without ever calling `prctl`. That is what makes the proxy's TOCTOU window
     * "the decision is re-read while the child exists but before it can become root".
     *
     * <p>Return values of [start]: a pid (> 0), or a negative transport error
     * ([START_ZERO_TOKEN], [START_FORK_FAILED], [START_LIMIT], [START_INVALID]).
     * [reap] returns the exit code, [REAP_RUNNING] when the deadline passed, or
     * [REAP_ERROR].
     */
    interface StreamRunner {
        fun start(
            token: Long,
            argv: Array<String>,
            stdinFd: Int,
            stdoutFd: Int,
            stderrFd: Int,
            globalMount: Boolean,
        ): Long

        fun commit(pid: Long): Boolean

        fun abort(pid: Long)

        fun reap(pid: Long, timeoutMillis: Int): Int

        fun kill(pid: Long, signal: Int)
    }

    /** `waitpid` says the child is still alive after the deadline. */
    const val REAP_RUNNING = -2

    /** `waitpid` failed; the caller must not report an exit that it did not observe. */
    const val REAP_ERROR = -1

    const val START_INVALID = -1L
    const val START_ZERO_TOKEN = -2L
    const val START_FORK_FAILED = -3L
    const val START_LIMIT = -4L

    /** Absolute session lifetime (design §4.3): SIGKILL and `SU_TIMEOUT` (124). */
    const val SESSION_LIFETIME_MILLIS = 300_000L

    private val loaded = AtomicBoolean(false)

    @Volatile private var injected: Runner? = null

    /**
     * Install a fake runner, or `null` to restore JNI dispatch. Only the host tests
     * call this; it exists so the gate and result handling can be tested without a
     * device and without the shared object.
     */
    @JvmStatic
    fun inject(runner: Runner?) {
        injected = runner
    }

    /**
     * Raw JNI entry. Returns `{code,out,err}` or null when the native side could not
     * even allocate the result; null is treated as an unavailable client, never 0.
     *
     * <p>JNI symbol: `Java_dev_maplesu_manager_runtime_NativeSu_run`.
     */
    external fun run(token: Long, argv: Array<String>, timeoutMs: Int): Bundle?

    /**
     * Run one argv behind the gate.
     *
     * @return the child's `{code,out,err}`. When the gate is not armed the result is
     *         `{126, "", "SU_GATE_NOT_ARMED"}` and the native layer is not called.
     */
    @JvmStatic
    @JvmOverloads
    fun execute(
        gate: SuGate.Gate,
        argv: Array<String>,
        timeoutMillis: Int = DEFAULT_TIMEOUT_MILLIS,
        fallback: File? = null,
    ): SuResult {
        if (!gate.armed) return SuResult(EXIT_GATE_DENIED, "", SuGate.ERROR_NOT_ARMED)
        val token = requireNotNull(gate.suToken) { SuGate.ERROR_NOT_ARMED }.value
        if (argv.isEmpty()) return SuResult(EXIT_GATE_DENIED, "", "SU_ARGV_EMPTY")
        val first = dispatch(token, argv, timeoutMillis)
        /*
         * ABI v1 reserves `<filesDir>/maplesu-su` as the second attempt. It is only
         * tried when the shell itself could not be exec'd (127). 126 is the gate's
         * own refusal and must never be retried, or a denied gate would look like a
         * path problem and a missing binary like a permission problem.
         */
        if (first.code != EXIT_EXEC_FAILED || fallback == null) return first
        val replacement = arrayOf(fallback.path) + argv.drop(1)
        val second = dispatch(token, replacement, timeoutMillis)
        /*
         * Both programs missing is one failure, and the interesting one is that the
         * shell itself could not start: returning the fallback's 127 would replace the
         * primary cause with its workaround. A fallback that fails any other way (the
         * binary exists and refused) is the more specific answer and is returned.
         */
        return if (second.code == EXIT_EXEC_FAILED) first else second
    }

    /** `su -c <script>` behind the gate; the shape `deploySu` and the daemon use. */
    @JvmStatic
    @JvmOverloads
    fun executeScript(
        gate: SuGate.Gate,
        script: String,
        fallback: File? = null,
        timeoutMillis: Int = DEFAULT_TIMEOUT_MILLIS,
    ): SuResult = execute(gate, arrayOf(SHELL, "-c", script), timeoutMillis, fallback)

    /** The `{code,out,err}` bundle `deploySu` returns to its caller. */
    @JvmStatic
    fun asBundle(result: SuResult): Bundle = Bundle().apply {
        putInt("code", result.code)
        putString("out", result.out)
        putString("err", result.err)
    }

    private fun dispatch(token: Long, argv: Array<String>, timeoutMillis: Int): SuResult {
        injected?.let { return it.run(token, argv, timeoutMillis) }
        ensureLoaded()
        val bundle = try {
            run(token, argv, timeoutMillis)
        } catch (error: UnsatisfiedLinkError) {
            // A missing symbol is a packaging fault, not a command result.
            throw IllegalStateException("SU_CLIENT_UNAVAILABLE", error)
        } ?: throw IllegalStateException("SU_CLIENT_UNAVAILABLE:null-bundle")
        return SuResult(
            code = bundle.getInt("code", -1),
            out = bundle.getString("out").orEmpty(),
            err = bundle.getString("err").orEmpty(),
        )
    }

    private fun ensureLoaded() {
        if (loaded.get()) return
        try {
            System.loadLibrary(LIBRARY)
            loaded.set(true)
        } catch (error: UnsatisfiedLinkError) {
            throw IllegalStateException("SU_CLIENT_UNAVAILABLE", error)
        }
    }

    // --- streaming entry points (design §4.2) ---------------------------------

    /**
     * Forks the prepared child. JNI symbol
     * `Java_dev_maplesu_manager_runtime_NativeSu_startStreaming`.
     */
    external fun startStreaming(
        token: Long,
        argv: Array<String>,
        stdinFd: Int,
        stdoutFd: Int,
        stderrFd: Int,
        globalMount: Boolean,
    ): Long

    external fun commitStreaming(pid: Long): Boolean

    external fun abortStreaming(pid: Long)

    external fun reapStreaming(pid: Long, timeoutMillis: Int): Int

    external fun killStreaming(pid: Long, signal: Int): Int

    @Volatile
    private var injectedStream: StreamRunner? = null

    /** Installs a fake streaming runner (host tests only); `null` restores JNI dispatch. */
    @JvmStatic
    fun injectStream(runner: StreamRunner?) {
        injectedStream = runner
    }

    /** True when a fake is installed; the endpoint uses it to decide whether to load the .so. */
    @JvmStatic
    fun hasInjectedStream(): Boolean = injectedStream != null

    /** The one streaming dispatcher; a packaging fault is reported, never treated as a result. */
    @JvmStatic
    fun streamRunner(): StreamRunner {
        injectedStream?.let { return it }
        return object : StreamRunner {
            override fun start(
                token: Long,
                argv: Array<String>,
                stdinFd: Int,
                stdoutFd: Int,
                stderrFd: Int,
                globalMount: Boolean,
            ): Long {
                require(argv.isNotEmpty()) { "SU_ARGV_EMPTY" }
                ensureLoaded()
                return try {
                    startStreaming(token, argv, stdinFd, stdoutFd, stderrFd, globalMount)
                } catch (error: UnsatisfiedLinkError) {
                    throw IllegalStateException("SU_CLIENT_UNAVAILABLE", error)
                }
            }

            override fun commit(pid: Long): Boolean {
                ensureLoaded()
                return try { commitStreaming(pid) }
                catch (error: UnsatisfiedLinkError) {
                    throw IllegalStateException("SU_CLIENT_UNAVAILABLE", error)
                }
            }

            override fun abort(pid: Long) {
                ensureLoaded()
                try { abortStreaming(pid) }
                catch (error: UnsatisfiedLinkError) {
                    throw IllegalStateException("SU_CLIENT_UNAVAILABLE", error)
                }
            }

            override fun reap(pid: Long, timeoutMillis: Int): Int {
                ensureLoaded()
                return try { reapStreaming(pid, timeoutMillis) }
                catch (error: UnsatisfiedLinkError) {
                    throw IllegalStateException("SU_CLIENT_UNAVAILABLE", error)
                }
            }

            override fun kill(pid: Long, signal: Int) {
                ensureLoaded()
                try { killStreaming(pid, signal) }
                catch (error: UnsatisfiedLinkError) {
                    throw IllegalStateException("SU_CLIENT_UNAVAILABLE", error)
                }
            }
        }
    }
}
