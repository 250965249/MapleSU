package dev.maplesu.manager.runtime

import android.content.ComponentName
import android.content.Context
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Bundle
import android.os.IBinder
import android.os.Looper
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import dev.maplesu.manager.jailbreak.JailbreakRequest
import dev.maplesu.manager.jailbreak.JailbreakStatus
import dev.maplesu.manager.workmode.ModeRuntime
import dev.maplesu.manager.workmode.WorkMode
import dev.maplesu.manager.workmode.gating.ModeComponentIds
import java.io.IOException
import java.util.concurrent.TimeUnit

/** Explicit Hook preparation restores its SU and module entry points after a Normal boot disabled them. */
internal fun enableHookComponents(mode: WorkMode?, enable: (String) -> Unit) {
    check(mode != WorkMode.KSU) { "SU_HOOK_ACTIVE_KSU" }
    enable(ModeComponentIds.COMPONENT_NATIVE_SU_DIRECTORY_PROVIDER)
    enable(ModeComponentIds.COMPONENT_NATIVE_SU_BROKER_SERVICE)
    enable(ModeComponentIds.COMPONENT_HOOK_SU_KEEPER_SERVICE)
    enable(ModeComponentIds.COMPONENT_LITE_MODULE_BOOT_RECEIVER)
    enable(ModeComponentIds.COMPONENT_LITE_MODULE_BOOT_SERVICE)
}

/** Trusted preparation only. Ordinary clients neither launch Root nor receive internal credentials. */
internal object NativeSuDaemon {
    @Volatile private var cached: IRootManagementService? = null
    @Volatile private var cachedOrigin: String? = null

    /**
     * Prepares one executor. A jailbreak request always names the origin it is
     * for, so an endpoint prepared for normal mode or for another attempt is never
     * returned as this attempt's executor.
     */
    @Synchronized
    /**
     * Normal/KSU prepare: the provider answers with the record it wrote, not with a
     * management binder (there is no lease to adopt). The old shared path demanded
     * `getBinder("manager")` and turned a successful KSU handover into
     * SU_EXECUTOR_UNAVAILABLE in the UI.
     */
    fun prepareKsu(context: Context, request: JailbreakRequest): Bundle {
        check(request.rootBackend == JailbreakRequest.BACKEND_KSU) { "SU_KSU_BACKEND_REQUIRED" }
        check(Looper.myLooper() != Looper.getMainLooper()) { "SU_BACKGROUND_THREAD_REQUIRED" }
        // A previous Normal boot persists this component's disabled state.
        // Only the private preparation entry is needed for a KSU attempt.
        context.packageManager.setComponentEnabledSetting(
            ComponentName(context.packageName, ModeComponentIds.COMPONENT_NATIVE_SU_DIRECTORY_PROVIDER),
            PackageManager.COMPONENT_ENABLED_STATE_ENABLED,
            PackageManager.DONT_KILL_APP,
        )
        val extras = Bundle().apply {
            putString("jailbreak", request.method)
            putString("attempt", request.attemptId)
            putString("boot", request.bootId)
            putString("rootBackend", request.rootBackend)
        }
        StageMark.mark(context, "daemon:prepareKsu:" + request.origin)
        return try {
            val call = {
                com.maplesu.core.ui.util.ProviderCall.call(context.contentResolver,
                    Uri.parse("content://${NativeSuDirectoryProvider.AUTHORITY}"),
                    "prepare", null, extras)
            }
            checkNotNull(if (request.method == "maplesu_93260")
                withWallClockBudget(hookPrepareBudgetMillis(request), "MAPLESU_93260_PREPARE_TIMEOUT", call)
            else call()) { "SU_KSU_PREPARE_EMPTY_REPLY" }
        } catch (error: Exception) {
            StageMark.mark(context, "daemon:prepareKsu:threw:" + (error.message ?: error.javaClass.simpleName))
            throw error
        }
    }

    fun management(context: Context, request: JailbreakRequest? = null): IRootManagementService {
        val origin = request?.origin ?: NORMAL_ORIGIN
        // S05: follow-up management/authorization/SU calls must reuse the live
        // executor of whatever origin produced it.
        if (request == null) {
            cached?.takeIf { it.asBinder().isBinderAlive }?.let { return it }
        }
        if (cachedOrigin == origin) {
            cached?.takeIf { it.asBinder().isBinderAlive }?.let { return it }
        }
        // Step-4 (D4-10/MF-12): the hook route publishes no management binder before L3,
        // so a management call is refused by name here - before the binder lookup that
        // would otherwise report the ambiguous SU_EXECUTOR_UNAVAILABLE.
        check(request?.rootBackend != JailbreakRequest.BACKEND_HOOK) {
            "HOOK_MANAGEMENT_UNAVAILABLE"
        }
        check(Looper.myLooper() != Looper.getMainLooper()) { "SU_BACKGROUND_THREAD_REQUIRED" }
        val extras = request?.let {
            Bundle().apply {
                putString("jailbreak", it.method)
                putString("attempt", it.attemptId)
                putString("boot", it.bootId)
                // Step-4 (item 14/MF-1): without this the provider rebuilds the request
                // with rootBackend == null and the hook branch is dead code.
                putString("rootBackend", it.rootBackend)
            }
        }
        StageMark.mark(context, "daemon:prepare:" + origin)
        val result = try {
            com.maplesu.core.ui.util.ProviderCall.call(context.contentResolver,Uri.parse("content://${NativeSuDirectoryProvider.AUTHORITY}"),
                "prepare", null, extras)
        } catch (error: Throwable) {
            StageMark.mark(context, "daemon:prepare:threw:" + (error.message ?: error.javaClass.simpleName))
            throw error
        }
        StageMark.mark(context, "daemon:prepare:returned:" + (result != null) +
            ":" + (result?.getBinder("manager") != null))
        val endpoint = checkNotNull(result?.getBinder("manager")) { "SU_EXECUTOR_UNAVAILABLE" }
        return IRootManagementService.Stub.asInterface(endpoint).also {
            val state = it.status()
            check(state.getInt("rootUid", -1) == 0 && state.getInt("rootPid", -1) > 1 &&
                state.getInt("managerUid", -1) == context.applicationInfo.uid && state.getInt("protocol") == 1) {
                "SU_EXECUTOR_IDENTITY_INVALID"
            }
            cached = it
            cachedOrigin = origin
            endpoint.linkToDeath({
                if (cached?.asBinder() == endpoint) { cached = null; cachedOrigin = null }
            }, 0)
        }
    }

    /** Adopts an endpoint prepared in this process so later calls reuse it. */
    @Synchronized
    fun adopt(endpoint: IRootManagementService, origin: String) {
        cached = endpoint
        cachedOrigin = origin
        val binder = endpoint.asBinder()
        binder.linkToDeath({ if (cached?.asBinder() === binder) { cached = null; cachedOrigin = null } }, 0)
    }

    /**
     * Step-4 (item 14, design §3.5/D4-11): the hook route's preparation.
     *
     * <p>The provider is the only place that may escalate, so this function must **not**
     * call [JailbreakExecutor.escalate] first: `escalateHook` marks this boot's kernel
     * window (`DirtyfragAttempt.markKernelWindow`), and a second attempt in the same boot
     * is refused with `DIRTYFRAG_REBOOT_REQUIRED_AFTER_ATTEMPT`. "Escalate, then prepare"
     * therefore destroys its own attempt (R-D13). This is the same shape the product path
     * (`JailbreakController.run(..., rootBackend = "hook")`) uses.
     *
     * <p>**M3/M5 (report `maplesu-ultra-attestation-stability-2026-10-31.md` §5).** Two
     * defects are fixed here:
     *
     *  - the provider's answer used to arrive as a binder exception, so the reason only
     *    existed in this process's stack (`NativeSuDaemon.kt:114` had no `try` at all).
     *    It is caught now, turned into a named token, and **written into the status
     *    record before this function returns** - the test process dying next cannot take
     *    the token with it;
     *  - `contentResolver.call` has no timeout of its own, so a provider that never
     *    answered parked this thread for as long as the instrument run lasted (P1/P6).
     *    The call now runs on its own thread behind a 90 s wall-clock budget and reports
     *    [HOOK_PREPARE_TIMEOUT] instead of waiting forever.
     *
     * @return the status the provider wrote - `DAEMON_READY` when the attestation proof
     *         held, otherwise the last honest stage with its refusal token.
     */
    @Synchronized
    fun prepareHook(context: Context, request: JailbreakRequest): JailbreakStatus {
        check(request.rootBackend == JailbreakRequest.BACKEND_HOOK) {
            "SU_HOOK_BACKEND_REQUIRED"
        }
        check(Looper.myLooper() != Looper.getMainLooper()) { "SU_BACKGROUND_THREAD_REQUIRED" }
        enableHookComponents(context)
        val extras = Bundle().apply {
            putString("jailbreak", request.method)
            putString("attempt", request.attemptId)
            putString("boot", request.bootId)
            putString("rootBackend", request.rootBackend)
        }
        StageMark.mark(context, "daemon:prepareHook:" + request.origin)
        val outcome = runCatching {
            withWallClockBudget(hookPrepareBudgetMillis(request), HOOK_PREPARE_TIMEOUT) {
                com.maplesu.core.ui.util.ProviderCall.call(context.contentResolver,
                    Uri.parse("content://${NativeSuDirectoryProvider.AUTHORITY}"),
                    "prepare", null, extras)
            }
        }
        val thrown = outcome.exceptionOrNull()
        // A thrown call and a refused-but-returned bundle are the same thing to the
        // caller: one named token. The provider already wrote its own refusals into the
        // record; re-reading it keeps the record the single source of truth.
        val token = thrown?.let { hookPrepareFailureToken(it) }
            ?: outcome.getOrNull()?.getString("failure")
        val current = runCatching { JailbreakStatus.read(context) }.getOrNull()
        if (token != null && current?.failure != token) {
            val target = hookPreparationFailure(
                current = current,
                request = request,
                token = token,
                message = hookPrepareFailureMessage(token, thrown),
                nowMillis = System.currentTimeMillis(),
                ownerPid = android.os.Process.myPid(),
            )
            if (target != null) {
                /*
                 * T3 / C1: `prepareHook` runs in the UI process. It answers with the
                 * record it built; only the provider persists a failure, so this method
                 * must never write `status.json`.
                 */
                StageMark.mark(context, "daemon:prepareHook:failed:" + token)
                return target
            }
        }
        StageMark.mark(context, "daemon:prepareHook:returned:" + (current?.stage ?: "missing"))
        // No binder is expected (and none is adopted): the hook route has no management
        // endpoint before L3. What the caller needs is the record the provider wrote.
        val status = current ?: failureStatusWithoutRecord(context, request)
        if (status.stage == JailbreakStatus.STAGE_DAEMON_READY && status.failure == null) {
            try {
                HookSuKeeperService.retain(context, status.attemptId)
                RuntimeDeployment.start(context)
            } catch (error: Exception) {
                return status.copy(failure = "HOOK_PUBLICATION_KEEPER_FAILED",
                    message = "Hook publication lifetime was not acknowledged")
            }
        }
        return status
    }

    /**
     * M3: `prepareHook` always returns a record. When the provider wrote none at all
     * (it died before its first write), the fallback is built in memory and returned -
     * it is never persisted from this process (T3 / C1).
     */
    private fun failureStatusWithoutRecord(context: Context,
                                           request: JailbreakRequest): JailbreakStatus {
        val token = "HOOK_BACKEND_NOT_READY:status_missing"
        val fallback = hookFailureStatus(
            current = null,
            request = request,
            token = token,
            message = "hook prepare left no status record (" + token + ")",
            nowMillis = System.currentTimeMillis(),
            ownerPid = android.os.Process.myPid(),
        ) ?: return JailbreakStatus(
            method = request.method,
            stage = JailbreakStatus.STAGE_FAILED,
            message = "hook prepare left no status record (" + token + ")",
            startedAtMillis = System.currentTimeMillis(),
            updatedAtMillis = System.currentTimeMillis(),
            bootId = request.bootId,
            attemptId = request.attemptId,
            rootBackend = JailbreakRequest.BACKEND_HOOK,
            failure = token,
        )
        // T3 / C1: returned to the caller only; the provider owns the record.
        StageMark.mark(context, "daemon:prepareHook:failed:" + token)
        return fallback
    }

    /**
     * §6.5: ask the provider to re-prove an existing carrier (soft reboot) and return
     * the attempt id when the session is usable again, or null when it is not.
     */
    fun reproveHook(context: Context): String? = reproveHookOutcome(context)
        ?.takeIf { it.stage == JailbreakStatus.STAGE_DAEMON_READY && it.failure == null }?.attemptId

    /** Null means no carrier; a failed recovery must never trigger a fresh one-shot attempt. */
    fun reproveHookOutcome(context: Context, scheduleDeployment: Boolean = true): dev.maplesu.manager.jailbreak.JailbreakController.Outcome? {
        val record = JailbreakStatus.read(context) ?: return null
        if (!record.isCurrentBoot(dev.maplesu.manager.jailbreak.DirtyfragAttempt.readBootId()) ||
            record.rootBackend != JailbreakRequest.BACKEND_HOOK) return null
        val expected = record.attemptId?.takeIf { it.isNotBlank() } ?: return null
        return try {
            enableHookComponents(context)
            val bundle = withWallClockBudget(HOOK_PREPARE_BUDGET_MILLIS, "HOOK_REPROVE_TIMEOUT") {
                com.maplesu.core.ui.util.ProviderCall.call(context.contentResolver,
                    Uri.parse("content://${NativeSuDirectoryProvider.AUTHORITY}"),
                    "reprove", null, Bundle())
            }
            val outcome = HookReproofResult(
                eligible = bundle?.takeIf { it.containsKey("eligible") }?.getBoolean("eligible"),
                reproved = bundle?.getBoolean("reproved", false) == true,
                attemptId = bundle?.getString("attemptId"),
                bootId = bundle?.getString("bootId"),
                failure = bundle?.getString("failure"),
            ).outcome(expected, dev.maplesu.manager.jailbreak.DirtyfragAttempt.readBootId())
            if (outcome?.stage == JailbreakStatus.STAGE_DAEMON_READY && outcome.failure == null) {
                HookSuKeeperService.retain(context, outcome.attemptId)
                if (scheduleDeployment) RuntimeDeployment.start(context)
            }
            outcome
        } catch (error: Exception) {
            val token = if (error is java.util.concurrent.TimeoutException) "HOOK_REPROVE_TIMEOUT"
                else "HOOK_BACKEND_NOT_READY:reproof_call_failed"
            dev.maplesu.manager.jailbreak.JailbreakController.Outcome(JailbreakStatus.STAGE_FAILED, token, token)
        }
    }

    private fun enableHookComponents(context: Context) {
        enableHookComponents(ModeRuntime.active) { className ->
            context.packageManager.setComponentEnabledSetting(
                ComponentName(context.packageName, className),
                PackageManager.COMPONENT_ENABLED_STATE_ENABLED,
                PackageManager.DONT_KILL_APP,
            )
        }
    }

    /** The live endpoint of this process, without preparing a new one. */
    @Synchronized
    fun current(): IRootManagementService? = cached?.takeIf { it.asBinder().isBinderAlive }

    /**
     * Runs one fixed argv through the current endpoint with a bounded output and a
     * deadline that covers draining both streams. Used by the trusted process to
     * publish the client without owning a second root transport.
     */
    fun run(context: Context, argv: Array<String>, timeoutMillis: Int = 30_000): Bundle {
        /*
         * L3 (ABI v1): on the hook route the root transport is the kernel gate, not a
         * management binder - refusing here by name is exactly the step-4 limitation
         * this replaces. The gate is re-read from the helper's root-owned record for
         * this attempt and boot; a missing or non-ARMED record returns
         * {126,"",SU_GATE_NOT_ARMED} and starts nothing.
         */
        val status = JailbreakStatus.read(context)
        if (status?.rootBackend == JailbreakRequest.BACKEND_HOOK) {
            val gate = SuGate.read(context, status.attemptId, status.bootId)
            return NativeSu.asBundle(
                NativeSu.execute(gate, argv, timeoutMillis,
                    java.io.File(context.filesDir, NativeSu.FALLBACK_NAME)))
        }
        val endpoint = current() ?: throw IllegalStateException("SU_EXECUTOR_UNAVAILABLE")
        val task = endpoint.start(argv, android.os.Binder(), false)
        val pool = java.util.concurrent.Executors.newFixedThreadPool(2)
        val out = StringBuilder()
        val err = StringBuilder()
        try {
            val drain: (android.os.ParcelFileDescriptor?, StringBuilder) -> java.util.concurrent.Future<*> =
                { descriptor, sink -> pool.submit { readBounded(descriptor, sink) } }
            val stdout = drain(task.openStdout(), out)
            val stderr = drain(task.openStderr(), err)
            val exit = task.awaitExit(timeoutMillis).getInt("exitCode", -1)
            runCatching { stdout.get(2, TimeUnit.SECONDS) }
            runCatching { stderr.get(2, TimeUnit.SECONDS) }
            return Bundle().apply {
                putInt("code", exit)
                putString("out", out.toString())
                putString("err", err.toString())
            }
        } finally {
            runCatching { task.close() }
            pool.shutdownNow()
        }
    }

    private fun readBounded(descriptor: android.os.ParcelFileDescriptor?, sink: StringBuilder) {
        if (descriptor == null) return
        android.os.ParcelFileDescriptor.AutoCloseInputStream(descriptor).use { stream ->
            val chunk = ByteArray(8192)
            var total = 0
            while (total < 256 * 1024) {
                val read = stream.read(chunk)
                if (read < 0) break
                synchronized(sink) { sink.append(String(chunk, 0, read, Charsets.UTF_8)); total += read }
            }
        }
    }

    /**
     * No-op: the trusted lifecycle no longer starts the root executor.
     *
     * <p>An authorised application uses the image delivered into its own library
     * directory, which admits itself, so nothing has to be running - or prepared - before
     * a request arrives. Management operations still call [management] directly and are
     * therefore started per operation instead of being held open for future su calls.
     */
    @Suppress("UNUSED_PARAMETER")
    fun ensure(context: Context) {
        // Intentionally empty. Kept as the one call site the retirement work has to
        // remove, so a re-introduced startup fails review instead of passing silently.
        check(Looper.myLooper() != Looper.getMainLooper()) { "SU_BACKGROUND_THREAD_REQUIRED" }
    }

    /**
     * Live probe of the attempt this process owns. It runs in `:root_directory`,
     * which is the only process that can see whether the lease transport still
     * exists; a persisted status record is not evidence on its own.
     */
    internal fun probeStatus(context: Context): Bundle? = runCatching {
        com.maplesu.core.ui.util.ProviderCall.call(context.contentResolver,Uri.parse("content://${NativeSuDirectoryProvider.AUTHORITY}"),
            "status", null, null)
    }.getOrNull()

    internal fun cancel(context: Context): Boolean = runCatching {
        com.maplesu.core.ui.util.ProviderCall.call(context.contentResolver,Uri.parse("content://${NativeSuDirectoryProvider.AUTHORITY}"),
            "cancel", null, null)?.getBoolean("cancelled") == true
    }.getOrDefault(false)

    internal fun service(context: Context): INativeSuService {
        management(context)
        return INativeSuService.Stub.asInterface(NativeSuDiscovery.peek(context.applicationInfo.uid))
    }

    // Historical transport error classification retained for baseline test compilation only.
    internal fun endpointMissing(error: IOException): Boolean {
        val errno = generateSequence<Throwable>(error) { it.cause }
            .filterIsInstance<ErrnoException>().firstOrNull()?.errno
        if (errno != null) return errno == OsConstants.ENOENT || errno == OsConstants.ECONNREFUSED
        return error.message == Os.strerror(OsConstants.ENOENT) || error.message == Os.strerror(OsConstants.ECONNREFUSED)
    }

    private const val NORMAL_ORIGIN = "normal"
}

/*
 * ---------------------------------------------------------------------------
 * M3/M5 (report `maplesu-ultra-attestation-stability-2026-10-31.md` §5).
 *
 * The hook prepare must never wait without a bound and never lose its reason.
 * Both are pure functions (plus one bounded executor) so the host tests can drive
 * them without a device, and so the token mapping cannot drift from the names the
 * acceptance script greps for.
 * ---------------------------------------------------------------------------
 */

/** M5: the whole prepare gets a wall clock, not just the binder call. */
internal const val HOOK_PREPARE_BUDGET_MILLIS = 90_000L

internal fun hookPrepareBudgetMillis(request: JailbreakRequest): Long =
    if (request.method == "maplesu_93260")
        (JailbreakRequest.MAPLESU_93260_TIMEOUT_SECONDS + 90) * 1_000
    else HOOK_PREPARE_BUDGET_MILLIS + if (request.method == "ghostlock" &&
        request.rootBackend == JailbreakRequest.BACKEND_HOOK
    ) JailbreakRequest.GHOSTLOCK_HANDOVER_TIMEOUT_SECONDS * 1_000 else 0L

/**
 * M5's named token. The status message also spells the report's
 * `HOOK_BACKEND_NOT_READY:prepare_timeout` form, so both the token and the older
 * `HOOK_BACKEND_NOT_READY:<reason>` grep keep working.
 */
internal const val HOOK_PREPARE_TIMEOUT = "HOOK_PREPARE_TIMEOUT"

/**
 * M5/M3: the sentence the record keeps for a failed prepare.
 *
 * <p>Two spellings on purpose: the token the caller matches
 * ([HOOK_PREPARE_TIMEOUT]) and the report's `HOOK_BACKEND_NOT_READY:prepare_timeout`
 * form that the existing `HOOK_BACKEND_NOT_READY:<reason>` grep already understands.
 * The failure token itself stays the single name [HOOK_PREPARE_TIMEOUT], so a reader
 * never has to guess which of the two is authoritative.
 */
internal fun hookPrepareFailureMessage(token: String, thrown: Throwable?): String =
    "hook prepare failed: " + token +
        (if (token == HOOK_PREPARE_TIMEOUT) " (HOOK_BACKEND_NOT_READY:prepare_timeout)"
         else "") +
        (thrown?.let { " (" + it.javaClass.simpleName + ")" } ?: "")

/**
 * Run [body] on its own thread and give up after [budgetMillis].
 *
 * <p>The abandoned thread cannot be cancelled (a binder call is not interruptible), and
 * that is deliberate: the goal is to free the *caller* - the instrumentation thread that
 * would otherwise sit in `am instrument` until the host's 600 s timeout - with a named
 * result, not to pretend the provider stopped working.
 */
internal fun <T> withWallClockBudget(
    budgetMillis: Long,
    timeoutToken: String,
    body: () -> T,
): T {
    val pool = java.util.concurrent.Executors.newSingleThreadExecutor { runnable ->
        Thread(runnable, "maplesu-hook-prepare").apply { isDaemon = true }
    }
    val future = pool.submit(java.util.concurrent.Callable { body() })
    return try {
        future.get(budgetMillis, TimeUnit.MILLISECONDS)
    } catch (timeout: java.util.concurrent.TimeoutException) {
        throw IllegalStateException(timeoutToken)
    } catch (wrapped: java.util.concurrent.ExecutionException) {
        // The provider's own exception is what carries the token; unwrap it.
        throw wrapped.cause ?: wrapped
    } finally {
        future.cancel(true)
        pool.shutdownNow()
    }
}

/**
 * M3: the token a failed prepare reports.
 *
 * <p>A token is a name the acceptance script can match, so it is only ever taken from a
 * message that already *is* one (`HOOK_…`, `SU_…`, `DIRTYFRAG_…`, `GHOSTLOCK_…`). Anything else - a
 * `SecurityException`, a dead binder, an OOM - becomes one named bucket instead of
 * leaking a stack-trace sentence into the record.
 */
internal fun hookPrepareFailureToken(thrown: Throwable): String {
    val message = generateSequence(thrown) { it.cause }
        .mapNotNull { it.message }
        .map { it.trim() }
        .firstOrNull { it.startsWith("HOOK_") || it.startsWith("SU_") ||
            it.startsWith("DIRTYFRAG_") || it.startsWith("GHOSTLOCK_") ||
            it.startsWith("MAPLESU_93260_") || it.startsWith("SHIZUKU_") }
    return when {
        message != null -> message
        generateSequence(thrown) { it.cause }.any {
            it is java.util.concurrent.TimeoutException
        } -> HOOK_PREPARE_TIMEOUT
        else -> "HOOK_BACKEND_NOT_READY:prepare_call_failed"
    }
}

/**
 * M3: the record a failed prepare leaves.
 *
 * <p>Pure, so the host test asserts the token reaches the file even if the process dies
 * right after the call. Returns null when there is nothing to change: a `DAEMON_READY`
 * record for *this* attempt is a success that a later failure must not overwrite.
 */
internal fun hookFailureStatus(
    current: JailbreakStatus?,
    request: JailbreakRequest,
    token: String,
    message: String,
    nowMillis: Long,
    ownerPid: Int?,
): JailbreakStatus? {
    if (current != null && current.stage == JailbreakStatus.STAGE_DAEMON_READY &&
        current.attemptId == request.attemptId
    ) {
        return null
    }
    // No record at all: FAILED is the honest stage (the attempt never reached a claim),
    // and it is terminal, so a later read cannot turn it into a live claim.
    val base = current ?: JailbreakStatus(
        method = request.method,
        stage = JailbreakStatus.STAGE_FAILED,
        message = message,
        startedAtMillis = nowMillis,
        updatedAtMillis = nowMillis,
        bootId = request.bootId,
        attemptId = request.attemptId,
        rootBackend = JailbreakRequest.BACKEND_HOOK,
        ownerPid = ownerPid,
    )
    return base.copy(
        failure = token,
        message = message,
        ownerPid = base.ownerPid ?: ownerPid,
        updatedAtMillis = nowMillis,
    )
}

/** Keep historical READY on disk, but never discard a failed current preparation reply. */
internal fun hookPreparationFailure(
    current: JailbreakStatus?,
    request: JailbreakRequest,
    token: String,
    message: String,
    nowMillis: Long,
    ownerPid: Int?,
): JailbreakStatus? {
    // A caller deadline must not erase a terminal result already written by this provider.
    if (token == HOOK_PREPARE_TIMEOUT && current?.failure != null &&
        current.method == request.method && current.attemptId == request.attemptId &&
        current.bootId == request.bootId && current.rootBackend == request.rootBackend
    ) return current
    return hookFailureStatus(current, request, token, message, nowMillis, ownerPid)
        ?: current?.copy(failure = token, message = message, updatedAtMillis = nowMillis)
}

