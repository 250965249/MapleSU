package dev.maplesu.manager.jailbreak

import com.ghostlock.app.data.asValueMap
import android.content.Context
import android.os.Process
import dev.maplesu.ghostlock.extract.GhostlockProfileStore
import dev.maplesu.manager.jailbreak.LeaseProtocol.Restore
import java.io.File
import java.io.IOException
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Privileged-side orchestration. Runs in the `:root_directory` process, which
 * already owns the trusted launcher, so a provider lease never has to cross a
 * process boundary before it becomes the daemon's root shell.
 *
 * Order is fixed: exact admission -> provider attempt -> authenticated lease ->
 * the consumer's own restoration report -> native-stage cleanup -> verified
 * restore gate -> trusted shell handover. A stage is only published after it was
 * actually observed, and the attempt never hands the shell to the daemon when the
 * restoration of the entry policy could not be verified.
 */
internal object JailbreakExecutor {
    /*
     * Short on purpose: the provider reports a dispatch failure within its own
     * window now, so a long wait only delays the verdict the user needs.
     */
    private const val PROVIDER_TIMEOUT_SECONDS = 45L
    private const val STAGE_EXIT_SECONDS = 60L
    /** Hook route: rule 4 of the evidence merge re-reads for up to 2 s (8 x 250 ms). */
    private const val HOOK_EVIDENCE_REREADS = 8
    private const val HOOK_EVIDENCE_REREAD_MILLIS = 250L
    /** Root backends this executor knows by name (D-6). */
    /* Step-4: the wire names live in JailbreakRequest, so the executor, the provider and
     * the controller cannot drift apart on the one string that selects the branch. */
    private const val BACKEND_IR = JailbreakRequest.BACKEND_IR
    private const val BACKEND_HOOK = JailbreakRequest.BACKEND_HOOK
    private const val BACKEND_KSU = JailbreakRequest.BACKEND_KSU

    @Volatile private var attemptInFlight: DirtyfragAttempt? = null
    @Volatile private var ghostlockInFlight: GhostlockAttempt? = null
    private val cancelRequested = AtomicBoolean(false)
    private val statusLock = Any()

    /** Cancels the lease transport; the native stage is still allowed to finish its own restore. */
    fun cancel() {
        cancelRequested.set(true)
        attemptInFlight?.cancelPending()
        ghostlockInFlight?.cancelPending()
        synchronized(statusLock) {
            val status = currentStatus
            val target = statusContext
            if (status != null && target != null && !status.isTerminal()) {
                val cancelled = status.advance(status.copy(
                    stage = JailbreakStatus.STAGE_CANCELLED, failure = "JAILBREAK_CANCELLED",
                    message = "cancel requested; provider cleanup may still be running",
                    updatedAtMillis = System.currentTimeMillis()))
                currentStatus = cancelled
                runCatching { cancelled.write(target) }
            }
        }
    }

    @Volatile private var currentStatus: JailbreakStatus? = null
    @Volatile private var statusContext: Context? = null

    fun escalate(context: Context, request: JailbreakRequest): JailbreakStatus {
        val started = System.currentTimeMillis()
        val bootId = DirtyfragAttempt.readBootId()
        cancelRequested.set(false)
        statusContext = context.applicationContext
        var status = JailbreakStatus(
            method = request.method, stage = JailbreakStatus.STAGE_IDLE,
            message = "attempt requested", startedAtMillis = started,
            updatedAtMillis = started, bootId = bootId, attemptId = request.attemptId,
            ownerPid = Process.myPid(), rootBackend = request.rootBackend,
        )
        currentStatus = status
        val publish: (JailbreakStatus) -> JailbreakStatus = { next ->
            synchronized(statusLock) {
                // cancel() and progress share one status owner; a late callback must
                // neither overwrite the persisted cancellation nor claim readiness.
                status = currentStatus?.takeIf { it.attemptId == request.attemptId } ?: status
                status = status.advance(next).copy(
                    startedAtMillis = status.startedAtMillis,
                    attemptId = request.attemptId,
                    ownerPid = Process.myPid(),
                    bootId = status.bootId,
                    updatedAtMillis = System.currentTimeMillis(),
                )
                currentStatus = status
                runCatching { status.write(context) }
                // One mark per published stage: the provider call is opaque, so the
                // last stage written is the only honest answer to "where did it stop".
                runCatching {
                    dev.maplesu.manager.runtime.StageMark.mark(context, "escalate:" + status.stage +
                        (status.failure?.let { ":" + it } ?: ""))
                }
                status
            }
        }
        return try {
            require(request.attemptId.isNotBlank()) { "JAILBREAK_ATTEMPT_ID_MISSING" }
            JailbreakDiagnostics.progress(context.filesDir, request, "admission",
                "device=${android.os.Build.MANUFACTURER} ${android.os.Build.MODEL} " +
                    "kernel=${android.system.Os.uname().release} sdk=${android.os.Build.VERSION.SDK_INT} " +
                    "uid=${Process.myUid()} backend=${request.rootBackend}")
            if (cancelRequested.get()) return fail(publish, "JAILBREAK_CANCELLED", "cancelled before start")
            JailbreakSelinuxHide.capture(context, request)
            JailbreakLeaseStore.begin(request.attemptId, request.method)
            when (request.method) {
                JailbreakMethod.DIRTYFRAG.wireName -> escalateDirtyFrag(context, request, publish)
                JailbreakMethod.GHOSTLOCK.wireName -> escalateGhostlock(context, request, publish)
                JailbreakMethod.MAPLESU_93260.wireName -> escalateMapleSu93260(context, request, publish)
                JailbreakMethod.GHOSTSAM.wireName -> escalateGhostsam(context, request, publish)
                else -> fail(publish, "JAILBREAK_METHOD_UNKNOWN", request.method)
            }
        } catch (error: IOException) {
            fail(publish, error.message ?: "JAILBREAK_ATTEMPT_FAILED", error.cause?.message ?: "")
        } catch (error: Exception) {
            fail(publish, error.javaClass.simpleName + ": " + (error.message ?: ""), "")
        } finally {
            attemptInFlight = null
            ghostlockInFlight = null
        }
    }

    private fun providerProgress(context: Context, request: JailbreakRequest) =
        DirtyfragAttempt.Progress { step, message ->
            // Native output already has a lossless file; retain the otherwise discarded setup steps.
            if (step != "native" || message == "first stage started") {
                JailbreakDiagnostics.progress(context.filesDir, request, step, message)
            }
        }

    private fun escalateMapleSu93260(
        context: Context,
        request: JailbreakRequest,
        publish: (JailbreakStatus) -> JailbreakStatus,
    ): JailbreakStatus {
        refuseSecondaryUser(publish)?.let { return it }
        val release = android.system.Os.uname().release
        publish(JailbreakStatus(method = request.method, stage = JailbreakStatus.STAGE_TARGET_CHECKED,
            message = "source=3.8.10 backend=${request.rootBackend}",
            startedAtMillis = 0, updatedAtMillis = 0, bootId = request.bootId,
            target = release, rootBackend = request.rootBackend))
        publish(JailbreakStatus(method = request.method, stage = JailbreakStatus.STAGE_PROVIDER_RUNNING,
            message = "MapleSU_93260 source flow started",
            startedAtMillis = 0, updatedAtMillis = 0, bootId = request.bootId,
            target = release, rootBackend = request.rootBackend))
        MapleSu93260Attempt.run(context, request, cancelRequested::get)
        if (cancelRequested.get()) return fail(publish, "JAILBREAK_CANCELLED", "")
        if (request.rootBackend == BACKEND_HOOK)
            return finishHook(context, request, publish, release, true, emptyList())
        return publish(JailbreakStatus(method = request.method,
            stage = JailbreakStatus.STAGE_ROOT_WORKER_OBSERVED,
            message = "SELinux Enforcing verified; shared KSU late-load verified",
            startedAtMillis = 0, updatedAtMillis = 0, bootId = request.bootId,
            target = release, rootBackend = BACKEND_KSU,
            restoreState = "RESTORED_OBSERVED", restoreOrigin = "Observed",
            restoreFailures = 0))
    }

    private fun escalateDirtyFrag(
        context: Context,
        request: JailbreakRequest,
        publish: (JailbreakStatus) -> JailbreakStatus,
    ): JailbreakStatus {
        refuseSecondaryUser(publish)?.let { return it }
        /*
         * Fail closed on an unknown backend before any route is chosen. Without this
         * check `rootBackend = "ksu"` (or any typo) fell through to the lease route,
         * so a caller asking for a target this build cannot deliver could get a
         * completely different installation and still see it reported as success.
         */
        JailbreakRequest.validateBackend(request.rootBackend)?.let { token ->
            return fail(publish, token, "")
        }
        /*
         * Declared-but-unimplemented targets must fail closed too. `"ksu"` is a legal
         * value in KNOWN_BACKENDS, so validation alone lets it through; without this
         * check it would fail the `wantsIr` test and land in the lease branch, i.e. a
         * caller asking for MapleSU_Normal would get the Ultra lease install and be
         * told it succeeded. The token names the target and the release.
         */
        val runningRelease = runCatching { android.system.Os.uname().release }.getOrNull()
        JailbreakRequest.unsupportedTarget(request.rootBackend, runningRelease)?.let { token ->
            return fail(publish, token, "")
        }
        /*
         * Route decision (manual 4.2 / W3, extended by step-3 D-6). "hook" is the
         * module-dispatched UMH route: it must never fall back to the lease route,
         * because a silent fallback is exactly the two-track helper problem step-3
         * removes. In step-3 the only delivery for it is the canary slot (R1), so
         * escalateHook() requires a --root-canary build and says so by name otherwise.
         */
        if (request.rootBackend == BACKEND_HOOK) return escalateHook(context, request, publish)
        if (request.rootBackend == BACKEND_KSU) return escalateKsu(context, request, publish)
        val wantsIr = request.rootBackend == BACKEND_IR ||
            (request.rootBackend == null && runningRelease != null &&
                IrImages.supports(context, runningRelease))
        if (wantsIr) return escalateIr(context, request, publish)
        val admission = try {
            DirtyfragAttempt.admit(context)
        } catch (error: IOException) {
            return fail(publish, error.message ?: "DIRTYFRAG_ADMISSION_FAILED", "")
        }
        publish(JailbreakStatus(
            method = request.method, stage = JailbreakStatus.STAGE_TARGET_CHECKED,
            message = "kmi=" + admission.kmi() + " target=" + admission.targetId,
            startedAtMillis = 0, updatedAtMillis = 0, bootId = request.bootId,
            target = admission.kernelRelease(),
        ))
        val attempt = try {
            DirtyfragAttempt.start(context, admission, providerProgress(context, request))
        } catch (error: IOException) {
            return fail(publish, error.message ?: "DIRTYFRAG_START_FAILED", "")
        }
        attemptInFlight = attempt
        // This boot's kernel-side window is spent from here on, even if the attempt
        // fails: the module's kernel-text patches are not reverted by unloading.
        DirtyfragAttempt.markKernelWindow(context, admission.bootId())
        publish(JailbreakStatus(
            method = request.method, stage = JailbreakStatus.STAGE_PROVIDER_RUNNING,
            message = "first stage started", startedAtMillis = 0, updatedAtMillis = 0,
            bootId = request.bootId, target = admission.kernelRelease(),
        ))
        val outcome = runCatching {
            val lease = attempt.await(PROVIDER_TIMEOUT_SECONDS, TimeUnit.SECONDS)
            val identity = lease.identity()
            val restore = lease.restore()
            // The restoration is a gate, not a log line: an unverified restore
            // fails the attempt and the lease is closed instead of being handed
            // to the daemon. `applied == 2` (provider-owned) is not a DirtyFrag
            // outcome, so it is refused here as a contradiction.
            restoreRefusal(restore)?.let { reason ->
                runCatching { lease.close() }
                throw IOException(reason)
            }
            if (cancelRequested.get()) {
                runCatching { lease.close() }
                throw IOException("JAILBREAK_CANCELLED")
            }
            // The native stage restores the file pages and publishes a verified
            // failure count; the count plus the absent markers is the cleanup
            // proof, and the lease is only recorded after both.
            val cleanup = verifyCleanup(context, attempt)
            if (cleanup.unclean) {
                runCatching { lease.close() }
                throw IOException("DIRTYFRAG_CLEANUP_UNVERIFIED:" + cleanup.summary)
            }
            JailbreakLeaseStore.record(lease, request.method, request.attemptId)
            Session(identity, restore, cleanup)
        }
        attemptInFlight = null
        val session = outcome.getOrElse { error ->
            // Every exit point after the provider transient owns the cleanup: the
            // stage is allowed to finish (verifyCleanup waits for its own exit)
            // and its verified result is reported even when the attempt failed.
            val cleanup = verifyCleanup(context, attempt)
            attempt.close()
            return fail(publish, error.message ?: "DIRTYFRAG_ATTEMPT_FAILED",
                "cleanup=" + cleanup.summary)
        }
        attempt.close()
        publish(JailbreakStatus(
            method = request.method, stage = JailbreakStatus.STAGE_HANDOFF_AUTHENTICATED,
            message = "lease authenticated; entry policy " + session.restore.state(),
            startedAtMillis = 0, updatedAtMillis = 0, bootId = request.bootId,
            workerPid = session.identity.workerPid(), workerDomain = session.identity.domain(),
            enforcingAtLease = session.identity.enforcing(),
            restoreState = session.restore.state(),
            restoreOrigin = session.restore.origin().name,
            restoreEnforcing = session.restore.enforcing(),
            restoreCheckreqprot = session.restore.checkreqprot(),
            restorePolicy = session.restore.policy(),
            restoreUnloadErrno = session.restore.unloadErrno(),
            restoreFailures = session.cleanup.failures,
            target = admission.kernelRelease(),
        ))
        /*
         * A patched page cache from an earlier attempt cannot be restored (the
         * original bytes are no longer readable), so this attempt must not pretend it
         * succeeded: report it as its own condition and tell the caller what clears it.
         */
        val staleFlag = File(context.createDeviceProtectedStorageContext().dataDir,
            "maplesu-stale-flag")
        if (staleFlag.isFile) {
            staleFlag.delete()
            return fail(publish, "PROVIDER_STALE_PAGE_CACHE",
                "a previous attempt left /system/lib64/libc++.so patched in the page cache; " +
                    "reboot the device before trying again")
        }
        return publish(JailbreakStatus(
            method = request.method, stage = JailbreakStatus.STAGE_ROOT_WORKER_OBSERVED,
            message = "consumer restored the entry policy and owns the shell",
            startedAtMillis = 0, updatedAtMillis = 0, bootId = request.bootId,
            workerPid = session.identity.workerPid(),
            restoreState = session.restore.state(),
            restoreFailures = session.cleanup.failures,
            target = admission.kernelRelease(),
        ))
    }


    /**
     * Packaged execution tuning. The upstream exporter always merges this document
     * before validating; without it every native tuning value stays zero and the
     * attack loops never run (G-1).
     */
    private fun ghostlockTuning(
        profiles: GhostlockProfiles,
    ): com.ghostlock.app.data.ValueMap? {
        val text = profiles.packagedDocument("execution-tuning.conf") ?: return null
        val parsed = runCatching {
            com.ghostlock.app.data.HoconSupport.parseValue(text)
                .asValueMap()?.get("execution").asValueMap()
        }.getOrNull()
        return parsed
    }

    /** Packaged per-route presets, keyed by the route token the profile uses. */
    private fun ghostlockRoutePresets(
        profiles: GhostlockProfiles,
    ): Map<String, com.ghostlock.app.data.ValueMap> {
        val out = LinkedHashMap<String, com.ghostlock.app.data.ValueMap>()
        /*
         * File and key both follow the RouteKind token: the packaged preset is
         * execution-select-stack.conf keyed by "select_stack", not "stack". Using the
         * short name silently produced an empty preset, which zeroed
         * execution.routes.select_stack.consumer_max_calls and made the consumer
         * burst loop run zero times.
         */
        for (kind in com.ghostlock.app.data.route.RouteKind.entries) {
            val token = kind.token
            val file = "execution-" + token.replace('_', '-') + ".conf"
            val text = profiles.packagedDocument(file) ?: continue
            val entry = runCatching {
                com.ghostlock.app.data.HoconSupport.parseValue(text)
                    .asValueMap()?.get("execution").asValueMap()
                    ?.get("routes").asValueMap()
                    ?.get(token).asValueMap()
            }.getOrNull() ?: continue
            out[token] = entry
        }
        return out
    }

    /**
     * Only the owner may start a provider, whichever path the request takes. The UI
     * already blocks it; this is the trusted-side counterpart.
     */
    private fun refuseSecondaryUser(publish: (JailbreakStatus) -> JailbreakStatus): JailbreakStatus? {
        val uid = runCatching { android.os.Process.myUid() }.getOrNull() ?: return null
        if (uid / 100_000 == 0) return null
        return fail(publish, "SECONDARY_USER_UNSUPPORTED", "")
    }

    private fun escalateGhostlock(
        context: Context,
        request: JailbreakRequest,
        publish: (JailbreakStatus) -> JailbreakStatus,
    ): JailbreakStatus {
        refuseSecondaryUser(publish)?.let { return it }
        JailbreakRequest.validateBackend(request.rootBackend)?.let { return fail(publish, it, "") }
        val target = GhostlockHandover.target(request.rootBackend)
        DirtyfragAttempt.requireUnusedKernelWindow(context)
        /*
         * An imported profile that the user parsed/imported and confirmed for this
         * exact release takes precedence over the packaged set (and over the KMI
         * template fallback): it was measured against this device's own OTA. It is
         * still validated by GhostlockProfileCodec below, so an incomplete import
         * fails closed instead of reaching the provider.
         *
         * The packaged profile set is loaded best-effort: it also provides the
         * execution tuning/presets, but an unavailable packaged set must not veto a
         * confirmed import for this kernel.
         */
        val release = android.system.Os.uname().release
        val imported = runCatching {
            GhostlockProfileStore.openIn(context.filesDir).confirmedFor(release)
        }.getOrNull()
        val profiles = runCatching { GhostlockProfiles.from(context) }.getOrNull()
        val profile = try {
            if (imported != null) {
                GhostlockProfiles.Profile(
                    release,
                    "imported:" + imported.name,
                    imported.text.toByteArray(Charsets.UTF_8),
                )
            } else if (profiles != null) {
                profiles.resolveForAttempt(release)
            } else {
                return fail(publish, "GHOSTLOCK_PROFILE_UNAVAILABLE", "")
            }
        } catch (error: IOException) {
            return fail(publish, error.message ?: "GHOSTLOCK_PROFILE_UNAVAILABLE", "")
        }
        /*
         * The marker travels inside the message of the one TARGET_CHECKED publish.
         * A second publish on the same stage is NOT dropped by advance() (it only
         * refuses stage regressions and takes the newer message), which is exactly
         * why publishing the marker separately would have been overwritten.
         */
        val profileMessage = buildString {
            append("profile=").append(profile.release()).append(" file=").append(profile.file())
            profile.assumptionMarker()?.let { append(" ").append(it) }
        }
        publish(JailbreakStatus(
            method = request.method, stage = JailbreakStatus.STAGE_TARGET_CHECKED,
            message = profileMessage,
            startedAtMillis = 0, updatedAtMillis = 0, bootId = request.bootId,
            target = profile.release(), rootBackend = request.rootBackend,
        ))
        // S02: the native decoder takes the typed wire v2 document, never the
        // HOCON text. Conversion and validation happen before a process exists.
        val wire = try {
            GhostlockProfileCodec.toWire(profile, profile.release(),
                profiles?.let { ghostlockTuning(it) },
                profiles?.let { ghostlockRoutePresets(it) } ?: emptyMap())
        } catch (error: IOException) {
            return fail(publish, error.message ?: "GHOSTLOCK_PROFILE_UNUSABLE", "")
        }
        /*
         * Same packaged-identity gate DirtyFrag uses: the provider and the shared
         * consumer must match the manifest before a process is created.
         */
        for (name in listOf("libmaplesu_ghostlock_provider.so", "libmaplesu_root_consumer.so")) {
            try {
                JailbreakArtifacts.require(context, name)
            } catch (error: IOException) {
                return fail(publish, error.message ?: "GHOSTLOCK_ARTIFACT_UNVERIFIED", "")
            }
        }
        val attempt = try {
            GhostlockHandover.stage(context, request)
            GhostlockAttempt.start(context, wire, profile, request) { step, state ->
                JailbreakDiagnostics.progress(context.filesDir, request, step,
                    "Ghostlock $step: $state")
            }
        } catch (error: IOException) {
            return fail(publish, error.message ?: "GHOSTLOCK_START_FAILED", "")
        }
        ghostlockInFlight = attempt
        publish(JailbreakStatus(
            method = request.method, stage = JailbreakStatus.STAGE_PROVIDER_RUNNING,
            message = "ghostlock provider started", startedAtMillis = 0, updatedAtMillis = 0,
            bootId = request.bootId, target = profile.release(),
        ))
        if (target == "ultra") {
            // Same delivery as DirtyFrag Ultra: the shared helper proves its own
            // load/ARM/restore, then finishHook checks the bound hook evidence.
            // A raw consumer after enforcing would add a separate privileged exec
            // and socket hop that this backend does not use.
            val outcome = runCatching {
                GhostlockHandover.awaitReceipt(context, request,
                    TimeUnit.SECONDS.toMillis(JailbreakRequest.GHOSTLOCK_HANDOVER_TIMEOUT_SECONDS),
                    cancelRequested::get, workerResult = attempt.workerResult(),
                    sourceFailure = attempt::failureBeforeHandover) { message ->
                    JailbreakDiagnostics.progress(context.filesDir, request, "handover",
                        "$message；来源阶段=${attempt.providerStage()}")
                }
            }
            ghostlockInFlight = null
            attempt.close()
            outcome.exceptionOrNull()?.let { error ->
                return fail(publish, error.message ?: "GHOSTLOCK_HANDOVER_FAILED", "")
            }
            return finishHook(context, request, publish, profile.release(), true, emptyList())
        }
        var restoreFailureDetail = ""
        val outcome = runCatching {
            val lease = attempt.await(if (target == null) PROVIDER_TIMEOUT_SECONDS else
                JailbreakRequest.GHOSTLOCK_HANDOVER_TIMEOUT_SECONDS, TimeUnit.SECONDS)
            val identity = lease.identity()
            val restore = lease.restore()
            val observation = ghostlockRestoreObservation(request, profile.release(), identity, restore)
            restoreFailureDetail = observation.message
            publish(observation)
            // S10: the provider's own restore is no longer a free pass. The
            // consumer re-verified the booleans after the script and reported
            // RESTORED_OBSERVED / RESTORED_BASELINE; anything else refuses the
            // handover. The policy identity stays "not compared" in the status.
            if (!restore.verified()) {
                runCatching { lease.close() }
                throw IOException("GHOSTLOCK_RESTORE_UNVERIFIED:" + restore.state())
            }
            if (cancelRequested.get()) {
                runCatching { lease.close() }
                throw IOException("JAILBREAK_CANCELLED")
            }
            if (target == null) {
                JailbreakLeaseStore.record(lease, request.method, request.attemptId)
            } else {
                try {
                    if (restore.enforcing() != 1) throw IOException("GHOSTLOCK_RESTORE_UNVERIFIED")
                    GhostlockHandover.requireReceipt(context, request)
                } finally { lease.close() }
            }
            Session(identity, restore, Cleanup(true, null, emptyList()))
        }
        ghostlockInFlight = null
        val session = outcome.getOrElse { error ->
            attempt.close()
            return fail(publish, error.message ?: "GHOSTLOCK_ATTEMPT_FAILED", restoreFailureDetail)
        }
        attempt.close()
        return publish(JailbreakStatus(
            method = request.method, stage = JailbreakStatus.STAGE_ROOT_WORKER_OBSERVED,
            message = "consumer handed over the provider-owned lease",
            startedAtMillis = 0, updatedAtMillis = 0, bootId = request.bootId,
            workerPid = session.identity.workerPid(),
            restoreState = session.restore.state(),
            target = profile.release(), rootBackend = request.rootBackend,
        ))
    }

    /**
     * In-kernel root route (manual C1-C10 / W3).
     *
     * No lease is awaited here. On this route the privileged side loads our module,
     * the module itself verifies every original byte, applies the kernel-text
     * patches and reads them back, the entry policy is restored, and the device
     * soft-reboots. The only verdict this process can honestly read is the
     * provider's own log, so that is the only thing the stage is published from:
     * a missing verdict is `MAPLESU_IR_NOT_READY`, never success.
     */
    private fun escalateIr(
        context: Context,
        request: JailbreakRequest,
        publish: (JailbreakStatus) -> JailbreakStatus,
    ): JailbreakStatus {
        refuseSecondaryUser(publish)?.let { return it }
        val release = runCatching { android.system.Os.uname().release }.getOrNull()
            ?: return fail(publish, "MAPLESU_IR_UNSUPPORTED:unknown", "uname unavailable")
        if (!IrImages.supports(context, release)) {
            // C10 / D5: refuse before any kernel-side action, with the release named.
            return fail(publish, IrImages.unsupported(release),
                "no packaged spec for this kernel release")
        }
        val admission = try {
            DirtyfragAttempt.admit(context)
        } catch (error: IOException) {
            return fail(publish, error.message ?: "DIRTYFRAG_ADMISSION_FAILED", "")
        }
        publish(JailbreakStatus(
            method = request.method, stage = JailbreakStatus.STAGE_TARGET_CHECKED,
            message = "rootBackend=ir kmi=" + admission.kmi() + " release=" + release,
            startedAtMillis = 0, updatedAtMillis = 0, bootId = request.bootId,
            target = admission.kernelRelease(), rootBackend = "ir",
        ))
        val attempt = try {
            // softReboot=false is the W0 probe: patch, restore policy, stay put.
            DirtyfragAttempt.start(context, admission, providerProgress(context, request), true, !request.softReboot)
        } catch (error: IOException) {
            // IrImages.stage surfaces MAPLESU_IR_UNSUPPORTED / MAPLESU_IR_SPEC_INVALID here.
            return fail(publish, error.message ?: "DIRTYFRAG_START_FAILED", "")
        }
        attemptInFlight = attempt
        DirtyfragAttempt.markKernelWindow(context, admission.bootId())
        publish(JailbreakStatus(
            method = request.method, stage = JailbreakStatus.STAGE_PROVIDER_RUNNING,
            message = "in-kernel route staged (module + spec + use-ir)",
            startedAtMillis = 0, updatedAtMillis = 0, bootId = request.bootId,
            target = admission.kernelRelease(), rootBackend = "ir",
        ))
        /*
         * The privileged side may soft-reboot at any moment, so the wait is bounded.
         * Whatever the outcome the attempt object is closed: the native stage owns its
         * own restore and the bootstrap owns the teardown on failure (S09).
         */
        val exited = runCatching { attempt.awaitStageExit(STAGE_EXIT_SECONDS, TimeUnit.SECONDS) }
            .getOrDefault(false)
        val lines = runCatching { attempt.log() }.getOrDefault(emptyList())
        val token = lines.firstNotNullOfOrNull { IR_FAILURE.find(it)?.groupValues?.get(1) }
            ?.let(::jailbreakErrorCode)
        val loaded = lines.any { it.contains(IR_LOADED) }
        attemptInFlight = null
        attempt.close()
        if (token != null) {
            return fail(publish, token, lines.lastOrNull { it.contains("ir: FAILED") } ?: "")
        }
        if (!loaded) {
            return fail(publish, "MAPLESU_IR_NOT_READY",
                "provider exited=" + exited + " without an ir verdict")
        }
        return publish(JailbreakStatus(
            method = request.method, stage = JailbreakStatus.STAGE_ROOT_WORKER_OBSERVED,
            message = "maplesu_ir loaded: kernel text verified+patched, policy restored, " +
                "soft reboot issued",
            startedAtMillis = 0, updatedAtMillis = 0, bootId = request.bootId,
            target = admission.kernelRelease(), rootBackend = "ir",
        ))
    }

    /**
     * Normal (KernelSU) route: the reference DirtyFragX handoff, unchanged in shape.
     *
     * The privileged half does the work - switch to `u:r:init:s0` while SELinux is
     * still permissive, run `ksud late-load --package-name <manager>` against the
     * staged daemon, wait for the daemon it double-forks away from, then
     * the late-load route selected by `use-ksu`. A missing verdict is a named
     * failure. The manager proves real SU before publishing readiness and before
     * the UI dispatches the requested soft reboot.
     */
    private fun escalateKsu(
        context: Context,
        request: JailbreakRequest,
        publish: (JailbreakStatus) -> JailbreakStatus,
    ): JailbreakStatus {
        refuseSecondaryUser(publish)?.let { return it }
        val admission = try {
            DirtyfragAttempt.admit(context)
        } catch (error: IOException) {
            return fail(publish, error.message ?: "DIRTYFRAG_ADMISSION_FAILED", "")
        }
        publish(JailbreakStatus(
            method = request.method, stage = JailbreakStatus.STAGE_TARGET_CHECKED,
            message = "rootBackend=ksu kmi=" + admission.kmi() + " manager=" +
                DirtyfragAttempt.KSU_MANAGER_PACKAGE,
            startedAtMillis = 0, updatedAtMillis = 0, bootId = request.bootId,
            target = admission.kernelRelease(), rootBackend = "ksu",
        ))
        val attempt = try {
            DirtyfragAttempt.startKernelSu(context, admission, providerProgress(context, request))
        } catch (error: IOException) {
            // A missing KernelSU manager surfaces MAPLESU_KSU_DAEMON_MISSING here.
            return fail(publish, error.message ?: "DIRTYFRAG_START_FAILED", "")
        }
        attemptInFlight = attempt
        DirtyfragAttempt.markKernelWindow(context, admission.bootId())
        publish(JailbreakStatus(
            method = request.method, stage = JailbreakStatus.STAGE_PROVIDER_RUNNING,
            message = "kernelsu route staged (ksud + use-ksu); late-load dispatched",
            startedAtMillis = 0, updatedAtMillis = 0, bootId = request.bootId,
            target = admission.kernelRelease(), rootBackend = "ksu",
        ))
        // The native late-load wait itself can take 120 s; keep its owner alive
        // through restoration rather than closing it at the general 60 s bound.
        runCatching { attempt.awaitStageExit(180L, TimeUnit.SECONDS) }
        var lines = runCatching { attempt.log() }.getOrDefault(emptyList())
        var loaded = lines.any { it.contains(KSU_LOADED) }
        if (!loaded) {
            /*
             * The verdict is the *last* line the helper writes ("ksu: loaded"). Reading
             * it the instant the stage exits races the reader thread and the final
             * flush - observed on 2026-11-02 as MAPLESU_KSU_NOT_READY while the device
             * was already rooted (su -c id -u == 0, kernelsu in /proc/modules).
             * Re-read the live stream and the persisted provider log, bounded.
             */
            val providerLog = File(DirtyfragAttempt.hookEvidence(context), "maplesu-ultravider.log")
            val deadline = System.currentTimeMillis() + 6_000
            while (!loaded && System.currentTimeMillis() < deadline) {
                Thread.sleep(200)
                lines = runCatching { attempt.log() }.getOrDefault(lines)
                val tail = runCatching { providerLog.readLines().takeLast(400) }
                    .getOrDefault(emptyList())
                loaded = lines.any { it.contains(KSU_LOADED) } ||
                    tail.any { it.contains(KSU_LOADED) }
            }
        }
        attemptInFlight = null
        runCatching { attempt.close() }
        val token = lines.firstNotNullOfOrNull { KSU_FAILURE.find(it)?.groupValues?.get(1) }
            ?.let(::jailbreakErrorCode)
        if (token != null) {
            return fail(publish, token, lines.lastOrNull { it.contains("ksu: FAILED") } ?: "")
        }
        if (!loaded) {
            return fail(publish, "MAPLESU_KSU_NOT_READY",
                "provider finished without a ksu verdict (no KernelSU handoff observed)")
        }
        return publish(JailbreakStatus(
            method = request.method, stage = JailbreakStatus.STAGE_ROOT_WORKER_OBSERVED,
            message = "kernelsu late-load accepted; live SU proof pending",
            startedAtMillis = 0, updatedAtMillis = 0, bootId = request.bootId,
            target = admission.kernelRelease(), rootBackend = "ksu",
        ))
    }

    private class Session(
        val identity: LeaseProtocol.Identity,
        val restore: Restore,
        val cleanup: Cleanup,
    )

    /**
     * Step-3 hook route (design §7.2, D3-8/R1). The module is delivered through the
     * canary slot by `--root-canary` packaging, so the attempt is the same stage-1 ->
     * dfroot -> in-memory `init_module` chain the IR route uses; what differs is what
     * counts as the verdict.
     *
     * <p>`install_ir()` ends in `MAPLESU_IR_MODULE_INVALID` by construction here: the
     * product IR slot carries the non-ELF stub on purpose, so the in-kernel installer
     * stops at the `.ir_spec` lookup *after* the canary probe loaded the hook module.
     * That token is therefore **not** a hook failure, and the verdict is read from the
     * helper's own evidence files instead ([HookEvidence]). A missing evidence file is
     * "no evidence", never success.
     *
     * <p>`softReboot` is forced off: step-3 acceptance needs the restore and the
     * unload observed in one boot, and a soft reboot would also re-open the attempt
     * window this attempt owns.
     */
    private fun escalateHook(
        context: Context,
        request: JailbreakRequest,
        publish: (JailbreakStatus) -> JailbreakStatus,
    ): JailbreakStatus {
        refuseSecondaryUser(publish)?.let { return it }
        val inventory = IrImages.inventory(context)
        /*
         * Either slot may carry the root module: a product build packages it in the
         * `root` block, a bring-up build in the canary slot. What must never happen is
         * a silent fall back to the lease route, so an absent module is named.
         */
        val hookModule = inventory.rootModule
            ?: (if (inventory.isRootCanary) inventory.canary else null)
        if (hookModule == null) {
            return fail(publish, "MAPLESU_HOOK_NOT_PACKAGED",
                "rootBackend=hook needs a packaged root module (root block or --root-canary)")
        }
        /*
         * No per-release spec check here on purpose. The hook module resolves every
         * kernel symbol at load time, so a packaged module is release-independent;
         * requiring a spec would re-introduce exactly the per-kernel coupling this
         * route exists to remove, and would refuse devices we have never seen.
         */
        val release = runCatching { android.system.Os.uname().release }.getOrNull()
        val admission = try {
            DirtyfragAttempt.admit(context)
        } catch (error: IOException) {
            return fail(publish, error.message ?: "DIRTYFRAG_ADMISSION_FAILED", "")
        }
        publish(JailbreakStatus(
            method = request.method, stage = JailbreakStatus.STAGE_TARGET_CHECKED,
            message = "rootBackend=hook kmi=" + admission.kmi() + " release=" + release,
            startedAtMillis = 0, updatedAtMillis = 0, bootId = request.bootId,
            target = admission.kernelRelease(), rootBackend = BACKEND_HOOK,
        ))
        val attempt = try {
            // irRoute=true stages module+spec+markers; the module itself is the canary
            // slot's (R1). irNoReboot=true is forced: never soft-reboot a hook attempt.
            // Step-4 (item 22): the attempt id is how the App's pre-entry baseline reaches
            // the helper (<DE>/maplesu-hook-env). Without it the helper has no target and
            // must not write selinuxfs at all.
            DirtyfragAttempt.start(context, admission, providerProgress(context, request), true, true,
                request.attemptId)
        } catch (error: IOException) {
            return fail(publish, error.message ?: "DIRTYFRAG_START_FAILED", "")
        }
        attemptInFlight = attempt
        DirtyfragAttempt.markKernelWindow(context, admission.bootId())
        publish(JailbreakStatus(
            method = request.method, stage = JailbreakStatus.STAGE_PROVIDER_RUNNING,
            message = "hook module staged in the canary slot; UMH handover runs in-kernel",
            startedAtMillis = 0, updatedAtMillis = 0, bootId = request.bootId,
            target = admission.kernelRelease(), rootBackend = BACKEND_HOOK,
        ))
        val exited = runCatching { attempt.awaitStageExit(STAGE_EXIT_SECONDS, TimeUnit.SECONDS) }
            .getOrDefault(false)
        val lines = runCatching { attempt.log() }.getOrDefault(emptyList())
        attemptInFlight = null
        attempt.close()
        return finishHook(context, request, publish, admission.kernelRelease(), exited, lines)
    }

    private fun finishHook(
        context: Context,
        request: JailbreakRequest,
        publish: (JailbreakStatus) -> JailbreakStatus,
        target: String,
        exited: Boolean,
        lines: List<String>,
    ): JailbreakStatus {
        val evidenceDirectory = DirtyfragAttempt.hookEvidence(context)
        /*
         * Rule 4 (design §5.4): PENDING means the unload child has not settled. Re-read
         * for up to 2 s before calling it DEGRADED; the helper writes its child record
         * inside the 1.5 s bound, so a later read usually resolves it.
         *
         * Step-4 R6: the read is `inspect`, not `read`, because "the file is there and I
         * am not allowed to read it" is a different fact from "there is no file". The old
         * `read()` let the `FileNotFoundException` escape into `escalate()`'s IOException
         * handler, which reported a permissions problem as a path-shaped failure (R3).
         */
        var reading = evidenceDirectory?.let { HookEvidence.inspect(it) }
            ?: HookEvidence.Reading(null, null)
        if (reading.merged == null || reading.merged.unloadState == HookEvidence.UNLOAD_PENDING) {
            repeat(HOOK_EVIDENCE_REREADS) {
                if (reading.merged != null &&
                    reading.merged.unloadState != HookEvidence.UNLOAD_PENDING) {
                    return@repeat
                }
                runCatching { Thread.sleep(HOOK_EVIDENCE_REREAD_MILLIS) }
                reading = evidenceDirectory?.let { HookEvidence.inspect(it) } ?: reading
            }
        }
        val merged = reading.merged
        if (merged == null) {
            // No evidence is not success. An unreadable record is named as such instead of
            // being folded into "missing", so the device evidence says which one it was.
            if (reading.unreadable != null) {
                return fail(publish, HookEvidence.TOKEN_EVIDENCE_UNREADABLE,
                    reading.unreadable +
                        " (the hook evidence exists and this process cannot read it)")
            }
            // Prefer the loader's named reason when the attempt never reached the module
            // at all (for example MAPLESU_IR_STAGE_MISSING).
            val token = lines.firstNotNullOfOrNull { IR_FAILURE.find(it)?.groupValues?.get(1) }
                ?.let(::jailbreakErrorCode)
            return fail(publish, token ?: HookEvidence.TOKEN_EVIDENCE_MISSING,
                "no maplesu-hook.json from the UMH helper (provider exited=" + exited + ")")
        }
        // R5: the evidence has to be *this* attempt's and *this* boot's before any of it
        // is published. A perfect-looking record from an earlier attempt is the one
        // failure mode that would otherwise pass silently.
        HookEvidence.bindingRefusal(merged, request.bootId, request.attemptId)?.let { token ->
            return fail(publish, token,
                "evidence boot=" + (merged.bootId ?: "missing") +
                    " attempt=" + (merged.attempt ?: "missing") +
                    " expected boot=" + (request.bootId ?: "?") +
                    " attempt=" + request.attemptId)
        }
        publish(JailbreakStatus(
            method = request.method, stage = JailbreakStatus.STAGE_HANDOFF_AUTHENTICATED,
            message = "hook evidence: verdict=" + merged.verdict + " restore=" +
                merged.restoreState + " unload=" + (merged.unloadState ?: "missing") +
                " daemon=" + (merged.daemon ?: "missing"),
            startedAtMillis = 0, updatedAtMillis = 0, bootId = request.bootId,
            target = target, rootBackend = JailbreakRequest.BACKEND_HOOK,
            /*
             * Step-4 item 3: no workerPid here. `merged.daemonPid` is the *helper's*
             * claim about a pid it forked, which is a JSON declaration and not proof;
             * the only pid that may be published is the one the kernel put in the
             * attestation's ucred, and that happens in the provider.
             */
            enforcingAtLease = merged.entryArgv?.toIntOrNull(),
            restoreState = merged.restoreState,
            restoreOrigin = merged.origin,
            restoreEnforcing = merged.enforcing,
            restoreUnloadErrno = merged.unloadErrno,
            restoreFailures = merged.failures,
        ))
        // The pass/fail decision and the token a refusal publishes live in HookEvidence
        // (pure Kotlin) so the step-3 acceptance path is host-tested (review M3).
        HookEvidence.refusalToken(merged)?.let { token ->
            return fail(publish, token,
                "verdict=" + merged.verdict + " restore=" + merged.restoreState +
                    " failures=" + (merged.failures?.toString() ?: "missing"))
        }
        return publish(JailbreakStatus(
            method = request.method, stage = JailbreakStatus.STAGE_ROOT_WORKER_OBSERVED,
            message = "UMH helper restored the entry policy and unloaded the module",
            startedAtMillis = 0, updatedAtMillis = 0, bootId = request.bootId,
            target = target, rootBackend = JailbreakRequest.BACKEND_HOOK,
            /* Same reason as above: the fork claim is not a proof, so no pid here. The
             * attestation check in the provider is what may fill workerPid. */
            restoreState = merged.restoreState,
            restoreFailures = merged.failures,
        ))
    }

    /** The refusal reason for a restoration that does not admit a handover. */
    private fun restoreRefusal(restore: Restore): String? = when {
        !restore.applicable() -> "DIRTYFRAG_RESTORE_NOT_APPLICABLE"
        restore.failed() -> "DIRTYFRAG_RESTORE_FAILED"
        !restore.verified() -> "DIRTYFRAG_RESTORE_UNVERIFIED:" + restore.state()
        restore.policy() == 1 -> "DIRTYFRAG_POLICY_CHANGED"
        else -> null
    }

    private data class Cleanup(val exited: Boolean, val failures: Int?, val markers: List<String>) {
        val unclean: Boolean get() = !exited || failures != 0 || markers.isNotEmpty()
        val summary: String
            get() = "restore=" + (failures?.toString() ?: "missing") +
                " stage=" + (if (exited) "exited" else "running") +
                " markers=" + (if (markers.isEmpty()) "none" else markers.joinToString(","))
    }

    private val RESTORE_LINE = Regex("maplesu-restore: failures=(\\d+)")
    /*
     * The bootstrap publishes exactly one stable MAPLESU_IR_* token per failure and
     * "ir: loaded" on success. Step-3 adds the handover namespace
     * MAPLESU_HANDOVER_* (design §7.1): the same errno can mean "module refused" or
     * "helper did not run", and only the module's own classified printk tells them
     * apart, so the bootstrap overrides the loader token with one of these. Both
     * namespaces are verdicts from this one channel; nothing else in the log is read
     * as a result.
     */
    private val IR_FAILURE = Regex("maplesu-dirtyfrag: ir: FAILED (${dev.maplesu.manager.compat.StoredInputs.IDENTITY_FAILURE_PREFIX}_(?:IR|HANDOVER)_[A-Z_]+)")
    private const val IR_LOADED = "maplesu-dirtyfrag: ir: loaded"

    /*
     * Normal (KernelSU) verdict vocabulary. Deliberately a different prefix from the
     * in-kernel route: the whole point of a second target is that a log line can
     * never be read as the other target's success.
     */
    private val KSU_FAILURE = Regex("maplesu-dirtyfrag: ksu: FAILED (${dev.maplesu.manager.compat.StoredInputs.IDENTITY_FAILURE_PREFIX}_KSU_[A-Z_]+)")
    private const val KSU_LOADED = "maplesu-dirtyfrag: ksu: loaded"
    /*
     * Attempt markers only. /dev/df is deliberately absent: it is init's one-shot
     * re-entry guard, kept for the rest of the boot by design (removing it re-arms the
     * hook and panicked this kernel, DEV-88) and cleared by the reboot.
     */
    private val ATTEMPT_MARKERS = listOf("/dev/dfm0")
    private const val TEARDOWN_FILE = "maplesu-teardown"

    /**
     * The native stage publishes a verified-restoration count after writing the
     * original bytes back and re-reading each region; the markers are checked
     * from here because an ordinary App can stat them without privilege.
     */
    private fun verifyCleanup(context: Context, attempt: DirtyfragAttempt): Cleanup {
        val exited = attempt.awaitStageExit(STAGE_EXIT_SECONDS, TimeUnit.SECONDS)
        var failures: Int? = null
        for (line in attempt.log()) {
            val match = RESTORE_LINE.find(line) ?: continue
            failures = match.groupValues[1].toIntOrNull()
        }
        // S09: when the bootstrap failed before the consumer existed, the native
        // stage never prints a report. The bootstrap's own teardown records the
        // same facts in the attempt directory, so the verdict stays truthful
        // instead of reading "missing" for a device that is actually clean.
        if (failures == null) {
            val record = File(context.createDeviceProtectedStorageContext().dataDir, TEARDOWN_FILE)
            if (record.isFile) {
                failures = runCatching {
                    Regex("failures=(\\d+)").find(record.readText())?.groupValues?.get(1)?.toInt()
                }.getOrNull()
            }
        }
        val markers = ATTEMPT_MARKERS.filter { File(it).exists() }
        return Cleanup(exited, failures, markers)
    }

    /**
     * GhostSam V2 route: the only product entry point for the MapleSU-side adapter.
     * All lease construction is MapleSU-owned; argv carries no nonce and the TLV travels
     * on the same 'C' connection. Any failure is a named, fail-closed token.
     */
    private fun escalateGhostsam(context: Context, request: JailbreakRequest,
                                 publish: (JailbreakStatus) -> JailbreakStatus): JailbreakStatus {
        val result = dev.maplesu.manager.jailbreak.ghostsam.GhostsamAttempt.run(context)
        if (!result.ok) return fail(publish, result.token ?: "GHOSTSAM_ADAPTER_FAILURE", "")
        return publish(JailbreakStatus(
            method = request.method, stage = JailbreakStatus.STAGE_DAEMON_READY,
            message = "ghostsam RAW_ROOT_LEASE", startedAtMillis = 0, updatedAtMillis = 0,
            bootId = request.bootId, attemptId = request.attemptId))
    }

    private fun fail(
        publish: (JailbreakStatus) -> JailbreakStatus,
        failure: String,
        detail: String,
    ): JailbreakStatus {
        JailbreakLeaseStore.recordFailure(failure)
        /*
         * C3/T3: once a carrier proved itself, an exception is a DEGRADED event - the
         * proof outranks anything we failed to observe. Only a record with no carrier
         * evidence may become FAILED.
         */
        val current = currentStatus
        /*
         * C3 (persisted form): the in-memory status is empty after a process restart,
         * so the guard has to read the record too. A record that still carries an ARMED
         * gate or a carrier proof must never be rewritten as FAILED.
         */
        val persisted = statusContext?.let { runCatching { JailbreakStatus.read(it) }.getOrNull() }
        val carrierAlive = current?.carrier != null || persisted?.carrier != null ||
            persisted?.suGate == "ARMED"
        if (carrierAlive) {
            statusContext?.let { context ->
                runCatching {
                    dev.maplesu.manager.runtime.StageMark.mark(context, "degraded:" + failure)
                }
            }
            return current ?: persisted ?: JailbreakStatus(
                method = JailbreakLeaseStore.provider ?: "unknown",
                stage = JailbreakStatus.STAGE_FAILED,
                message = detail.ifEmpty { "attempt failed" },
                startedAtMillis = 0, updatedAtMillis = 0,
                bootId = DirtyfragAttempt.readBootId(), failure = failure,
            )
        }
        return publish(JailbreakStatus(
            method = JailbreakLeaseStore.provider ?: "unknown",
            stage = JailbreakStatus.STAGE_FAILED,
            message = detail.ifEmpty { "attempt failed" }, startedAtMillis = 0, updatedAtMillis = 0,
            bootId = DirtyfragAttempt.readBootId(), failure = failure,
        ))
    }
}

/** Keep authenticated restore observations even when the restore gate rejects the lease. */
internal fun ghostlockRestoreObservation(
    request: JailbreakRequest,
    target: String,
    identity: LeaseProtocol.Identity,
    restore: Restore,
): JailbreakStatus = JailbreakStatus(
    method = request.method, stage = JailbreakStatus.STAGE_HANDOFF_AUTHENTICATED,
    message = "lease authenticated; provider restore=" + restore.state() +
        " origin=" + restore.origin().name + " enforcing=" + restore.enforcing() +
        " checkreqprot=" + restore.checkreqprot() + " policy=" + restore.policy(),
    startedAtMillis = 0, updatedAtMillis = 0, bootId = request.bootId,
    attemptId = request.attemptId, workerPid = identity.workerPid(), workerDomain = identity.domain(),
    enforcingAtLease = identity.enforcing(),
    restoreState = restore.state(), restoreOrigin = restore.origin().name,
    restoreEnforcing = restore.enforcing(), restoreCheckreqprot = restore.checkreqprot(),
    restorePolicy = restore.policy(), restoreFailures = if (restore.failed()) 1 else 0,
    target = target, rootBackend = request.rootBackend,
)
