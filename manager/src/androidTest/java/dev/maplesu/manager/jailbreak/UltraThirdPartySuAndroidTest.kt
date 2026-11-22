package dev.maplesu.manager.jailbreak

import android.os.Bundle
import android.os.IBinder
import android.os.Parcel
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import dev.maplesu.manager.runtime.NativeSuDaemon
import dev.maplesu.manager.runtime.NativeSuDiscovery
import dev.maplesu.manager.runtime.SuGate
import dev.maplesu.manager.runtime.authorization.AuthorizationSnapshot
import dev.maplesu.manager.runtime.authorization.SuperuserControl
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.io.IOException
import java.util.UUID

/** One restricted-su attempt as the fixture (another process, another UID) saw it. */
private data class Trial(
    val label: String,
    val accepted: Boolean,
    val finished: Boolean,
    val uid: Int,
    val exitCode: Int,
    val stdout: String,
    val stderr: String,
    val denial: String?,
    val denialDetail: String?,
    val threw: String?,
    val entryAbsent: Boolean,
    /**
     * The SELinux domain of a **second** session started with
     * `id -u; cat /proc/self/attr/current`, so every scenario records uid **and** domain
     * (`SuDomainEvidence`). A refused scenario records the refusal, not a domain.
     */
    val suDomain: JSONObject,
) {
    /** The domain this scenario's su child ended up in, or null when none was observed. */
    val domain: String?
        get() = if (suDomain.isNull("domain")) null
        else suDomain.optString("domain").takeIf { it.isNotEmpty() }

    fun json(): JSONObject = JSONObject()
        .put("label", label)
        .put("accepted", accepted)
        .put("finished", finished)
        .put("uid", uid)
        .put("exitCode", exitCode)
        .put("stdout", bound(stdout))
        .put("stderr", bound(stderr))
        .put("denial", denial ?: JSONObject.NULL)
        .put("denialDetail", denialDetail ?: JSONObject.NULL)
        .put("threw", threw ?: JSONObject.NULL)
        .put("entryAbsent", entryAbsent)
        .put("domain", domain ?: JSONObject.NULL)
        .put("suDomain", suDomain)
}

private fun bound(text: String, limit: Int = 512): String =
    if (text.length <= limit) text else text.take(limit) + "...(truncated)"

/**
 * Ultra (hook backend) third-party `su`: does another UID reach uid 0, or is it refused?
 *
 * <p>**Orchestration contract (2026-10-31, one attempt per boot).** The hook route's
 * kernel window is one-shot: `/dev/df` and the app-private `jailbreak-kernel-window`
 * marker refuse a second DirtyFrag admission in the same boot
 * (`DirtyfragAttempt.admit`, `DIRTYFRAG_GUARD_PRESENT_REBOOT_REQUIRED` /
 * `DIRTYFRAG_REBOOT_REQUIRED_AFTER_ATTEMPT`). A run that ignored that produced
 * `ULTRA_THIRD_PARTY_SU_NOT_WIRED:attempt_not_ready:FAILED:
 * DIRTYFRAG_GUARD_PRESENT_REBOOT_REQUIRED` after the L3 test had already spent the
 * window, and then blamed the product for a test-order fact. This test therefore:
 *
 *  1. checks whether **this boot** already has an attempt (any stage) before doing
 *     anything else. If it does, no second `prepareHook` is made: a live
 *     `DAEMON_READY` attempt is reused (endpoint via `NativeSuDiscovery.peek`), a
 *     live-but-not-ready claim or a terminal one whose guard markers say the window was
 *     spent is reported as `attempt_not_ready` + reboot, and a terminal failure with no
 *     guard marker (it failed before the kernel work) is retried exactly once;
 *  2. otherwise calls [NativeSuDaemon.prepareHook] **exactly once** and waits for the
 *     provider's `DAEMON_READY` (the provider is the only escalator; `escalate()`
 *     first would spend the window on itself - R-D13);
 *  3. resolves the published restricted endpoint the ordinary way
 *     (`NativeSuDiscovery.peek(managerUid)`); it never calls `management`, never
 *     `prepare` again, and records `prepareHookCalls`/`managementCalls` so that is
 *     checkable from the JSON;
 *  4. drives scenarios **A** no grant -> refused, **B** a grant written through the
 *     Manager transaction ([SuperuserControl], i.e. the same one the UI uses) ->
 *     `accepted`, `uid=peer`, `id -u` == `0`, **C** revoked again -> refused, all
 *     from [IDENTITY_PROBE] (the test APK's own `:identity_probe` process/UID);
 *  5. on any prepare failure writes `failure=...:attempt_not_ready:<token>` plus
 *     `rebootRequired` and `remediation` (hard reboot, then run this class **first**;
 *     do not run L3/other attempt tests in that boot). Verdict is
 *     `ATTEMPT_NOT_READY`, never `NOT_WIRED`.
 *
 * <p>**Process liveness (2026-10-31, second pass).** The first keep-alive attempt started
 * the App's own `MainActivity` from this (same) instrumentation process with
 * `startActivitySync`; the device answered with
 *
 * ```
 * I/wm_finish_activity: [0,...,dev.maplesu.manager/com.maplesu.core.ui.MainActivity,
 *                        proc died without state saved]
 * ```
 *
 * and the process died **before `prepareHook`** (`phase=pre`, `foreground.ok=true`,
 * `prepareHookCalls=0`, no `am_kill`). The Activity launch itself is the trigger, so this
 * test now starts **no Activity by default** (`foreground.mode=DISABLED_BY_DEFAULT`) and
 * the keep-alive is exactly the platform doze exemption:
 *
 *  - `deviceIdle{whitelistBefore, whitelistAdd, whitelistAfter, setInactive, inactiveAfter}`
 *    from `cmd deviceidle whitelist +<pkg>` and `am set-inactive <pkg> false`, each read
 *    back - attempted, recorded, never fatal;
 *  - `foreground{mode=DISABLED_BY_DEFAULT, started=false, ok=false, ...}`: no Activity is
 *    launched. The old path survives only behind `-e maplesuForeground activity`;
 *  - `processKill{lines, killRecords, systemKill, cachedReclaim, crashBuffer, windowManager,
 *    exitInfo}` plus `processKillAttribution{...}` when the attempt ends. A
 *    `Cached(nirvana)`-class reclaim that can be attributed to this attempt's pids (or to
 *    this run's window) replaces the failure token with
 *    `...:PROCESS_KILLED_BY_SYSTEM:<line>`.
 *
 * <p>**The fixture is bound first (2026-10-31, third pass).** `.analysis/ultra3p7-132937/
 * evidence.json` shows the failure that hid everything else: all three trials carried
 * `threw=AssertionError: the identity fixture did not bind`, the su-domain probes turned
 * that into `SU_DOMAIN_UNAVAILABLE:HARNESS:...`, and the run ended as
 * `manager_transaction_failed:SU_TRANSPORT_UNAVAILABLE` - three layers of symptom over a
 * harness that never produced a foreign-UID caller. This class now:
 *
 *  - binds [FixtureBinding] **before** `prepareHook`, so a harness failure does not spend
 *    the boot's one-shot kernel window (`prepareHookCalls=0` in that case);
 *  - writes `fixture{bound, error, servicePackage, uid, elapsedMillis, diagnostics}`,
 *    where `diagnostics` holds the component/package facts (exported/enabled/process/uid/
 *    signature/testOnly/stopped/QUERY_ALL_PACKAGES), **every** bind attempt with its
 *    `ServiceConnection` callbacks, and the AMS/logcat/`dumpsys package` answer;
 *  - reports `failure=...:fixture_not_bound:<hint>` and `verdict=HARNESS_FIXTURE_UNAVAILABLE`
 *    instead of throwing a bare `AssertionError`, and each trial records
 *    `denial=threw=FIXTURE_NOT_BOUND` because it was never asked;
 *  - records `authorization.grantDiagnostics{ok, code, kind, gate/suGate at the call}` so
 *    a `SU_TRANSPORT_UNAVAILABLE` grant is split into "gate not resolvable" and "root tool
 *    child did not answer" (the SIGSYS/`setgid` finding) - neither is a fixture failure.
 *
 * <p>**su domain (2026-10-31, second pass).** A uid of 0 is not proof of working root: the
 * kernel log has `avc: denied { search } for comm="su" ... scontext=u:r:untrusted_app:s0 ...
 * tcontext=u:object_r:kernel:s0` and the daemon's children die with `SIGABRT`
 * (`Cmdline: <random> --suicide`, `uid: 0`). So every scenario A/B/C now also records the
 * domain of a `id -u; cat /proc/self/attr/current` session (`trials[i].domain`,
 * `trials[i].suDomain`), the shell-UID probe
 * `su -c 'id -u; cat /proc/self/attr/current'` is recorded as `suDomain.probes.shell`, and
 * `suDomain.unexpectedToken` carries `SU_DOMAIN_UNEXPECTED:<domain>` when the su child is
 * still in an `untrusted_app` domain. The token is evidence and never changes the A/B/C
 * verdict.
 *
 * <p>Evidence is written **before** any assertion to
 * `filesDir/jailbreak-evidence/ultra-thirdparty-su.json` and to logcat as
 * `MAPLESU_ULTRA_3P_SU_EVIDENCE <json>`. The final record also carries
 * `logcat{crash,events,amProcDied,exitInfo}`, so the R4 App-side crash can be
 * explained from the same file on the next run (androidTest only; main untouched).
 *
 * <p>Run it with:
 * `am instrument -w -e class dev.maplesu.manager.jailbreak.UltraThirdPartySuAndroidTest#thirdPartyGetsUidZeroOrIsDenied dev.maplesu.manager.test/androidx.test.runner.AndroidJUnitRunner`
 */
@RunWith(AndroidJUnit4::class)
class UltraThirdPartySuAndroidTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context get() = instrumentation.targetContext
    private val fixturePackage get() = instrumentation.context.packageName
    private val managerUid get() = context.applicationInfo.uid

    /**
     * The fixture binding this run opened (closed in `finally`). It is bound **before**
     * the one-shot attempt on purpose: a harness that cannot produce a foreign-UID caller
     * must not spend this boot's only kernel window.
     */
    private var fixtureBinding: FixtureBinding? = null

    @Test
    fun thirdPartyGetsUidZeroOrIsDenied() {
        val runStartedAtMillis = System.currentTimeMillis()
        /*
         * (0) Process liveness, before any product call. **No Activity is started**: on
         *     2026-10-31 `startActivitySync(MainActivity)` from this very process was
         *     followed by `wm_finish_activity ... proc died without state saved` and the
         *     process was gone before `prepareHook` (phase=pre, prepareHookCalls=0, no
         *     am_kill). `ForegroundSession.activate` therefore returns
         *     `mode=DISABLED_BY_DEFAULT` unless the run explicitly asks for the old path
         *     (`-e maplesuForeground activity`). What is left is the platform keep-alive
         *     that does not touch the target process: the doze allowlist and
         *     `am set-inactive <pkg> false`, both read back. Neither can fail the test.
         */
        val foreground = ForegroundSession.activate(context)
        val deviceIdle = DeviceIdlePolicy.apply(context)
        val peer = fixtureUid()
        val bootBefore = DirtyfragAttempt.readBootId()
        val enforcingBefore = DirtyfragAttempt.readEnforcing()
        /*
         * (0b) The orchestration preflight, before any product call. `JailbreakStatus.read`
         * expires a live claim whose owner process is gone, so an attempt from *this*
         * boot is visible here even after the test process that started it died.
         */
        val observed = runCatching { JailbreakStatus.read(context) }.getOrNull()
        val inherited = observed?.takeIf {
            it.attemptId != null && it.bootId != null && it.bootId == bootBefore
        }
        val guardBefore = AttemptGuard.read(context, bootBefore)

        val trials = mutableListOf<Trial>()
        val document = JSONObject()
            .put("schemaVersion", 1)
            .put("hook", "ultra/third-party-su")
            .put("phase", "pre")
            .put("startedAtMillis", System.currentTimeMillis())
            .put("writtenAtMillis", System.currentTimeMillis())
            .put("peer", JSONObject()
                .put("package", fixturePackage)
                .put("uid", peer)
                .put("managerUid", managerUid)
                .put("differentUid", peer != managerUid))
            .put("boot", JSONObject().put("before", bootBefore ?: JSONObject.NULL))
            .put("enforcing", JSONObject().put("before", enforcingBefore))
            .put("foreground", foreground.evidence())
            .put("deviceIdle", deviceIdle)
            .put("orchestration", JSONObject()
                .put("policy", ONE_ATTEMPT_POLICY)
                .put("prepareHookCalls", 0)
                .put("managementCalls", 0)
                .put("attemptOwnership", "pending")
                .put("prepareAttempted", false)
                .put("inheritedAttempt", attemptSnapshot(inherited))
                .put("guardBefore", guardBefore))
            .put("trials", JSONArray())
            .put("fixture", FixtureBinding.notAttempted(
                fixturePackage, peer, "not_attempted_before_the_attempt"))
            .put("failure", JSONObject.NULL)

        /* The pre-attempt record: never lost to a freeze inside the handover. */
        var writeError = writeEvidence(document)

        var status: JailbreakStatus? = null
        var prepareCalls = 0
        var attemptOwnership = "none"
        var attemptError: String? = null
        var entry: IBinder? = null
        var entryError: String? = null
        var entryAttemptId: String? = null
        var failure: String? = null
        /* Set only when the attempt/stage says so; a stale marker alone is not a verdict. */
        var rebootRequired = false
        var authorizationTouched = false
        var originalEnabled = false
        var originalGrant = false
        var snapshotAtGrant: JSONObject? = null
        var grantedAuthority: AuthorizationSnapshot? = null
        var grantResult: SuperuserControl.Result? = null
        /* `{ok, code, kind, gate/suGate at the call}`; `attempted=false` until B commits. */
        var grantDiagnostics = JSONObject().put("attempted", false)
        var restoredState: JSONObject? = null
        var deniedTrial: Trial? = null
        var grantedTrial: Trial? = null
        var revokedTrial: Trial? = null
        /* The shell-UID su domain probe, collected on the way out (never fatal). */
        var shellDomain: JSONObject? = null
        /* The `fixture{...}` node: rewritten once the bind was attempted, never guessed. */
        var fixtureEvidence = FixtureBinding.notAttempted(
            fixturePackage, peer, "not_attempted_before_the_attempt")
        val toolResults = JSONObject()

        try {
            /*
             * (0c) The identity fixture, **before any product call**. A/B/C can only be
             *     driven by a Binder caller whose Linux UID is not the Manager's, so the
             *     fixture is bound first: when that fails, this boot's one-shot kernel
             *     window is NOT spent, the `fixture{...}` node names the reason, and the
             *     verdict is HARNESS_FIXTURE_UNAVAILABLE rather than a product verdict.
             *     (2026-10-31: this used to be
             *     `assertTrue("the identity fixture did not bind", bindService(...))`,
             *     which discarded the bind result, every ServiceConnection callback, the
             *     package/component state and the AMS log line - see FixtureBinding.)
             */
            val fixture = FixtureBinding.open(context, instrumentation)
            fixtureBinding = fixture
            fixtureEvidence = fixture.evidence()
            document.put("fixture", fixtureEvidence)
            val fixtureFailed = !fixture.bound
            if (fixtureFailed) {
                failure = FAILURE_PREFIX + "fixture_not_bound:" + (fixture.error ?: "unknown")
            }

            /*
             * (1) Exactly one attempt. An attempt already recorded for this boot is the
             *     product's one window: do not prepare a second one (that is what made
             *     the previous run fail with DIRTYFRAG_GUARD_PRESENT_REBOOT_REQUIRED).
             *     - a live DAEMON_READY claim is reused without any prepare call;
             *     - a live-but-not-ready claim, or a terminal one whose guard markers
             *       say the window was spent, is reported as attempt_not_ready + reboot;
             *     - a terminal failure with no guard marker failed *before* spending
             *       the window, so one fresh attempt is legitimate (the product's own
             *       admission decides, and its token is what gets recorded).
             */
            if (!fixtureFailed && inherited != null &&
                inherited.stage == JailbreakStatus.STAGE_DAEMON_READY) {
                status = inherited
                attemptOwnership = "inherited_live_claim_reused"
                // Starting instrumentation stops the previous Manager processes, including
                // the published Binder. Restore only this boot's existing carrier before
                // observing it; this never creates another kernel attempt.
                if (InstrumentationRegistry.getArguments().getString("reproveExistingHook") == "true") {
                    val recovered = NativeSuDaemon.reproveHookOutcome(context)
                    if (recovered?.stage != JailbreakStatus.STAGE_DAEMON_READY ||
                        recovered.failure != null || recovered.attemptId != inherited.attemptId) {
                        failure = attemptNotReady(recovered?.failure ?: "reproof_not_ready")
                    }
                    document.put("existingCarrierReproved", failure == null)
                }
                val resolved = resolveEntry()
                entry = resolved.first
                entryError = resolved.second
                entryAttemptId = inherited.attemptId
            } else if (!fixtureFailed && inherited != null &&
                (inherited.stage in JailbreakStatus.LIVE_CLAIM ||
                    guardBefore.optBoolean("rebootRequired", false))
            ) {
                status = inherited
                attemptOwnership = "inherited_claim_not_reusable"
                failure = attemptNotReady(inherited.failure ?: inherited.stage)
                rebootRequired = true
            } else if (!fixtureFailed) {
                attemptOwnership = if (inherited == null) {
                    "owned_by_this_test"
                } else {
                    "owned_by_this_test_retry_after_earlier_failure"
                }
                val request = JailbreakRequest(
                    method = "dirtyfrag",
                    attemptId = UUID.randomUUID().toString(),
                    bootId = bootBefore,
                    // One boot, one attempt: a soft reboot would invalidate the
                    // acceptance and could not be observed from here.
                    softReboot = false,
                    rootBackend = JailbreakRequest.BACKEND_HOOK,
                )
                document.put("attemptRequest", JSONObject()
                    .put("method", request.method)
                    .put("attemptId", request.attemptId)
                    .put("bootId", request.bootId ?: JSONObject.NULL)
                    .put("rootBackend", request.rootBackend ?: JSONObject.NULL))
                /* The only attempt-creating call of this test, made exactly once. */
                prepareCalls = 1
                val direct = runCatching { NativeSuDaemon.prepareHook(context, request) }
                    .onFailure { attemptError = describe(it) }
                    .getOrNull()
                /*
                 * Never let a record from another attempt/boot answer for this one: when
                 * the call threw before the provider wrote anything, the only honest
                 * status is "none", and the thrown reason is the token.
                 */
                status = direct ?: runCatching { JailbreakStatus.read(context) }.getOrNull()
                    ?.takeIf { it.attemptId == request.attemptId }
                if (status?.stage != JailbreakStatus.STAGE_DAEMON_READY) {
                    failure = attemptNotReady(
                        attemptError ?: status?.failure ?: status?.stage ?: "missing")
                    rebootRequired = true
                } else {
                    val resolved = resolveEntry()
                    entry = resolved.first
                    entryError = resolved.second
                    entryAttemptId = status?.attemptId ?: request.attemptId
                }
            }
            if (failure != null && !fixtureFailed) {
                rebootRequired = rebootRequired ||
                    guardBefore.optBoolean("rebootRequired", false) ||
                    rebootToken(status?.failure ?: inherited?.failure)
            }

            /*
             * (2) The entry an ordinary third party would use, resolved the ordinary
             *     way. A null answer here is a real product state ("no restricted su was
             *     published for this boot"), not an attempt-ownership failure.
             */
            if (failure == null && entry == null) {
                failure = FAILURE_PREFIX + "no_published_entry:" +
                    (entryError ?: ENTRY_ABSENT)
            }

            /*
             * (3) Scenarios A/B/C. The authorization snapshot is taken *after* the
             *     attempt exists on purpose: on this route the store is reached through
             *     the attempt's L3 gate, so reading it before the attempt would only
             *     produce SU_TRANSPORT_UNAVAILABLE.
             */
            if (failure == null) {
                val originalSnapshot = SuperuserControl.snapshot(context)
                if (originalSnapshot == null) {
                    failure = FAILURE_PREFIX + "su_transport_unavailable:snapshot"
                } else {
                    originalEnabled = originalSnapshot.enabled
                    originalGrant = originalSnapshot.grants.containsKey(peer)
                    authorizationTouched = true

                    /* A: master switch on, no grant. A refusal can only be the per-uid rule. */
                    val enableA = SuperuserControl.setEnabled(context, true)
                    val revokeA = SuperuserControl.revoke(context, peer)
                    toolResults.put("setEnabledForA", resultJson(enableA))
                    toolResults.put("revokeForA", resultJson(revokeA))
                    if (!enableA.ok || !revokeA.ok) {
                        /*
                         * Without a committed baseline, an "admitted" A would say nothing
                         * about the per-uid rule (the switch or the revoke never landed).
                         */
                        failure = FAILURE_PREFIX + "manager_transaction_failed:baseline:" +
                            (if (!enableA.ok) "set_enabled=" + (enableA.code ?: "unknown")
                            else "revoke=" + (revokeA.code ?: "unknown"))
                    } else {
                        deniedTrial = attempt("A_unauthorised", entry, fixture.binder)
                        trials += deniedTrial

                        /* B: the Manager transaction (same call the UI uses), then retry. */
                        toolResults.put("setEnabledForB",
                            resultJson(SuperuserControl.setEnabled(context, true)))
                        val grantOutcome = SuperuserControl.grant(context, peer)
                        grantResult = grantOutcome
                        toolResults.put("grantForB", resultJson(grantOutcome))
                        /*
                         * Why the grant failed matters: `SU_TRANSPORT_UNAVAILABLE` has two
                         * very different causes - the L3 gate was not resolvable at that
                         * moment, or it was resolvable and the one-shot root tool child died
                         * (`.analysis/transport-su-gate-20261031/report.md` §6 documents
                         * SIGSYS on `setgid`, exit 159, in that child). The snapshot below
                         * is taken at the exact call so the next round does not have to
                         * guess. Neither cause involves the identity fixture.
                         */
                        val statusAtGrant = runCatching { JailbreakStatus.read(context) }.getOrNull()
                        val gateAtGrant = runCatching {
                            SuGate.read(context, statusAtGrant?.attemptId, statusAtGrant?.bootId)
                        }.getOrNull()
                        grantDiagnostics = JSONObject()
                            .put("ok", grantOutcome.ok)
                            .put("code", grantOutcome.code ?: JSONObject.NULL)
                            .put("kind", when {
                                grantOutcome.ok -> "COMMITTED"
                                gateAtGrant?.armed != true -> "GATE_UNAVAILABLE_AT_GRANT"
                                else -> "ROOT_TOOL_CALL_FAILED_AFTER_GATE_RESOLVED"
                            })
                            .put("attemptStageAtGrant", statusAtGrant?.stage ?: JSONObject.NULL)
                            .put("suGateAtGrant", statusAtGrant?.suGate ?: JSONObject.NULL)
                            .put("gateBoundAtGrant", gateAtGrant?.bound ?: false)
                            .put("gateArmedAtGrant", gateAtGrant?.armed ?: false)
                            .put("gateStateAtGrant", gateAtGrant?.state ?: JSONObject.NULL)
                            .put("ownerPidAtGrant", statusAtGrant?.ownerPid ?: JSONObject.NULL)
                            .put(
                                "note",
                                "GATE_UNAVAILABLE_AT_GRANT = the hook transport could not be " +
                                    "resolved when the call was made; ROOT_TOOL_CALL_FAILED_" +
                                    "AFTER_GATE_RESOLVED = the gate resolved and the one-shot " +
                                    "root child did not answer (the SIGSYS/setgid finding), " +
                                    "which is not a fixture failure",
                            )
                        val grantedSnapshot = SuperuserControl.snapshot(context)
                        grantedAuthority = grantedSnapshot
                        snapshotAtGrant = JSONObject()
                            .put("enabled", grantedSnapshot?.enabled ?: false)
                            .put("granted", grantedSnapshot?.grants?.containsKey(peer) ?: false)
                            .put("rev", grantedSnapshot?.rev ?: grantOutcome.rev)
                            .put("grantOk", grantOutcome.ok)
                            .put("grantCode", grantOutcome.code ?: JSONObject.NULL)
                            .put("pendingApply", snapshotAtGrantPending(grantedSnapshot))
                            .put("grantCount", grantedSnapshot?.grants?.size ?: 0)
                            .put("listPath", grantStorePath())
                            .put("listPresent", File(grantStorePath()).isFile)
                        grantedTrial = attempt("B_granted", entry, fixture.binder)
                        trials += grantedTrial

                        /* C: revoked again. Proves the list is re-read per request. */
                        toolResults.put("revokeForC",
                            resultJson(SuperuserControl.revoke(context, peer)))
                        revokedTrial = attempt("C_revoked_again", entry, fixture.binder)
                        trials += revokedTrial
                    }
                }
            }

            /* (4) The verdict, named. Written before the assertions below. */
            if (failure == null) {
                val deniedNow = deniedTrial
                val grantedNow = grantedTrial
                val revokedNow = revokedTrial
                failure = when {
                    deniedNow?.accepted == true ->
                        "ULTRA_THIRD_PARTY_SU_UNAUTHORIZED_ADMITTED"
                    grantedNow == null ->
                        FAILURE_PREFIX + "granted_trial_missing"
                    /*
                     * A refused B is only a product refusal when the Manager transaction
                     * actually committed. Without this split, a failed transport would be
                     * reported as "entry refused the grant", which is a different defect.
                     */
                    grantResult?.ok != true ->
                        FAILURE_PREFIX + "manager_transaction_failed:" +
                            (grantResult?.code ?: "unknown")
                    snapshotAtGrant?.optBoolean("granted") != true ->
                        FAILURE_PREFIX + "grant_not_visible_in_manager_store:" +
                            (grantResult?.detail ?: "unknown")
                    !grantedNow.accepted ->
                        FAILURE_PREFIX + "granted_but_refused:" +
                            (grantedNow.denialDetail ?: grantedNow.denial
                                ?: grantedNow.threw ?: "unknown")
                    grantedNow.exitCode != 0 || grantedNow.stdout.trim() != "0" ->
                        FAILURE_PREFIX + "no_uid0:exit=" + grantedNow.exitCode +
                            ":out=" + bound(grantedNow.stdout) +
                            ":err=" + bound(grantedNow.stderr)
                    revokedNow?.accepted == true ->
                        FAILURE_PREFIX + "revoke_not_enforced"
                    else -> null
                }
                /*
                 * The domain session is a *second* request in the same scenario, so it must
                 * obey the same authorization: an admitted domain session in A (no grant)
                 * or C (revoked) is the same security defect as an admitted su, and is not
                 * allowed to sit in the evidence as a fact nobody reads.
                 */
                if (failure == null && deniedTrial?.suDomain?.optBoolean("accepted", false) == true) {
                    failure = FAILURE_PREFIX + "unauthorized_domain_session_admitted"
                }
                if (failure == null && revokedTrial?.suDomain?.optBoolean("accepted", false) == true) {
                    failure = FAILURE_PREFIX + "revoked_domain_session_admitted"
                }
            }
        } catch (error: Throwable) {
            if (failure == null) failure = FAILURE_PREFIX + "harness:" + describe(error)
        } finally {
            /* Restore the authorization state this test borrowed, whatever happened. */
            if (authorizationTouched) {
                restoredState = runCatching {
                    SuperuserControl.setEnabled(context, originalEnabled)
                    if (originalGrant) SuperuserControl.grant(context, peer)
                    else SuperuserControl.revoke(context, peer)
                    val after = SuperuserControl.snapshot(context)
                    JSONObject()
                        .put("enabled", after?.enabled ?: false)
                        .put("grant", after?.grants?.containsKey(peer) ?: false)
                        .put("rev", after?.rev ?: JSONObject.NULL)
                        .put("expectedEnabled", originalEnabled)
                        .put("expectedGrant", originalGrant)
                        .put("matchesOriginal",
                            (after?.enabled ?: false) == originalEnabled &&
                                (after?.grants?.containsKey(peer) ?: false) == originalGrant)
                }.getOrElse {
                    JSONObject().put("error", describe(it))
                }
            }

            val bootAfter = runCatching { DirtyfragAttempt.readBootId() }.getOrNull()
            val enforcingAfter = DirtyfragAttempt.readEnforcing()
            val guardAfter = AttemptGuard.read(context, bootAfter)
            /*
             * One attempt means one attempt id. If some other path created another one
             * during the trials, the record says so instead of quietly mixing attempts.
             */
            val statusAfter = runCatching { JailbreakStatus.read(context) }.getOrNull()
            val ownedAttemptId = status?.attemptId ?: inherited?.attemptId
            val secondAttempt = ownedAttemptId != null &&
                statusAfter?.attemptId != null && statusAfter.attemptId != ownedAttemptId
            if (secondAttempt && failure == null) {
                failure = FAILURE_PREFIX + "orchestration_second_attempt:" +
                    ownedAttemptId + "->" + statusAfter?.attemptId
            }

            /*
             * (5) Process liveness, closed on the way out: finish the foreground handle
             *     (with mode=DISABLED_BY_DEFAULT there is nothing to finish), then read the
             *     platform's own record of this package's processes dying. A cached-state
             *     reclaim (`Cached(nirvana)`) is a system kill, not a crash, and it is
             *     named as such instead of being reported as "the product is not wired".
             */
            foreground.finish()
            /* The domain question, from a caller that is neither the Manager nor the fixture. */
            shellDomain = SuDomainEvidence.probeShell("ultra/shell")
            val processKill = ProcessKillEvidence.collect(
                context, "ultra-thirdparty-su", runStartedAtMillis)
            val deathPids = setOfNotNull(
                status?.ownerPid, status?.workerPid,
                inherited?.ownerPid, statusAfter?.ownerPid)
            val killLine = ProcessKillEvidence.systemKillLine(
                processKill, deathPids, runStartedAtMillis)
            val failureBeforeKill = failure
            if (failureBeforeKill != null && killLine != null &&
                deathExplainsFailure(failureBeforeKill, status, inherited)
            ) {
                failure = FAILURE_PREFIX + ProcessKillEvidence.token(killLine)
                rebootRequired = true
            }

            val grantedReachedUid0 = grantedTrial?.let {
                it.accepted && it.exitCode == 0 && it.stdout.trim() == "0"
            } == true
            val sameListAsUltra = grantedReachedUid0 && deniedTrial?.accepted == false
            val sameListReason = when {
                entry == null -> "entry_not_published"
                grantedReachedUid0 ->
                    "grant_written_through_manager_transaction_was_honoured"
                grantedTrial?.accepted == true -> "grant_honoured_without_uid0"
                grantedTrial == null -> "granted_trial_missing"
                else -> "grant_written_but_entry_refused:" +
                    (grantedTrial?.denialDetail ?: grantedTrial?.denial ?: "unknown")
            }
            val grantedRev = grantedAuthority?.rev ?: -1L
            val ksuApplied = grantedAuthority?.appliedOf(KSU_MIRROR_BACKEND)
            val sameListAsKsuNormal =
                ksuApplied != null && ksuApplied.rev == grantedRev && ksuApplied.ok
            val ksuBasis = when {
                ksuApplied == null -> "no_ksu_mirror_backend_in_this_mode"
                ksuApplied.rev == grantedRev -> "applied_watermark_points_at_decision_rev"
                else -> "applied_rev_" + ksuApplied.rev + "_decision_rev_" + grantedRev
            }

            document.put("phase", "final")
            document.put("writtenAtMillis", System.currentTimeMillis())
            document.put("trials", trialsJson(trials))
            document.put("attempt", attemptJson(status, attemptOwnership))
            document.put("attemptFailure", attemptError ?: JSONObject.NULL)
            document.put("entry", JSONObject()
                .put("published", entry != null)
                .put("alive", entry?.isBinderAlive ?: false)
                .put("attemptId", entryAttemptId ?: JSONObject.NULL)
                .put("error", entryError ?: JSONObject.NULL)
                .put("resolution",
                    "dev.maplesu.manager.runtime.NativeSuDiscovery.peek(managerUid)"))
            document.put("orchestration", JSONObject()
                .put("policy", ONE_ATTEMPT_POLICY)
                .put("prepareHookCalls", prepareCalls)
                .put("managementCalls", 0)
                .put("attemptOwnership", attemptOwnership)
                .put("prepareAttempted", prepareCalls == 1)
                .put("inheritedAttempt", attemptSnapshot(inherited))
                .put("guardBefore", guardBefore)
                .put("guardAfter", guardAfter)
                .put("attemptIdOwned", ownedAttemptId ?: JSONObject.NULL)
                .put("attemptIdAfter", statusAfter?.attemptId ?: JSONObject.NULL)
                .put("attemptIdStable", !secondAttempt)
                .put("secondAttemptDetected", secondAttempt)
                .put("rebootRequired", rebootRequired))
            document.put("authorization", JSONObject()
                .put("listSource", LIST_SOURCE)
                .put("listPath", grantStorePath())
                .put("transportSnapshotAvailable", authorizationTouched)
                .put("granted", snapshotAtGrant?.optBoolean("granted") ?: false)
                .put("deniedCode",
                    deniedTrial?.denialDetail ?: deniedTrial?.denial ?: JSONObject.NULL)
                .put("deniedErr",
                    deniedTrial?.stderr?.takeIf { it.isNotEmpty() } ?: JSONObject.NULL)
                .put("sameListAsUltra", sameListAsUltra)
                .put("sameListAsUltraReason", sameListReason)
                .put("atGrant", snapshotAtGrant ?: JSONObject.NULL)
                .put("grantDiagnostics", grantDiagnostics)
                .put("toolResults", toolResults)
                .put("restored", restoredState ?: JSONObject.NULL)
                .put("sameListAsKsuNormal", sameListAsKsuNormal)
                .put("ksuNormalListSource", KSU_LIST_SOURCE)
                .put("crossModeBasis", ksuBasis))
            document.put("boot", JSONObject()
                .put("before", bootBefore ?: JSONObject.NULL)
                .put("after", bootAfter ?: JSONObject.NULL)
                .put("unchanged", bootBefore != null && bootBefore == bootAfter))
            document.put("enforcing", JSONObject()
                .put("before", enforcingBefore)
                .put("after", enforcingAfter)
                .put("restored", enforcingAfter == 1)
                .put("observed", enforcingAfter != -1))
            document.put("foreground", foreground.evidence())
            document.put("processKill", processKill)
            document.put("processKillAttribution", JSONObject()
                .put("pids", JSONArray().apply { deathPids.sorted().forEach { put(it) } })
                .put("attributedLine", killLine ?: JSONObject.NULL)
                .put("failureBeforeKill", failureBeforeKill ?: JSONObject.NULL)
                .put("failureReplaced", failure != failureBeforeKill))
            /*
             * (6) The SELinux domain of every su child this run started. `uid: 0` alone is
             *     not working root: the 2026-10-31 kernel log shows a uid-0 child in
             *     `u:r:untrusted_app:s0` being refused `search` on the daemon directory.
             *     Evidence only - the token never rewrites the A/B/C verdict.
             */
            val suDomain = SuDomainEvidence.summary(
                "A_unauthorised" to deniedTrial?.suDomain,
                "B_granted" to grantedTrial?.suDomain,
                "C_revoked_again" to revokedTrial?.suDomain,
                "shell" to shellDomain,
            )
            val suDomainToken = if (suDomain.isNull("unexpectedToken")) null
            else suDomain.optString("unexpectedToken").takeIf { it.isNotEmpty() }
            document.put("suDomain", suDomain)
            document.put("suDomainToken", suDomainToken ?: JSONObject.NULL)
            document.put("suDomainUnexpected", suDomainToken != null)
            /*
             * The fixture node, re-read at the end: `bound` is what the run actually got,
             * and `diagnostics` keeps the package/component facts, every bind attempt and
             * the AMS log lines even when the bind failed. Closing the connection here
             * never changes `bound`.
             */
            fixtureBinding?.close()
            fixtureEvidence = fixtureBinding?.evidence() ?: fixtureEvidence
            document.put("fixture", fixtureEvidence)
            document.put("fixtureFailure", fixtureBinding?.error ?: JSONObject.NULL)
            document.put("failure", failure ?: JSONObject.NULL)
            document.put("rebootRequired", rebootRequired)
            document.put("remediation", when {
                failure != null && failure.contains("PROCESS_KILLED_BY_SYSTEM") ->
                    killRemediation(rebootRequired)
                failure != null && failure.startsWith(FAILURE_PREFIX + "fixture_not_bound:") ->
                    fixtureRemediation()
                rebootRequired -> REBOOT_REMEDIATION
                failure != null -> minimalFix()
                suDomainToken != null -> SuDomainEvidence.remediation(suDomainToken)
                else -> JSONArray()
            })
            document.put("verdict", when {
                failure == null -> "PASS"
                failure == "ULTRA_THIRD_PARTY_SU_UNAUTHORIZED_ADMITTED" -> "SECURITY_FAIL"
                failure.contains("PROCESS_KILLED_BY_SYSTEM") -> "PROCESS_KILLED_BY_SYSTEM"
                failure.startsWith(FAILURE_PREFIX + "attempt_not_ready:") -> "ATTEMPT_NOT_READY"
                failure.startsWith(FAILURE_PREFIX + "fixture_not_bound:") ->
                    "HARNESS_FIXTURE_UNAVAILABLE"
                else -> "NOT_WIRED"
            })
            /* R4: the crash facts travel with the verdict, but never decide it. */
            document.put("logcat", LogcatEvidence.collect(context, "ultra-thirdparty-su"))
            writeError = writeEvidence(document)
        }

        /* ---------------------------------------------------------------------------
         * Assertions last: every failure has already left the record on disk.
         * ------------------------------------------------------------------------- */

        assertEquals("the evidence record was not written: " + writeError, "", writeError)
        val target = evidenceFile()
        assertTrue("the evidence record is missing: " + target.path, target.isFile)
        val written = runCatching { target.readText() }.getOrDefault("")
        /*
         * Parse, do not substring-match: org.json escapes '/' as '\/', so the previous
         * `contains("\"ultra/third-party-su\"")` failed on a perfectly valid record and
         * hid the real verdict behind a schema assertion.
         */
        val parsed = runCatching { JSONObject(written) }.getOrNull()
        assertNotNull("the evidence record is not JSON: " + bound(written), parsed)
        if (parsed == null) return
        assertEquals("the evidence record is not this test's schema: " + bound(written),
            "ultra/third-party-su", parsed.optString("hook"))
        assertEquals("the evidence record has an unexpected schemaVersion", 1,
            parsed.optInt("schemaVersion", -1))
        assertTrue("the fixture must be a different UID than the Manager", peer != managerUid)
        assertTrue("this test must never create more than one attempt: prepareHookCalls=" +
            prepareCalls, prepareCalls <= 1)
        assertFalse("a second attempt id appeared during the run: " +
            parsed.optJSONObject("orchestration"), parsed.optJSONObject("orchestration")
            ?.optBoolean("secondAttemptDetected", false) ?: false)

        if (failure != null) {
            fail(failure + " | " + (if (rebootRequired) REBOOT_INSTRUCTION else "") +
                " | evidence: " + target.path)
            return
        }

        assertFalse("A: the unauthorised third party was admitted",
            deniedTrial?.accepted ?: false)

        val authorized = grantedTrial
        val revoked = revokedTrial
        if (authorized == null) {
            fail("B: the authorised trial was never attempted | evidence: " + target.path)
            return
        }
        assertTrue("B: the authorised third party was refused: " + authorized.json(),
            authorized.accepted)
        assertEquals("B: the session ran for another uid than the fixture",
            peer, authorized.uid)
        assertTrue("B: the child did not finish: " + authorized.json(), authorized.finished)
        assertEquals("B: `id -u` did not exit 0: " + authorized.json(), 0, authorized.exitCode)
        assertEquals("B: the third party did not get uid 0: " + authorized.json(),
            "0", authorized.stdout.trim())
        assertFalse("C: a revoked caller was admitted", revoked?.accepted ?: false)
    }

    /** The fixture's UID: the test APK runs in its own process under its own Linux UID. */
    private fun fixtureUid(): Int =
        context.packageManager.getApplicationInfo(fixturePackage, 0).uid

    /**
     * Whether [failure] is the class of failure a **dead attempt process** produces, so a
     * system reclaim can be named as its cause.
     *
     * <p>A spent-window failure (`DIRTYFRAG_GUARD_PRESENT_REBOOT_REQUIRED`) is deliberately
     * not in this class: that is orchestration, not a death, and calling it a kill would be
     * the same mistake in the other direction. A live claim whose owner process is gone is
     * the death case, and `JailbreakStatus.read` reports it as `STAGE_EXPIRED` /
     * `JAILBREAK_OWNER_EXITED`.
     */
    private fun deathExplainsFailure(
        failure: String,
        status: JailbreakStatus?,
        inherited: JailbreakStatus?,
    ): Boolean {
        if (failure.contains("JAILBREAK_OWNER_EXITED")) return true
        if (failure.contains("EXISTING_ATTEMPT")) return true
        if (status?.stage == JailbreakStatus.STAGE_EXPIRED) return true
        if (inherited?.stage == JailbreakStatus.STAGE_EXPIRED) return true
        val owner = status?.ownerPid ?: inherited?.ownerPid
        return owner != null && failure.contains("attempt_not_ready") && !ownerAlive(owner)
    }

    /** A live process of this package with that pid; a reused pid of another app is not. */
    private fun ownerAlive(pid: Int): Boolean = runCatching {
        File("/proc/$pid/cmdline").readBytes().toString(Charsets.UTF_8)
            .contains(context.packageName)
    }.getOrDefault(false)

    private fun evidenceFile(): File =
        File(File(context.filesDir, EVIDENCE_DIRECTORY), EVIDENCE_FILE)

    /**
     * Resolves the endpoint an ordinary client uses, retrying briefly because the
     * broker publication is completed inside `prepareHook` before it returns.
     * Never creates an attempt and never falls back to `management`.
     */
    private fun resolveEntry(): Pair<IBinder?, String?> {
        var last: String? = null
        repeat(ENTRY_RESOLVE_ATTEMPTS) {
            try {
                val binder = NativeSuDiscovery.peek(managerUid)
                if (binder.isBinderAlive) return binder to null
                last = "SU_BINDER_NOT_ALIVE"
            } catch (error: Throwable) {
                last = describe(error)
            }
            runCatching { Thread.sleep(ENTRY_RESOLVE_DELAY_MILLIS) }
        }
        return null to last
    }

    /**
     * Writes the record and the one logcat line, before anything is asserted.
     *
     * @return non-empty when the record could not be written; the caller asserts on it.
     */
    @Synchronized
    private fun writeEvidence(document: JSONObject): String {
        val text = document.toString(2)
        android.util.Log.i("MapleSU", "MAPLESU_ULTRA_3P_SU_EVIDENCE " + document)
        return try {
            val directory = File(context.filesDir, EVIDENCE_DIRECTORY)
            if (!directory.isDirectory && !directory.mkdirs() && !directory.isDirectory) {
                throw IOException("mkdirs failed: " + directory.path)
            }
            val target = File(directory, EVIDENCE_FILE)
            val staging = File(directory, EVIDENCE_FILE + ".new")
            staging.writeText(text)
            if (!staging.renameTo(target)) {
                target.writeText(text)
                staging.delete()
            }
            ""
        } catch (error: Throwable) {
            describe(error)
        }
    }

    /**
     * One attempt from the fixture's UID. A missing entry is recorded as its own result
     * (denial `SU_EXECUTOR_NOT_PUBLISHED`) instead of being skipped, so `trials` always
     * says what was asked and what came back.
     *
     * <p>Every scenario runs **two** sessions on the same binding: the product command
     * (`/system/bin/id -u`, the uid-0 verdict) and the domain probe
     * (`id -u; cat /proc/self/attr/current`, the SELinux domain of the same child). A
     * refused scenario refuses both, which is the expected answer and is recorded as a
     * refusal rather than as a missing domain.
     */
    private fun attempt(label: String, target: IBinder?, fixture: IBinder?): Trial {
        if (target == null) {
            return Trial(label, accepted = false, finished = false, uid = -1, exitCode = -1,
                stdout = "", stderr = "", denial = ENTRY_ABSENT, denialDetail = null,
                threw = null, entryAbsent = true,
                suDomain = SuDomainEvidence.notAttempted(label + "/domain", ENTRY_ABSENT))
        }
        if (fixture == null) {
            /*
             * No foreign-UID caller: this scenario was never asked. A record that said
             * "refused" here would be a product verdict the harness did not earn, so the
             * trial carries the harness token instead (the run's `failure` already names
             * `fixture_not_bound:<hint>`, and `fixture{...}` says why).
             */
            return Trial(label, accepted = false, finished = false, uid = -1, exitCode = -1,
                stdout = "", stderr = "", denial = FIXTURE_UNAVAILABLE, denialDetail = null,
                threw = FIXTURE_UNAVAILABLE, entryAbsent = false,
                suDomain = SuDomainEvidence.notAttempted(
                    label + "/domain", FIXTURE_UNAVAILABLE))
        }
        return try {
            val result = transactSession(fixture, target, SU_COMMAND)
            Trial(
                label = label,
                accepted = result.accepted,
                finished = result.finished,
                uid = result.uid,
                exitCode = result.exitCode,
                stdout = result.stdout,
                stderr = result.stderr,
                denial = result.denial,
                denialDetail = result.denialDetail,
                threw = null,
                entryAbsent = false,
                suDomain = domainProbe(label, fixture, target),
            )
        } catch (error: Throwable) {
            Trial(label, accepted = false, finished = false, uid = -1, exitCode = -1,
                stdout = "", stderr = "", denial = null, denialDetail = null,
                threw = describe(error), entryAbsent = false,
                suDomain = SuDomainEvidence.notAttempted(
                    label + "/domain", "HARNESS:" + describe(error)))
        }
    }

    /**
     * The domain half of one scenario: the same restricted session, with a command that
     * prints the uid and the SELinux domain of the child it forked
     * ([SuDomainEvidence.SESSION_COMMAND]). Never throws, never fails the test.
     */
    private fun domainProbe(label: String, fixture: IBinder, target: IBinder): JSONObject = try {
        val result = transactSession(fixture, target, SuDomainEvidence.SESSION_COMMAND)
        if (!result.accepted) {
            SuDomainEvidence.refused(label + "/domain", SuDomainEvidence.SESSION_COMMAND,
                result.denial, result.denialDetail)
        } else {
            SuDomainEvidence.fromOutput(
                label = label + "/domain",
                command = SuDomainEvidence.SESSION_COMMAND,
                executed = "mode 6 session: /system/bin/sh -c \"" +
                    SuDomainEvidence.SESSION_COMMAND + "\"",
                stdout = result.stdout,
                rc = result.exitCode,
                stderr = result.stderr,
                runner = "NativeSuProbe mode 6 (the published restricted endpoint) driven " +
                    "by the test APK's own UID",
                callerUid = runCatching { fixtureUid() }.getOrDefault(-1),
                accepted = result.accepted,
            )
        }
    } catch (error: Throwable) {
        SuDomainEvidence.notAttempted(label + "/domain", "HARNESS:" + describe(error))
    }

    /** What mode 6 of `NativeSuProbe` answered, before it is dressed as a [Trial]. */
    private class SessionResult(
        val accepted: Boolean,
        val finished: Boolean,
        val uid: Int,
        val exitCode: Int,
        val stdout: String,
        val stderr: String,
        val denial: String?,
        val denialDetail: String?,
    )

    /**
     * Mode 6 of `NativeSuProbe`: a restricted session started by the fixture itself, with
     * real pipes, so `Binder.getCallingUid()` inside the entry is the fixture's UID.
     * [command] is what the entry runs as `/system/bin/sh -c <command>`.
     */
    private fun transactSession(
        fixture: IBinder,
        target: IBinder,
        command: String,
    ): SessionResult {
        val request = Parcel.obtain()
        val response = Parcel.obtain()
        try {
            request.writeInterfaceToken(FIXTURE_DESCRIPTOR)
            request.writeInt(6)
            request.writeStrongBinder(target)
            request.writeString(command)
            request.writeString("/")
            request.writeByteArray(ByteArray(0))
            request.writeStringArray(arrayOf("PATH=/system/bin:/system/xbin"))
            request.writeInt(0)
            request.writeInt(-1)
            check(fixture.transact(IBinder.FIRST_CALL_TRANSACTION + 4, request, response, 0)) {
                "the identity fixture did not answer the su request"
            }
            response.readException()
            val result = requireNotNull(response.readTypedObject(Bundle.CREATOR)) {
                "the identity fixture returned no result"
            }
            return SessionResult(
                accepted = result.getBoolean("accepted"),
                finished = result.getBoolean("finished"),
                uid = result.getInt("uid", -1),
                exitCode = result.getInt("exitCode", -1),
                stdout = String(result.getByteArray("stdout") ?: ByteArray(0)),
                stderr = String(result.getByteArray("stderr") ?: ByteArray(0)),
                denial = result.getString("denial"),
                denialDetail = result.getString("denialDetail"),
            )
        } finally {
            request.recycle()
            response.recycle()
        }
    }

    private fun attemptJson(status: JailbreakStatus?, ownership: String): JSONObject = JSONObject()
        .put("attemptId", status?.attemptId ?: JSONObject.NULL)
        .put("method", status?.method ?: JSONObject.NULL)
        .put("rootBackend", status?.rootBackend ?: JSONObject.NULL)
        .put("bootId", status?.bootId ?: JSONObject.NULL)
        .put("stage", status?.stage ?: JSONObject.NULL)
        .put("failure", status?.failure ?: JSONObject.NULL)
        .put("message", status?.message ?: JSONObject.NULL)
        .put("restoreState", status?.restoreState ?: JSONObject.NULL)
        .put("restoreEnforcing", status?.restoreEnforcing ?: JSONObject.NULL)
        .put("restoreFailures", status?.restoreFailures ?: JSONObject.NULL)
        .put("workerPid", status?.workerPid ?: JSONObject.NULL)
        .put("suGate", status?.suGate ?: JSONObject.NULL)
        .put("ownership", ownership)
        .put("reusedLiveAttempt", ownership.startsWith("inherited_live_claim"))
        .put("daemonReady", status?.stage == JailbreakStatus.STAGE_DAEMON_READY)

    private fun attemptSnapshot(status: JailbreakStatus?): JSONObject {
        if (status == null) return JSONObject().put("present", false)
        return JSONObject()
            .put("present", true)
            .put("attemptId", status.attemptId ?: JSONObject.NULL)
            .put("bootId", status.bootId ?: JSONObject.NULL)
            .put("method", status.method)
            .put("stage", status.stage)
            .put("rootBackend", status.rootBackend ?: JSONObject.NULL)
            .put("failure", status.failure ?: JSONObject.NULL)
            .put("message", status.message)
            .put("ownerPid", status.ownerPid ?: JSONObject.NULL)
    }

    private fun trialsJson(trials: List<Trial>): JSONArray = JSONArray().apply {
        trials.forEach { put(it.json()) }
    }

    private fun resultJson(result: SuperuserControl.Result): JSONObject = JSONObject()
        .put("ok", result.ok)
        .put("rev", result.rev)
        .put("code", result.code ?: JSONObject.NULL)
        .put("pendingApply", result.pendingApply)
        .put("detail", result.detail)

    private fun snapshotAtGrantPending(snapshot: AuthorizationSnapshot?): Boolean =
        runCatching { snapshot?.pendingApply() ?: false }.getOrDefault(false)

    /** The Manager-side store this build's Ultra entry consults, verbatim. */
    private fun grantStorePath(): String =
        "/data/adb/maplesu/authorization/$managerUid/superuser-journal.json"

    private fun describe(thrown: Throwable): String =
        thrown.javaClass.simpleName + ": " + (thrown.message ?: "")

    private companion object {
        const val EVIDENCE_DIRECTORY = "jailbreak-evidence"
        const val EVIDENCE_FILE = "ultra-thirdparty-su.json"
        const val FIXTURE_DESCRIPTOR = "dev.maplesu.manager.identityProbe"

        /** `id -u`: the only number that separates "uid 0" from "a shell that started". */
        const val SU_COMMAND = "/system/bin/id -u"

        /** What a client sees when nothing was published for this boot. */
        const val ENTRY_ABSENT = "SU_EXECUTOR_NOT_PUBLISHED"

        /** What a scenario records when the foreign-UID caller never existed. */
        const val FIXTURE_UNAVAILABLE = "FIXTURE_NOT_BOUND"

        const val FAILURE_PREFIX = "ULTRA_THIRD_PARTY_SU_NOT_WIRED:"

        /** The endpoint is published inside prepareHook; retry only across that hand-off. */
        const val ENTRY_RESOLVE_ATTEMPTS = 5
        const val ENTRY_RESOLVE_DELAY_MILLIS = 200L

        /** The one-attempt rule this test implements, written into every record. */
        const val ONE_ATTEMPT_POLICY =
            "one kernel attempt per boot: this class creates it at most once " +
                "(NativeSuDaemon.prepareHook, wait for DAEMON_READY), then only resolves " +
                "the published endpoint (NativeSuDiscovery.peek) and drives the fixture. " +
                "It never calls management/prepare a second time. An attempt already " +
                "recorded for this boot is reused when live; a live-but-not-ready or " +
                "guard-marked terminal one is reported as attempt_not_ready (reboot " +
                "required); a terminal failure with no guard marker (failed before the " +
                "kernel work) is retried once. A spent window is an orchestration fact, " +
                "not 'product not wired'."

        const val REBOOT_INSTRUCTION =
            "REBOOT REQUIRED: this boot's only kernel attempt is already spent or its " +
                "published endpoint belonged to a dead process. Hard-reboot the device, " +
                "then run ONLY this class on the fresh boot: " +
                "am instrument -w -e class " +
                "dev.maplesu.manager.jailbreak.UltraThirdPartySuAndroidTest " +
                "dev.maplesu.manager.test/androidx.test.runner.AndroidJUnitRunner. " +
                "Do not run L3SuGateAndroidTest (or any other attempt test) in that boot."

        /** The store the Ultra entry's authorization rule is written against. */
        const val LIST_SOURCE =
            "dev.maplesu.manager.runtime.authorization.RootAuthorizationStore " +
                "(authorizations.bin + superuser-journal.json under " +
                "/data/adb/maplesu/authorization/<managerUid>/, root 0600; decided by " +
                "ManagerSuperuserPolicy and served by SuperuserControl.grant/revoke)"

        /** Normal (KSU) mirrors the same decision into the kernel allowlist. */
        const val KSU_LIST_SOURCE =
            "KSU kernel allowlist /data/adb/ksu/.allowlist, written only by the " +
                "KSU_ALLOWLIST mirror of the same transaction (applied watermark)"

        const val KSU_MIRROR_BACKEND = "KSU_ALLOWLIST"

        /**
         * What has to change for Ultra to serve a third party at all. Kept next to the
         * failure token so the record names the file and line, not just the symptom.
         */
        val MINIMAL_FIX = listOf(
            "manager/.../NativeSuDirectoryProvider.kt (publishHookSu) - the hook branch " +
                "publishes the restricted endpoint and the broker only after " +
                "claimHookDaemonReady returns ok, on both the first prepare and the resume " +
                "path.",
            "manager/.../HookSuEndpoint.kt (start) - authorization is " +
                "ManagerSuperuserPolicy.decide over the Manager's store; the gate is " +
                "SuGate.read for this attempt/boot; the child is forked blocked and released " +
                "only after a second decision (AUTH_REVOKED otherwise).",
            "manager/.../authorization/SuperuserControl.kt - the store is reached through " +
                "a one-shot root SuperuserTool behind the L3 gate; a missing transport is " +
                "SU_TRANSPORT_UNAVAILABLE, never a locally fabricated grant.",
            "manager/.../authorization/SuperuserTransaction.kt - grant/revoke write " +
                "superuser-journal.json before authorizations.bin, mirror after the " +
                "decision, and record the applied watermark.",
        )

        val REBOOT_REMEDIATION = JSONArray().apply {
            put("Do not treat this run as a product verdict: the attempt was never " +
                "created (or its process was already dead).")
            put("Hard-reboot the device so /dev/df and the kernel-window marker are gone.")
            put("On the fresh boot run only UltraThirdPartySuAndroidTest first; it must " +
                "own the single prepareHook of that boot.")
            put("Do not run L3SuGateAndroidTest (or any other attempt test) before it in " +
                "the same boot; each of them spends the same one-shot window.")
        }

        fun minimalFix(): JSONArray = JSONArray().apply { MINIMAL_FIX.forEach { put(it) } }

        /**
         * What to do when the foreign-UID caller could not be created. The product was
         * never asked (no `prepareHook` was made in that run), so the record says so.
         */
        fun fixtureRemediation(): JSONArray = JSONArray().apply {
            put("No product verdict: fixture.bound=false, so A/B/C were never asked and " +
                "this boot's one-shot kernel window was NOT spent (prepareHookCalls=0).")
            put("Read fixture{bound, error, servicePackage, uid, elapsedMillis, diagnostics}: " +
                "diagnostics.package carries exported/enabled/process/uid/signature/" +
                "testOnly/stopped/QUERY_ALL_PACKAGES, diagnostics.attempts carries every " +
                "bind result and ServiceConnection callback, and diagnostics.shell.amsLog " +
                "carries the AMS sentence ('not found', 'Permission Denial', 'not " +
                "exported') plus pidof/ps/dumpsys package of the fixture process.")
            put("Reproduce the bind outside the harness: " +
                "`am startservice -n dev.maplesu.manager.test/" +
                "dev.maplesu.manager.runtime.IdentityProbeService` must succeed, and " +
                "`dumpsys package dev.maplesu.manager.test` must show the service " +
                "exported=true (a test-only install is the first thing to rule out).")
            put("Only after fixture.bound=true is it meaningful to read A/B/C: " +
                "A must be refused, B must be uid 0 through the Manager transaction, C " +
                "must be refused again - each with trials[i].uid and trials[i].domain.")
        }

        /**
         * What to do when the attempt process was reclaimed by the system. The point is
         * that nothing about the product changed: the process died while it was a cached
         * candidate, so the keep-alive and the reboot are the actionable items.
         */
        fun killRemediation(reboot: Boolean): JSONArray = JSONArray().apply {
            put("The attempt process was reclaimed by the system (am_kill ... " +
                "Cached(nirvana)), not crashed: logcat -b crash is empty and there is no " +
                "FATAL EXCEPTION for this package.")
            put("This run already applied the doze allowlist and ran with the App in the " +
                "foreground; check deviceIdle.whitelistAdd.ok and foreground.ok above. A " +
                "false foreground.ok means the keep-alive itself did not take effect.")
            put("Keep the App visible for the whole handover " +
                "(prepareHook -> DAEMON_READY -> A/B/C); do not lock the screen or switch " +
                "apps during it.")
            if (reboot) {
                put("Hard-reboot before the next attempt: the claim written by the killed " +
                    "process is dead and this boot's kernel window may already be spent.")
            }
        }

        fun attemptNotReady(token: String?): String =
            FAILURE_PREFIX + "attempt_not_ready:" +
                (token?.takeIf { it.isNotBlank() } ?: "unknown")

        fun rebootToken(token: String?): Boolean {
            if (token == null) return false
            return token.contains("DIRTYFRAG_GUARD_PRESENT_REBOOT_REQUIRED") ||
                token.contains("DIRTYFRAG_REBOOT_REQUIRED_AFTER_ATTEMPT") ||
                token.contains("JAILBREAK_OWNER_EXITED") ||
                token.contains("EXISTING_ATTEMPT")
        }
    }
}
