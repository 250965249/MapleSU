package dev.maplesu.manager.jailbreak

import android.content.Context
import org.json.JSONObject
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.StandardCopyOption

/**
 * Attempt status shared between the `:root_directory` process (where the provider
 * runs and the Root executor is launched) and the UI process.
 *
 * v2 (T1): `read` is a pure function. It never downgrades `stage`, never synthesises
 * a `failure` and never writes. Facts about *this* process (boot changed, owner
 * alive, carrier live) are reported in [derived] and are for presentation only.
 */
data class JailbreakStatus(
    val method: String,
    val stage: String,
    val message: String,
    val startedAtMillis: Long,
    val updatedAtMillis: Long,
    val bootId: String?,
    val attemptId: String? = null,
    val ownerPid: Int? = null,
    val workerPid: Int? = null,
    val workerDomain: String? = null,
    val enforcingAtLease: Int? = null,
    val restoreState: String? = null,
    val restoreOrigin: String? = null,
    val restoreEnforcing: Int? = null,
    val restoreCheckreqprot: Int? = null,
    val restorePolicy: Int? = null,
    val restoreUnloadErrno: Int? = null,
    val restoreFailures: Int? = null,
    val target: String? = null,
    /**
     * Requested or selected backend: "ir" for our own in-kernel installer, "hook"
     * for the module-dispatched UMH handover, "ksu" for KernelSU. An explicit request
     * is recorded from IDLE so admission failures remain bound to that request.
     * This field identifies the route; readiness still requires stage and carrier proof.
     */
    val rootBackend: String? = null,
    /**
     * L3 su gate as the UMH helper's own record stated it for this attempt:
     * "ARMED" or "UNAVAILABLE" (never a third value), plus the 16-hex token when it
     * is armed. It is written at the same moment as [STAGE_DAEMON_READY] and is
     * observability only: the su path re-reads the helper's record through
     * `SuGate.read`, so a stale status can never arm a gate.
     */
    val suGate: String? = null,
    val suToken: String? = null,
    val failure: String? = null,
    /** 2 for records written by this build; 1 for a legacy record with no schema field. */
    val schema: Int = 2,
    /** Monotonic write counter; every accepted write increments it. */
    val revision: Long = 0L,
    /** Carrier proof (T1 type; filled by the prover from T6 on). */
    val carrier: CarrierProof? = null,
) {
    /**
     * Facts observed *now* by whoever read the record. Not persisted: a derived view
     * must never become a stored fact (C2).
     */
    var derived: Derived? = null
        private set

    internal fun withDerived(value: Derived): JailbreakStatus = apply { derived = value }

    fun isTerminal(): Boolean = stage in TERMINAL

    /** History survives reboot; only an explicitly matching boot can own a live session. */
    fun isCurrentBoot(currentBootId: String?): Boolean =
        !bootId.isNullOrBlank() && !currentBootId.isNullOrBlank() &&
            bootId == currentBootId && derived?.bootChanged != true

    fun claimsCurrentBoot(currentBootId: String?): Boolean =
        stage in LIVE_CLAIM && failure == null && isCurrentBoot(currentBootId)

    /** Rejects a transition that would move the attempt backwards. */
    fun advance(next: JailbreakStatus): JailbreakStatus {
        // The provider may still finish its cleanup after Cancel. Its late progress
        // describes that cleanup, not a new user request or a successful attempt.
        if (stage == STAGE_CANCELLED) return this
        val current = ORDER.indexOf(stage)
        val wanted = ORDER.indexOf(next.stage)
        require(isTerminal() || wanted >= current ||
            next.stage == STAGE_FAILED || next.stage == STAGE_CANCELLED) {
            "JAILBREAK_STAGE_REGRESSION:$stage->${next.stage}"
        }
        // S06: a later stage used to be published from a sparse record, dropping
        // restoration evidence. Keep everything already observed.
        return next.copy(
            startedAtMillis = if (next.startedAtMillis != 0L) next.startedAtMillis else startedAtMillis,
            bootId = next.bootId ?: bootId,
            attemptId = next.attemptId ?: attemptId,
            ownerPid = next.ownerPid ?: ownerPid,
            workerPid = next.workerPid ?: workerPid,
            workerDomain = next.workerDomain ?: workerDomain,
            enforcingAtLease = next.enforcingAtLease ?: enforcingAtLease,
            restoreState = next.restoreState ?: restoreState,
            restoreOrigin = next.restoreOrigin ?: restoreOrigin,
            restoreEnforcing = next.restoreEnforcing ?: restoreEnforcing,
            restoreCheckreqprot = next.restoreCheckreqprot ?: restoreCheckreqprot,
            restorePolicy = next.restorePolicy ?: restorePolicy,
            restoreUnloadErrno = next.restoreUnloadErrno ?: restoreUnloadErrno,
            restoreFailures = next.restoreFailures ?: restoreFailures,
            target = next.target ?: target,
            rootBackend = next.rootBackend ?: rootBackend,
            suGate = next.suGate ?: suGate,
            suToken = next.suToken ?: suToken,
            failure = next.failure ?: failure,
            schema = next.schema,
            revision = next.revision,
            carrier = next.carrier ?: carrier,
        )
    }

    /** Writes the record atomically; a failure is returned, never thrown (T1.3). */
    fun write(context: Context): Result<Unit> {
        // Capture late helper output before the next attempt clears fixed-path files.
        runCatching {
            val previous = parse(file(context))
            if (previous?.attemptId != null && previous.attemptId != attemptId) {
                JailbreakDiagnostics.record(context.createDeviceProtectedStorageContext().dataDir,
                    context.filesDir, previous, file(context).readText())
            }
        }
        return writeFile(file(context), this).onSuccess {
            runCatching {
                JailbreakDiagnostics.record(context.createDeviceProtectedStorageContext().dataDir,
                    context.filesDir, this, file(context).readText())
            }.onFailure { android.util.Log.w("JailbreakDiagnostics", "Attempt snapshot failed", it) }
        }
    }

    companion object {
        const val DIRECTION = "jailbreak"
        const val STAGE_IDLE = "IDLE"
        const val STAGE_TARGET_CHECKED = "TARGET_CHECKED"
        const val STAGE_PROVIDER_RUNNING = "PROVIDER_RUNNING"
        const val STAGE_HANDOFF_AUTHENTICATED = "HANDOFF_AUTHENTICATED"
        const val STAGE_ROOT_WORKER_OBSERVED = "ROOT_WORKER_OBSERVED"
        /** §6.1: carrier evidence written, independent probe not yet passed. */
        const val STAGE_CARRIER_PROVEN = "CARRIER_PROVEN"
        const val STAGE_DAEMON_READY = "DAEMON_READY"
        const val STAGE_FAILED = "FAILED"
        /** Legacy v1 stage: only produced when reading a record written by an old build. */
        const val STAGE_EXPIRED = "EXPIRED"
        const val STAGE_CANCELLED = "CANCELLED"
        /** §6.1/C4: boot changed or carrier gone; the old attempt is unusable. */
        const val STAGE_SUPERSEDED = "SUPERSEDED"
        val ORDER = listOf(STAGE_IDLE, STAGE_TARGET_CHECKED, STAGE_PROVIDER_RUNNING,
            STAGE_HANDOFF_AUTHENTICATED, STAGE_ROOT_WORKER_OBSERVED, STAGE_CARRIER_PROVEN,
            STAGE_DAEMON_READY)
        val TERMINAL = setOf(STAGE_DAEMON_READY, STAGE_FAILED, STAGE_EXPIRED, STAGE_CANCELLED,
            STAGE_SUPERSEDED)
        /** Stages that claim something is currently usable. */
        val LIVE_CLAIM = setOf(STAGE_ROOT_WORKER_OBSERVED, STAGE_CARRIER_PROVEN, STAGE_DAEMON_READY)
        /** Stages reachable before carrier evidence exists (C4: FAILED only from these). */
        private val PRE_CARRIER = setOf(STAGE_IDLE, STAGE_TARGET_CHECKED, STAGE_PROVIDER_RUNNING,
            STAGE_HANDOFF_AUTHENTICATED, STAGE_ROOT_WORKER_OBSERVED)

        private fun file(context: Context): File =
            File(File(context.filesDir, DIRECTION), "status.json")

        /**
         * Reads the persisted attempt. The stage is returned exactly as persisted;
         * boot/owner/carrier facts land in [derived] (T1/C2).
         */
        fun read(context: Context): JailbreakStatus? =
            readFile(file(context), DirtyfragAttempt.readBootId(), { pid -> ownerAliveByProc(pid) })

        /**
         * Pure, context-free read used by the host tests: the caller supplies the current
         * boot id, the owner-liveness probe and the carrier probe, so nothing here touches
         * another process, the clock or the disk.
         */
        internal fun readFile(
            file: File,
            currentBootId: String?,
            ownerAlive: (Int) -> Boolean = { pid -> ownerAliveByProc(pid) },
            carrierLive: (JailbreakStatus) -> Boolean? = { null },
        ): JailbreakStatus? {
            val record = parse(file) ?: return null
            // C2: the stage is returned exactly as persisted. Boot, owner and carrier
            // observations are derived facts for presentation only; none of them is
            // allowed to rewrite the record or synthesise a failure.
            val bootChanged = record.bootId != null && currentBootId != null &&
                record.bootId != currentBootId
            val owner = if (record.stage in LIVE_CLAIM) record.ownerPid?.let(ownerAlive) else null
            val carrier = runCatching { carrierLive(record) }.getOrNull()
            return record.withDerived(Derived(bootChanged = bootChanged, ownerAlive = owner,
                carrierLive = carrier))
        }

        /**
         * C1/T1.2: the only accepted writer is the attempt's provider. `apply` validates
         * monotonicity and the revision and returns the record to persist; it never writes.
         */
        internal fun apply(current: JailbreakStatus?, next: JailbreakStatus, writer: Writer,
                           expectedRevision: Long? = null): ApplyResult {
            // C1: only the attempt's provider is an accepted writer.
            if (writer != Writer.PROVIDER) {
                return ApplyResult.Rejected("JAILBREAK_WRITER_NOT_PROVIDER:$writer")
            }
            if (current == null) {
                if (next.stage != STAGE_IDLE) {
                    return ApplyResult.Rejected("JAILBREAK_STATUS_NO_CURRENT:${next.stage}")
                }
                return ApplyResult.Applied(next.copy(schema = 2, revision = 0L))
            }
            if (expectedRevision != null && expectedRevision != current.revision) {
                return ApplyResult.Rejected(
                    "JAILBREAK_STATUS_STALE_REVISION:expected=$expectedRevision,current=${current.revision}")
            }
            if (next.attemptId != null && current.attemptId != null &&
                next.attemptId != current.attemptId) {
                return ApplyResult.Rejected("JAILBREAK_ATTEMPT_MISMATCH")
            }
            if (current.stage in setOf(STAGE_SUPERSEDED, STAGE_FAILED, STAGE_CANCELLED)) {
                return ApplyResult.Rejected("JAILBREAK_STATUS_TERMINAL:${current.stage}")
            }
            val carrier = next.carrier ?: current.carrier
            when (next.stage) {
                // C3/C4: FAILED is only admissible before carrier evidence, and only
                // while nothing has proven the carrier is alive.
                STAGE_FAILED -> {
                    if (current.stage !in PRE_CARRIER) {
                        return ApplyResult.Rejected("JAILBREAK_FAILED_AFTER_CARRIER:${current.stage}")
                    }
                    if (carrier != null) {
                        return ApplyResult.Rejected("JAILBREAK_FAILED_WITH_CARRIER")
                    }
                }
                STAGE_SUPERSEDED, STAGE_CANCELLED -> Unit
                STAGE_CARRIER_PROVEN -> {
                    if (current.stage != STAGE_ROOT_WORKER_OBSERVED) {
                        return ApplyResult.Rejected(
                            "JAILBREAK_CARRIER_PROVEN_FROM:${current.stage}")
                    }
                    if (carrier == null) {
                        return ApplyResult.Rejected("JAILBREAK_CARRIER_PROOF_MISSING")
                    }
                }
                // §6.1: READY follows CARRIER_PROVEN. The ROOT_WORKER_OBSERVED edge is
                // the pre-T6 product path and is removed once T6 wires the prover.
                STAGE_DAEMON_READY -> {
                    if (current.stage != STAGE_CARRIER_PROVEN &&
                        current.stage != STAGE_ROOT_WORKER_OBSERVED) {
                        return ApplyResult.Rejected("JAILBREAK_READY_FROM:${current.stage}")
                    }
                }
                else -> {
                    val currentIndex = ORDER.indexOf(current.stage)
                    val targetIndex = ORDER.indexOf(next.stage)
                    if (targetIndex < 0) {
                        return ApplyResult.Rejected("JAILBREAK_STAGE_UNKNOWN:${next.stage}")
                    }
                    if (targetIndex < currentIndex) {
                        return ApplyResult.Rejected(
                            "JAILBREAK_STAGE_REGRESSION:${current.stage}->${next.stage}")
                    }
                }
            }
            return ApplyResult.Applied(next.copy(
                schema = 2,
                // The revision belongs to the store, not to the caller: a record that
                // says otherwise was copied from a stale read.
                revision = current.revision + 1,
                bootId = next.bootId ?: current.bootId,
                attemptId = next.attemptId ?: current.attemptId,
                startedAtMillis = if (next.startedAtMillis != 0L) next.startedAtMillis
                                  else current.startedAtMillis,
                carrier = carrier,
            ))
        }

        /** Atomic write with fsync; returns the failure instead of throwing it (T1.3). */
        internal fun writeFile(file: File, status: JailbreakStatus): Result<Unit> = runCatching {
            val json = status.toJson()
            file.parentFile?.mkdirs()
            val staging = File(file.parentFile, file.name + ".new")
            FileOutputStream(staging).use { stream ->
                stream.write(json.toString().toByteArray(Charsets.UTF_8))
                stream.fd.sync()
            }
            try {
                Files.move(staging.toPath(), file.toPath(),
                    StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
            } catch (_: AtomicMoveNotSupportedException) {
                Files.move(staging.toPath(), file.toPath(), StandardCopyOption.REPLACE_EXISTING)
            }
        }

        private fun JailbreakStatus.toJson(): JSONObject = JSONObject().apply {
            put("schema", schema)
            put("revision", revision)
            put("method", method); put("stage", stage); put("message", message)
            put("startedAtMillis", startedAtMillis); put("updatedAtMillis", updatedAtMillis)
            put("bootId", bootId ?: JSONObject.NULL)
            put("attemptId", attemptId ?: JSONObject.NULL)
            put("ownerPid", ownerPid ?: JSONObject.NULL)
            put("workerPid", workerPid ?: JSONObject.NULL)
            put("workerDomain", workerDomain ?: JSONObject.NULL)
            put("enforcingAtLease", enforcingAtLease ?: JSONObject.NULL)
            put("restoreState", restoreState ?: JSONObject.NULL)
            put("restoreOrigin", restoreOrigin ?: JSONObject.NULL)
            put("restoreEnforcing", restoreEnforcing ?: JSONObject.NULL)
            put("restoreCheckreqprot", restoreCheckreqprot ?: JSONObject.NULL)
            put("restorePolicy", restorePolicy ?: JSONObject.NULL)
            put("restoreUnloadErrno", restoreUnloadErrno ?: JSONObject.NULL)
            put("restoreFailures", restoreFailures ?: JSONObject.NULL)
            put("target", target ?: JSONObject.NULL)
            put("rootBackend", rootBackend ?: JSONObject.NULL)
            put("suGate", suGate ?: JSONObject.NULL)
            put("suToken", suToken ?: JSONObject.NULL)
            put("failure", failure ?: JSONObject.NULL)
            put("carrier", carrier?.toJson() ?: JSONObject.NULL)
        }

        private fun parse(file: File): JailbreakStatus? = try {
            val json = JSONObject(file.readText())
            JailbreakStatus(
                method = json.getString("method"),
                stage = json.getString("stage"),
                message = json.optString("message"),
                startedAtMillis = json.optLong("startedAtMillis"),
                updatedAtMillis = json.optLong("updatedAtMillis"),
                bootId = json.optString("bootId").takeIf { it.isNotEmpty() && it != "null" },
                attemptId = json.optString("attemptId").takeIf { it.isNotEmpty() && it != "null" },
                ownerPid = json.optInt("ownerPid", -1).takeIf { it > 1 },
                workerPid = json.optInt("workerPid", -1).takeIf { it > 1 },
                workerDomain = json.optString("workerDomain").takeIf { it.isNotEmpty() && it != "null" },
                enforcingAtLease = json.optInt("enforcingAtLease", -1).takeIf { it >= 0 },
                restoreState = json.optString("restoreState").takeIf { it.isNotEmpty() && it != "null" },
                restoreOrigin = json.optString("restoreOrigin").takeIf { it.isNotEmpty() && it != "null" },
                restoreEnforcing = json.optInt("restoreEnforcing", -1).takeIf { it >= 0 },
                restoreCheckreqprot = json.optInt("restoreCheckreqprot", -1).takeIf { it >= 0 },
                restorePolicy = json.optInt("restorePolicy", -1).takeIf { it >= 0 },
                restoreUnloadErrno = json.optInt("restoreUnloadErrno", Int.MIN_VALUE)
                    .takeIf { it != Int.MIN_VALUE },
                restoreFailures = json.optInt("restoreFailures", Int.MIN_VALUE)
                    .takeIf { it != Int.MIN_VALUE },
                target = json.optString("target").takeIf { it.isNotEmpty() && it != "null" },
                rootBackend = json.optString("rootBackend").takeIf { it.isNotEmpty() && it != "null" },
                suGate = json.optString("suGate").takeIf { it.isNotEmpty() && it != "null" },
                suToken = json.optString("suToken").takeIf { it.isNotEmpty() && it != "null" },
                failure = json.optString("failure").takeIf { it.isNotEmpty() && it != "null" }
                    ?.let(::jailbreakErrorCode),
                schema = json.optInt("schema", 1),
                revision = json.optLong("revision", 0L),
                carrier = json.optJSONObject("carrier")?.let { CarrierProof.fromJson(it) },
            )
        } catch (_: IOException) {
            null
        } catch (_: org.json.JSONException) {
            null
        }

        /** A process of this package is still there; a reused pid of another app is not. */
        private fun ownerAliveByProc(pid: Int): Boolean = runCatching {
            val command = File("/proc/$pid/cmdline").readBytes().toString(Charsets.UTF_8)
            command.contains("dev.maplesu.manager")
        }.getOrDefault(false)

        fun clear(context: Context) {
            runCatching {
                val previous = parse(file(context))
                if (previous != null) JailbreakDiagnostics.record(
                    context.createDeviceProtectedStorageContext().dataDir,
                    context.filesDir, previous, file(context).readText())
            }.onFailure { android.util.Log.w("JailbreakDiagnostics", "Previous attempt snapshot failed", it) }
            file(context).delete()
        }
    }
}

/** Facts that were true when the record was read; never persisted (C2). */
data class Derived(
    val bootChanged: Boolean = false,
    val ownerAlive: Boolean? = null,
    val carrierLive: Boolean? = null,
)

/** One real child-process probe: argv, exit code, stdout and the uid it ran as. */
data class ProbeResult(
    val argv: String,
    val exitCode: Int,
    val stdout: String,
    val uid: Int,
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("argv", argv); put("exit", exitCode); put("stdout", stdout); put("uid", uid)
    }

    companion object {
        fun fromJson(json: JSONObject): ProbeResult = ProbeResult(
            argv = json.optString("argv"),
            exitCode = json.optInt("exit", -1),
            stdout = json.optString("stdout"),
            uid = json.optInt("uid", -1),
        )
    }
}

/** §6.2: the carrier itself proved it is live for this attempt and boot. */
data class CarrierProof(
    val kind: String,
    val attemptId: String,
    val bootId: String,
    val provenAtMillis: Long,
    val provenByPid: Int? = null,
    val facts: Map<String, String> = emptyMap(),
    val probe: ProbeResult? = null,
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("kind", kind); put("attemptId", attemptId); put("bootId", bootId)
        put("provenAtMillis", provenAtMillis)
        put("provenByPid", provenByPid ?: JSONObject.NULL)
        put("facts", JSONObject(facts))
        put("probe", probe?.toJson() ?: JSONObject.NULL)
    }

    companion object {
        fun fromJson(json: JSONObject): CarrierProof {
            val factsJson = json.optJSONObject("facts")
            val facts = linkedMapOf<String, String>()
            factsJson?.keys()?.forEach { key -> facts[key] = factsJson.optString(key) }
            return CarrierProof(
                kind = json.optString("kind"),
                attemptId = json.optString("attemptId"),
                bootId = json.optString("bootId"),
                provenAtMillis = json.optLong("provenAtMillis"),
                provenByPid = json.optInt("provenByPid", -1).takeIf { it > 1 },
                facts = facts,
                probe = json.optJSONObject("probe")?.let { ProbeResult.fromJson(it) },
            )
        }
    }
}

/** C1: only the attempt's provider may write `status.json`. */
enum class Writer { PROVIDER, UI, ROOT }

sealed interface ApplyResult {
    data class Applied(val status: JailbreakStatus) : ApplyResult
    data class Rejected(val reason: String) : ApplyResult
}
