package dev.maplesu.manager.runtime

import android.content.Context
import dev.maplesu.manager.jailbreak.CarrierProof
import dev.maplesu.manager.jailbreak.DirtyfragAttempt
import dev.maplesu.manager.jailbreak.HookEvidence
import dev.maplesu.manager.jailbreak.JailbreakStatus
import dev.maplesu.manager.jailbreak.ProbeResult
import java.io.File
import java.security.MessageDigest

/**
 * §6.2 / §7 T6–T7: the carrier proves itself, the App only records what it observed.
 *
 * <p>Two independent proofs share one shape ([CarrierProof]):
 *  - `l3-gate`  : the L3 helper's root-owned record is ARMED for this attempt and boot,
 *                 the hook evidence says OK, and a real child behind that gate printed
 *                 `0` for `id -u`;
 *  - `ksu-lkm`  : `kernelsu` is in `/proc/modules`, the packaged `ksud` answers and a
 *                 real child through it printed `0` for `id -u`.
 *
 * <p>Every refusal names the missing fact; no refusal is turned into a success and no
 * fact is invented. The decision functions are pure so the whole refusal table is
 * host-testable; only [proveUltra] / [proveNormal] touch the device.
 */
object CarrierProver {
    const val KIND_L3 = "l3-gate"
    const val KIND_KSU = "ksu-lkm"

    /** One command executed through a root transport (caller supplies the transport). */
    data class CommandResult(val code: Int, val out: String, val err: String = "")

    sealed interface Result {
        data class Proven(val proof: CarrierProof) : Result
        data class Rejected(val reason: String) : Result
    }

    /** Everything [decideUltra] may look at; all of it is observed, never defaulted. */
    data class UltraFacts(
        val gateArmed: Boolean,
        val gateAttempt: String?,
        val gateBootId: String?,
        val tokenHex: String?,
        val recordOwnerUid: Int?,
        val evidenceRefusal: String?,
        val evidenceVerdict: String?,
        val probe: ProbeResult?,
        val deviceKmi: String? = null,
        val artifactKmi: String? = null,
    )

    /** Everything [decideNormal] may look at. */
    data class NormalFacts(
        val kernelsuInProcModules: Boolean,
        val ksudPath: String?,
        val ksudExecutable: Boolean,
        val ksudVersion: String?,
        val probe: ProbeResult?,
    )

    /**
     * §5 C6: the proof is the conjunction of the four facts. Each refusal branch is a
     * distinct reason so an evidence bundle can say which one failed.
     */
    internal fun decideUltra(
        attemptId: String?,
        bootId: String?,
        nowMillis: Long,
        pid: Int,
        facts: UltraFacts,
    ): Result {
        if (attemptId.isNullOrBlank() || bootId.isNullOrBlank()) return Result.Rejected("attempt_or_boot_missing")
        if (!facts.gateArmed) return Result.Rejected("gate_not_armed")
        if (facts.gateAttempt != attemptId) return Result.Rejected("gate_foreign_attempt")
        if (facts.gateBootId != bootId) return Result.Rejected("gate_foreign_boot")
        if (facts.recordOwnerUid != 0) return Result.Rejected("record_not_root_owned")
        if (facts.evidenceRefusal != null) return Result.Rejected("hook_evidence:" + facts.evidenceRefusal)
        if (facts.evidenceVerdict != HookEvidence.VERDICT_OK) {
            return Result.Rejected("hook_verdict:" + (facts.evidenceVerdict ?: "missing"))
        }
        val probe = facts.probe ?: return Result.Rejected("probe_missing")
        if (probe.exitCode != 0) return Result.Rejected("probe_exit:" + probe.exitCode)
        if (probe.stdout.trim() != "0") return Result.Rejected("probe_stdout:" + probe.stdout.trim())
        if (probe.uid != 0) return Result.Rejected("probe_uid:" + probe.uid)
        val token = facts.tokenHex
        return Result.Proven(CarrierProof(
            kind = KIND_L3,
            attemptId = attemptId,
            bootId = bootId,
            provenAtMillis = nowMillis,
            provenByPid = pid,
            facts = linkedMapOf(
                "gate" to SuGate.ARMED,
                "recordOwnerUid" to "0",
                "tokenSha256" to sha256Hex(token ?: ""),
                "gateReason" to SuGate.ARMED,
                "deviceKmi" to (facts.deviceKmi ?: "unknown"),
                "artifactKmi" to (facts.artifactKmi ?: "unknown"),
            ),
            probe = probe,
        ))
    }

    internal fun decideNormal(
        attemptId: String?,
        bootId: String?,
        nowMillis: Long,
        pid: Int,
        facts: NormalFacts,
    ): Result {
        if (attemptId.isNullOrBlank() || bootId.isNullOrBlank()) return Result.Rejected("attempt_or_boot_missing")
        if (!facts.kernelsuInProcModules) return Result.Rejected("kernelsu_not_loaded")
        if (facts.ksudPath.isNullOrBlank()) return Result.Rejected("ksud_path_missing")
        if (!facts.ksudExecutable) return Result.Rejected("ksud_not_executable")
        if (facts.ksudVersion.isNullOrBlank()) return Result.Rejected("ksud_version_unavailable")
        val probe = facts.probe ?: return Result.Rejected("probe_missing")
        if (probe.exitCode != 0) return Result.Rejected("probe_exit:" + probe.exitCode)
        if (probe.stdout.trim() != "0") return Result.Rejected("probe_stdout:" + probe.stdout.trim())
        if (probe.uid != 0) return Result.Rejected("probe_uid:" + probe.uid)
        return Result.Proven(CarrierProof(
            kind = KIND_KSU,
            attemptId = attemptId,
            bootId = bootId,
            provenAtMillis = nowMillis,
            provenByPid = pid,
            facts = linkedMapOf(
                "module" to "kernelsu",
                "procModules" to "true",
                "ksud" to facts.ksudPath,
                "ksudVersion" to facts.ksudVersion,
                "lateLoad" to "OK",
            ),
            probe = probe,
        ))
    }

    /**
     * §7 T6: read the real records and run one real child behind the gate. The probe
     * is `sh -c id -u`; its stdout is the only source of the uid in the proof.
     */
    fun proveUltra(context: Context, status: JailbreakStatus): Result {
        val attempt = status.attemptId
        val boot = status.bootId
        if (attempt.isNullOrBlank() || boot.isNullOrBlank()) return Result.Rejected("attempt_or_boot_missing")
        val gate = SuGate.read(context, attempt, boot)
        val directory = DirtyfragAttempt.hookEvidence(context)
        val record = File(directory, SuGate.DAEMON_FILE)
        val owner = runCatching { android.system.Os.stat(record.path).st_uid }.getOrNull()
        val merged = HookEvidence.read(directory)
        val refusal = when {
            merged == null -> "MAPLESU_HOOK_EVIDENCE_MISSING"
            else -> HookEvidence.refusalToken(merged)
                ?: HookEvidence.bindingRefusal(merged, boot, attempt)
        }
        val probe = runCatching {
            val result = NativeSu.executeScript(
                gate, "/system/bin/sh -c 'id -u'",
                File(context.filesDir, NativeSu.FALLBACK_NAME))
            val uid = result.out.trim().toIntOrNull() ?: -1
            ProbeResult("/system/bin/sh -c 'id -u'", result.code, result.out.trim(), uid)
        }.getOrNull()
        return decideUltra(attempt, boot, System.currentTimeMillis(), android.os.Process.myPid(),
            UltraFacts(
                gateArmed = gate.armed,
                gateAttempt = gate.attempt,
                gateBootId = gate.bootId,
                tokenHex = gate.suToken?.hex,
                recordOwnerUid = owner,
                evidenceRefusal = refusal,
                evidenceVerdict = merged?.verdict,
                probe = probe,
            ))
    }

    /**
     * §7 T7: `kernelsu` in `/proc/modules` + the packaged `ksud` answering + a real
     * child through it printing `0`. The caller supplies the root transport because
     * this module must not grow a second one (§5 C11).
     */
    fun proveNormal(
        context: Context,
        status: JailbreakStatus,
        exec: (String) -> CommandResult?,
    ): Result {
        val attempt = status.attemptId
        val boot = status.bootId
        if (attempt.isNullOrBlank() || boot.isNullOrBlank()) return Result.Rejected("attempt_or_boot_missing")
        val modules = runCatching { File("/proc/modules").readText() }.getOrDefault("")
        val loaded = modules.lineSequence().any { it.startsWith("kernelsu ") }
        val ksud = "/data/adb/ksud"
        val executable = exec("test -x $ksud && echo ok")?.out?.contains("ok") == true
        val version = exec("$ksud -V")?.out?.trim()
        val probe = exec("id -u")?.let { result ->
            val uid = result.out.trim().toIntOrNull() ?: -1
            ProbeResult("/system/bin/sh -c 'id -u'", result.code, result.out.trim(), uid)
        }
        return decideNormal(attempt, boot, System.currentTimeMillis(), android.os.Process.myPid(),
            NormalFacts(loaded, ksud, executable, version, probe))
    }

    /** §5 C12: the token never travels in clear; the proof carries its hash. */
    internal fun sha256Hex(value: String): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(value.toByteArray(Charsets.UTF_8))
        return digest.joinToString("") { "%02x".format(it) }
    }
}
