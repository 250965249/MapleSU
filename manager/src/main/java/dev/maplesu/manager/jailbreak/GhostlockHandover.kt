package dev.maplesu.manager.jailbreak

import android.content.Context
import dev.maplesu.manager.runtime.hookPrepareBudgetMillis
import org.json.JSONObject
import java.io.File
import java.io.IOException
import java.security.MessageDigest
import java.util.concurrent.TimeUnit

/** Inputs and receipt for the existing bootstrap's Ghostlock handover mode. */
internal object GhostlockHandover {
    fun target(backend: String?): String? = when (backend) {
        JailbreakRequest.BACKEND_HOOK -> "ultra"
        JailbreakRequest.BACKEND_KSU -> "normal"
        null -> null
        else -> throw IOException("GHOSTLOCK_BACKEND_UNSUPPORTED:$backend")
    }

    fun stage(context: Context, request: JailbreakRequest) {
        val target = target(request.rootBackend) ?: return
        val boot = request.bootId ?: throw IOException("GHOSTLOCK_BOOT_ID_MISSING")
        val directory = DirtyfragAttempt.attemptDirectory(context)
        DirtyfragAttempt.clearStaleHookArtifacts(directory)
        IrImages.clear(directory)
        val marker = File(directory, DirtyfragAttempt.USE_KSU)
        if (marker.exists() && !marker.delete()) throw IOException("MAPLESU_KSU_MARKER_UNWRITABLE")
        val rootDigest: String
        if (target == "ultra") {
            rootDigest = IrImages.stageHookModule(context, directory)
                ?.takeIf { it.isNotEmpty() } ?: throw IOException("MAPLESU_HOOK_L3_NOT_PACKAGED")
            if (!HookEnv.write(directory, request.attemptId, boot, DirtyfragAttempt.readEnforcing())) {
                throw IOException("DIRTYFRAG_HOOK_ENV_UNWRITABLE")
            }
            // Armed before provider startup: cover staging, the native wait and claim.
            HookAttestServer.listen(context, request.attemptId, boot,
                hookPrepareBudgetMillis(request).toInt())
        } else {
            val ksud = DirtyfragAttempt.stageKernelSuDaemon(context)
                ?: throw IOException("MAPLESU_KSU_DAEMON_MISSING")
            rootDigest = MessageDigest.getInstance("SHA-256").digest(File(ksud).readBytes())
                .joinToString("") { "%02x".format(it) }
        }
        JailbreakArtifacts.require(context, "libmaplesu_dirtyfrag_bootstrap.so")
        DirtyfragAttempt.stageBootstrap(context, directory)
        File(directory, "maplesu-handover.json").let {
            if (it.exists() && !it.delete()) throw IOException("GHOSTLOCK_HANDOVER_STALE_EVIDENCE")
        }
        val env = File(directory, "maplesu-handover-env")
        env.writeText("schema=maplesu.handover.env.v1 boot=$boot attempt=${request.attemptId} " +
            "target=$target root_sha256=$rootDigest" +
            (if (target == "ultra") " stage2_sha256=$rootDigest" else "") +
            (if (request.method == JailbreakMethod.MAPLESU_93260.wireName)
                " provider=${request.method}" else "") + "\n")
        android.system.Os.chmod(env.path, 384)
    }

    fun requireReceipt(context: Context, request: JailbreakRequest) {
        val file = File(DirtyfragAttempt.hookEvidence(context), "maplesu-handover.json")
        val text = runCatching { file.readText() }.getOrNull()
            ?: throw IOException("GHOSTLOCK_HANDOVER_EVIDENCE_MISSING")
        refusal(text, request)?.let { throw IOException(it) }
    }

    fun awaitReceipt(context: Context, request: JailbreakRequest, timeoutMillis: Long,
                     cancelled: () -> Boolean, workerResult: File? = null,
                     sourceFailure: () -> String? = { null },
                     progress: (String) -> Unit = {}) {
        val file = File(DirtyfragAttempt.hookEvidence(context), "maplesu-handover.json")
        val readWorker: (() -> String?)? = workerResult?.let { result ->
            { runCatching { result.readText() }.getOrNull() }
        }
        awaitReceipt(request, timeoutMillis,
            { runCatching { file.readText() }.getOrNull() }, cancelled, readWorker,
            sourceFailure, progress)
    }

    /** Ultra requires the source's completion and DirtyFrag's bound backend proof. */
    internal fun awaitReceipt(request: JailbreakRequest, timeoutMillis: Long,
                              read: () -> String?, cancelled: () -> Boolean,
                              readWorker: (() -> String?)? = null,
                              sourceFailure: () -> String? = { null },
                              progress: (String) -> Unit = {}) {
        val started = System.nanoTime()
        val deadline = started + TimeUnit.MILLISECONDS.toNanos(timeoutMillis)
        var nextProgress = started
        while (true) {
            if (cancelled() || Thread.currentThread().isInterrupted) throw IOException("JAILBREAK_CANCELLED")
            // Read source completion first: a terminal write follows the backend's
            // final write, so the receipt read below cannot be an earlier snapshot.
            val worker = readWorker?.invoke()
            val workerDone = worker != null && runCatching { JSONObject(worker) }.isSuccess
            val text = read()
            val receiptDone = text != null && runCatching { JSONObject(text) }.isSuccess
            // A failed backend can publish before the source's restore tail.
            // Wait for its terminal record before completing either outcome.
            if (receiptDone && (readWorker == null || workerDone)) {
                refusal(text!!, request)?.let { throw IOException(it) }
            }
            if (workerDone) workerRefusal(worker!!, request)?.let { throw IOException(it) }
            if (receiptDone && (readWorker == null || workerDone)) {
                progress("Ghostlock 来源收尾与共享接管回执通过")
                return
            }
            if (workerDone) throw IOException("GHOSTLOCK_HANDOVER_EVIDENCE_MISSING")
            sourceFailure()?.let { throw IOException(it) }
            val now = System.nanoTime()
            if (now >= nextProgress) {
                progress("等待 Ghostlock 结果：${TimeUnit.NANOSECONDS.toSeconds(now - started)}s；" +
                    "共享回执=${text?.length ?: -1} bytes；来源收尾=${worker?.length ?: -1} bytes")
                nextProgress = now + TimeUnit.SECONDS.toNanos(5)
            }
            if (now >= deadline) throw IOException("GHOSTLOCK_HANDOVER_TIMEOUT")
            try { Thread.sleep(50) } catch (error: InterruptedException) {
                Thread.currentThread().interrupt()
                throw IOException("JAILBREAK_CANCELLED", error)
            }
        }
    }

    internal fun workerRefusal(text: String, request: JailbreakRequest): String? = runCatching {
        val document = JSONObject(text)
        if (document.getString("schema") != "maplesu.ghostlock.worker.v1" ||
            document.getString("provider") != request.method ||
            document.getString("bootId") != request.bootId ||
            document.getString("attempt") != request.attemptId) {
            return "GHOSTLOCK_WORKER_BINDING_MISMATCH"
        }
        val code = document.getInt("exitCode")
        if (code != 0) "GHOSTLOCK_WORKER_FAILED:$code" else null
    }.getOrElse { "GHOSTLOCK_WORKER_EVIDENCE_INVALID" }

    /** A log line or a successful lease alone never proves the requested backend. */
    internal fun refusal(text: String, request: JailbreakRequest): String? = runCatching {
        val document = JSONObject(text)
        if (document.getString("schema") != "maplesu.handover.v1" ||
            (request.method == JailbreakMethod.MAPLESU_93260.wireName &&
                document.optString("provider") != request.method) ||
            document.getString("bootId") != request.bootId ||
            document.getString("attempt") != request.attemptId ||
            document.getString("target") != target(request.rootBackend)) {
            return "GHOSTLOCK_HANDOVER_BINDING_MISMATCH"
        }
        // Ultra checks the shared helper's final restore and the hook evidence.
        // Normal also requires the consumer's final restoration frame.
        if (document.getString("verdict") != "OK") {
            return document.optString("token").takeIf { it.isNotBlank() }
                ?: "GHOSTLOCK_HANDOVER_NOT_READY"
        }
        val carrier = document.getJSONObject("carrier")
        if (request.rootBackend == JailbreakRequest.BACKEND_HOOK) {
            if (carrier.getString("kind") != "l3-gate" || carrier.getString("gate") != "ARMED") {
                return "GHOSTLOCK_HANDOVER_NOT_READY"
            }
            if (carrier.optString("stage2") !in listOf("LOADED", "ALREADY_RESIDENT")) {
                return "MAPLESU_HANDOVER_LOAD_FAILED"
            }
            val restore = document.getJSONObject("restore")
            if (restore.optInt("enforcingFinal", -1) != 1 || restore.optInt("failures", -1) != 0) {
                return "MA_HOOK_RESTORE_FAILED"
            }
        } else if (carrier.getString("kind") != "ksu-lkm" ||
            carrier.getString("ksu") != "LATE_LOAD_OK") {
            return "GHOSTLOCK_HANDOVER_NOT_READY"
        }
        null
    }.getOrElse { "GHOSTLOCK_HANDOVER_EVIDENCE_INVALID" }
}
