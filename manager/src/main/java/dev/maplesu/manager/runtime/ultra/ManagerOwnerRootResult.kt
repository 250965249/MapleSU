package dev.maplesu.manager.runtime.ultra

import android.os.Process
import org.json.JSONObject

internal data class ManagerOwnerRootProof(
    val owner: UltraRuntimeClient.ManagerOwnerIdentity,
    val capabilityMask: String,
    val elapsedMicros: Long,
)

internal data class ManagerOwnerRootResult(
    val receipt: NativeReceipt,
    val proof: ManagerOwnerRootProof?,
    val rootCommitted: Boolean?,
) {
    val verified: Boolean get() = proof != null
}

/** Facts describe the authenticated worker's credentials, independently of environment readiness. */
internal fun parseManagerOwnerRoot(receipt: NativeReceipt): ManagerOwnerRootResult {
    fun invalid(committed: Boolean? = null): ManagerOwnerRootResult {
        if (!receipt.succeeded) return ManagerOwnerRootResult(receipt, null, committed)
        val raw = JSONObject(receipt.raw).put("ok", false)
            .put("sdkError", "MAPLESU_OWNER_ROOT_PROOF_INVALID").put("sdkErrorCode", -1001)
        return ManagerOwnerRootResult(requireNotNull(NativeReceipt.parse(raw.toString())), null, committed)
    }
    fun integer(json: JSONObject, name: String): Long? = when (val value = json.opt(name)) {
        is Int -> value.toLong()
        is Long -> value
        else -> null
    }
    fun numberText(json: JSONObject, name: String): Long? = (json.opt(name) as? String)?.toLongOrNull()
    fun hex(json: JSONObject, name: String): String? = (json.opt(name) as? String)?.takeIf {
        it.length == 16 && it.all { character -> character in '0'..'9' || character in 'a'..'f' }
    }
    val envelope = runCatching { JSONObject(receipt.raw) }.getOrNull()
        ?: return ManagerOwnerRootResult(NativeReceipt.bridgeFailure("probe_manager_owner_root",
            "MAPLESU_OWNER_ROOT_PROOF_INVALID", null), null, null)
    if (envelope.opt("backend") as? String != UltraRuntimeClient.BACKEND ||
        envelope.opt("operation") as? String != "probe_manager_owner_root" ||
        integer(envelope, "schemaVersion") != 1L || integer(envelope, "bridgeVersion") != 1L) return invalid()
    val data = envelope.opt("data") as? JSONObject ?: return invalid()
    if (integer(data, "abiVersion") != 1L) return invalid()
    val root = data.opt("root") as? JSONObject ?: return invalid()
    val effects = integer(root, "effects")?.takeIf { it in 0L..0xffff_ffffL }
    val checkpointReceived = data.opt("rootCheckpointReceived") as? Boolean == true
    val committed = when {
        checkpointReceived && root.opt("attempted") as? Boolean == false &&
            data.opt("rootCommitted") as? Boolean == false -> false
        checkpointReceived && root.opt("attempted") as? Boolean == true && root.opt("replyObserved") as? Boolean == true &&
            root.opt("completed") as? Boolean == true && integer(root, "command") == 10L && effects != null ->
            ((effects and 8L) != 0L).takeIf { data.opt("rootCommitted") as? Boolean == it }
        else -> null
    }
    if (!receipt.succeeded || envelope.opt("ok") as? Boolean != true ||
        envelope.opt("sdkError") as? String != "OK" || integer(envelope, "sdkErrorCode") != 0L ||
        committed != true) return invalid(committed)
    val childExited = data.opt("childStatusValid") as? Boolean ?: return invalid(committed)
    val childStatus = integer(data, "childStatus")?.takeIf { it in Int.MIN_VALUE.toLong()..Int.MAX_VALUE.toLong() }
        ?: return invalid(committed)
    val cleanupPending = data.opt("cleanupPending") as? Boolean ?: return invalid(committed)
    val cleanupScheduled = data.opt("cleanupScheduled") as? Boolean ?: return invalid(committed)
    if (if (childExited) childStatus != 0L || cleanupPending || cleanupScheduled
        else !cleanupPending || !cleanupScheduled) return invalid(committed)
    if (data.opt("receiptComplete") as? Boolean != true || data.opt("rootCheckpointReceived") as? Boolean != true ||
        data.opt("watchdogArmed") as? Boolean != true || integer(data, "watchdogError") != 0L ||
        integer(data, "childPid") !in 1L..Int.MAX_VALUE.toLong() || integer(data, "cleanupError") != 0L ||
        integer(data, "probeAdmissionError") != 0L ||
        data.opt("timedOut") as? Boolean != false || data.opt("terminationRequested") as? Boolean != false ||
        integer(data, "terminationError") != 0L || integer(data, "transportError") != 0L ||
        integer(data, "waitError") != 0L || data.opt("childException") as? Boolean != false ||
        integer(data, "childIoError") != 0L || data.opt("modeSelected") as? Boolean != true ||
        data.opt("ownerBound") as? Boolean != true || data.opt("rootVerified") as? Boolean != true ||
        numberText(data, "modeError") != 0L || numberText(data, "channelError") != 0L) return invalid(committed)
    val uid = integer(data, "fullUid") ?: return invalid(committed)
    val epoch = integer(data, "epoch") ?: return invalid(committed)
    val host = data.opt("hostInstance") as? String ?: return invalid(committed)
    val elapsed = numberText(data, "elapsedMicros")?.takeIf { it >= 0 } ?: return invalid(committed)
    if (uid != Process.myUid().toLong() || epoch !in 1L..0xffff_ffffL || host.length != 32 ||
        host.any { it !in '0'..'9' && it !in 'a'..'f' } || host.all { it == '0' }) return invalid(committed)
    fun commandSucceeded(value: JSONObject, command: Long, effect: Long): Boolean =
        value.opt("attempted") as? Boolean == true && value.opt("replyObserved") as? Boolean == true &&
            value.opt("completed") as? Boolean == true && integer(value, "command") == command &&
            numberText(value, "error") == 0L && integer(value, "status") == 0L &&
            integer(value, "effects") == effect && hex(value, "result") == "0000000000000000" &&
            hex(value, "handle") == "0000000000000000"
    val close = data.opt("close") as? JSONObject ?: return invalid(committed)
    if (!commandSucceeded(root, 10L, 8L) || !commandSucceeded(close, 5L, 16L)) return invalid(committed)
    val credentials = data.opt("credentials") as? JSONObject ?: return invalid(committed)
    for (field in listOf("uidObserved", "gidObserved", "capsObserved", "ambientPresent", "capLimitObserved",
        "securebitsObserved", "matchesRoot")) {
        if (credentials.opt(field) as? Boolean != true) return invalid(committed)
    }
    for (field in listOf("ruid", "euid", "suid", "rgid", "egid", "sgid", "securebits", "uidError", "gidError",
        "capLimitError", "securebitsError")) {
        if (integer(credentials, field) != 0L) return invalid(committed)
    }
    if (numberText(credentials, "capsError") != 0L) return invalid(committed)
    val lastCap = integer(credentials, "capLastCap")?.takeIf { it in 0L..63L } ?: return invalid(committed)
    val expectedMask = (-1L ushr (63 - lastCap.toInt())).toULong().toString(16).padStart(16, '0')
    for (field in listOf("capabilityMask", "inheritable", "permitted", "effective", "bounding", "ambient")) {
        if (hex(credentials, field) != expectedMask) return invalid(committed)
    }
    return ManagerOwnerRootResult(receipt, ManagerOwnerRootProof(
        UltraRuntimeClient.ManagerOwnerIdentity(uid.toInt(), epoch, host), expectedMask, elapsed,
    ), committed)
}
