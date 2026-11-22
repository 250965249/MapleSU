package dev.maplesu.manager.runtime.ultra

import org.json.JSONObject

/** The legacy report's text remains diagnostic; only its same-call credential facts prove Root. */
internal fun rootStatusReportVerified(receipt: NativeReceipt): Boolean {
    if (!receipt.succeeded || receipt.operation != "get_root_status_report") return false
    fun integer(json: JSONObject, field: String): Long? = when (val value = json.opt(field)) {
        is Int -> value.toLong()
        is Long -> value
        else -> null
    }
    val json = runCatching { JSONObject(receipt.raw) }.getOrNull() ?: return false
    if (integer(json, "schemaVersion") != 1L || integer(json, "bridgeVersion") != 1L ||
        json.opt("backend") as? String != UltraRuntimeClient.BACKEND ||
        json.opt("operation") as? String != "get_root_status_report" ||
        json.opt("ok") as? Boolean != true || json.opt("sdkError") as? String != "OK" ||
        integer(json, "sdkErrorCode") != 0L) return false
    val data = json.opt("data") as? JSONObject ?: return false
    if (integer(data, "diagnosticVersion") != 1L || integer(data, "phase") != 6L ||
        data.opt("error") as? String != "0" || data.opt("rootError") as? String != "0" ||
        data.opt("encoding") as? String != "url" || data.opt("report") !is String ||
        data.opt("reportAvailable") as? Boolean != true ||
        integer(data, "process") !in 1L..Int.MAX_VALUE.toLong() ||
        integer(data, "childPid") !in 1L..Int.MAX_VALUE.toLong() ||
        integer(data, "childStatus") != 0L) return false
    for (field in listOf("rootVerified", "rootAttempted", "rootReturned", "receiptComplete", "childStatusValid")) {
        if (data.opt(field) as? Boolean != true) return false
    }
    for (field in listOf("systemError", "transportError", "waitError")) {
        if (integer(data, field) != 0L) return false
    }
    val facts = data.opt("facts") as? JSONObject ?: return false
    for (field in listOf("uidObserved", "gidObserved", "fsidsObserved", "capsObserved", "ambientPresent",
        "capLimitObserved", "securebitsObserved", "matchesRoot")) {
        if (facts.opt(field) as? Boolean != true) return false
    }
    for (field in listOf("ruid", "euid", "suid", "rgid", "egid", "sgid", "fsuid", "fsgid", "securebits",
        "uidError", "gidError", "fsuidError", "fsgidError", "capLimitError", "securebitsError")) {
        if (integer(facts, field) != 0L) return false
    }
    if (facts.opt("capsError") as? String != "0") return false
    val lastCap = integer(facts, "capLastCap")?.takeIf { it in 0L..63L } ?: return false
    val mask = (-1L ushr (63 - lastCap.toInt())).toULong().toString(16).padStart(16, '0')
    for (field in listOf("capabilityMask", "inheritable", "permitted", "effective", "bounding", "ambient")) {
        if (facts.opt(field) as? String != mask) return false
    }
    return true
}

internal fun parseRootStatusReport(receipt: NativeReceipt): NativeReceipt {
    if (receipt.operation != "get_root_status_report" || receipt.sdkError != "OK" ||
        receipt.sdkErrorCode != 0 || rootStatusReportVerified(receipt)) return receipt
    val json = JSONObject(receipt.raw).put("ok", false)
    // SDK OK with an incomplete credential proof keeps its original SDK number.
    if (!json.has("bridgeError")) {
        json.put("bridgeError", "MAPLESU_ROOT_PROOF_INVALID").put("bridgeErrorCode", -1001)
    }
    if (!json.has("reason")) json.put("reason", "Root credential proof is incomplete or unknown.")
    return requireNotNull(NativeReceipt.parse(json.toString()))
}
