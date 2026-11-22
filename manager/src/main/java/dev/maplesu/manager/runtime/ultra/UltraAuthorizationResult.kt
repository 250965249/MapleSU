// SPDX-License-Identifier: GPL-3.0-only
package dev.maplesu.manager.runtime.ultra

import org.json.JSONObject

/** Additive diagnostics for one SDK mutation. Ordinary receipt success stays independent. */
data class UltraAuthorizationResult(
    val operationResultAvailable: Boolean,
    val operation: Long,
    val resultCode: String,
    val primaryErrorCode: String?,
    val primaryPhase: Long?,
    val recovery: List<Recovery>?,
    val recoveryTotal: Long?,
    val diagnosticsComplete: Boolean,
    val commitState: Long,
    val restoreState: Long,
    val deliveryState: Long,
    val transport: Transport,
    val raw: JSONObject,
) {
    data class Recovery(val phase: Long, val errorCode: String)
    data class Transport(val status: Long, val errno: Int, val childWaitStatus: Int, val valid: Boolean)

    /** This invocation's delivery fact is independent of an earlier durable decision. */
    internal val deliveryConfirmed: Boolean get() = operationResultAvailable && diagnosticsComplete &&
        resultCode == "0" && deliveryState == 2L && transport.status == 1L &&
        transport.valid && transport.childWaitStatus == 0

    companion object {
        private fun JSONObject.integer(name: String, range: LongRange): Long? =
            when (val value = opt(name)) {
                is Byte, is Short, is Int, is Long -> value.toString().toLongOrNull()?.takeIf { it in range }
                else -> null
            }

        private fun JSONObject.uint(name: String): Long? = integer(name, 0L..0xffffffffL)
        private fun JSONObject.sint(name: String): Int? =
            integer(name, Int.MIN_VALUE.toLong()..Int.MAX_VALUE.toLong())?.toInt()

        private fun JSONObject.code(name: String): String? = (opt(name) as? String)?.takeIf {
            it.toLongOrNull()?.toString() == it
        }

        internal fun parse(value: JSONObject?): UltraAuthorizationResult? {
            val json = value ?: return null
            if (json.uint("schemaVersion") != 1L) return null
            val available = json.opt("operationResultAvailable") as? Boolean ?: return null
            val operation = json.integer("operation", 1L..4L) ?: return null
            val resultCode = json.code("resultCode") ?: return null
            val complete = json.opt("diagnosticsComplete") as? Boolean ?: return null
            val commit = json.integer("commitState", 0L..2L) ?: return null
            val restore = json.integer("restoreState", 0L..3L) ?: return null
            val delivery = json.integer("deliveryState", 0L..2L) ?: return null
            val transfer = json.optJSONObject("transport") ?: return null
            val transport = Transport(
                transfer.integer("status", 0L..7L) ?: return null,
                transfer.sint("errno") ?: return null,
                transfer.sint("childWaitStatus") ?: return null,
                transfer.opt("valid") as? Boolean ?: return null,
            )
            var primaryCode: String? = null
            var primaryPhase: Long? = null
            var recoveries: List<Recovery>? = null
            var total: Long? = null
            if (available) {
                primaryCode = json.code("primaryErrorCode") ?: return null
                primaryPhase = json.uint("primaryPhase") ?: return null
                if (primaryPhase !in 0L..2L && primaryPhase !in 10L..15L &&
                    primaryPhase !in 20L..25L && primaryPhase !in 30L..43L && primaryPhase != 50L) return null
                if ((primaryCode == "0") != (primaryPhase == 0L)) return null
                if (resultCode == "0" && primaryPhase != 0L) return null
                val count = json.uint("recoveryCount")?.takeIf { it <= 6 } ?: return null
                total = json.uint("recoveryTotal")?.takeIf { it >= count } ?: return null
                val array = json.optJSONArray("recovery") ?: return null
                if (array.length().toLong() != count) return null
                if (complete) {
                    if (total != count) return null
                } else if (count != 6L || total <= 6L || restore != 0L) return null
                recoveries = (0 until array.length()).map { index ->
                    val record = array.optJSONObject(index) ?: return null
                    Recovery(record.integer("phase", 100L..106L) ?: return null, record.code("errorCode") ?: return null)
                }
            } else {
                if (complete || commit != 0L || restore != 0L || delivery != 0L) return null
                if (listOf("primaryErrorCode", "primaryPhase", "recovery", "recoveryCount", "recoveryTotal")
                        .any(json::has)) return null
            }
            return UltraAuthorizationResult(available, operation, resultCode, primaryCode, primaryPhase,
                recoveries, total, complete, commit, restore, delivery, transport, json)
        }
    }
}
