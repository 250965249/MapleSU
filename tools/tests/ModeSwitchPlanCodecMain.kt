package dev.maplesu.manager.workmode.service

import android.os.Bundle

/** Uses the production codec with a host Bundle map seam, without Binder or partition I/O. */
fun main() {
    var checks = 0
    fun verify(value: Boolean) {
        checks++
        check(value) { "plan codec check $checks failed" }
    }
    for ((from, to, target, source) in listOf(
        listOf("KSU", "LITE", "boot", "init_boot"),
        listOf("LITE", "KSU", "init_boot", "boot"),
        listOf("LITE", "KSU", "boot", ""),
    )) {
        val fields = mapOf("fromMode" to from, "toMode" to to, "baselineId" to "",
            "targetPartition" to target, "sourcePartition" to source)
        val decoded = ModeSwitchAidlCodec.decodePlanFields(ModeSwitchAidlCodec.planBundle("switch-1", fields))
        for ((key, value) in fields) verify(decoded[key] == value)
        verify(decoded["schema"] == "MAPLESU_SWITCH_PLAN_V1" && decoded["switchId"] == "switch-1")
    }
    val legacy = ModeSwitchAidlCodec.decodePlanFields(ModeSwitchAidlCodec.planBundle("legacy",
        mapOf("fromMode" to "LITE", "toMode" to "KSU")))
    verify("targetPartition" !in legacy && "sourcePartition" !in legacy)
    verify(legacy["baselineId"] == "")
    val emptySource = ModeSwitchAidlCodec.decodePlanFields(ModeSwitchAidlCodec.planBundle("empty",
        mapOf("fromMode" to "LITE", "toMode" to "KSU", "sourcePartition" to "")))
    verify("sourcePartition" in emptySource && emptySource.getValue("sourcePartition").isEmpty())
    val direct = Bundle().apply {
        putString("targetPartition", "invalid-partition")
        putString("sourcePartition", "init_boot")
        putString("step.0.partition", "boot")
        putString("planSha256", "plan-digest")
        putString("unexpected", "ignored")
    }
    val decoded = ModeSwitchAidlCodec.decodePlanFields(direct)
    verify(decoded["targetPartition"] == "invalid-partition") // Request validation owns rejection.
    verify(decoded["sourcePartition"] == "init_boot")
    verify(decoded["step.0.partition"] == "boot" && decoded["planSha256"] == "plan-digest")
    verify("unexpected" !in decoded)
    val forced = ModeSwitchAidlCodec.decodePlanFields(ModeSwitchAidlCodec.planBundle("actual-id",
        mapOf("schema" to "other-schema", "switchId" to "other-id", "unexpected" to "ignored")))
    verify(forced["schema"] == "MAPLESU_SWITCH_PLAN_V1" && forced["switchId"] == "actual-id")
    verify("unexpected" !in forced)
    println("mode-switch-plan-codec: $checks checks, 0 failures")
}
