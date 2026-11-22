package dev.maplesu.manager.workmode.gating

object ModeComponentIds { const val APP_PRO_AUTOPAIR = "startup" }
object ModeGateFormat { enum class Reason { NOT_APPLICABLE } }
object ModeGate {
    fun allow(id: String) {}
    fun skip(id: String, reason: ModeGateFormat.Reason) {}
}
