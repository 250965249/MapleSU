package dev.maplesu.manager.workmode.service

import java.io.File

/** The ordinary switch still captures its baseline. Only explicit AVB requests use the
 * native signed batch writer, keeping the generic switch partition allowlist intact. */
interface SignedSwitchClient : ModeSwitchClient {
    fun owns(switchId: String): Boolean
    fun latestId(): String? = null
    fun standalone(switchId: String): Boolean = false
}

class LenovoSignedSwitchClient(
    val ordinary: ModeSwitchClient,
    private val signed: SignedSwitchClient,
) : ModeSwitchClient {
    var signedActive: Boolean = false
        private set
    fun isSignedTask(id: String) = signed.owns(id)

    override suspend fun preflight(switchId: String, planFields: Map<String, String>): ClientResult {
        signedActive = !planFields["lenovoSigning"].isNullOrEmpty() || planFields["vivoCompatibility"] == "1"
        if (planFields["vivoCompatibility"] == "1") return signed.preflight(switchId, planFields)
        return ordinary.preflight(switchId, planFields)
    }
    override suspend fun begin(switchId: String, planFields: Map<String, String>, superuserJson: File, settingsMirrorJson: File): ClientResult {
        if (planFields["vivoCompatibility"] == "1") {
            signedActive = true
            return signed.begin(switchId, planFields, superuserJson, settingsMirrorJson)
        }
        val result = ordinary.begin(switchId, planFields, superuserJson, settingsMirrorJson)
        if (!result.ok || planFields["lenovoSigning"].isNullOrEmpty()) return result
        signedActive = true
        return signed.begin(switchId, planFields, superuserJson, settingsMirrorJson)
    }
    override suspend fun snapshot(switchId: String): ClientResult {
        if (signed.standalone(switchId)) return signed.snapshot(switchId)
        val result = ordinary.snapshot(switchId)
        if (!result.ok || !signed.owns(switchId)) return result
        val prepared = signed.snapshot(switchId)
        // Native owns its full PRE now. Retire the unused baseline transaction while
        // the source root backend is still present, not after reboot into another mode.
        if (prepared.ok) return retireBaseline(switchId, prepared)
        val cancelled = signed.abort(switchId)
        return if (cancelled.ok) retireBaseline(switchId, prepared) else cancelled
    }
    private suspend fun retireBaseline(id: String, result: ClientResult): ClientResult {
        if (signed.standalone(id)) return result
        val previous = ordinary.statusExact(id) ?: return result
        if (previous.state in setOf("CANCELLED", "FAILED_PRE_WRITE")) return result
        if (previous.state !in setOf("BEGIN", "SNAPSHOT", "PRODUCE"))
            return ClientResult(false, "LENOVO_AVB_BASELINE_RETIRE_FAILED", previous.state, result.status)
        val retired = ordinary.abort(id)
        return if (retired.ok || ordinary.statusExact(id)?.state == "CANCELLED") result
            else retired.copy(status = result.status)
    }
    private fun route(id: String): ModeSwitchClient = if (signed.owns(id)) signed.also { signedActive = true } else ordinary
    override suspend fun exportImage(switchId: String, kind: String, partition: String, destination: File) =
        route(switchId).exportImage(switchId, kind, partition, destination)
    override suspend fun submitCandidate(switchId: String, partition: String, candidate: File, candidateSha256: String) =
        route(switchId).submitCandidate(switchId, partition, candidate, candidateSha256)
    override suspend fun commit(switchId: String) = route(switchId).commit(switchId)
    override suspend fun rollback(switchId: String): ClientResult {
        if (!signed.owns(switchId)) return ordinary.rollback(switchId)
        val result = signed.rollback(switchId)
        return if (result.ok) retireBaseline(switchId, result) else result
    }
    override suspend fun abort(switchId: String): ClientResult {
        if (!signed.owns(switchId)) return ordinary.abort(switchId)
        val result = signed.abort(switchId)
        return if (result.ok) retireBaseline(switchId, result) else result
    }
    override fun status(switchId: String): ClientStatus? {
        if (switchId.isNotEmpty()) return route(switchId).status(switchId)
        val latest = ordinary.status("")
        val signedId = signed.latestId()
        if (signedId != null) {
            val native = signed.status(signedId)
            if (native != null && (native.pending || latest == null || latest.switchId == signedId)) {
                signedActive = true
                return native
            }
        }
        return latest?.let { if (signed.owns(it.switchId)) signed.status(it.switchId) else it }
    }
    override fun statusExact(switchId: String) = if (switchId.isEmpty()) status(switchId) else route(switchId).statusExact(switchId)
    override suspend fun verify(switchId: String): ClientResult {
        if (!signed.owns(switchId)) return ordinary.verify(switchId)
        val result = signed.verify(switchId)
        return if (result.ok) retireBaseline(switchId, result) else result
    }
    override suspend fun markRebootRequested(switchId: String) = route(switchId).markRebootRequested(switchId)
    override suspend fun exportLog(switchId: String, destination: File) = ordinary.exportLog(switchId, destination)
}
