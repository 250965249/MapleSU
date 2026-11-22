package dev.maplesu.manager.workmode.service

import dev.maplesu.manager.workmode.switch.ModeSwitchCodes
import java.io.File
import java.util.concurrent.ConcurrentHashMap

/** New tasks stay on Ultra; an existing SERVICE authority keeps its original executor. */
internal class ServiceResumeModeSwitchClient(
    private val primary: ModeSwitchClient,
    private val service: ModeSwitchClient,
    private val hasServiceHistory: () -> Boolean,
) : ModeSwitchClient by primary {
    private val owners = ConcurrentHashMap<String, ModeSwitchClient>()

    override suspend fun begin(switchId: String, planFields: Map<String, String>,
                               superuserJson: File, settingsMirrorJson: File): ClientResult {
        owners.remove(switchId)
        var accepted = false
        try {
            return primary.begin(switchId, planFields, superuserJson, settingsMirrorJson).also {
                accepted = it.ok
                if (accepted) owners[switchId] = primary
            }
        } finally {
            if (!accepted) owners.remove(switchId)
        }
    }

    override fun status(switchId: String): ClientStatus? = statusExact(switchId)

    override fun statusExact(switchId: String): ClientStatus? {
        if (switchId.isNotEmpty()) {
            owners[switchId]?.let { return it.statusExact(switchId) }
            val current = primary.statusExact(switchId)
            val previous = if (hasServiceHistory()) service.statusExact(switchId) else null
            check(current == null || previous == null) { "${ModeSwitchCodes.PLAN_CONFLICT}: $switchId has two owners" }
            return remember(current, primary) ?: remember(previous, service)
        }
        val current = primary.statusExact("")
        val previous = if (hasServiceHistory()) service.statusExact("") else null
        check(current == null || previous == null ||
            current.switchId != previous.switchId && !(current.pending && previous.pending)) {
            "${ModeSwitchCodes.PLAN_CONFLICT}: Ultra=${current?.switchId} SERVICE=${previous?.switchId}"
        }
        return when {
            current?.pending == true -> remember(current, primary)
            previous?.pending == true || current == null -> remember(previous, service)
            else -> remember(current, primary)
        }
    }

    private fun remember(status: ClientStatus?, owner: ModeSwitchClient): ClientStatus? = status?.also {
        owners[it.switchId] = owner
    }

    private fun owner(switchId: String): ModeSwitchClient {
        owners[switchId]?.let { return it }
        check(statusExact(switchId) != null) { "${ModeSwitchCodes.PLAN_INVALID}: no switch record $switchId" }
        return owners.getValue(switchId)
    }

    fun isServiceTask(switchId: String): Boolean {
        owners[switchId]?.let { return it === service }
        if (statusExact(switchId) == null) return false
        return owners.getValue(switchId) === service
    }

    override suspend fun snapshot(switchId: String) = owner(switchId).snapshot(switchId)
    override suspend fun exportImage(switchId: String, kind: String, partition: String, destination: File) =
        owner(switchId).exportImage(switchId, kind, partition, destination)
    override suspend fun submitCandidate(switchId: String, partition: String, candidate: File, candidateSha256: String) =
        owner(switchId).submitCandidate(switchId, partition, candidate, candidateSha256)
    override suspend fun commit(switchId: String) = owner(switchId).commit(switchId)
    override suspend fun rollback(switchId: String) = owner(switchId).rollback(switchId)
    override suspend fun abort(switchId: String) = owner(switchId).abort(switchId)
    override suspend fun verify(switchId: String) = owner(switchId).verify(switchId)
    override suspend fun markRebootRequested(switchId: String) = owner(switchId).markRebootRequested(switchId)
    override suspend fun exportLog(switchId: String, destination: File) = owner(switchId).exportLog(switchId, destination)
}
