package dev.maplesu.manager.workmode.ui

import androidx.compose.runtime.Immutable
import dev.maplesu.manager.workmode.WorkMode
import dev.maplesu.manager.workmode.migration.MigrationDetectionUi
import dev.maplesu.manager.workmode.migration.MigrationFailureUi
import dev.maplesu.manager.workmode.migration.MigrationResultUi
import dev.maplesu.manager.workmode.migration.MigrationStage
import dev.maplesu.manager.workmode.migration.MigrationUiSnapshot

/** Presentation only; migration decisions and writes stay in the existing facade/reducer. */
@Immutable
data class MigrationUiState(val snapshot: MigrationUiSnapshot = MigrationUiSnapshot()) {
    val stage: MigrationStage get() = snapshot.stage
    val detection: MigrationDetectionUi? get() = snapshot.detection
    val selectedTarget: WorkMode? get() = snapshot.selectedTarget
    val canStart: Boolean get() = snapshot.canStart
    val canAbort: Boolean get() = snapshot.canAbort && snapshot.migrationId.isNotBlank() &&
        !stage.destructiveStarted
    val unavailable: Boolean get() = stage == MigrationStage.UNAVAILABLE
    val blocksBack: Boolean get() = stage.blocksBack
    val residualWarning: Boolean get() = snapshot.residualWarning
    val failure: MigrationFailureUi? get() = snapshot.failure
    val result: MigrationResultUi? get() = snapshot.result

    fun restorePartitions(): List<String> = snapshot.restorePartitions

    fun technicalLines(): List<String> = buildList {
        if (snapshot.migrationId.isNotBlank()) add("migration.id=${snapshot.migrationId}")
        add("migration.stage=${stage.wire}")
        detection?.let {
            it.uapi?.let { uapi -> add("kernel.uapi=$uapi") }
            add("partitions.patched=${it.patchedPartitions.joinToString()}")
            add("partitions.restore=${restorePartitions().joinToString()}")
            add("stock.backups=${it.usableStockBackups}/${it.totalStockBackups}")
        }
        snapshot.backup?.let { add("backup.verified=${it.complete}; objects=${it.objectCount}; bytes=${it.totalBytes}") }
        failure?.let { add("error=${it.code}; stage=${it.stage.wire}") }
        if (snapshot.unavailableCode.isNotBlank()) add("error=${snapshot.unavailableCode}")
        if (snapshot.progress.logLine.isNotBlank()) add(snapshot.progress.logLine)
        result?.let { result ->
            result.modules.forEach { add("${it.moduleId}: ${it.decision.name}") }
            result.residues.forEach { add("residue=$it") }
            if (result.errorCode.isNotBlank()) add("error=${result.errorCode}")
        }
    }
}

/** A carried target is an explicit choice: never silently replace an unsupported one. */
internal fun migrationEntrySelection(
    detected: MigrationUiSnapshot,
    initialTarget: WorkMode?,
    confirmOnOpen: Boolean,
): MigrationUiSnapshot {
    val selected = if (initialTarget == null) detected.selectedTarget else {
        initialTarget.takeIf { target -> detected.targetOptions.any { it.mode == target && it.enabled } }
    }
    val state = detected.copy(selectedTarget = selected)
    return if (confirmOnOpen && state.canStart) {
        dev.maplesu.manager.workmode.migration.MigrationUiReducer.reduce(
            state, dev.maplesu.manager.workmode.migration.MigrationUiEvent.ConfirmRequested,
        )
    } else state
}
