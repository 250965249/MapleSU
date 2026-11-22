package dev.maplesu.manager.workmode

import dev.maplesu.manager.runtime.ultra.Fixture
import dev.maplesu.manager.workmode.detect.ModeState

enum class WorkMode { LITE, KSU }
data class Trace(val id: String, val ok: Boolean?)
data class Detection(val state: ModeState? = null, val trace: List<Trace> = listOf(Trace("S1", false)))
object ModeRuntime {
    var active: WorkMode? = WorkMode.LITE
    var detectionComplete = true
    var detectionFailure: Throwable? = null
    var latestDetection: Detection? = Detection()
    suspend fun awaitDetectionSettled(timeout: Long) { Fixture.calls += "await-detection" }
}
