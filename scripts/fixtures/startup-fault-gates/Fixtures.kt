package dev.maplesu.manager.runtime.ultra

import android.content.Context
import dev.maplesu.manager.workmode.*
import dev.maplesu.manager.workmode.ui.WorkModeSwitchSession

internal object Fixture {
    val calls = mutableListOf<String>()
    var key: String? = "fixture-key-a"
    var boot: String? = "fixture-boot-a"
    var session: String? = null
    var recoveryResult = "RECOVERY_ROOT_NOT_VERIFIED"
    var pair = false
    var ready = false
    var uid: Int? = null
    var pairedObservation: UltraEnvironmentProbe.Snapshot? = null
    var sdkObservation = UltraEnvironmentProbe.Snapshot(UltraEnvironmentProbe.State.Running)
    fun reset() {
        android.os.SystemClock.now = 0L
        calls.clear(); key = "fixture-key-a"; boot = "fixture-boot-a"; session = null
        recoveryResult = "RECOVERY_ROOT_NOT_VERIFIED"; pair = false; ready = false; uid = null
        pairedObservation = null
        sdkObservation = UltraEnvironmentProbe.Snapshot(UltraEnvironmentProbe.State.Running)
        ModeRuntime.active = WorkMode.LITE; ModeRuntime.detectionComplete = true
        ModeRuntime.detectionFailure = null; ModeRuntime.latestDetection = Detection()
        WorkModeSwitchSession.executing = false
        observe(UltraEnvironmentProbe.Snapshot())
    }
    fun observe(observation: UltraEnvironmentProbe.Snapshot) {
        UltraEnvironmentProbe.snapshot = observation
        UltraEnvironmentProbe.snapshotKey = session ?: key
        UltraEnvironmentProbe.snapshotBootId = boot
    }
}
object UltraSdkCredentials {
    fun read(context: Context) = Fixture.session ?: Fixture.key
    fun suspended(context: Context) = false
    fun hookWithoutSdk(context: Context) = false
}
object UltraEnvironmentAutoSetup {
    fun currentBootId() = Fixture.boot
    fun hasPostBootUltraSwitchRecovery(context: Context) = false
    fun hasVerifiedUltraIdentity(context: Context) = false
    fun blockedReason(context: Context, bootSession: Boolean) = null
    fun ensure(context: Context) { Fixture.calls += "setup" }
}
object UltraInstallCredentialRecovery { fun hasPendingInstallCredential(context: Context) = false }
object UltraSdkSession {
    data class Result(val ready: Boolean)
    fun current(context: Context) = Fixture.session
    fun ensure(context: Context): Result { Fixture.calls += "boot-ready"; return Result(Fixture.ready) }
}
object UltraAutoPair {
    data class Result(val paired: Boolean, val state: String = "fixture", val reason: String = "fixture")
    fun ensure(context: Context): Result {
        Fixture.calls += "pair"
        Fixture.pairedObservation?.let(Fixture::observe)
        return Result(Fixture.pair)
    }
}
object UltraSdkLogging {
    fun ensureDisabled(context: Context) { Fixture.calls += "persistent-log" }
    fun apply(client: UltraRuntimeClient) { Fixture.calls += "persistent-log" }
}
object UltraKeyPairedStore { fun isPaired(context: Context) = Fixture.pair }
object UltraPairingMaintenance {
    fun request(context: Context, key: String) { Fixture.calls += "maintenance" }
}
class UltraRuntimeClient(val key: () -> String?)
