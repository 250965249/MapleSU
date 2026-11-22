package dev.maplesu.manager.workmode.service

import dev.maplesu.manager.workmode.Hashes
import dev.maplesu.manager.workmode.TestFixtures
import dev.maplesu.manager.workmode.WorkMode
import dev.maplesu.manager.workmode.superuser.ApplyFailure
import dev.maplesu.manager.workmode.switch.BeginInputs
import dev.maplesu.manager.workmode.switch.BatteryFacts
import dev.maplesu.manager.workmode.switch.HookResult
import dev.maplesu.manager.workmode.switch.ModeSwitchCodes
import dev.maplesu.manager.workmode.switch.SwitchDeviceFacts
import dev.maplesu.manager.workmode.superuser.ReconcileResult
import dev.maplesu.manager.workmode.superuser.SuperuserSync
import dev.maplesu.manager.workmode.superuser.SyncState
import dev.maplesu.manager.workmode.superuser.SyncStatus
import dev.maplesu.manager.workmode.superuser.ExportResult
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.util.UUID

/**
 * 生产接线：S1 `MirrorProvider`（设置镜像 + 共享授权导出）与 S6.4
 * `SuperuserSyncReconciler`（apply/verify/revoke 语义）。全部依赖 host fake。
 */
class ModeSwitchProductionWireTest {

    // ------------------------------------------------------------------ S1 MirrorProvider

    private class ProviderHarness {
        val temp: File = TestFixtures.tempDir("mirror-provider").toFile()
        var mode: WorkMode? = WorkMode.LITE
        var settingsArtifact: MirrorArtifact = MirrorArtifact(File(temp, "settings.json").apply { writeText("{}") })
        var superuserArtifact: MirrorArtifact = MirrorArtifact(File(temp, "superuser.json").apply { writeText("{}") })
        var throwSettings = false
        var throwSuperuser = false

        val provider = AndroidModeSwitchMirrorProvider(
            activeMode = { mode },
            settingsExporter = SettingsMirrorExporter {
                if (throwSettings) error("settings boom") else settingsArtifact
            },
            superuserExporter = SuperuserMirrorExporter {
                if (throwSuperuser) error("superuser boom") else superuserArtifact
            },
        )
    }

    @Test
    fun providerSuccessReturnsBothMirrorFiles() {
        val h = ProviderHarness()
        val inputs = h.provider.provide()
        assertTrue(inputs.error, inputs.error.isEmpty())
        assertEquals(h.settingsArtifact.file, inputs.settingsMirrorJson)
        assertEquals(h.superuserArtifact.file, inputs.superuserJson)
    }

    @Test
    fun providerWithoutActiveModeFailsClosed() {
        val h = ProviderHarness().apply { mode = null }
        val inputs = h.provider.provide()
        assertEquals(ModeSwitchCodes.STATE_UNDETERMINED, inputs.error)
        assertFalse(inputs.error.isEmpty())
    }

    @Test
    fun settingsExportFailurePropagatesExplicitCode() {
        val h = ProviderHarness().apply {
            settingsArtifact = MirrorArtifact(null, ModeSwitchCodes.PREPARE_EXPORT_FAILED, "prefs unreadable")
        }
        val inputs = h.provider.provide()
        assertEquals(ModeSwitchCodes.PREPARE_EXPORT_FAILED, inputs.error)
    }

    @Test
    fun superuserExportFailurePropagatesExplicitCode() {
        val h = ProviderHarness().apply {
            superuserArtifact = MirrorArtifact(null, "SUPERUSER_BACKEND_UNAVAILABLE", "no backend")
        }
        val inputs = h.provider.provide()
        assertEquals("SUPERUSER_BACKEND_UNAVAILABLE", inputs.error)
    }

    @Test
    fun exporterExceptionNeverBecomesEmptySuccess() {
        val h = ProviderHarness().apply { throwSettings = true }
        val settingsInputs = h.provider.provide()
        assertEquals(ModeSwitchCodes.PREPARE_EXPORT_FAILED, settingsInputs.error)

        val h2 = ProviderHarness().apply { throwSuperuser = true }
        val superuserInputs = h2.provider.provide()
        assertEquals("SUPERUSER_EXPORT_FAILED", superuserInputs.error)
    }

    @Test
    fun providerFilesFeedS1AndStartSwitchNoLongerFailsPrepareExport() = runBlocking {
        val h = ProviderHarness()
        val client = MinimalClient()
        val environment = MinimalEnvironment(h.provider)
        val facade = ModeSwitchFacade(
            client = client,
            environment = environment,
            producers = mapOf(
                WorkMode.LITE to dev.maplesu.manager.workmode.switch.SwitchCandidateProducer {
                    dev.maplesu.manager.workmode.switch.CandidateResult(null, "", 0, "PRODUCE_FAILED", "unused")
                },
                WorkMode.KSU to dev.maplesu.manager.workmode.switch.SwitchCandidateProducer { input ->
                    val image = File(input.workDir, "candidate.bin")
                    image.writeBytes(ByteArray(4096) { 'C'.code.toByte() })
                    dev.maplesu.manager.workmode.switch.CandidateResult(
                        image, Hashes.sha256(image.readBytes()), image.length(),
                    )
                },
            ),
            workRoot = File(h.temp, "work"),
            snapshots = object : dev.maplesu.manager.workmode.switch.ModeSwitchSnapshots {
                override suspend fun preSwitchSnapshot(request: dev.maplesu.manager.workmode.switch.ModeSwitchRequest) =
                    dev.maplesu.manager.workmode.switch.GatewayOutcome(true, "")
                override suspend fun restoreAfterRollback(request: dev.maplesu.manager.workmode.switch.ModeSwitchRequest) =
                    dev.maplesu.manager.workmode.switch.GatewayOutcome(true, "")
            },
            hooks = object : dev.maplesu.manager.workmode.switch.SwitchQuiesceHooks {
                override fun quiesce(fromMode: WorkMode) = HookResult.OK
                override fun restoreAfterFailure(fromMode: WorkMode) = HookResult.OK
                override fun withdrawLiteImplants() = HookResult.OK
                override fun implantRestoreReady() = true
                override fun restoreProducerSideEffects() = HookResult.OK
            },
        )
        val outcome = facade.startSwitch(WorkMode.KSU)
        assertTrue("unexpected: $outcome", outcome is SwitchOutcome.AwaitingReboot)
        assertTrue("S1 must call begin", client.calls.contains("begin"))
    }

    // ------------------------------------------------------------------ S6.4 Reconciler

    private class FakeSync(
        var result: ReconcileResult = ReconcileResult(1, 0, 0, emptyList(), SyncState.VERIFIED),
        var error: Exception? = null,
    ) : SuperuserSync {
        override suspend fun exportBeforeSwitch(from: WorkMode, rev: Long): ExportResult =
            ExportResult.Ok(rev, 1, 0, 0)
        override suspend fun reconcileAfterBoot(mode: WorkMode): ReconcileResult {
            error?.let { throw it }
            return result
        }
        override fun status(): SyncStatus = SyncStatus(SyncState.VERIFIED, 1, 1, 0, 0)
    }

    @Test
    fun reconcilerSuccessIsOk() = runBlocking {
        val reconciler = SuperuserSyncReconciler({ FakeSync() })
        assertEquals(HookResult.OK, reconciler.reconcileAfterBoot(WorkMode.KSU))
    }

    @Test
    fun reconcilerVerifyFailureIsExplicit() = runBlocking {
        val reconciler = SuperuserSyncReconciler({
            FakeSync(ReconcileResult(0, 2, 0, emptyList(), SyncState.PARTIAL_PENDING))
        })
        val result = reconciler.reconcileAfterBoot(WorkMode.KSU)
        assertFalse(result.ok)
        assertEquals("VERIFY_SUPERUSER_FAILED", result.code)
    }

    @Test
    fun reconcilerDangerousRevokeFailureIsNeverSilent() = runBlocking {
        val reconciler = SuperuserSyncReconciler({
            FakeSync(
                ReconcileResult(
                    1, 0, 0,
                    listOf(ApplyFailure(10001, "com.demo", "revoke", "KSU_APPLY_REJECTED")),
                    SyncState.PARTIAL_PENDING,
                ),
            )
        })
        val result = reconciler.reconcileAfterBoot(WorkMode.KSU)
        assertFalse(result.ok)
        assertEquals("SUPERUSER_REVOKE_FAILED", result.code)
    }

    @Test
    fun reconcilerWithoutBackendFailsClosed() = runBlocking {
        val reconciler = SuperuserSyncReconciler({ null })
        val result = reconciler.reconcileAfterBoot(WorkMode.KSU)
        assertFalse(result.ok)
        assertEquals("SUPERUSER_BACKEND_UNAVAILABLE", result.code)
    }

    @Test
    fun reconcilerWithoutTargetRootChannelFailsClosed() = runBlocking {
        val reconciler = SuperuserSyncReconciler({ FakeSync() }, targetRootAvailable = { false })
        val result = reconciler.reconcileAfterBoot(WorkMode.KSU)
        assertFalse(result.ok)
        assertEquals("SUPERUSER_BACKEND_UNAVAILABLE", result.code)
    }

    @Test
    fun reconcilerBlockedStateAndExceptionsAreExplicit() = runBlocking {
        val blocked = SuperuserSyncReconciler({
            FakeSync(ReconcileResult(0, 0, 0, emptyList(), SyncState.BLOCKED))
        }).reconcileAfterBoot(WorkMode.LITE)
        assertFalse(blocked.ok)
        assertEquals("VERIFY_SUPERUSER_FAILED", blocked.code)

        val thrown = SuperuserSyncReconciler({ FakeSync(error = IllegalStateException("boom")) })
            .reconcileAfterBoot(WorkMode.LITE)
        assertFalse(thrown.ok)
        assertEquals("VERIFY_SUPERUSER_FAILED", thrown.code)
    }

    @Test
    fun facadeSurfacesReconcileFailureInsteadOfVerified() = runBlocking {
        val temp: File = TestFixtures.tempDir("facade-sync").toFile()
        val client = MinimalClient().apply {
            currentStatus = MinimalClient.rebootRequiredStatus()
        }
        val environment = MinimalEnvironment(MirrorProviderStub(temp))
        val facade = ModeSwitchFacade(
            client = client,
            environment = environment,
            producers = emptyMap(),
            workRoot = File(temp, "work"),
            superuser = SuperuserSyncReconciler({
                FakeSync(ReconcileResult(0, 1, 0, emptyList(), SyncState.PARTIAL_PENDING))
            }),
        )
        val outcome = facade.reopenAfterReboot()
        assertTrue("unexpected: $outcome", outcome is SwitchOutcome.Incomplete)
        assertEquals("VERIFY_SUPERUSER_FAILED", (outcome as SwitchOutcome.Incomplete).code)
    }

    // ------------------------------------------------------------------ fakes

    private class MirrorProviderStub(private val temp: File) : ModeSwitchMirrorProvider {
        override fun provide(): BeginInputs {
            val su = File(temp, "su.json").apply { writeText("{}") }
            val settings = File(temp, "settings.json").apply { writeText("{}") }
            return BeginInputs(su, settings)
        }
    }

    private class MinimalEnvironment(
        private val mirrors: ModeSwitchMirrorProvider,
    ) : ModeSwitchAppEnvironment {
        private val tempDir = File(TestFixtures.tempDir("mini-env").toFile(), "w").apply { mkdirs() }
        override fun activeMode(): WorkMode? = WorkMode.LITE
        override fun modeStateName(): String? = "MODE_A_ACTIVE"
        override fun bootId(): String = "boot-1"
        override fun deviceFacts(): SwitchDeviceFacts =
            SwitchDeviceFacts("_a", "fw", "5.10.198-android13-8-g", "Enforcing")
        override fun battery(): BatteryFacts = BatteryFacts(80, false)
        override fun freeBytes(): Long = 1L shl 40
        override fun beginInputs(): BeginInputs = mirrors.provide()
    }

    private class MinimalClient : ModeSwitchClient {
        val calls = mutableListOf<String>()
        var currentStatus: ClientStatus? = null
        private var verifyOk = true

        override suspend fun preflight(switchId: String, planFields: Map<String, String>): ClientResult {
            calls += "preflight"
            return ClientResult(true)
        }

        override suspend fun begin(switchId: String, planFields: Map<String, String>,
                                   superuserJson: File, settingsMirrorJson: File): ClientResult {
            calls += "begin"
            currentStatus = snapshotStatus(switchId)
            return ClientResult(true)
        }

        override suspend fun snapshot(switchId: String): ClientResult {
            calls += "snapshot"
            return ClientResult(true, status = snapshotStatus(switchId))
        }

        override suspend fun exportImage(switchId: String, kind: String, partition: String,
                                         destination: File): Boolean {
            calls += "exportImage"
            destination.parentFile?.mkdirs()
            destination.writeBytes(ByteArray(4096) { 'I'.code.toByte() })
            return true
        }

        override suspend fun submitCandidate(switchId: String, partition: String,
                                             candidate: File, candidateSha256: String): ClientResult {
            calls += "submitCandidate"
            return ClientResult(true)
        }

        override suspend fun commit(switchId: String): ClientResult {
            calls += "commit"
            currentStatus = rebootRequiredStatus(switchId)
            return ClientResult(true, status = currentStatus)
        }

        override suspend fun rollback(switchId: String): ClientResult = ClientResult(true)
        override suspend fun abort(switchId: String): ClientResult = ClientResult(true)
        override fun status(switchId: String): ClientStatus? = currentStatus
        override suspend fun verify(switchId: String): ClientResult =
            ClientResult(verifyOk, status = if (verifyOk) currentStatus else null)
        override suspend fun markRebootRequested(switchId: String): Boolean {
            calls += "markReboot"
            return true
        }
        override suspend fun exportLog(switchId: String, destination: File): File? = destination

        companion object {
            fun rebootRequiredStatus(switchId: String = UUID.randomUUID().toString()) = ClientStatus(
                switchId, "REBOOT_REQUIRED", "S4", "4g", "LITE", "KSU", "", "", "a".repeat(64),
                true, false, true, false, 0, partitions(),
            )

            fun snapshotStatus(switchId: String) = ClientStatus(
                switchId, "SNAPSHOT", "S2", "snapshot", "LITE", "KSU", "", "", "", false, false,
                false, false, 0, partitions(),
            )

            private fun partitions() = listOf(
                ClientPartition("boot", "RESTORE_BASELINE", 4096,
                    "p".repeat(64), "t".repeat(64), "", "PENDING"),
                ClientPartition("init_boot", "WRITE_CANDIDATE", 4096,
                    "q".repeat(64), "u".repeat(64), "", "PENDING"),
            )
        }
    }
}
