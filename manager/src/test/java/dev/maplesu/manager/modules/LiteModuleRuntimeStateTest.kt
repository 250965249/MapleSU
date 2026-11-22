package dev.maplesu.manager.modules

import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.util.Properties

class LiteModuleRuntimeStateTest {
    @Test fun blockedPolicyIsTerminalUntilTheNextBootWithoutReportingSuccess() {
        val status = LiteModuleRuntimeState.policyStageStatus(LiteModuleRuntimeState.POLICY_DISABLED_EXIT)
        assertEquals("skipped", status)
        assertEquals("ok", LiteModuleRuntimeState.policyStageStatus(0))
        assertEquals("failed", LiteModuleRuntimeState.policyStageStatus(1))
        assertEquals("failed", LiteModuleRuntimeState.policyStageStatus(75))
        val state = LiteModuleRuntimeState(installed).withStage("policy", current, status,
            LiteModuleRuntimeState.POLICY_DISABLED_EXIT)
        val file = temporary.newFile()
        state.save(file)
        val reloaded = LiteModuleRuntimeState.read(file)
        assertEquals(state, reloaded)
        assertTrue(reloaded.pendingStages(current, true, listOf("policy")).isEmpty())
        assertEquals(listOf("policy"), reloaded.pendingStages(
            "00000000-0000-0000-0000-000000000003", true, listOf("policy")))
    }

    @org.junit.Test fun nextBootHintRequiresAChangeInThisBootAndBootWork() {
        val boot = "11111111-1111-1111-1111-111111111111"
        val previous = "22222222-2222-2222-2222-222222222222"
        org.junit.Assert.assertTrue(LiteModuleRuntimeState(boot).needsReboot(boot, true, true))
        org.junit.Assert.assertFalse(LiteModuleRuntimeState(previous).needsReboot(boot, true, true))
        org.junit.Assert.assertFalse(LiteModuleRuntimeState(boot).needsReboot(boot, false, true))
        org.junit.Assert.assertFalse(LiteModuleRuntimeState(boot).needsReboot(boot, true, false))
        org.junit.Assert.assertFalse(LiteModuleRuntimeState(boot, remove = true).needsReboot(boot, true, true))
    }

    @get:Rule val temporary = TemporaryFolder()
    private val installed = "00000000-0000-0000-0000-000000000001"
    private val current = "00000000-0000-0000-0000-000000000002"

    @Test fun receiptDoesNotDeclareZygiskPermanentlyUnsupported() {
        val file = temporary.newFile()
        LiteModuleRuntimeState(installed).save(file)
        val values = Properties().apply { file.inputStream().use { load(it) } }
        assertEquals("", values.getProperty("unsupported"))
    }

    @Test fun zygiskPayloadNeedsARunningProvider() {
        assertEquals(listOf("zygisk"), LiteModuleRuntimeState.unsupportedCapabilities(true, false))
        assertTrue(LiteModuleRuntimeState.unsupportedCapabilities(true, true).isEmpty())
    }

    @Test fun ordinaryScriptDoesNotRequireAZygiskHost() {
        assertTrue(LiteModuleRuntimeState.unsupportedCapabilities(false, false).isEmpty())
        assertTrue(LiteModuleRuntimeState.unsupportedCapabilities(false, true).isEmpty())
    }

    @Test fun configuredModuleNeedsANewBootAndCannotRepeatAnObservedStage() {
        val state = LiteModuleRuntimeState(installed)
        assertTrue(state.pendingStages(installed, true, listOf("service")).isEmpty())
        assertTrue(state.pendingStages(current, false, listOf("service")).isEmpty())
        assertEquals(listOf("service"), state.pendingStages(current, true, listOf("service")))
        val queued = state.withStage("service", current, "queued")
        assertTrue(queued.pendingStages(current, true, listOf("service")).isEmpty())
        assertTrue(queued.withStage("service", current, "failed", 37)
            .pendingStages(current, true, listOf("service")).isEmpty())
    }

    @Test fun removalIsDeferredAndExecutionReceiptsSurviveReopening() {
        val state = LiteModuleRuntimeState(installed, remove = true, removeRequestedBootId = installed)
            .withStage("action", installed, "failed", 37)
        assertTrue(state.pendingStages(installed, true, listOf("service")).isEmpty())
        assertEquals(listOf("uninstall"), state.pendingStages(current, false, listOf("service")))
        val file = temporary.newFile()
        state.save(file)
        assertEquals(state, LiteModuleRuntimeState.read(file))
        assertEquals(37, LiteModuleRuntimeState.read(file).stages["action"]?.exitCode)
    }

    @Test fun explicitDiskRemovalBindsTheDirectoryAndDoesNotAuthorizeBootScripts() {
        val state = LiteModuleRuntimeState(installed, remove = true, removeRequestedBootId = installed,
            removalIdentity = "65111:300")
        val file = temporary.newFile()
        state.save(file)
        assertEquals(state, LiteModuleRuntimeState.read(file))
        assertTrue(state.pendingStages(installed, true, listOf("service")).isEmpty())
        assertEquals(listOf("uninstall"), state.pendingStages(current, false, listOf("service")))
        assertTrue(state.copy(remove = false).pendingStages(current, true, listOf("service")).isEmpty())
    }

    @Test fun uninstallCanBeCancelledUntilTheScriptActuallyStarts() {
        val state = LiteModuleRuntimeState(installed, remove = true)
        assertTrue(state.withStage("uninstall", current, "queued").canCancelRemoval(current))
        for (status in listOf("running", "started", "ok")) {
            assertFalse(state.withStage("uninstall", current, status).canCancelRemoval(current))
        }
        assertTrue(state.withStage("uninstall", current, "failed").canCancelRemoval(current))
    }

    @Test fun acknowledgedBackgroundStageSurvivesReopeningWithoutClaimingExitOrReplaying() {
        val state = LiteModuleRuntimeState(installed)
            .withStage("service", current, "started", detail = "Background launch acknowledged")
        val file = temporary.newFile()
        state.save(file)
        val reopened = LiteModuleRuntimeState.read(file)
        assertEquals(state, reopened)
        assertNull(reopened.stages["service"]?.exitCode)
        assertTrue(reopened.pendingStages(current, true, listOf("service")).isEmpty())
    }

    @Test fun servicePrecedesBootCompletedEvenWhenTheArchiveListsCompletionFirst() {
        val state = LiteModuleRuntimeState(installed)
        assertEquals(listOf("service", "boot-completed"),
            state.pendingStages(current, true, listOf("boot-completed", "service")))
        assertEquals(listOf("boot-completed"), state.withStage("service", current, "succeeded", 0)
            .pendingStages(current, true, listOf("boot-completed", "service")))
    }

    @Test fun propertiesAreAppliedAfterPostFsDataAndBeforeMetamoduleMounting() {
        val stages = LiteModuleRuntimeState.bootStageOrder
        assertTrue(stages.indexOf("post-fs-data") < stages.indexOf("props"))
        assertTrue(stages.indexOf("props") < stages.indexOf("mount"))
        assertTrue(stages.indexOf("mount") < stages.indexOf("post-mount"))
    }
}
