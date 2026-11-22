package dev.maplesu.manager.workmode.service

import dev.maplesu.manager.installer.BootPartitionIdentity
import dev.maplesu.manager.installer.BootPartitionSnapshot
import dev.maplesu.manager.installer.InstallerSnapshot
import dev.maplesu.manager.installer.InstallerSnapshotParser
import dev.maplesu.manager.workmode.TestFixtures
import dev.maplesu.manager.workmode.WorkMode
import dev.maplesu.manager.workmode.switch.ModeSwitchCodes
import dev.maplesu.manager.workmode.switch.ModeSwitchRequest
import dev.maplesu.manager.workmode.switch.RecordingSwitchJournal
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.UUID

class LocalInstallerGatewayPartitionTest {
    private val gateway = LocalInstallerGateway(TestFixtures.tempDir("local-carriers").toFile()) {
        RecordingSwitchJournal()
    }

    private fun snapshot(vararg names: String) = InstallerSnapshot(
        "5.10.198-android12-8-test", "fw-1", "_a", "Enforcing",
        names.associateWith { name -> BootPartitionSnapshot(name,
            InstallerSnapshotParser.partitionPath(name, "_a"), "/dev/block/sde$name", 4096,
            "a".repeat(64), BootPartitionIdentity(1, 2, 3)) },
    )

    private fun request(from: WorkMode = WorkMode.LITE, target: String? = null, source: String? = null) =
        ModeSwitchRequest(UUID.randomUUID().toString(), from,
            if (from == WorkMode.LITE) WorkMode.KSU else WorkMode.LITE, "bl-1",
            targetPartition = target, sourcePartition = source)

    @Test
    fun android12WithOnlyBootPassesActualGatewayPreflight() {
        val result = gateway.preflight(request(), snapshot("boot"))
        assertTrue("${result.code}/${result.detail}", result.ok)
        assertEquals(setOf("boot"), result.partitionInventory!!.present)
    }

    @Test
    fun explicitMissingInitBootIsRejected() {
        val result = gateway.preflight(request(target = "init_boot"), snapshot("boot"))
        assertEquals(ModeSwitchCodes.LAYOUT_UNSUPPORTED, result.code)
        assertEquals("init_boot", result.detail)
    }

    @Test
    fun knownMissingSourceIsRejectedInsteadOfChangingIt() {
        val result = gateway.preflight(request(WorkMode.KSU, "boot", "init_boot"), snapshot("boot"))
        assertEquals(ModeSwitchCodes.LAYOUT_UNSUPPORTED, result.code)
        assertEquals("init_boot", result.detail)
    }

    @Test
    fun unknownSourceUsesExistingBootAndStillRequiresBoot() {
        assertTrue(gateway.preflight(request(WorkMode.KSU), snapshot("boot")).ok)
        assertEquals("boot-missing", gateway.preflight(request(), snapshot("init_boot")).detail)
    }
}
