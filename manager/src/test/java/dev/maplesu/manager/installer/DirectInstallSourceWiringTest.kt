package dev.maplesu.manager.installer

import org.junit.Assert.*
import org.junit.Test
import java.io.File

/** Complements the executed flow tests: guards the production call sites that select its input. */
class DirectInstallSourceWiringTest {
    private fun source(path: String) = File("src/main/java/$path").readText()

    @Test fun selectingDirectInstallDoesNotInferRestorationFromManagerIdentity() {
        val screen = source("com/maplesu/core/ui/screen/install/InstallScreen.kt")
        val select = screen.substringAfter("onSelectMethod = { method ->").substringBefore("onSelectBootImage =")
        assertFalse(select.contains("managerInstalled != true || migrationEntry"))
        assertTrue(select.contains("restoreOriginalImage = false"))
        assertFalse(screen.contains("StockInstallPreflight.inspect("))
        assertFalse(screen.contains("restoreOriginalForInstall"))
        assertTrue(screen.contains("restoreOriginalImage = restoreOriginalImage"))
    }

    @Test fun allBootEntryDefaultsUseTheChosenImageOrCurrentPre() {
        val cli = source("com/maplesu/core/ui/util/KsuCli.kt")
        val requests = source("com/maplesu/core/ui/screen/flash/FlashUtils.kt")
        assertEquals(2, Regex("restoreOriginalImage: Boolean = false").findAll(cli).count())
        assertEquals(2, Regex("restoreOriginalImage: Boolean = false").findAll(requests).count())
        val upgrade = cli.substringAfter("internal fun installUltraKernelUpdate(").substringBefore("private class InstallBuildStopped")
        assertTrue(upgrade.contains("restoreOriginal = false"))
    }

    @Test fun normalRepatchUsesTheProducerWithoutAManagerOrMarkerGate() {
        val cli = source("com/maplesu/core/ui/util/KsuCli.kt")
        val producer = source("dev/maplesu/manager/ksu/KsuInstallProducer.kt")
        assertTrue(cli.contains("producer.produceCandidate(source"))
        assertFalse(cli.contains("allowKsuRepatch"))
        assertFalse(producer.contains("PRODUCE_SOURCE_ALREADY_PATCHED"))
        assertFalse(producer.contains("confirmedKsuRepatch"))
    }

    @Test fun explicitStockRestorationKeepsTheRootOwnedRestoreAction() {
        val cli = source("com/maplesu/core/ui/util/KsuCli.kt")
        val restore = cli.substringAfter("fun restoreBoot(").substringBefore("fun installBoot(")
        assertTrue(restore.contains("InstallerServiceClient.restoreStockImages(ksuApp, taskId)"))
        val preflight = source("dev/maplesu/manager/installer/StockInstallPreflight.kt")
        assertTrue(preflight.contains("fun discoverTarget("))
        assertFalse(preflight.contains("fun inspect("))
        assertFalse(preflight.contains("productionBaselineProvisioner"))
    }

    @Test fun ultraDirectInstallRechecksTheCarrierAndPreservesTheExplicitTarget() {
        val screen = source("com/maplesu/core/ui/screen/install/InstallScreen.kt")
        assertTrue(screen.contains("val requestedPartition = selectedPartition.wire"))
        assertTrue(screen.contains("resolvedUltraInstallAction(ultraAction, requestedPartition, observedCarrier"))

        val cli = source("com/maplesu/core/ui/util/KsuCli.kt")
        val selection = cli.substringAfter("val discoveredTarget =").substringBefore("val partitionResolution =")
        assertTrue(selection.contains("StockInstallPreflight.discoverTarget"))
        assertTrue(selection.contains("partition.isNullOrBlank() || requestedTarget == InstallTargetMode.ULTRA"))
        assertTrue(selection.contains("InstallerServiceClient.installedCarrierPartition"))
        assertTrue(selection.contains("artifact.targetBoot.length() == boot.size"))
        assertTrue(selection.contains("artifact.targetBootSha256.equals(boot.sha256"))
        assertTrue(cli.contains("partition = resolvedPartition"))
        assertTrue(cli.contains("requestedTarget, requireNotNull(resolvedPartition)"))
        assertTrue(cli.contains("initBootArtifact = ultraInitBootArtifact ?: automaticArtifact"))
        assertTrue(cli.contains("restoreOriginalImage || changesUltraCarrier"))

        val client = source("dev/maplesu/manager/installer/InstallerServiceClient.kt")
        assertTrue(client.contains("fun installedCarrierPartition(context: Context, observed: InstallerSnapshot): String?"))
        assertTrue(client.contains("installedCarrierPartition(context, observed) ?: \"boot\""))
        assertTrue(client.contains("recovery.installedSpec(image, receipts) != null"))
        assertTrue(client.contains("recovery.generatedKernelWithDeployment(image, receipts) != null"))
    }
}
