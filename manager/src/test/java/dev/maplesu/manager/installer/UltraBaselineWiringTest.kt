package dev.maplesu.manager.installer

import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/** Keeps the original-image gate ahead of the irreversible installer boundary. */
class UltraBaselineWiringTest {
    @Test
    fun directInstallPublishesOriginalsBeforePreparingOrWriting() {
        val module = if (File("src/main").isDirectory) File(".") else File("manager")
        val source = File(module, "src/main/java/com/maplesu/core/ui/util/UltraKernelInstall.kt").readText()
        val body = source.substringAfter("internal fun ultraDirectInstall(")
            .substringBefore("internal fun ultraImageBuildCandidate(")
        val ensure = body.indexOf("baselineProvisioner.ensureBaseline()")
        val backup = body.indexOf("flow.backupCurrentBoot()")
        val prepare = body.indexOf("flow.prepare(")
        val write = body.indexOf("InstallerServiceClient.installBoot(")
        assertTrue("baseline must be ready before transaction backup", ensure >= 0 && backup > ensure)
        assertTrue("prepare must follow the baseline gate", prepare > ensure)
        assertTrue("write must follow both baseline and rollback backup", write > prepare && write > backup)
        val gate = body.substring(ensure, backup)
        assertTrue(gate.contains("is BaselineProvisionOutcome.Failed"))
        assertTrue(gate.contains("return FlashResult(1, message, false, FlashOutcome.FAILED)"))
        assertTrue(body.contains("requiredPartitions = observed.partitions.keys.intersect(setOf(\"boot\", \"init_boot\"))"))
    }
}
