package dev.maplesu.manager.installer

import java.io.File
import org.junit.Assert.*
import org.junit.Test

class InstallerStatusReconciliationWiringTest {
    @Test fun statusReconcilesInterruptedTransactionsBeforeReturningTheirState() {
        val service = File("src/main/java/dev/maplesu/manager/installer/InstallerPartitionService.kt").readText()
        val status = service.substringAfter("override fun getBootInstall(").substringBefore("override fun verifyBootInstall(")
        val reconcile = status.indexOf("NativeInstallTransaction.reconcileForStatus()")
        assertTrue("Installation status still returns a stale RECOVERY_REQUIRED record", reconcile >= 0)
        assertTrue(reconcile < status.indexOf("NativeInstallTransaction.status(taskId)"))
        assertTrue("A live operation must exclude reconciliation", status.contains("if (!active)"))
    }

    @Test fun statusUsesTheDeviceLockAndPreservesUncommittedPreparations() {
        val transaction = File("src/main/java/dev/maplesu/manager/installer/NativeInstallTransaction.kt").readText()
        assertTrue(transaction.contains("fun reconcileForStatus() = locked {"))
        assertTrue(transaction.contains("reconcileInstallRecords(cancelPrepared = false)"))
    }
}
