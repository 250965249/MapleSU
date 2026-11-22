package dev.maplesu.manager.installer

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class NativeInstallSourceExportContractTest {
    @Test fun nativeSourceIsExportedThroughTheServiceCacheSnapshot() {
        val service = File("src/main/java/dev/maplesu/manager/installer/InstallerPartitionService.kt").readText()
        assertTrue(service.contains("NativeInstallTransaction.openImage(taskId, partition, meta, cacheDir)"))
        val transaction = File("src/main/java/dev/maplesu/manager/installer/NativeInstallTransaction.kt").readText()
        val export = transaction.substringAfter("fun openImage(").substringBefore("fun commit(")
        assertFalse(export.contains("ParcelFileDescriptor.open(source,"))
        assertTrue(export.contains("openReadOnlySnapshot(source, cacheDirectory"))
    }

    @Test fun readFailureKeepsItsStageInTheFlashResult() {
        val flow = File("src/main/java/dev/maplesu/manager/installer/StockInstallFlow.kt").readText()
        assertTrue(flow.contains("IllegalStateException(\"INSTALLER_SOURCE_READ_FAILED\", error)"))
        val cli = File("src/main/java/com/maplesu/core/ui/util/KsuCli.kt").readText()
        assertTrue(cli.contains("installerFailureDiagnostic(error, status?.getString(\"error\").orEmpty())"))
    }
}
