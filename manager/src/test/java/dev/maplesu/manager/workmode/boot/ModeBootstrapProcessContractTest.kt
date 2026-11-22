package dev.maplesu.manager.workmode.boot

import java.io.File
import org.junit.Assert.*
import org.junit.Test

class ModeBootstrapProcessContractTest {
    @Test fun auxiliaryProcessesKeepLocalDetectionButDoNotStartRootProbesOrWriteManagerState() {
        val source = File("src/main/java/dev/maplesu/manager/workmode/boot/ModeBootstrap.kt").readText()
        assertTrue(source.contains("managerProcess = android.app.Application.getProcessName() == appContext.packageName"))
        assertTrue(source.contains("environmentOverride = if (managerProcess)"))
        assertTrue(source.contains("environmentStore = if (managerProcess)"))
        assertTrue(source.substringAfter("private fun executePhaseTwo(").substringBefore("val coordinator").contains("if (!managerProcess) return"))
        assertTrue(source.contains("coordinator.runPhaseOne()"))
    }
}
