package dev.maplesu.manager.runtime.ultra

import java.io.File
import org.junit.Assert.*
import org.junit.Test

class UltraForegroundRecoveryWiringTest {
    private fun source(path: String): String = listOf(File("src/main/java/$path"),
        File("manager/src/main/java/$path")).first { it.isFile }.readText()

    @Test fun startupAndForegroundUseTheSameRecoveryQueue() {
        val app = source("com/maplesu/core/KernelSUApplication.kt")
        assertTrue(app.contains("fun requestUltraRecovery()"))
        assertTrue(app.contains("UltraRecoveryRequests("))
        assertTrue(app.contains("warmup = { requestUltraRecovery() }"))
        val request = app.substringAfter("fun requestUltraRecovery()")
            .substringBefore("private suspend fun recoverUltraEnvironment()")
        assertTrue(request.contains("Application.getProcessName() != packageName"))
        assertTrue(request.contains("!isUserUnlocked()"))
        assertTrue(request.contains("ultraRecoveryRequests.request()"))
        assertFalse(request.contains("Thread.sleep"))
    }

    @Test fun boundForegroundRecoveryResumesPublicationIndependentlyOfModuleReadiness() {
        val recovery = source("com/maplesu/core/KernelSUApplication.kt")
            .substringAfter("private suspend fun recoverUltraEnvironment()")
            .substringBefore("override fun onCreate()")
        assertTrue(recovery.contains("if (warmup.ran && dev.maplesu.manager.runtime.ultra.UltraSdkSession.current(this) != null)"))
        val publish = recovery.substringAfter("if (warmup.ran &&")
            .substringBefore("if (warmup.paired &&")
        assertTrue(publish.contains("ensureActive()"))
        assertTrue(publish.contains("RuntimeDeployment.resumeBootSdk(this)"))
    }

    @Test fun everyActivityResumeRequestsRecoveryEvenAwayFromHome() {
        val resume = source("com/maplesu/core/ui/MainActivity.kt")
            .substringAfter("override fun onResume()")
            .substringBefore("private val managerRestoreConfirmation")
        assertTrue(resume.contains("ksuApp.requestUltraRecovery()"))
    }

    @Test fun eachRecoveryWriteBoundaryChecksTheCallingCoroutine() {
        val recovery = source("com/maplesu/core/KernelSUApplication.kt")
            .substringAfter("private suspend fun recoverUltraEnvironment()")
            .substringBefore("override fun onCreate()")
        assertTrue(recovery.contains("recoveryContext.ensureActive()"))
        for (callback in listOf("setupEnvironment", "pairEnvironment", "recoverIdentity", "retryDetection")) {
            val body = recovery.substringAfter("$callback = {").trimStart()
            assertTrue("$callback must stop before its next action", body.startsWith("ensureActive()"))
        }
    }

    @Test fun cancellationAndInterruptAreNotConvertedIntoAnOrdinaryFailedPass() {
        val recovery = source("com/maplesu/core/KernelSUApplication.kt")
            .substringAfter("private suspend fun recoverUltraEnvironment()")
            .substringBefore("override fun onCreate()")
        assertTrue(recovery.contains("if (error is java.util.concurrent.CancellationException) throw error"))
        assertTrue(recovery.contains("if (error is InterruptedException)"))
        assertTrue(recovery.contains("Thread.currentThread().interrupt()"))
        assertTrue(recovery.contains("initCause(error)"))
        assertTrue(recovery.contains("if (error !is Exception) throw error"))
        assertEquals(4, Regex("onFailure \\{ failed\\(").findAll(recovery).count())
    }
}
