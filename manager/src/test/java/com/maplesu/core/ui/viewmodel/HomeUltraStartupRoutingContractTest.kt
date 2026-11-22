package com.maplesu.core.ui.viewmodel

import java.io.File
import org.junit.Assert.assertTrue
import org.junit.Test

/** The Android VM must apply the same live-Ultra-first branch covered by detector tests. */
class HomeUltraStartupRoutingContractTest {
    @Test fun verifiedUltraIdentityKeepsTheLegacyRuntimeOutOfTemporaryProbeFailures() {
        val relative = "src/main/java/com/maplesu/core/ui/viewmodel/HomeViewModel.kt"
        val source = listOf(File(relative), File("manager/$relative")).first { it.isFile }.readText().replace("\r\n", "\n")
        val branch = source.substringAfter("ModeRuntime.runIfLite {").substringBefore("val ultraEnvironmentRunning")
        val ultra = branch.indexOf("UltraEnvironmentProbe.refresh(ksuApp, force = false) == UltraEnvironmentProbe.State.Running")
        val legacy = branch.indexOf("if (!ultraRunning && !UltraEnvironmentProbe.usesUltraBackend(ksuApp) &&\n                    !UltraEnvironmentProbe.isSafeMode(ksuApp) && MapleSuRuntime.refresh(ksuApp))")
        assertTrue("live SDK result must be read before legacy work", ultra >= 0 && legacy > ultra)
        assertTrue("a failed SDK refresh must still check verified identity", branch.contains(".getOrDefault(false)"))
    }
}
