package dev.maplesu.manager.litehidden

import org.junit.Assert.*
import org.junit.Test
import java.io.File

class UltraRecoveryBootTest {
    @Test fun ultraBootEntryWaitsForAndroidAndUsesIndependentRecovery() {
        val source = listOf(File("src/main/java/dev/maplesu/manager/runtime/ultra/UltraIdentityRecovery.kt"),
            File("manager/src/main/java/dev/maplesu/manager/runtime/ultra/UltraIdentityRecovery.kt"))
            .first(File::isFile).readText().substringAfter("private fun startScript()")
        assertTrue(source.indexOf("sys.boot_completed") < source.indexOf("UltraRecoveryBoot.content()"))
        assertTrue(source.indexOf("UltraRecoveryBoot.content()") < source.indexOf("exec /system/bin/app_process"))
        val script = UltraRecoveryBoot.content()
        assertTrue(script.contains("parasite-start.sh"))
        assertTrue(script.contains("webui.paused"))
        assertTrue(script.contains("lite_hidden"))
        assertTrue(script.contains("= LITE"))
        assertTrue(script.contains("disabled"))
        assertFalse(script.contains("am start"))
    }
}
