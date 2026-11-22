package dev.maplesu.manager.jailbreak

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * S04 launcher: the launch line must be predictable and must not be able to carry
 * a second command. It replaces the shell with the executor, so it is written once
 * per attempt and owns the lease transport afterwards.
 */
class JailbreakDaemonCommandTest {
    private val apk = "/data/app/~~abc/dev.maplesu.manager-1/base.apk"

    @Test fun launchesTheExecutorInPlaceOfTheShell() {
        val command = JailbreakDaemonCommand.launch(apk, "dev.maplesu.manager:root:0", 10481)
        assertEquals(
            "unset LD_LIBRARY_PATH; export CLASSPATH=$apk; exec app_process64" +
                " -Xnoimage-dex2oat /system/bin --nice-name=dev.maplesu.manager:root:0 " +
                "dev.maplesu.manager.runtime.JailbreakDaemonMain 10481",
            command,
        )
        assertTrue("the launcher must replace itself", command.contains(" exec app_process64 "))
        assertTrue("the executor needs the APK on CLASSPATH",
            command.contains("export CLASSPATH=$apk;"))
    }

    @Test fun refusesAnythingThatCouldBreakOutOfOneCommand() {
        for (value in listOf("$apk;id", "$apk\nid", "$apk\$(id)", "$apk --arg", "relative/base.apk")) {
            assertThrows(IllegalArgumentException::class.java) {
                JailbreakDaemonCommand.launch(value, "dev.maplesu.manager:root:0", 10481)
            }
        }
        for (name in listOf("", " ", "a b", "a;b", "a\nb")) {
            assertThrows(IllegalArgumentException::class.java) {
                JailbreakDaemonCommand.launch(apk, name, 10481)
            }
        }
        assertThrows(IllegalArgumentException::class.java) {
            JailbreakDaemonCommand.launch(apk, "dev.maplesu.manager:root:0", 0)
        }
    }

    @Test fun keepsTheExecutorIdentity() {
        assertEquals("dev.maplesu.manager.runtime.JailbreakDaemonMain",
            JailbreakDaemonCommand.MAIN_CLASS)
        assertTrue(JailbreakDaemonCommand.launch(apk, "dev.maplesu.manager:root:0", 10481)
            .contains(" --nice-name=dev.maplesu.manager:root:0 "))
    }
}
