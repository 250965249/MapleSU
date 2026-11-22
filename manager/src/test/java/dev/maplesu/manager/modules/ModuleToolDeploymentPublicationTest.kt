package dev.maplesu.manager.modules

import dev.maplesu.manager.runtime.ultra.NativeReceipt
import dev.maplesu.manager.runtime.ultra.UltraPolicyBackendDeployment
import dev.maplesu.manager.runtime.ultra.SuExecResult
import java.io.File
import java.net.URLDecoder
import java.nio.file.Files
import java.util.concurrent.TimeUnit
import org.junit.Assert.*
import org.junit.Test

class ModuleToolDeploymentPublicationTest {
    @Test fun productionScriptPublishesTwiceAndKeepsUnchangedBinaries() = fixture { directory ->
        val first = publish(directory)
        assertNull(first.first)
        assertTrue(first.second.contains("MAPLESU_TOOL_HOST:updated "))
        val second = publish(directory)
        assertNull(second.first)
        for (name in listOf("HOST", "POLICY", "BUSYBOX")) {
            assertTrue(second.second.contains("MAPLESU_TOOL_$name:unchanged "))
        }
    }

    @Test fun sourceAndLabelFailuresReportTheExactStage() = fixture { directory ->
        val labelFailure = publish(directory, 9)
        assertEquals("MODULE_TOOLS_EXIT:9:host-publish", labelFailure.first)
        assertNull(publish(directory).first)
        assertEquals(2, File(directory, "labels").readLines().count { it.endsWith("/maplesu-tools") })
        assertTrue(File(directory, "apk/libmaplesu_tools.so").delete())
        assertEquals("MODULE_TOOLS_EXIT:1:host-source", publish(directory).first)
    }

    @Test fun matchingBytesStillRepairInterruptedBinaryPermissions() = fixture { directory ->
        assertNull(publish(directory).first)
        assertNull(publish(directory, before = "chmod 0600 /fixture/adb/maplesu/bin/maplesu-tools " +
            "/fixture/adb/maplesu/bin/maplesu-policy /fixture/adb/maplesu/bin/busybox").first)
    }

    @Test fun publicationNeverLeaksItsExitTrapOrSetEIntoTheCallingShell() = fixture { directory ->
        assertEquals("MODULE_TOOLS_EXIT:17", publish(directory, after = "exit 17").first)
        assertNull(publish(directory, after = "false\nprintf 'CALLER_CONTINUES\\n'").first)
    }

    @Test fun firstInstallPreparesTheNativeBackendRegardlessOfInheritedUmask() {
        for (mask in listOf("0000", "0002", "0022", "0077", "0777")) fixture { directory ->
            val prepared = publish(directory, before = "$compileBackendVerifier\numask $mask", after = verifyBackend)
            assertNull("First install with inherited umask=$mask\n${prepared.second}", prepared.first)
            assertTrue(prepared.second.contains("MAPLESU_BACKEND_PREPARATION:result=0 adb_mode=700"))
            assertTrue(prepared.second.contains("CALLER_UMASK:$mask"))
        }
    }

    @Test fun retryRepairsTheRootOwnedParentCreatedByAnEarlierFailedInstallation() {
        for (mode in listOf("0777", "0770", "0755")) fixture { directory ->
            val prepared = publish(directory, before = """
                $compileBackendVerifier
                mkdir /fixture/adb
                chmod $mode /fixture/adb
                printf preserved >/fixture/adb/existing
                umask 0077
            """.trimIndent(), after = verifyBackend)
            assertNull("Existing root-owned adb mode=$mode\n${prepared.second}", prepared.first)
            assertTrue(prepared.second.contains("MAPLESU_BACKEND_PREPARATION:result=0 adb_mode=700"))
            assertEquals("preserved", File(directory, "adb/existing").readText())
            assertNull(publish(directory, after = verifyBackend).first)
        }
    }

    @Test fun sharedParentLinksForeignOwnersAndFilesAreRejectedBeforeToolPublication() {
        for (setup in listOf(
            "mkdir /fixture/other; ln -s /fixture/other /fixture/adb",
            "mkdir /fixture/adb; chown 10315:10315 /fixture/adb; test \"\$(stat -c %u /fixture/adb)\" = 10315 || exit 91",
            "printf 'existing' >/fixture/adb",
        )) fixture { directory ->
            val rejected = publish(directory, before = setup)
            assertEquals(rejected.second, "MODULE_TOOLS_EXIT:1:directories", rejected.first)
            assertFalse(rejected.second.contains("MAPLESU_TOOL_HOST:"))
            assertFalse(File(directory, "adb/maplesu").exists())
        }
    }

    private val compileBackendVerifier = """
        c++ -std=c++17 -UNDEBUG -Wall -Wextra -Werror \
          -I/runtime/maplesu-sdk/include -I/runtime/ultra/policy \
          '-DMAPLESU_POLICY_DIRECTORY="/fixture"' \
          /runtime/ultra/upgrade/executable_publish.cpp /runtime/ultra/policy/backend_publish.cpp \
          /runtime/tests/policy_backend_preparation_test.cpp \
          -Wl,--wrap=fsetxattr -Wl,--wrap=fgetxattr -o /fixture/backend-preparation-test
    """.trimIndent()

    private val verifyBackend = """
        deployment_exit=${'$'}?
        [ "${'$'}deployment_exit" -eq 0 ] || exit "${'$'}deployment_exit"
        printf 'CALLER_UMASK:%s\n' "${'$'}(umask)"
        /fixture/backend-preparation-test
    """.trimIndent()

    private fun publish(directory: File, labelExit: Int = 0, before: String = "", after: String = ""): Pair<String?, String> {
        // The complete production script runs in Linux. Only Android paths and
        // SELinux labeling are fixture boundaries; file operations and links are real.
        val script = ModuleToolDeployment.script("/fixture/apk", "#!/system/bin/sh\nexit 0\n",
            "#!/system/bin/sh\nprintf '%s\\n' \"\$*\"\n")
            .replace(File("/fixture/apk/libmaplesu_tools.so").absolutePath, "/fixture/apk/libmaplesu_tools.so")
            .replace("/data/adb", "/fixture/adb")
            .replace("/system/bin/chcon", "/fixture/chcon")
            .replace("/system/bin/", "/usr/bin/")
        File(directory, "chcon").writeText("#!/bin/sh\nprintf '%s\\n' \"\$2\" >>/fixture/labels\nexit $labelExit\n")
        var output = ""
        val failure = UltraPolicyBackendDeployment.prepareTools("$script\n$after", { command ->
            File(directory, "run.sh").writeText("chmod +x /fixture/chcon\n$before\n$command 2>&1\n")
            val process = ProcessBuilder("docker", "run", "--rm", "--pull", "never", "--network", "none",
                "--mount", "type=bind,source=${directory.absolutePath},target=/fixture",
                "--mount", "type=bind,source=${File("../runtime").canonicalPath},target=/runtime,readonly",
                "ghcr.io/ylarod/ddk-min:android15-6.6-20260828", "/bin/sh", "/fixture/run.sh")
                .redirectErrorStream(true).redirectOutput(File(directory, "process.log")).start()
            // Docker startup and verifier compilation are part of the host fixture.
            val completed = process.waitFor(60, TimeUnit.SECONDS)
            if (!completed) process.destroyForcibly().waitFor(5, TimeUnit.SECONDS)
            output = File(directory, "process.log").readText()
            assertTrue("The production publication script did not complete\n$output", completed)
            assertEquals(output, 0, process.exitValue())
            NativeReceipt.rootCommand(SuExecResult(0, output))
        }, { it?.let { value -> URLDecoder.decode(value, "UTF-8") } })
        return failure to output
    }

    private fun fixture(run: (File) -> Unit) {
        val directory = Files.createTempDirectory("maplesu-tool-publication-").toFile()
        try {
            val apk = File(directory, "apk").also { assertTrue(it.mkdir()) }
            File(apk, "libmaplesu_tools.so").writeText("#!/bin/sh\nprintf 'resetprop fixture\\n'\n")
            File(apk, "libmaplesu_policy.so").writeText("policy fixture\n")
            File(apk, "libmaplesu_busybox.so").writeText("busybox fixture\n")
            run(directory)
        } finally {
            assertTrue(directory.deleteRecursively())
        }
    }
}
