package dev.maplesu.manager.ksu

import java.io.File
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class NormalBootUserlandTest {
    @get:Rule val temporary = TemporaryFolder()

    private inner class Fixture {
        val libraries = temporary.newFolder("libraries")
        val data = temporary.newFolder("data-adb")
        val daemon = File(libraries, KsuCommands.DAEMON_LIB_NAME).apply { writeText("bundled-ksud") }
        val library = File(libraries, KsuBootstrap.LIBADBROOT_NAME).apply { writeText("bundled-adbroot") }
        val sha = KsuInstallProducer.sha256(daemon)
        val librarySha = KsuInstallProducer.sha256(library)
        val commands = mutableListOf<String>()
        var deployed = false
        var executable = true
        var installCode = 0
        var version = "MAPLESU_KSUD_BUILD_V1 version=32650 uapi=7"
        var busyboxCode = 0
        var wrongDigest = false
        var wrongLibraryDigest = false
        val runner = KsuRootCommandRunner { command, _ ->
            commands += command
            when {
                " install " in command -> {
                    if (installCode == 0) deployed = true
                    KsuShellResult(installCode, emptyList(), emptyList())
                }
                "/system/bin/mkdir" in command -> KsuShellResult(0, emptyList(), emptyList())
                "/system/bin/test" in command -> {
                    val present = deployed && (" -x " !in command || executable)
                    KsuShellResult(if (present) 0 else 1, if (present) listOf("MAPLESU_PROBE_OK") else emptyList(), emptyList())
                }
                "sha256sum" in command -> KsuShellResult(0,
                    listOf(if ("libadbroot.so" in command) {
                        if (wrongLibraryDigest) "0".repeat(64) else librarySha
                    } else if (wrongDigest) "0".repeat(64) else sha), emptyList())
                " debug build-info" in command -> KsuShellResult(0, listOf(version), emptyList())
                "busybox" in command && command.endsWith(" true") ->
                    KsuShellResult(busyboxCode, emptyList(), emptyList())
                else -> error("unexpected command: $command")
            }
        }
        fun ensure() = ensureNormalBootUserland(libraries, runner, dataAdbRoot = data)
    }

    @Test fun firstDeploymentUsesExistingRootAndStaticUserspaceIdentity() {
        val fixture = Fixture()
        val result = fixture.ensure()
        assertTrue(result.detail, result.ok)
        assertEquals(KsuBootstrapResult.Status.DEPLOYED, result.status)
        val install = fixture.commands.single { " install " in it }
        assertTrue(install.contains("--stage-for-switch"))
        assertTrue(install.contains(fixture.daemon.absolutePath))
        assertTrue(fixture.commands.none { " debug su" in it || " debug info" in it })
        assertTrue(fixture.commands.indexOfFirst { "/system/bin/mkdir" in it } < fixture.commands.indexOf(install))
    }

    @Test fun verifiedExistingDeploymentSkipsInstallation() {
        val fixture = Fixture().apply { deployed = true }
        assertEquals(KsuBootstrapResult.Status.ALREADY_PRESENT, fixture.ensure().status)
        assertTrue(fixture.commands.none { " install " in it || "/system/bin/mkdir" in it })
    }

    @Test fun installationFailureIsExplicit() {
        val fixture = Fixture().apply { installCode = 42 }
        assertEquals(KsuBootstrap.CODE_INSTALL_FAILED, fixture.ensure().failureCode)
    }

    @Test fun missingExecutionPermissionNeverProvesBootReadiness() {
        val fixture = Fixture().apply { deployed = true; executable = false }
        assertFalse(fixture.ensure().ok)
        assertTrue(fixture.commands.any { " install " in it })
    }

    @Test fun staticUapiDigestAndBusyboxFailuresPreventBootReadiness() {
        for (failure in listOf("uapi", "digest", "library-digest", "busybox")) {
            val fixture = Fixture().apply {
                if (failure == "uapi") version = "MAPLESU_KSUD_BUILD_V1 version=32650 uapi=6"
                if (failure == "digest") wrongDigest = true
                if (failure == "library-digest") { deployed = true; wrongLibraryDigest = true }
                if (failure == "busybox") busyboxCode = 139
            }
            assertFalse(failure, fixture.ensure().ok)
            temporary.root.listFiles().orEmpty().forEach { it.deleteRecursively() }
        }
    }
}
