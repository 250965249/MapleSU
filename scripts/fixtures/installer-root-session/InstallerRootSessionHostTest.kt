package dev.maplesu.manager.installer

import com.topjohnwu.superuser.Shell
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

/** Calls the actual discoverBootTarget -> read -> fromOutput chain without opening Root. */
class InstallerRootSessionHostTest {
    private fun session(slot: String, nodes: List<String>, code: Int = 0, uid: String = "0"): InstallerRootSession {
        val shell = Shell(mapOf(
            "id -u" to Shell.Result(0, listOf(uid), emptyList()),
            "getprop ro.boot.slot_suffix" to Shell.Result(0, listOf(slot), emptyList()),
            InstallerBootTarget.discoveryCommand(slot) to Shell.Result(code, nodes, emptyList()),
        ))
        val constructor = InstallerRootSession::class.java.getDeclaredConstructor(
            Shell::class.java, RootSource::class.java, KsuKernelProof::class.java)
        constructor.isAccessible = true
        return constructor.newInstance(shell, RootSource.EXPLICIT_SU, KsuKernelProof(0, 0))
    }

    @Test fun bothCurrentSlotPartitionsSurviveTheTransport() {
        session("_a", listOf("init_boot", "boot")).use {
            assertEquals(InstallerBootTarget("_a", setOf("boot", "init_boot")), it.discoverBootTarget())
        }
    }

    @Test fun bootOnlyRemainsValid() {
        session("_b", listOf("boot")).use {
            assertEquals(InstallerBootTarget("_b", setOf("boot")), it.discoverBootTarget())
        }
    }

    @Test fun initBootOnlyRetainsTheMissingBootError() {
        session("_a", listOf("init_boot")).use {
            assertEquals("INSTALLER_BLOCK_DEVICE_REQUIRED",
                assertThrows(IllegalStateException::class.java) { it.discoverBootTarget() }.message)
        }
    }

    @Test fun unslottedDiscoveryKeepsBothPartitions() {
        session("", listOf("init_boot", "boot")).use {
            assertEquals(InstallerBootTarget("", setOf("boot", "init_boot")), it.discoverBootTarget())
        }
    }

    @Test fun emptyOutputLinesDoNotMergePartitionNames() {
        session("_a", listOf("init_boot", "", "boot")).use {
            assertEquals(setOf("boot", "init_boot"), it.discoverBootTarget().availablePartitions)
        }
    }

    @Test fun nonzeroDiscoveryExitStillFailsBeforeParsingOutput() {
        session("_a", listOf("init_boot", "boot"), code = 7).use {
            assertEquals("INSTALLER_READ_FAILED: ${InstallerBootTarget.discoveryCommand("_a")}",
                assertThrows(IllegalStateException::class.java) { it.discoverBootTarget() }.message)
        }
    }

    @Test fun nonRootIdentityStillFailsBeforeDiscovery() {
        session("_a", listOf("boot"), uid = "2000").use {
            assertEquals("INSTALLER_ROOT_REQUIRED",
                assertThrows(IllegalStateException::class.java) { it.discoverBootTarget() }.message)
        }
    }
}
