package dev.maplesu.manager.modules

import org.junit.Assert.*
import org.junit.Test

class RootModuleTreeTest {
    @Test fun onlySnapshotsUseTheReadOnlyTransportAndMutationsKeepTheirOriginalRunner() {
        var reads = 0
        var commands = 0
        val runner = object : ModuleScriptRunner {
            override fun run(script: String): ModuleScriptOutput {
                commands++
                return ModuleScriptOutput(0, "MAPLESU_SNAPSHOT_OK\n")
            }
            override fun readSnapshot(script: String): ModuleScriptOutput {
                reads++
                assertTrue(script.contains("MAPLESU_SNAPSHOT_OK"))
                return ModuleScriptOutput(0, "D\tfixture\nMAPLESU_SNAPSHOT_OK\n")
            }
        }
        val tree = RootModuleTree(runner)
        assertTrue(tree.snapshot(listOf("fixture")).getValue("fixture").directory)
        assertEquals(1, reads)
        assertEquals(0, commands)
        tree.marker("fixture", "remove", true)
        assertEquals(1, reads)
        assertEquals(1, commands)
    }

    @Test fun failedSnapshotTransportIsNotRetriedThroughTheCommandRunner() {
        var commands = 0
        val tree = RootModuleTree(object : ModuleScriptRunner {
            override fun run(script: String): ModuleScriptOutput {
                commands++
                return ModuleScriptOutput(0, "MAPLESU_SNAPSHOT_OK\n")
            }
            override fun readSnapshot(script: String) = ModuleScriptOutput(-1, err = "SDK_BUSY")
        })
        val error = assertThrows(IllegalStateException::class.java) { tree.snapshot(listOf("fixture")) }
        assertTrue(error.message!!.contains("SDK_BUSY"))
        assertEquals(0, commands)
    }

    @Test fun snapshotDoesNotStartAnExternalFormatterForEveryModuleRow() {
        val tree = RootModuleTree(ModuleScriptRunner { script ->
            val perModule = script.substringAfter("read_module() {\n").substringBefore("\n}\n")
            assertFalse("Android mksh uses an external printf, making every row spawn a process", perModule.contains("printf "))
            ModuleScriptOutput(0, "MAPLESU_SNAPSHOT_OK\n")
        })
        tree.snapshot(listOf("fixture"))
    }

    @Test fun metamoduleInstallerAndUninstallerAreInventoriedFromRoot() {
        val tree = RootModuleTree(ModuleScriptRunner { script ->
            assertTrue(script.contains("'metainstall.sh'"))
            assertTrue(script.contains("'metauninstall.sh'"))
            ModuleScriptOutput(0, "D\tfixture\nF\tfixture\tmetainstall.sh\nF\tfixture\tmetauninstall.sh\nMAPLESU_SNAPSHOT_OK\n")
        })
        assertEquals(setOf("metainstall.sh", "metauninstall.sh"), tree.snapshot(listOf("fixture")).getValue("fixture").files)
    }

    @Test fun discoversNormalModulesWithoutAnUltraCatalogOrOwnerMarker() {
        val metadata = "id=normal_fixture\nname=Normal module\nversionCode=7\n"
        val hex = metadata.toByteArray().joinToString("") { "%02x".format(it.toInt() and 255) }
        val tree = RootModuleTree(ModuleScriptRunner { script ->
            assertTrue(script.contains("for d in '/data/adb/modules'/*"))
            ModuleScriptOutput(0, "D\tnormal_fixture\nF\tnormal_fixture\tmodule.prop\n" +
                "F\tnormal_fixture\tdisable\nI\tnormal_fixture\t1:300\nM\tnormal_fixture\t$hex\nMAPLESU_SNAPSHOT_OK\n")
        })
        val module = tree.snapshot(emptyList(), discover = true).getValue("normal_fixture")
        assertEquals(metadata, module.metadata)
        assertFalse(module.enabled)
        assertEquals("", module.revision)
        val report = dev.maplesu.manager.ModuleArchiveInspector.installedKsu("normal_fixture", metadata,
            module.identity, module.files, module.directories, module.zygisk)
        assertEquals("normal_fixture", report.id)
        assertEquals(7, report.versionCode)
        val changedDescription = dev.maplesu.manager.ModuleArchiveInspector.installedKsu("normal_fixture",
            metadata + "description=running\n", module.identity, module.files, module.directories, module.zygisk)
        assertEquals("Runtime descriptions must not rerun already completed stages", report.sha256, changedDescription.sha256)
    }

    @Test fun installedMetadataWithAnInvalidVersionRemainsOperable() {
        val report = dev.maplesu.manager.ModuleArchiveInspector.installedKsu("normal_fixture",
            "name=Existing module\nversionCode=not-a-number\n", "1:300", setOf("module.prop"), emptySet(), false)
        assertEquals("normal_fixture", report.id)
        assertEquals(0, report.versionCode)
    }

    @Test fun unfinishedTransactionIsDiscoveredEvenWhenPublicationHasNoDirectory() {
        val tree = RootModuleTree(ModuleScriptRunner {
            ModuleScriptOutput(0, "T\tfixture\nMAPLESU_SNAPSHOT_OK\n")
        })
        val state = tree.snapshot(emptyList(), discover = true).getValue("fixture")
        assertTrue(state.pendingTransaction)
        assertFalse(state.directory)
    }

    @Test fun rootSnapshotRemainsUsableWhenTheAppUidCannotStatTheTree() {
        val commands = mutableListOf<String>()
        val tree = RootModuleTree(ModuleScriptRunner { script ->
            commands += script
            ModuleScriptOutput(0, "D\tfixture\nF\tfixture\tmodule.prop\nF\tfixture\tcustomize.sh\n" +
                "F\tfixture\tdisable\nS\tfixture\tsystem\nZ\tfixture\nR\tfixture\t${"a".repeat(64)}\nMAPLESU_SNAPSHOT_OK\n")
        })
        val state = tree.snapshot(listOf("fixture")).getValue("fixture")
        assertTrue(state.directory)
        assertTrue("customize.sh" in state.files)
        assertTrue(state.zygisk)
        assertFalse(state.enabled)
        assertFalse(state.removed)
        assertEquals("a".repeat(64), state.revision)
        assertEquals(1, commands.size)
    }

    @Test fun missingRootReceiptIsAnErrorInsteadOfAnEmptyInstalledList() {
        val tree = RootModuleTree(ModuleScriptRunner { ModuleScriptOutput(0, "partial-output") })
        assertThrows(IllegalStateException::class.java) { tree.snapshot(listOf("fixture")) }
    }

    @Test fun toggleUsesKsuMarkersAndChecksTheResult() {
        val commands = mutableListOf<String>()
        val tree = RootModuleTree(ModuleScriptRunner { commands += it; ModuleScriptOutput(0) })
        tree.marker("fixture", "disable", true)
        tree.marker("fixture", "disable", false)
        tree.marker("fixture", "remove", true)
        assertTrue(commands[0].contains("/data/adb/modules/fixture/disable"))
        assertTrue(commands[0].contains("test -f"))
        assertTrue(commands[1].contains("test ! -e"))
        assertTrue(commands[2].contains("/data/adb/modules/fixture/remove"))
    }

    @Test fun failedMarkerWriteNeverReportsSuccess() {
        val tree = RootModuleTree(ModuleScriptRunner { ModuleScriptOutput(1, err = "permission denied") })
        assertThrows(IllegalStateException::class.java) { tree.marker("fixture", "disable", false) }
    }

    @Test fun invalidIdentityDoesNotSubmitAnyRootCommand() {
        var calls = 0
        val tree = RootModuleTree(ModuleScriptRunner { calls++; ModuleScriptOutput(0) })
        listOf("../foreign", "fixture/other", "fixture\nother", "/").forEach { id ->
            assertThrows(IllegalArgumentException::class.java) { tree.marker(id, "disable", true) }
        }
        assertThrows(IllegalArgumentException::class.java) { tree.marker("fixture", "module.prop", true) }
        assertEquals(0, calls)
    }
    @Test fun batchedMetadataPreservesEveryByteAndModuleBoundary() {
        val first = "id=first\nname=模块一\n\n"
        val second = "id=second\nname=Second module"
        val a = first.toByteArray(); val b = second.toByteArray()
        val hex = (a + b).joinToString("") { "%02x".format(it.toInt() and 255) }
        val tree = RootModuleTree(ModuleScriptRunner { script ->
            assertFalse("Per-module hex pipelines made the 49-module scan exceed the page deadline",
                script.substringAfter("read_module() {").substringBefore("\n}\n").contains("od -An"))
            ModuleScriptOutput(0, "D\tfirst\nB\tfirst\t${a.size}\nD\tsecond\nB\tsecond\t${b.size}\n" +
                "H\t$hex\nMAPLESU_SNAPSHOT_OK\n")
        })
        val modules = tree.snapshot(listOf("first", "second"))
        assertEquals(first, modules.getValue("first").metadata)
        assertEquals(second, modules.getValue("second").metadata)
    }

    @Test fun largeSnapshotMetadataDecodingHasBoundedAllocations() {
        val bean = java.lang.management.ManagementFactory.getThreadMXBean() as? com.sun.management.ThreadMXBean
        org.junit.Assume.assumeTrue(bean?.isThreadAllocatedMemorySupported == true)
        bean!!.isThreadAllocatedMemoryEnabled = true
        val metadata = "x".repeat(65536)
        val output = "D\tfixture\nB\tfixture\t65536\nH\t${"78".repeat(65536)}\nMAPLESU_SNAPSHOT_OK\n"
        val tree = RootModuleTree(ModuleScriptRunner { ModuleScriptOutput(0, output) })
        assertEquals(metadata, tree.snapshot(listOf("fixture")).getValue("fixture").metadata)
        val thread = Thread.currentThread().id
        val before = bean.getThreadAllocatedBytes(thread)
        val actual = tree.snapshot(listOf("fixture")).getValue("fixture").metadata
        val allocated = bean.getThreadAllocatedBytes(thread) - before
        assertEquals(metadata, actual)
        assertTrue("One 64 KiB metadata decode allocated $allocated bytes", allocated < 2_000_000)
    }

    @Test fun batchedMetadataKeepsStrictLowercaseAsciiHexValidation() {
        for (hex in listOf("AA", "gg", "Ａa", "a ", "a")) {
            val output = "D\tfixture\nB\tfixture\t1\nH\t$hex\nMAPLESU_SNAPSHOT_OK\n"
            val tree = RootModuleTree(ModuleScriptRunner { ModuleScriptOutput(0, output) })
            assertThrows(IllegalStateException::class.java) { tree.snapshot(listOf("fixture")) }
        }
    }

    @Test fun truncatedBatchedMetadataNeverPublishesAnIncompleteInventory() {
        val tree = RootModuleTree(ModuleScriptRunner {
            ModuleScriptOutput(0, "D\tfixture\nB\tfixture\t32\nH\t6162\nMAPLESU_SNAPSHOT_OK\n")
        })
        assertThrows(IllegalStateException::class.java) { tree.snapshot(listOf("fixture")) }
    }

}
