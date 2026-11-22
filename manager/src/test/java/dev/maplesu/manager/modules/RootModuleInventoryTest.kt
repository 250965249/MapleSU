package dev.maplesu.manager.modules

import java.io.File
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class RootModuleInventoryTest {
    @get:Rule val temporary = TemporaryFolder()

    @Test fun existingKsuModuleWithoutAnOwnerIsVisibleButNotAdoptedForExecution() {
        val (backend, receipts) = backend("")
        val entries = inventory(backend)
        assertEquals(setOf("normal_fixture"), entries.keys)
        assertTrue("Discovery must not authorize scripts", receipts.listFiles()!!.isEmpty())
        val entry = entries.values.single()!!
        val report = entry.javaClass.getDeclaredField("report").apply { isAccessible = true }.get(entry)
        assertEquals(false, backend.javaClass.getDeclaredMethod("owns", report.javaClass)
            .apply { isAccessible = true }.invoke(backend, report))
    }

    @Test fun alreadyAdoptedDiskModuleHasAnExecutionReceipt() {
        val (backend, receipts) = backend("a".repeat(64))
        assertEquals(setOf("normal_fixture"), inventory(backend).keys)
        assertEquals(1, receipts.listFiles()!!.size)
    }

    @Test fun invalidOwnerIsExcludedWithoutCreatingAnExecutionReceipt() {
        val (backend, receipts) = backend("INVALID_OWNER")
        assertTrue(inventory(backend).isEmpty())
        assertTrue(receipts.listFiles()!!.isEmpty())
    }

    private fun backend(owner: String): Pair<LiteScriptModuleBackend, File> {
        val type = LiteScriptModuleBackend::class.java
        val unsafe = sun.misc.Unsafe::class.java.getDeclaredField("theUnsafe").apply { isAccessible = true }
            .get(null) as sun.misc.Unsafe
        val backend = unsafe.allocateInstance(type) as LiteScriptModuleBackend
        fun field(name: String, value: Any) = type.getDeclaredField(name).apply { isAccessible = true }.set(backend, value)
        val metadata = "id=normal_fixture\nname=Existing KSU module\nversionCode=7\n"
        val hex = metadata.toByteArray().joinToString("") { "%02x".format(it.toInt() and 255) }
        field("catalog", ModuleCatalog(temporary.newFolder("catalog")))
        val receipts = temporary.newFolder("receipts")
        field("receipts", receipts)
        field("diskEntries", emptyMap<String, Any>())
        field("rootSnapshot", emptyMap<String, RootModuleTree.Snapshot>())
        field("rootTrees", RootModuleTree(ModuleScriptRunner {
            ModuleScriptOutput(0, "D\tnormal_fixture\nF\tnormal_fixture\tmodule.prop\n" +
                "F\tnormal_fixture\tservice.sh\nI\tnormal_fixture\t1:300\n" +
                (if (owner.isEmpty()) "" else "R\tnormal_fixture\t$owner\n") +
                "M\tnormal_fixture\t$hex\nMAPLESU_SNAPSHOT_OK\n")
        }))
        return backend to receipts
    }

    private fun inventory(backend: LiteScriptModuleBackend): Map<*, *> {
        val type = backend.javaClass
        type.getDeclaredMethod("refreshTrees").apply { isAccessible = true }.invoke(backend)
        return type.getDeclaredField("diskEntries").apply { isAccessible = true }.get(backend) as Map<*, *>
    }
}
