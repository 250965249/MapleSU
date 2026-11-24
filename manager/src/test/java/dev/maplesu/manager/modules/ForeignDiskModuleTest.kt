package dev.maplesu.manager.modules

import java.io.File
import java.lang.reflect.InvocationTargetException
import org.junit.After
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class ForeignDiskModuleTest {
    @get:Rule val temporary = TemporaryFolder()

    private fun backend(identity: String, files: Set<String> = emptySet()): Pair<LiteScriptModuleBackend, Any> {
        val type = LiteScriptModuleBackend::class.java
        val unsafe = sun.misc.Unsafe::class.java.getDeclaredField("theUnsafe").apply { isAccessible = true }.get(null) as sun.misc.Unsafe
        val backend = unsafe.allocateInstance(type) as LiteScriptModuleBackend
        fun set(name: String, value: Any) = type.getDeclaredField(name).apply { isAccessible = true }.set(backend, value)
        val catalog = temporary.newFolder()
        listOf("staged", "revisions", "installed").forEach { File(catalog, it).mkdir() }
        set("catalog", ModuleCatalog(catalog))
        for (name in listOf("receipts", "revisions", "earlyRevisions")) set(name, temporary.newFolder())
        set("rootSnapshot", emptyMap<String, RootModuleTree.Snapshot>())
        set("diskEntries", emptyMap<String, Any>())
        val prop = "id=foreign_fixture\nname=Foreign KSU module\nversionCode=1\n"
        val hex = prop.toByteArray().joinToString("") { "%02x".format(it.toInt() and 255) }
        val root = temporary.newFolder()
        val tree = File(root, "foreign_fixture").apply { mkdir() }
        (files + "module.prop" + "action.sh").forEach { File(tree, it).writeText("") }
        set("rootTrees", RootModuleTree(ModuleScriptRunner { ModuleScriptOutput(0,
            "D\tforeign_fixture\nI\tforeign_fixture\t$identity\nF\tforeign_fixture\tmodule.prop\n" +
                "F\tforeign_fixture\taction.sh\n" + files.joinToString("") { "F\tforeign_fixture\t$it\n" } +
                "M\tforeign_fixture\t$hex\nMAPLESU_SNAPSHOT_OK\n") }, root = root.absolutePath))
        type.getDeclaredMethod("refreshTrees").apply { isAccessible = true }.invoke(backend)
        val entry = (type.getDeclaredField("diskEntries").apply { isAccessible = true }.get(backend) as Map<*, *>).values.single()!!
        val report = requireNotNull(entry.javaClass.getDeclaredField("report").apply { isAccessible = true }.get(entry))
        return backend to report
    }
    private fun call(backend: LiteScriptModuleBackend, name: String, report: Any): Any? =
        backend.javaClass.getDeclaredMethod(name, report.javaClass).apply { isAccessible = true }.invoke(backend, report)

    @After fun clearReservations() {
        val scheduled = LiteScriptModuleBackend::class.java.getDeclaredField("scheduled").apply { isAccessible = true }
        (scheduled.get(null) as MutableSet<*>).clear()
    }

    private fun queue(backend: LiteScriptModuleBackend, boot: String): List<LiteScriptModuleBackend.BootTask> {
        val entries = backend.javaClass.getDeclaredField("diskEntries").apply { isAccessible = true }
            .get(backend) as Map<*, *>
        @Suppress("UNCHECKED_CAST")
        return backend.javaClass.getDeclaredMethod("queueBootTasks", List::class.java, String::class.java)
            .apply { isAccessible = true }.invoke(backend, entries.values.toList(), boot) as List<LiteScriptModuleBackend.BootTask>
    }

    private fun snapshot(backend: LiteScriptModuleBackend, change: (RootModuleTree.Snapshot) -> RootModuleTree.Snapshot) {
        val field = backend.javaClass.getDeclaredField("rootSnapshot").apply { isAccessible = true }
        @Suppress("UNCHECKED_CAST")
        val values = field.get(backend) as Map<String, RootModuleTree.Snapshot>
        field.set(backend, values.mapValues { change(it.value) })
    }

    private val firstBoot = "00000000-0000-0000-0000-000000000001"
    private val nextBoot = "00000000-0000-0000-0000-000000000002"

    @Test fun existingKsuTreeCanRunWithoutAdoptingOrCreatingAReceipt() {
        val (backend, report) = backend("1:300")
        assertEquals(false, call(backend, "owns", report))
        assertEquals(true, call(backend, "canRun", report))
        val state = call(backend, "state", report) as LiteModuleRuntimeState
        assertTrue(state.stages.isEmpty())
        val boot = "00000000-0000-0000-0000-000000000001"
        assertEquals(listOf("service"), state.pendingStages(boot, true, listOf("service")))
        assertTrue(state.withStage("service", boot, "completed", 0).pendingStages(boot, true, listOf("service")).isEmpty())
        assertFalse((call(backend, "receipt", report) as File).exists())
    }
    @Test fun missingTreeIdentityDoesNotGrantExecution() {
        for (identity in listOf("", "invalid", "1:")) {
            val (backend, report) = backend(identity, setOf("service.sh"))
            assertEquals(false, call(backend, "canRun", report))
            assertTrue(queue(backend, firstBoot).none { !it.common })
            assertFalse((call(backend, "receipt", report) as File).exists())
        }
        val (backend, report) = backend("1:300", setOf("service.sh"))
        snapshot(backend) { it.copy(directory = false) }
        assertEquals(false, call(backend, "canRun", report))
        assertTrue(queue(backend, firstBoot).none { !it.common })
    }
    @Test fun uninstallKeepsTheExactUserSelectedTreeIdentity() {
        val (backend, report) = backend("1:300")
        snapshot(backend) { it.copy(files = it.files + "remove") }
        val method = backend.javaClass.getDeclaredMethod("canRemove", report.javaClass, LiteModuleRuntimeState::class.java).apply { isAccessible = true }
        for ((identity, expected) in listOf(null to false, "1:301" to false, "1:300" to true)) {
            assertEquals(expected, method.invoke(backend, report, LiteModuleRuntimeState("boot", remove = true, removalIdentity = identity)))
            LiteModuleRuntimeState("00000000-0000-0000-0000-000000000000", remove = true,
                removalIdentity = identity).save(call(backend, "receipt", report) as File)
            val tasks = queue(backend, firstBoot).filter { !it.common }
            assertEquals(if (expected) listOf("uninstall") else emptyList<String>(), tasks.map { it.stage })
            tasks.forEach(backend::abandonBootTask)
        }
    }
    @Test fun aCorruptExistingReceiptRemainsAnError() {
        val (backend, report) = backend("1:300", setOf("service.sh"))
        (call(backend, "receipt", report) as File).writeText("corrupt receipt")
        try { call(backend, "state", report); fail("Existing corruption must not become a fresh state") }
        catch (expected: InvocationTargetException) { assertTrue(expected.cause is IllegalArgumentException) }
        try { queue(backend, firstBoot); fail("Scheduling must preserve existing receipt errors") }
        catch (expected: InvocationTargetException) { assertTrue(expected.cause is IllegalArgumentException) }
        snapshot(backend) { it.copy(files = it.files + "remove") }
        try { queue(backend, firstBoot); fail("Removal must preserve existing receipt errors") }
        catch (expected: InvocationTargetException) { assertTrue(expected.cause is IllegalArgumentException) }
        assertEquals("corrupt receipt", (call(backend, "receipt", report) as File).readText())
        val receipt = call(backend, "receipt", report) as File
        assertTrue(receipt.delete())
        assertTrue(receipt.mkdir())
        try { queue(backend, firstBoot); fail("A receipt directory must remain an error") }
        catch (expected: InvocationTargetException) { assertTrue(expected.cause is IllegalArgumentException) }
        assertTrue(receipt.isDirectory)
    }

    @Test fun foreignLifecycleStagesAreScheduledOncePerBoot() {
        val (backend, report) = backend("1:300", setOf("post-fs-data.sh", "service.sh"))
        assertFalse((call(backend, "receipt", report) as File).exists())
        val first = queue(backend, firstBoot).filter { !it.common }
        assertEquals(listOf("post-fs-data", "props", "service"), first.map { it.stage })
        val state = call(backend, "state", report) as LiteModuleRuntimeState
        assertEquals("00000000-0000-0000-0000-000000000000", state.installedBootId)
        assertEquals(setOf("post-fs-data", "service"), state.stages.keys)
        assertTrue(state.stages.values.all { it.bootId == firstBoot && it.status == "queued" })
        assertEquals(false, call(backend, "owns", report))
        assertTrue(queue(backend, firstBoot).none { !it.common })
        // Exercise the production release path; interruption must not replay this boot.
        first.forEach(backend::abandonBootTask)
        (call(backend, "state", report) as LiteModuleRuntimeState).copy(propsBootId = firstBoot)
            .save(call(backend, "receipt", report) as File)
        assertTrue(queue(backend, firstBoot).none { !it.common })
        val next = queue(backend, nextBoot).filter { !it.common }
        assertEquals(listOf("post-fs-data", "props", "service"), next.map { it.stage })
        assertTrue(next.all { it.bootId == nextBoot })
        next.forEach(backend::abandonBootTask)
    }

    @Test fun ownedLifecycleStagesKeepExistingReceiptSemantics() {
        val (backend, report) = backend("1:300", setOf("post-fs-data.sh", "service.sh"))
        val key = call(backend, "moduleKey", report) as String
        snapshot(backend) { it.copy(revision = key) }
        val receipt = call(backend, "receipt", report) as File
        assertEquals(true, call(backend, "owns", report))
        assertTrue(queue(backend, firstBoot).none { !it.common })
        LiteModuleRuntimeState(firstBoot).save(receipt)
        assertTrue(queue(backend, firstBoot).none { !it.common })
        val next = queue(backend, nextBoot).filter { !it.common }
        assertEquals(listOf("post-fs-data", "props", "service"), next.map { it.stage })
        next.forEach(backend::abandonBootTask)
        (call(backend, "state", report) as LiteModuleRuntimeState).copy(propsBootId = nextBoot).save(receipt)
        assertTrue(queue(backend, nextBoot).none { !it.common })
    }

    @Test fun foreignPolicyAndMountSelectionIncludesFreshEnabledTrees() {
        val (backend, report) = backend("1:300", setOf("sepolicy.rule", "service.sh"))
        val active = backend.javaClass.getDeclaredMethod("activeModules").apply { isAccessible = true }
        assertEquals(1, (active.invoke(backend) as List<*>).size)
        assertFalse((call(backend, "receipt", report) as File).exists())
        assertTrue(queue(backend, firstBoot).any { it.common && it.stage == "policy" })
        snapshot(backend) { it.copy(files = it.files + "disable") }
        assertTrue((active.invoke(backend) as List<*>).isEmpty())
        assertTrue(queue(backend, nextBoot).none { !it.common })
        snapshot(backend) { it.copy(files = it.files - "disable" + "remove") }
        assertTrue((active.invoke(backend) as List<*>).isEmpty())
    }
}
