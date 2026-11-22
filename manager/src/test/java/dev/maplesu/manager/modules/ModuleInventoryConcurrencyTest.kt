package dev.maplesu.manager.modules

import java.io.File
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class ModuleInventoryConcurrencyTest {
    @get:Rule val temporary = TemporaryFolder()

    @Test fun abandoningARunningTaskRetainsItsReservationUntilCancellationReturns() {
        val type = LiteScriptModuleBackend::class.java
        val unsafe = sun.misc.Unsafe::class.java.getDeclaredField("theUnsafe").apply {
            isAccessible = true
        }.get(null) as sun.misc.Unsafe
        val backend = unsafe.allocateInstance(type) as LiteScriptModuleBackend
        fun field(name: String, value: Any) { type.getDeclaredField(name).apply { isAccessible = true }.set(backend, value) }
        val report = dev.maplesu.manager.ModuleArchiveInspector.installedKsu("cancel_fixture",
            "name=Cancellation fixture\nversionCode=1\n", "1:300", setOf("module.prop"), emptySet(), false)
        val key = type.getDeclaredMethod("moduleKey", report.javaClass).apply { isAccessible = true }.invoke(backend, report) as String
        val entryType = type.declaredClasses.single { it.simpleName == "ScriptEntry" }
        val entry = entryType.declaredConstructors.single { it.parameterCount == 4 }.apply { isAccessible = true }
            .newInstance(report, null, true, true)
        val receipts = temporary.newFolder("receipts")
        field("receipts", receipts)
        field("diskEntries", mapOf(report.id to entry))
        field("rootSnapshot", mapOf(report.id to RootModuleTree.Snapshot(revision = key)))
        val boot = "00000000-0000-0000-0000-000000000001"
        LiteModuleRuntimeState(boot).withStage("service", boot, "running").save(File(receipts, "$key.properties"))
        val cancelling = CountDownLatch(1)
        val release = CountDownLatch(1)
        val process = object : Process() {
            override fun getInputStream() = java.io.ByteArrayInputStream(byteArrayOf())
            override fun getErrorStream() = java.io.ByteArrayInputStream(byteArrayOf())
            override fun getOutputStream() = java.io.ByteArrayOutputStream()
            override fun waitFor() = 0
            override fun exitValue() = 0
            override fun destroy() = Unit
            override fun destroyForcibly(): Process { cancelling.countDown(); check(release.await(3, TimeUnit.SECONDS)); return this }
        }
        val monitor = checkNotNull(type.getDeclaredField("lock").apply { isAccessible = true }.get(null))
        @Suppress("UNCHECKED_CAST")
        val scheduled = type.getDeclaredField("scheduled").apply { isAccessible = true }.get(null) as MutableSet<String>
        @Suppress("UNCHECKED_CAST")
        val running = type.getDeclaredField("running").apply { isAccessible = true }.get(null) as MutableMap<String, Process>
        val taskKey = "$key:service"
        synchronized(monitor) { scheduled.add(taskKey); running[taskKey] = process }
        val worker = Executors.newSingleThreadExecutor()
        try {
            val cleanup = worker.submit { backend.abandonBootTask(LiteScriptModuleBackend.BootTask(report.id, report.sha256, "service", boot)) }
            assertTrue(cancelling.await(2, TimeUnit.SECONDS))
            assertTrue(synchronized(monitor) { taskKey in scheduled })
            release.countDown()
            cleanup.get(2, TimeUnit.SECONDS)
            assertFalse(synchronized(monitor) { taskKey in scheduled })
        } finally {
            release.countDown(); worker.shutdownNow(); worker.awaitTermination(3, TimeUnit.SECONDS)
            synchronized(monitor) { scheduled.remove(taskKey); running.remove(taskKey) }
        }
    }

    @Test fun rootInventoryDoesNotOwnTheSharedModuleStateMonitorWhileWaitingForRoot() = checkAdmission("refreshTrees")
    @Test fun toggleDoesNotInvertTheInventoryAndStateLocks() = checkAdmission("setEnabled")
    @Test fun removeDoesNotInvertTheInventoryAndStateLocks() = checkAdmission("markRemove")

    @Test fun simultaneousPageReadsReuseTheBootInventoryButAMutationReadsFreshState() {
        val type = LiteScriptModuleBackend::class.java
        val unsafe = sun.misc.Unsafe::class.java.getDeclaredField("theUnsafe").apply { isAccessible = true }
            .get(null) as sun.misc.Unsafe
        val backend = unsafe.allocateInstance(type) as LiteScriptModuleBackend
        fun field(name: String, value: Any) = type.getDeclaredField(name).apply { isAccessible = true }.set(backend, value)
        val reads = java.util.concurrent.atomic.AtomicInteger()
        field("catalog", ModuleCatalog(temporary.newFolder("coalesced-catalog")))
        field("rootTrees", RootModuleTree(ModuleScriptRunner {
            reads.incrementAndGet()
            ModuleScriptOutput(0, "MAPLESU_SNAPSHOT_OK\n")
        }))
        field("rootSnapshot", emptyMap<String, RootModuleTree.Snapshot>())
        field("inventoryReadAt", Long.MIN_VALUE)
        val read = type.getDeclaredMethod("refreshTreesForRead").apply { isAccessible = true }
        val refresh = type.getDeclaredMethod("refreshTrees").apply { isAccessible = true }
        val workers = Executors.newFixedThreadPool(4)
        try {
            refresh.invoke(backend) // boot preparation completed
            (1..4).map { workers.submit { read.invoke(backend) } }.forEach { it.get(2, TimeUnit.SECONDS) }
            assertEquals("An immediate page must reuse the complete boot inventory", 1, reads.get())
            refresh.invoke(backend) // toggles/removals must observe live markers
            assertEquals(2, reads.get())
        } finally { workers.shutdownNow() }
    }

    @Test fun eachPageInventoryReturnsItsVerifiedCatalogAndStillRejectsLaterArchiveChanges() {
        val type = LiteScriptModuleBackend::class.java
        val unsafe = sun.misc.Unsafe::class.java.getDeclaredField("theUnsafe").apply { isAccessible = true }
            .get(null) as sun.misc.Unsafe
        val backend = unsafe.allocateInstance(type) as LiteScriptModuleBackend
        fun field(name: String, value: Any) = type.getDeclaredField(name).apply { isAccessible = true }.set(backend, value)
        val archive = temporary.newFile("inventory.zip")
        java.util.zip.ZipOutputStream(archive.outputStream()).use { zip ->
            zip.putNextEntry(java.util.zip.ZipEntry("module.prop"))
            zip.write("id=inventory_fixture\nname=Inventory fixture\nversionCode=1\n".toByteArray())
            zip.closeEntry()
        }
        val report = dev.maplesu.manager.ModuleArchiveInspector.inspect(archive)
        val catalog = ModuleCatalog(temporary.newFolder("verified-catalog"))
        val entry = catalog.commit(catalog.stage(archive, report.type, report.sha256).token)
        val roots = java.util.concurrent.atomic.AtomicInteger()
        field("catalog", catalog)
        field("rootTrees", RootModuleTree(ModuleScriptRunner {
            roots.incrementAndGet()
            ModuleScriptOutput(0, "MAPLESU_SNAPSHOT_OK\n")
        }))
        field("rootSnapshot", emptyMap<String, RootModuleTree.Snapshot>())
        field("diskEntries", emptyMap<String, Any>())
        field("inventoryReadAt", Long.MIN_VALUE)
        val read = type.getDeclaredMethod("refreshTreesForRead").apply { isAccessible = true }
        val verified = read.invoke(backend) as? List<*>
        assertNotNull("Return the already verified catalog instead of making the caller reread every ZIP", verified)
        assertEquals(report.sha256, (verified!!.single() as ModuleCatalog.Entry).report.sha256)
        assertEquals(1, roots.get())
        assertEquals(1, (read.invoke(backend) as List<*>).size)
        assertEquals("An immediate page reuses only root inventory", 1, roots.get())
        entry.archive.writeText("corrupt archive")
        try {
            read.invoke(backend)
            fail("A later page must validate catalog bytes even inside the root snapshot TTL")
        } catch (error: java.lang.reflect.InvocationTargetException) {
            assertTrue(error.cause is java.io.IOException)
        }
    }

    @Test fun pageWaitingForBootPreparationReusesTheInventoryCompletedDuringItsWait() {
        val type = LiteScriptModuleBackend::class.java
        val unsafe = sun.misc.Unsafe::class.java.getDeclaredField("theUnsafe").apply { isAccessible = true }
            .get(null) as sun.misc.Unsafe
        val backend = unsafe.allocateInstance(type) as LiteScriptModuleBackend
        fun field(name: String, value: Any) = type.getDeclaredField(name).apply { isAccessible = true }.set(backend, value)
        val reads = java.util.concurrent.atomic.AtomicInteger()
        field("catalog", ModuleCatalog(temporary.newFolder("waiting-catalog")))
        field("rootTrees", RootModuleTree(ModuleScriptRunner {
            reads.incrementAndGet()
            ModuleScriptOutput(0, "MAPLESU_SNAPSHOT_OK\n")
        }))
        field("rootSnapshot", emptyMap<String, RootModuleTree.Snapshot>())
        field("inventoryReadAt", Long.MIN_VALUE)
        val read = type.getDeclaredMethod("refreshTreesForRead").apply { isAccessible = true }
        val refresh = type.getDeclaredMethod("refreshTrees").apply { isAccessible = true }
        val transaction = checkNotNull(type.getDeclaredField("installLock").apply { isAccessible = true }.get(null))
        val result = java.util.concurrent.CompletableFuture<Any?>()
        val page = Thread {
            try { result.complete(read.invoke(backend)) }
            catch (error: Throwable) { result.completeExceptionally(error) }
        }
        synchronized(transaction) {
            page.start()
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2)
            while (page.state != Thread.State.BLOCKED && System.nanoTime() < deadline) Thread.yield()
            assertEquals(Thread.State.BLOCKED, page.state)
            refresh.invoke(backend)
            // Boot migration can hold the transaction longer than the page snapshot TTL.
            Thread.sleep(1_100)
        }
        result.get(3, TimeUnit.SECONDS)
        page.join(3_000)
        assertEquals("Do not rescan root after waiting for this exact inventory", 1, reads.get())
    }

    private fun checkAdmission(operation: String) {
        val unsafe = sun.misc.Unsafe::class.java.getDeclaredField("theUnsafe").apply {
            isAccessible = true
        }.get(null) as sun.misc.Unsafe
        val backend = unsafe.allocateInstance(LiteScriptModuleBackend::class.java) as LiteScriptModuleBackend
        fun field(name: String, value: Any) {
            LiteScriptModuleBackend::class.java.getDeclaredField(name).apply { isAccessible = true }.set(backend, value)
        }
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val root = RootModuleTree(ModuleScriptRunner {
            entered.countDown()
            check(release.await(10, TimeUnit.SECONDS))
            ModuleScriptOutput(0, "MAPLESU_SNAPSHOT_OK\n")
        })
        field("catalog", ModuleCatalog(temporary.newFolder("catalog")))
        field("rootTrees", root)
        field("rootSnapshot", emptyMap<String, RootModuleTree.Snapshot>())
        val monitor = LiteScriptModuleBackend::class.java.getDeclaredField("lock").apply { isAccessible = true }.get(null)
        val transaction = LiteScriptModuleBackend::class.java.getDeclaredField("installLock").apply { isAccessible = true }.get(null)
        val refresh = if (operation == "refreshTrees") LiteScriptModuleBackend::class.java.getDeclaredMethod(operation)
            else LiteScriptModuleBackend::class.java.getDeclaredMethod(operation, String::class.java, Boolean::class.javaPrimitiveType)
        refresh.isAccessible = true
        val workers = Executors.newFixedThreadPool(2)
        try {
            val loading = synchronized(transaction) {
                workers.submit { if (operation == "refreshTrees") refresh.invoke(backend)
                    else refresh.invoke(backend, "fixture", true) }.also {
                    assertFalse("Inventory recovery must wait for a pending module transaction", entered.await(100, TimeUnit.MILLISECONDS))
                }
            }
            assertTrue(entered.await(2, TimeUnit.SECONDS))
            workers.submit<Boolean> { synchronized(monitor) { true } }.get(1, TimeUnit.SECONDS)
            assertFalse(loading.isDone)
        } finally { release.countDown(); workers.shutdownNow(); workers.awaitTermination(3, TimeUnit.SECONDS) }
    }
}
