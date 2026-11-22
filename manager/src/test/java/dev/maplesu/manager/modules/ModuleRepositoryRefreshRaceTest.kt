package dev.maplesu.manager.modules

import com.maplesu.core.data.repository.ModuleRepositoryImpl
import dev.maplesu.manager.workmode.WorkMode
import java.io.File
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test

class ModuleRepositoryRefreshRaceTest {
    @Test fun toggleInvalidatesAListAlreadyBeingReadBeforeItsNewStateCanBeDisplayed() = runBlocking {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val enabled = AtomicBoolean(true)
        val reads = AtomicInteger()
        val port = object : ModuleOpsPort {
            override fun isAvailable() = true
            override fun listJson(): String {
                val observed = enabled.get().toString()
                if (reads.incrementAndGet() == 1) {
                    entered.countDown()
                    check(release.await(3, TimeUnit.SECONDS))
                }
                return observed
            }
            override fun toggle(id: String, enable: Boolean): Boolean { enabled.set(enable); return true }
            override fun uninstall(id: String) = false
            override fun undoUninstall(id: String) = false
            override fun install(zip: File) = false
        }
        val projected = mutableListOf<String>()
        val repository = ModuleRepositoryImpl(mode = { WorkMode.LITE }, litePort = port,
            listParser = ModuleListParser { json -> projected += json; emptyList() })
        val pending = async { repository.getModules() }
        try {
            kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
                assertTrue(entered.await(2, TimeUnit.SECONDS))
            }
            assertTrue(repository.toggleModule("fixture", false).getOrThrow())
            release.countDown()
            assertTrue(pending.await().isSuccess)
            assertEquals("false", projected.last())
            assertEquals(2, reads.get())
        } finally { release.countDown() }
    }
}
