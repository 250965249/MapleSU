package dev.maplesu.manager.runtime.ultra

import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.*
import org.junit.Test

/** Runs real client admission; substitutes JNI only after the SDK slot was acquired. */
class UltraSdkResponsivenessTest {
    private val unsafe = sun.misc.Unsafe::class.java.getDeclaredField("theUnsafe").apply {
        isAccessible = true
    }.get(null) as sun.misc.Unsafe

    private fun client(key: () -> String?): UltraRuntimeClient =
        (unsafe.allocateInstance(UltraRuntimeClient::class.java) as UltraRuntimeClient).also { client ->
            UltraRuntimeClient::class.java.getDeclaredField("rootKeyProvider").apply { isAccessible = true }.set(client, key)
            UltraRuntimeClient::class.java.getDeclaredField("lock").apply { isAccessible = true }.set(client, Any())
        }

    @Test fun pagesReturnBusyWhileALongRootCommandOwnsTheSdkSlot() {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val calls = AtomicInteger()
        val client = client {
            calls.incrementAndGet(); entered.countDown()
            check(release.await(15, TimeUnit.SECONDS))
            null
        }
        val workers = Executors.newFixedThreadPool(4)
        try {
            val command = workers.submit<NativeReceipt> { client.runRootCommand("long-module-script") }
            assertTrue(entered.await(2, TimeUnit.SECONDS))
            val reads = listOf<() -> NativeReceipt>({ client.environmentState() }, { client.suAuthList() }, { client.moduleList() })
                .map { read -> workers.submit<NativeReceipt> { read() } }
            reads.forEach { read ->
                val receipt = read.get(3, TimeUnit.SECONDS)
                assertFalse(receipt.succeeded)
                assertEquals("MAPLESU_SDK_BUSY", receipt.sdkError)
            }
            assertEquals("Only the admitted command may reach its JNI/key boundary", 1, calls.get())
            assertFalse(command.isDone)
        } finally { release.countDown(); workers.shutdownNow(); workers.awaitTermination(3, TimeUnit.SECONDS) }
    }

    @Test fun contendedMutationIsNotSubmittedOrReplayed() {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val calls = AtomicInteger()
        val client = client {
            calls.incrementAndGet(); entered.countDown()
            check(release.await(15, TimeUnit.SECONDS)); null
        }
        val workers = Executors.newFixedThreadPool(2)
        try {
            workers.submit<NativeReceipt> { client.runRootCommand("long-module-script") }
            assertTrue(entered.await(2, TimeUnit.SECONDS))
            val result = workers.submit<NativeReceipt> { client.addSuAuth("fixture.app") }.get(3, TimeUnit.SECONDS)
            assertEquals("MAPLESU_SDK_BUSY", result.sdkError)
            assertEquals(1, calls.get())
        } finally { release.countDown(); workers.shutdownNow(); workers.awaitTermination(3, TimeUnit.SECONDS) }
    }

    @Test fun interruptionLeavesTheSdkOwnerIntactAndDoesNotSubmitAQuery() {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val client = client { entered.countDown(); check(release.await(15, TimeUnit.SECONDS)); null }
        val workers = Executors.newFixedThreadPool(2)
        try {
            val owner = workers.submit<NativeReceipt> { client.runRootCommand("long-module-script") }
            assertTrue(entered.await(2, TimeUnit.SECONDS))
            val result = workers.submit<Pair<NativeReceipt, Boolean>> {
                Thread.currentThread().interrupt()
                client.environmentState() to Thread.currentThread().isInterrupted
            }.get(2, TimeUnit.SECONDS)
            assertEquals("MAPLESU_SDK_INTERRUPTED", result.first.sdkError)
            assertTrue(result.second)
            assertFalse(owner.isDone)
        } finally { release.countDown(); workers.shutdownNow(); workers.awaitTermination(3, TimeUnit.SECONDS) }
    }
}