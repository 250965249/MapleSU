package dev.maplesu.manager.workmode.service

import java.io.File
import java.nio.file.Files
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import org.junit.Assert.*
import org.junit.Test

class ModeSwitchRootTokenLockTest {
    @Test fun concurrentSessionsWaitAndReadTheSamePersistentToken() {
        val directory = Files.createTempDirectory("mode-root-token").toFile()
        val file = File(directory, "token")
        val token = ByteArray(32) { it.toByte() }
        val firstLocked = CountDownLatch(1)
        val secondStarted = CountDownLatch(1)
        val releaseFirst = CountDownLatch(1)
        val workers = Executors.newFixedThreadPool(2)
        try {
            val first = workers.submit<ByteArray> {
                withLockedModeSwitchRootToken(file) { handle ->
                    firstLocked.countDown()
                    check(releaseFirst.await(5, TimeUnit.SECONDS))
                    handle.write(token)
                    handle.fd.sync()
                    token.copyOf()
                }
            }
            assertTrue(firstLocked.await(5, TimeUnit.SECONDS))
            val second = workers.submit<ByteArray> {
                secondStarted.countDown()
                withLockedModeSwitchRootToken(file) { handle ->
                    assertEquals(32L, handle.length())
                    ByteArray(32).also(handle::readFully)
                }
            }
            assertTrue(secondStarted.await(5, TimeUnit.SECONDS))
            assertThrows(TimeoutException::class.java) { second.get(250, TimeUnit.MILLISECONDS) }
            releaseFirst.countDown()
            assertArrayEquals(token, first.get(5, TimeUnit.SECONDS))
            assertArrayEquals(token, second.get(5, TimeUnit.SECONDS))
            assertArrayEquals(token, file.readBytes())
        } finally {
            releaseFirst.countDown()
            workers.shutdownNow()
            assertTrue(workers.awaitTermination(5, TimeUnit.SECONDS))
            directory.deleteRecursively()
        }
    }

    @Test fun failedValidationReleasesTheFileAndProcessLocks() {
        val directory = Files.createTempDirectory("mode-root-token-error").toFile()
        val file = File(directory, "token")
        try {
            assertThrows(IllegalStateException::class.java) {
                withLockedModeSwitchRootToken(file) { error("validation failed") }
            }
            withLockedModeSwitchRootToken(file) { it.write(byteArrayOf(1, 2, 3)) }
            assertArrayEquals(byteArrayOf(1, 2, 3), file.readBytes())
        } finally {
            directory.deleteRecursively()
        }
    }
}
