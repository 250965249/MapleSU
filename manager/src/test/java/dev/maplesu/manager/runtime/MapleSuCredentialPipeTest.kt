package dev.maplesu.manager.runtime

import org.junit.Assert.*
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream

class MapleSuCredentialPipeTest {
    private class FixtureProcess(private val failure: Int = 0, private val cleanupFails: Boolean = false) : Process() {
        val writeError = IOException("credential pipe failed")
        var destroyed = false
        var stdinClosed = false
        var stdoutClosed = false
        var stderrClosed = false
        val bytes = ByteArrayOutputStream()
        private var writes = 0
        private fun closeFailure() {
            if (cleanupFails) throw IOException("cleanup failed")
        }
        private val stdin = object : OutputStream() {
            override fun write(value: Int) = bytes.write(value)
            override fun write(data: ByteArray, offset: Int, length: Int) {
                if (++writes == failure) throw writeError
                bytes.write(data, offset, length)
            }
            override fun flush() {
                if (failure == 3) throw writeError
            }
            override fun close() {
                stdinClosed = true
                closeFailure()
            }
        }
        private fun reader(onClose: () -> Unit) = object : InputStream() {
            override fun read(): Int = -1
            override fun close() {
                onClose()
                closeFailure()
            }
        }
        private val stdout = reader { stdoutClosed = true }
        private val stderr = reader { stderrClosed = true }
        override fun getOutputStream(): OutputStream = stdin
        override fun getInputStream(): InputStream = stdout
        override fun getErrorStream(): InputStream = stderr
        override fun waitFor(): Int = 0
        override fun exitValue(): Int = 0
        override fun destroy() { destroyed = true }
        override fun destroyForcibly(): Process {
            destroyed = true
            closeFailure()
            return this
        }
    }

    @Test fun writeAndFlushFailuresCloseAllStreamsAndPreserveOriginalError() {
        for (stage in 1..3) {
            for (cleanupFails in listOf(false, true)) {
                val process = FixtureProcess(stage, cleanupFails)
                try {
                    writeMapleSuCredential(process, ByteArray(48) { 'A'.code.toByte() })
                    fail("Credential failure was accepted")
                } catch (error: IOException) {
                    assertSame(process.writeError, error)
                }
                assertTrue(process.destroyed)
                assertTrue(process.stdinClosed)
                assertTrue(process.stdoutClosed)
                assertTrue(process.stderrClosed)
            }
        }
    }

    @Test fun successfulHandoffKeepsProcessAndStreamsOwnedByCaller() {
        val process = FixtureProcess()
        val credential = ByteArray(48) { 'B'.code.toByte() }
        assertSame(process, writeMapleSuCredential(process, credential))
        assertArrayEquals(byteArrayOf(0, 0, 0, 48) + credential, process.bytes.toByteArray())
        assertFalse(process.destroyed)
        assertFalse(process.stdinClosed)
        assertFalse(process.stdoutClosed)
        assertFalse(process.stderrClosed)
        process.outputStream.write(7)
        assertEquals(7, process.bytes.toByteArray().last().toInt())
    }
}
