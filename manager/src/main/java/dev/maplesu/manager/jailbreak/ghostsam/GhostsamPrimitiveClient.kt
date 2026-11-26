package dev.maplesu.manager.jailbreak.ghostsam

import android.net.LocalSocket
import android.net.LocalSocketAddress
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * GhostSam `'C'` primitive client: `/data/local/tmp/temp_su.sock`, frame
 * `'C' + LE u32 length + UTF-8 command`. The daemon returns raw stdout (no exit code);
 * output is diagnostic ONLY and must never be used as root/lease proof.
 */
class GhostsamPrimitiveClient(
    private val socketPath: String = "/data/local/tmp/temp_su.sock",
    private val timeoutMs: Int = 20_000,
) {
    sealed interface Result {
        data object Sent : Result
        data class ConnectDenied(val detail: String) : Result
        data object Timeout : Result
        data class Io(val detail: String) : Result
    }

    fun send(command: String): Result = sendWithStdin(command, null)

    /**
     * F1: write the 'C' frame, then (same connection!) the consumer's stdin TLV first packet.
     * GhostSam's daemon dup2()s this conn to the child's stdin (su_daemon.h), so the bytes after
     * the command frame are delivered to the self-built consumer's stdin.
     */
    fun sendWithStdin(command: String, stdinBytes: ByteArray?): Result {
        if (command.indexOf('\u0000') >= 0) return Result.Io("COMMAND_NUL_INVALID")
        val payload = command.toByteArray(Charsets.UTF_8)
        if (payload.size > Int.MAX_VALUE) return Result.Io("COMMAND_TOO_LONG")
        val socket = LocalSocket()
        return try {
            socket.connect(LocalSocketAddress(socketPath, LocalSocketAddress.Namespace.FILESYSTEM))
            socket.soTimeout = timeoutMs
            val header = ByteBuffer.allocate(1 + 4).order(ByteOrder.LITTLE_ENDIAN)
            header.put(0x43)                       // 'C'
            header.putInt(payload.size)            // LE u32 length
            socket.outputStream.write(header.array())
            socket.outputStream.write(payload)
            if (stdinBytes != null) socket.outputStream.write(stdinBytes)
            socket.outputStream.flush()
            // Drain stdout for diagnostics only (bounded); never parse as proof.
            val out = socket.inputStream
            val sink = ByteArrayOutputStream()
            val buf = ByteArray(4096)
            while (sink.size() < 1 shl 20) {
                val n = try { out.read(buf) } catch (t: Throwable) { break }
                if (n <= 0) break
                sink.write(buf, 0, n)
            }
            Result.Sent
        } catch (t: java.net.SocketTimeoutException) {
            Result.Timeout
        } catch (t: java.io.IOException) {
            Result.ConnectDenied(t.message ?: t.javaClass.simpleName)
        } catch (t: Throwable) {
            Result.Io(t.message ?: t.javaClass.simpleName)
        } finally {
            runCatching { socket.close() }
        }
    }
}
