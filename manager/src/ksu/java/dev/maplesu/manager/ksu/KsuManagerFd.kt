package dev.maplesu.manager.ksu

import android.content.Context
import android.net.LocalServerSocket
import android.os.Process
import android.system.Os
import android.system.OsConstants
import android.system.StructPollfd
import dev.maplesu.manager.modules.ModuleToolDeployment
import java.io.FileDescriptor
import java.util.UUID
import java.util.concurrent.TimeUnit

/** Retain one real driver descriptor in a Manager that predates late-load. */
internal object KsuManagerFd {
    private var descriptor: FileDescriptor? = null

    @Synchronized fun ensure(context: Context) {
        awaitDriver(
            ready = { KsuNativeCalls.version > 0 && KsuNativeCalls.isLateLoadMode && KsuNativeCalls.isManager },
            acquire = { if (descriptor == null) descriptor = receive(context) },
            pause = Thread::sleep,
        )
    }

    internal fun awaitDriver(ready: () -> Boolean, acquire: () -> Unit, pause: (Long) -> Unit) {
        if (ready()) return
        acquire()
        // The original JNI scanner deliberately throttles failed scans for 2s.
        repeat(10) {
            if (ready()) return
            pause(250)
        }
        check(ready()) { "KSU_MANAGER_FD_NOT_OBSERVED" }
    }

    private fun receive(context: Context): FileDescriptor {
        val name = "maplesu-ksu-fd-" + UUID.randomUUID()
        LocalServerSocket(name).use { server ->
            // The first descriptor must not depend on an already working root shell.
            val helper = ProcessBuilder(
                ModuleToolDeployment.policySource(context).absolutePath, "ksu-manager-fd", name,
                Process.myUid().toString(), Process.myPid().toString(),
            ).redirectErrorStream(true).start()
            try {
                check(helper.waitFor(3, TimeUnit.SECONDS)) { "KSU_MANAGER_FD_TIMEOUT" }
                check(helper.exitValue() == 0) {
                    "KSU_MANAGER_FD_COMMAND:${helper.inputStream.bufferedReader().readText().trim().take(256)}"
                }
                val event = StructPollfd().apply {
                    fd = server.fileDescriptor
                    events = OsConstants.POLLIN.toShort()
                }
                check(Os.poll(arrayOf(event), 3000) == 1 &&
                    event.revents.toInt() and OsConstants.POLLIN != 0) { "KSU_MANAGER_FD_TIMEOUT" }
                server.accept().use { peer ->
                    peer.soTimeout = 3000
                    check(peer.peerCredentials.uid == Process.myUid()) { "KSU_MANAGER_FD_PEER" }
                    val marker = peer.inputStream.read()
                    val received = peer.ancillaryFileDescriptors.orEmpty()
                    try {
                        check(marker == 'K'.code && received.size == 1) { "KSU_MANAGER_FD_PROTOCOL" }
                        val driver = received.single()
                        // JNI can discover this fd concurrently. Keep the received
                        // descriptor itself alive; dup/close would leave its cache stale.
                        descriptor = driver
                        Os.fcntlInt(driver, OsConstants.F_SETFD, OsConstants.FD_CLOEXEC)
                        return driver
                    } finally {
                        received.filter { it !== descriptor }.forEach { runCatching { Os.close(it) } }
                    }
                }
            } finally {
                helper.destroy()
                helper.inputStream.close()
                helper.errorStream.close()
                helper.outputStream.close()
            }
        }
    }
}
