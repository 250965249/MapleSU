package dev.maplesu.manager.jailbreak.ghostsam

import android.net.LocalServerSocket
import android.net.LocalSocket
import dev.maplesu.manager.jailbreak.LeaseProtocol
import java.io.InputStream

/**
 * F1: concrete AdapterProvider.LeaseTransport. After the adapter writes the 'C' command + stdin
 * TLV, the self-built consumer connects back to this App-side LocalServerSocket and writes its
 * MJBL v2 identity frame. We accept, take SO_PEERCRED, and delegate identity parsing to the
 * unchanged production reader `LeaseProtocol.readIdentity` (sole App-side MJBL reader).
 */
class DefaultLeaseTransport(
    private val serverSocket: LocalServerSocket,
    private val provider: LeaseProtocol.Provider = LeaseProtocol.Provider.GHOSTLOCK,
) : AdapterProvider.LeaseTransport {
    override fun awaitIdentity(lease: GhostsamLeaseFactory.Lease): MjblV2.Identity {
        val socket: LocalSocket = serverSocket.accept()
        try {
            socket.soTimeout = 20_000
            val cred = socket.peerCredentials
            val input: InputStream = socket.inputStream
            val identity = LeaseProtocol.readIdentity(
                input, provider, lease.nonce, lease.bootId, cred.pid, cred.uid)
            return MjblV2.Identity(
                provider = identity.provider().wireId, pid = identity.workerPid(), uid = identity.uid(),
                starttime = identity.workerStarttime(), bootId = identity.bootId(),
                domain = identity.domain(), enforcing = identity.enforcing(), seccomp = identity.seccomp())
        } finally {
            runCatching { socket.close() }
        }
    }
}
