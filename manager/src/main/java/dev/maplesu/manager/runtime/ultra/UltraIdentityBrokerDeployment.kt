package dev.maplesu.manager.runtime.ultra

import java.util.concurrent.CancellationException

/** A root socket owner is a restart target, never an identity or readiness proof. */
internal object UltraIdentityBrokerDeployment {
    class Endpoint<T>(val ownerPid: Int?, val identity: T?)

    fun <T> readEndpoint(peerUid: Int, peerPid: Int, read: () -> T?): Endpoint<T> {
        if (peerUid != 0 || peerPid <= 1) return Endpoint(null, null)
        val identity = try {
            if (Thread.currentThread().isInterrupted) null else read()
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            null
        } catch (_: Exception) {
            null
        }
        return Endpoint(peerPid, if (Thread.currentThread().isInterrupted) null else identity)
    }

    data class Observation(val ownerPid: Int?, val matches: Boolean)

    interface Port {
        fun observe(): Observation
        fun prepare(): String?
        fun eligible(): Boolean
        fun stop(pid: Int): Boolean
        fun start(): Boolean
        fun complete(): String
        fun pause(millis: Long) = Thread.sleep(millis)
    }

    fun ensure(force: Boolean, port: Port): String {
        fun eligible() = !Thread.currentThread().isInterrupted && port.eligible()
        fun complete(): String {
            if (!eligible()) return "IDENTITY_SUSPENDED"
            val result = port.complete()
            return if (eligible()) result else "IDENTITY_SUSPENDED"
        }
        if (!eligible()) return "IDENTITY_SUSPENDED"
        val running = port.observe()
        if (!eligible()) return "IDENTITY_SUSPENDED"
        if (!force && running.matches) return complete()
        port.prepare()?.let { return it }
        if (!eligible()) return "IDENTITY_SUSPENDED"
        val current = port.observe()
        if (!eligible()) return "IDENTITY_SUSPENDED"
        if (current.matches) return complete()
        if (current.ownerPid != null && (current.ownerPid <= 1 || !port.stop(current.ownerPid))) {
            return "IDENTITY_RESTART_UNVERIFIED"
        }
        if (!eligible()) return "IDENTITY_SUSPENDED"
        if (!port.start()) return "IDENTITY_START_FAILED"
        repeat(15) {
            if (!eligible()) return "IDENTITY_SUSPENDED"
            val observed = port.observe()
            if (!eligible()) return "IDENTITY_SUSPENDED"
            if (observed.matches) return complete()
            try {
                port.pause(200)
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                return "IDENTITY_SUSPENDED"
            }
        }
        return "IDENTITY_HANDSHAKE_PENDING"
    }
}
