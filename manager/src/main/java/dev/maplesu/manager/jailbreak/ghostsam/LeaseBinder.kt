package dev.maplesu.manager.jailbreak.ghostsam

/**
 * V2 lease binder. Lease params come from [GhostsamLeaseFactory] (no upstream RootShellLease).
 * The 'C' command carries NO nonce; nonce/endpoint/uid/boot go to the self-built consumer as a
 * stdin TLV first packet (t21 §4.3). One-shot await; transport closed on failure.
 */
class LeaseBinder(
    private val primitive: GhostsamPrimitiveClient,
    private val consumerPath: String,
    private val factory: GhostsamLeaseFactory,
    private val provider: String = "ghostlock",
) {
    private var used = false
    @Volatile private var transportOpen = false
    private var lease: GhostsamLeaseFactory.Lease? = null

    /** Bind an already-created (e.g. endpoint-bound) lease; used by the product route. */
    fun bind(lease: GhostsamLeaseFactory.Lease): GhostsamLeaseFactory.Lease {
        this.lease = lease
        return lease
    }

    fun prepare(): GhostsamLeaseFactory.Lease {
        val p = factory.create(provider)
        lease = p
        return p
    }

    fun awaitOnce(): GhostsamLeaseFactory.Lease {
        if (used) throw LeaseWireException("LEASE_AWAIT_ALREADY_USED")
        used = true
        val p = lease ?: throw LeaseWireException("LEASE_PENDING_MISSING")
        transportOpen = true
        val cmd = CommandBuilder.buildCommand(consumerPath, p.endpoint, p.nonceHex, p.managerUid,
            p.bootId, p.provider, enforce = null, includeNonce = false, fdArgs = true)
        // F1: same 'C' connection also carries the stdin TLV first packet to the consumer.
        val sent = primitive.sendWithStdin(cmd, p.stdinPacket())
        if (sent !is GhostsamPrimitiveClient.Result.Sent) {
            close()
            throw LeaseWireException(when (sent) {
                is GhostsamPrimitiveClient.Result.ConnectDenied -> "GHOSTSAM_PRIMITIVE_DENIED"
                GhostsamPrimitiveClient.Result.Timeout -> "LEASE_TIMEOUT"
                else -> "GHOSTSAM_PRIMITIVE_IO"
            })
        }
        return p
    }

    /** Bytes the adapter writes to the consumer's stdin first packet (TLV). */
    fun stdinPacket(p: GhostsamLeaseFactory.Lease): ByteArray = p.stdinPacket()

    fun close() {
        transportOpen = false
        runCatching { lease?.server?.close() }
        lease = null
    }

    fun isTransportOpen(): Boolean = transportOpen
}
