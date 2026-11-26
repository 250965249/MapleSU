package dev.maplesu.manager.jailbreak.ghostsam

/**
 * Orchestrates one GhostSam-adapter attempt: admission -> consumer artifact -> MapleSU-side
 * lease -> self-built-consumer identity frame -> DAEMON_READY. Any failure is a named token,
 * never a silent success. Only RAW_ROOT_LEASE capability is declared.
 */
class AdapterProvider(
    private val provisioner: ConsumerProvisioner,
    private val binder: LeaseBinder,
    private val transport: LeaseTransport,
    private val admission: () -> String? = { null }, // non-null = blocker token
) {
    data class Request(val facts: Map<String, Any?> = emptyMap())
    data class Result(val ok: Boolean, val token: String, val capability: Set<String> = emptySet())

    interface LeaseTransport {
        /** Reads + validates the MJBL v2 identity frame from the accepted consumer transport. */
        fun awaitIdentity(lease: GhostsamLeaseFactory.Lease): MjblV2.Identity
    }

    fun run(request: Request): Result {
        admission()?.let { return Result(false, it) }
        return try {
            provisioner.resolve()
            binder.prepare()
            val pending = binder.awaitOnce()
            CapabilityGate.assertNoUltra(request.facts)
            transport.awaitIdentity(pending)
            Result(true, "DAEMON_READY", CapabilityGate.allowed)
        } catch (e: LeaseWireException) {
            binder.close()
            Result(false, e.token)
        } catch (t: Throwable) {
            binder.close()
            Result(false, "ADAPTER_IO_FAILURE:" + (t.message ?: t.javaClass.simpleName))
        }
    }
}
