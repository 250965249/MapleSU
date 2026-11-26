package dev.maplesu.manager.jailbreak.ghostsam

import android.content.Context
import dev.maplesu.manager.jailbreak.JailbreakArtifacts
import java.io.File
import java.io.IOException

/**
 * Product entry point for the GhostSam V2 provider (called from JailbreakExecutor after the
 * same admission checks as every provider). Constructs a MapleSU-owned lease, binds the App
 * LocalServerSocket to that exact endpoint, sends 'C' + the stdin TLV on one connection, then
 * reads/validates the MJBL v2 identity via the concrete DefaultLeaseTransport.
 *
 * Everything here fails closed with a named token; only RAW_ROOT_LEASE is declared.
 */
object GhostsamAttempt {
    data class Result(val ok: Boolean, val token: String? = null)

    fun run(context: Context): Result {
        // Artifact presence is the same check admission performs for every provider.
        try {
            JailbreakArtifacts.require(context, GhostsamBackend.ARTIFACT)
        } catch (_: IOException) {
            return Result(false, "ARTIFACT_UNVERIFIED")
        }
        return try {
            val nativeDir = File(context.applicationInfo.nativeLibraryDir)
            val provisioner = ConsumerProvisioner(nativeDir, GhostsamBackend.expectedConsumerSha256(context))
            val consumer = provisioner.resolve()
            val factory = GhostsamLeaseFactory()
            val lease = factory.create()
            try {
                val binder = LeaseBinder(GhostsamPrimitiveClient(), consumer.path, factory).also { it.bind(lease) }
                val bound = binder.awaitOnce()
                // N2: reuse the factory-owned listener; do not create a second socket here.
                DefaultLeaseTransport(lease.server).awaitIdentity(bound)
                CapabilityGate.assertNoUltra(emptyMap())
                Result(true)
            } finally {
                factory.close(lease)
            }
        } catch (e: LeaseWireException) {
            Result(false, e.token)
        } catch (t: Throwable) {
            Result(false, "GHOSTSAM_ADAPTER_FAILURE")
        }
    }
}
