package dev.maplesu.manager.jailbreak.ghostsam

import android.content.Context
import dev.maplesu.manager.jailbreak.JailbreakArtifacts
import dev.maplesu.manager.jailbreak.JailbreakRequest
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

    fun run(context: Context, request: JailbreakRequest,
            facts: Map<String, Any?> = GhostsamBackend.ghostsamFacts()): Result {
        val nativeDir = File(context.applicationInfo.nativeLibraryDir)
        val provisioner = ConsumerProvisioner(nativeDir, GhostsamBackend.expectedConsumerSha256(context))
        val factory = GhostsamLeaseFactory()
        val consumerPath = File(nativeDir, GhostsamBackend.ARTIFACT).absolutePath
        val binder = LeaseBinder(GhostsamPrimitiveClient(), consumerPath, factory)
        // F2/F3: single production entry through AdapterProvider (one capability gate, one failure map).
        val provider = AdapterProvider(
            provisioner = provisioner,
            binder = binder,
            transportFactory = { lease -> DefaultLeaseTransport(lease.server) },
            admission = {
                try {
                    JailbreakArtifacts.require(context, GhostsamBackend.ARTIFACT)
                    null
                } catch (_: IOException) {
                    "ARTIFACT_UNVERIFIED"
                }
            },
        )
        val result = provider.run(AdapterProvider.Request(facts))
        binder.close()
        return if (result.ok) Result(true) else Result(false, result.token)
    }
}
