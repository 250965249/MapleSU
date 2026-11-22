package dev.maplesu.manager.runtime.ultra

import dev.maplesu.manager.runtime.authorization.ApplicationIdentity
import dev.maplesu.manager.ultrakernel.UltraKernelCredential
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.io.EOFException
import java.util.concurrent.CancellationException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull

/** Environment trust survives APK removal; UIDs and install timestamps deliberately do not. */
internal class UltraReinstallTrust(val packageName: String, val userId: Int, signers: Set<String>,
                                private val signingLineage: (ApplicationIdentity) -> List<String>? = { null }) {
    val signers = signers.toSet()
    init {
        require(packageName == "dev.maplesu.manager" && userId >= 0)
        require(signers.isNotEmpty() && signers.all { it.matches(Regex("[0-9a-f]{64}")) })
    }

    fun allows(peerUid: Int, identity: ApplicationIdentity?): Boolean {
        if (identity == null || peerUid != identity.uid || peerUid / 100_000 != userId ||
            identity.packageName != packageName) return false
        if (identity.signers == signers) return true
        if (signers.size != 1 || identity.signers.size != 1) return false
        val history = signingLineage(identity) ?: return false
        return history.size >= 2 && history.toSet().size == history.size &&
            history.all { it.matches(Regex("[0-9a-f]{64}")) } &&
            history.last() == identity.signers.single() && signers.single() in history.dropLast(1)
    }

    /** The persisted signer pin stays unchanged; the platform supplies any rotation proof. */
    fun withSigningLineage(proof: (ApplicationIdentity) -> List<String>?): UltraReinstallTrust =
        UltraReinstallTrust(packageName, userId, signers, proof)

    companion object {
        /** Only the root-owned environment config may supply this trust anchor. */
        fun fromConfig(payload: String): UltraReinstallTrust? = try {
            if (payload.length !in 1..8192) null else {
                val value = Json.parseToJsonElement(payload) as? JsonObject
                val schema = (value?.get("schema") as? JsonPrimitive)?.intOrNull
                val name = (value?.get("packageName") as? JsonPrimitive)?.contentOrNull
                val user = (value?.get("userId") as? JsonPrimitive)?.intOrNull
                val certificates = (value?.get("signers") as? JsonArray)?.map {
                    (it as? JsonPrimitive)?.contentOrNull ?: ""
                }?.toSet()
                if (schema != UltraIdentityHandshake.VERSION || name == null || user == null || certificates == null) null
                else UltraReinstallTrust(name, user, certificates)
            }
        } catch (_: Exception) { null }
    }
}

/** The native SU table stores UIDs; only this independently checked manager may be regranted. */
internal object UltraManagerSignatureAuthorization {
    const val IDENTITY_PENDING = "MANAGER_IDENTITY_PENDING"

    fun refresh(trust: UltraReinstallTrust, identity: () -> ApplicationIdentity?,
                packages: () -> List<String>?, grant: () -> String, revoke: () -> String,
                refreshAll: () -> String): String =
        legacyStatus { refreshAttempt(trust, identity, packages, { legacy(grant()) }, { legacy(revoke()) },
            { legacy(refreshAll()) }) }

    fun refreshAttempt(trust: UltraReinstallTrust, identity: () -> ApplicationIdentity?,
                       packages: () -> List<String>?, grant: () -> UltraAuthorizationAttempt,
                       revoke: () -> UltraAuthorizationAttempt,
                       refreshAll: () -> UltraAuthorizationAttempt): UltraAuthorizationRestoreResult =
        reconcile(trust, identity, packages, grant, revoke, refreshAll, null)

    private fun legacy(status: String): UltraAuthorizationAttempt =
        UltraAuthorizationAttempt.local(status.takeUnless { it == "OK" })

    private fun legacyStatus(action: () -> UltraAuthorizationRestoreResult): String = try {
        action().status
    } catch (completed: UltraAuthorizationRestoreException) {
        throw completed.original
    }

    /** The broker rereads PM/list state each pass, renewing stable grants once a minute. */
    class Session(private val trust: UltraReinstallTrust,
                  private val now: () -> Long = { System.nanoTime() / 1_000_000L }) {
        private var verified: ApplicationIdentity? = null
        private var grantedAt = 0L

        fun refresh(identity: () -> ApplicationIdentity?, packages: () -> List<String>?,
                    grant: () -> String, revoke: () -> String): String =
            legacyStatus { refreshAttempt(identity, packages, { legacy(grant()) }, { legacy(revoke()) }) }

        @Synchronized
        fun refreshAttempt(identity: () -> ApplicationIdentity?, packages: () -> List<String>?,
                           grant: () -> UltraAuthorizationAttempt,
                           revoke: () -> UltraAuthorizationAttempt): UltraAuthorizationRestoreResult {
            val age = now() - grantedAt
            val previous = verified.takeIf { age in 0 until 60_000L }
            // A failed/throwing pass never preserves an earlier success.
            verified = null
            var observed: ApplicationIdentity? = null
            var granted = false
            val result = reconcile(trust, { identity().also { observed = it } }, packages,
                { granted = true; grant() }, revoke, { UltraAuthorizationAttempt.local() }, previous)
            if (result.status == "OK" && observed?.let { trust.allows(it.uid, it) } == true) {
                verified = observed
                if (granted) grantedAt = now()
            }
            return result
        }
    }

    private fun reconcile(trust: UltraReinstallTrust, identity: () -> ApplicationIdentity?,
                          packages: () -> List<String>?, grant: () -> UltraAuthorizationAttempt,
                          revoke: () -> UltraAuthorizationAttempt, refreshAll: () -> UltraAuthorizationAttempt,
                          verified: ApplicationIdentity?): UltraAuthorizationRestoreResult {
        var completed: UltraAuthorizationAttempt? = null
        try {
            val before = identity()
            val listed = packages() ?: return UltraAuthorizationRestoreResult.local("MANAGER_AUTH_LIST_UNREADABLE")
            if (before == null) {
                var revoked: UltraAuthorizationAttempt? = null
                if (trust.packageName in listed) {
                    revoked = revoke().also { completed = it }
                    if (!revoked.succeeded) return UltraAuthorizationRestoreResult.primary(revoked)
                    if (packages()?.contains(trust.packageName) != false)
                        return UltraAuthorizationRestoreResult.primary(revoked, "MANAGER_AUTH_REVOKE_UNVERIFIED")
                }
                // PackageManager failure and an absent installation both produce null.
                // Revoke a stale manager once, then retry identity without rewriting UIDs.
                return revoked?.let { UltraAuthorizationRestoreResult.primary(it, IDENTITY_PENDING) }
                    ?: UltraAuthorizationRestoreResult.local(IDENTITY_PENDING)
            }
            if (trust.allows(before.uid, before)) {
                val stable = before == verified && trust.packageName in listed
                val granted = if (stable) null else grant().also { completed = it }
                if (granted != null && !granted.succeeded) return UltraAuthorizationRestoreResult.primary(granted)
                val readback = if (stable) true else packages()?.contains(trust.packageName)
                if (identity() != before) return UltraAuthorizationRestoreResult.identityChanged(granted, revoke())
                if (readback != true) return requireNotNull(granted).let {
                    UltraAuthorizationRestoreResult.primary(it, "MANAGER_AUTH_READBACK_FAILED")
                }
                // add already rebuilt the complete UID table. Do not remap the
                // manager name again after its identity was checked.
                return granted?.let { UltraAuthorizationRestoreResult.primary(it) }
                    ?: UltraAuthorizationRestoreResult.local()
            } else if (trust.packageName in listed) {
                val revoked = revoke().also { completed = it }
                if (!revoked.succeeded) return UltraAuthorizationRestoreResult.primary(revoked)
                if (packages()?.contains(trust.packageName) != false)
                    return UltraAuthorizationRestoreResult.primary(revoked, "MANAGER_AUTH_REVOKE_UNVERIFIED")
                return UltraAuthorizationRestoreResult.primary(revoked)
            }
            return UltraAuthorizationRestoreResult.refresh(refreshAll())
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (interrupted: InterruptedException) {
            throw interrupted
        } catch (error: Exception) {
            val primary = completed ?: throw error
            throw UltraAuthorizationRestoreException(
                UltraAuthorizationRestoreResult.primary(primary, "MANAGER_AUTH_RESTORE_EXCEPTION"), error)
        }
    }

    fun <T> recover(trust: UltraReinstallTrust?, identity: () -> ApplicationIdentity?, read: () -> T?): T? {
        val before = identity() ?: return null
        if (trust == null || !trust.allows(before.uid, before)) return null
        val result = read()
        return result.takeIf { identity() == before }
    }
}

/** Managers use their socket UID; root transports must delegate a manager UID checked against pinned trust. */
internal object UltraIdentityHandshake {
    const val VERSION = 1
    const val BUILD_VERSION = 2
    const val DEPLOYMENT_VERSION = 3
    const val DELEGATED_VERSION = 4

    fun serve(trust: UltraReinstallTrust, peerUid: Int, identity: (Int) -> ApplicationIdentity?,
              input: InputStream, output: OutputStream, readKey: () -> String?,
              buildIdentity: () -> String? = { UltraSdkBuild.BUILD_ID },
              deploymentIdentity: () -> String? = { null }) {
        val directIdentity = if (peerUid == 0) null else identity(peerUid)
        if (peerUid != 0 && !trust.allows(peerUid, directIdentity)) return
        val request = DataInputStream(input)
        val protocol = request.readInt()
        // Root is a transport for the original manager UID, not a credential recipient.
        if (peerUid == 0 && protocol != DELEGATED_VERSION) return
        val targetUid: Int
        val version: Int
        if (protocol == DELEGATED_VERSION) {
            if (peerUid != 0) return
            val delegated = try { request.readInt() to request.readInt() } catch (_: EOFException) { return }
            targetUid = delegated.first
            if (targetUid % 100_000 !in 10_000..19_999) return
            version = delegated.second
        } else {
            targetUid = peerUid
            version = protocol
        }
        if (version !in VERSION..DEPLOYMENT_VERSION) return
        val before = if (targetUid == peerUid) directIdentity else identity(targetUid)
        if (!trust.allows(targetUid, before)) return
        val key = readKey() ?: return
        if (!UltraKernelCredential.isValid(key) || !UltraKernelCredential.of(key).sdkMetadataValid) return
        val build = if (version >= BUILD_VERSION) buildIdentity() ?: return else null
        val deployment = if (version == DEPLOYMENT_VERSION) {
            deploymentIdentity()?.takeIf { it.matches(Regex("[0-9a-f]{64}")) } ?: return
        } else null
        if (targetUid != 0 && identity(targetUid) != before) return
        val bytes = key.toByteArray(Charsets.US_ASCII)
        try {
            DataOutputStream(output).apply {
                writeInt(version)
                write(bytes)
                if (version >= BUILD_VERSION) writeUTF(requireNotNull(build))
                if (version == DEPLOYMENT_VERSION) writeUTF(requireNotNull(deployment))
                flush()
            }
        } finally { bytes.fill(0) }
    }
}

/** A real uid-0 command proves the kernel accepts this key; su refresh is best effort. */
internal object UltraReinstallPairing {
    fun recover(
        candidate: String?,
        rootUid: (String) -> Int?,
        refreshAuthorization: (String) -> Unit,
        store: (String) -> Unit,
    ): String {
        if (candidate == null || !UltraKernelCredential.isValid(candidate) ||
            !UltraKernelCredential.of(candidate).sdkMetadataValid) return "RECOVERY_KEY_INVALID"
        val key = requireNotNull(candidate)
        if (rootUid(key) != 0) return "RECOVERY_ROOT_NOT_VERIFIED"
        store(key)
        runCatching { refreshAuthorization(key) }
        return "RECOVERED"
    }
}
