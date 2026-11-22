package dev.maplesu.manager.runtime.ultra

import dev.maplesu.manager.runtime.authorization.ApplicationIdentity
import dev.maplesu.manager.runtime.authorization.PackageIdentityReader
import dev.maplesu.manager.runtime.authorization.PackageSnapshotSource
import java.security.MessageDigest
import java.util.Locale

/** Only PackageManager's verified rotation history may extend the persisted signer pin. */
internal class UltraSigningLineage(private val source: PackageSnapshotSource) {
    fun read(identity: ApplicationIdentity): List<String>? = runCatching {
        val reader = PackageIdentityReader(source)
        if (reader.read(identity.uid) != identity) return null
        val info = source.packageInfo(identity.packageName) ?: return null
        val app = info.applicationInfo ?: return null
        if (info.packageName != identity.packageName || app.uid != identity.uid ||
            info.firstInstallTime != identity.firstInstallTime || info.lastUpdateTime != identity.lastUpdateTime ||
            app.sourceDir != identity.apkPath) return null
        val signing = info.signingInfo ?: return null
        if (signing.hasMultipleSigners()) return null
        val current = signing.apkContentsSigners?.map { digest(it.toByteArray()) } ?: return null
        if (current.size != 1 || current.toSet() != identity.signers) return null
        val history = signing.signingCertificateHistory?.map { digest(it.toByteArray()) } ?: return null
        history.takeIf { reader.read(identity.uid) == identity }
    }.getOrNull()

    private fun digest(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes)
        .joinToString("") { "%02x".format(Locale.ROOT, it.toInt() and 255) }
}
