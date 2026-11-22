package dev.maplesu.manager.runtime

import android.content.Context
import android.content.pm.PackageManager
import android.os.Binder
import com.maplesu.core.BuildConfig
import java.security.MessageDigest

/** Called under the service identity, after capturing Binder.getCallingUid(). */
internal class ManagerCallerVerifier(context: Context) {
    private val pm = context.packageManager
    private val expected = readIdentity()
    private val policy = ManagerCallerPolicy(expected)

    init {
        // libsu loads this package's Context for the launching Android user.
        require(context.packageName == BuildConfig.APPLICATION_ID &&
            context.applicationInfo.uid == expected.uid &&
            context.applicationInfo.sourceDir == expected.apkPath)
    }

    fun enforce(callerUid: Int) {
        try {
            policy.enforce(callerUid, pm.getPackagesForUid(callerUid)?.toList(), readIdentity())
        } catch (exception: Exception) {
            throw SecurityException("Manager caller identity could not be verified", exception)
        }
    }

    fun <T> withCallingManager(block: () -> T): T {
        val callerUid = Binder.getCallingUid()
        val token = Binder.clearCallingIdentity()
        try {
            enforce(callerUid)
            return block()
        } finally {
            Binder.restoreCallingIdentity(token)
        }
    }

    @Suppress("DEPRECATION")
    private fun readIdentity(): ManagerIdentity {
        val info = pm.getPackageInfo(BuildConfig.APPLICATION_ID, PackageManager.GET_SIGNING_CERTIFICATES)
        val app = requireNotNull(info.applicationInfo)
        val signers = requireNotNull(info.signingInfo?.apkContentsSigners)
        require(signers.isNotEmpty())
        val hashes = signers.map { signature ->
            MessageDigest.getInstance("SHA-256").digest(signature.toByteArray())
                .joinToString("") { "%02x".format(it) }
        }.toSet()
        return ManagerIdentity(app.uid, info.packageName, hashes,
            info.firstInstallTime, info.lastUpdateTime, app.sourceDir)
    }
}
