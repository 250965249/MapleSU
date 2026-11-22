package dev.maplesu.manager.runtime.authorization

import android.content.Context
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import java.security.MessageDigest
import java.util.Locale

/**
 * The package facts one authorization decision needs, behind a tiny seam.
 *
 * <p>The App process reads them through its own `Context`'s `PackageManager`; the
 * one-shot root tool must not create a `Context` at all. Creating one is what crashed
 * the tool: `ActivityThread.systemMain()` reaches
 * `android.content.res.Resources.<init>` → `AssetManager.getSystem` →
 * `createImmutableFrameworkIdmapsInZygote` → `createIdmap` → `ExecuteBinary`, and that
 * helper child calls `setgid`, which the App's inherited seccomp filter traps with
 * `SIGSYS` (`syscall 144`, exit 128+31). The tool is a fork of the App, so no user-space
 * code can lift that filter.
 *
 * <p>So the root tool asks the system package service directly
 * ([SystemPackageSnapshotSource]) and never asks for a `Context`/`Resources`. The
 * identity validation itself stays in one place ([PackageIdentityReader]), which is the
 * same rule the App-side path has always used - duplicating that rule would be a way for
 * the two paths to disagree about a signer or a UID.
 */
internal interface PackageSnapshotSource {
    /** Package names installed for [uid], or null when the question cannot be answered. */
    fun packagesForUid(uid: Int): List<String>?

    /** The current installation record of [packageName], or null when it is not installed. */
    fun packageInfo(packageName: String): PackageInfo?

    /** Installation for the target UID's Android user, not necessarily the Manager's. */
    fun packageInfo(packageName: String, uid: Int): PackageInfo? = packageInfo(packageName)
}

/** The App-side source: `PackageManager` already scoped to this App's Android user. */
internal class ContextPackageSnapshotSource(context: Context) : PackageSnapshotSource {
    private val packageManager = context.packageManager
    private val contextUid = context.applicationInfo.uid
    private val systemSource by lazy { SystemPackageSnapshotSource(contextUid) }

    override fun packagesForUid(uid: Int): List<String>? =
        runCatching { packageManager.getPackagesForUid(uid)?.toList() }.getOrNull()

    override fun packageInfo(packageName: String): PackageInfo? =
        runCatching {
            packageManager.getPackageInfo(packageName, PackageManager.GET_SIGNING_CERTIFICATES)
        }.getOrNull()

    override fun packageInfo(packageName: String, uid: Int): PackageInfo? =
        if (SystemPackageSnapshotSource.userIdOf(uid) == SystemPackageSnapshotSource.userIdOf(contextUid)) {
            packageInfo(packageName)
        } else {
            systemSource.packageInfo(packageName, uid)
        }
}

/**
 * The one-shot root tool's source: `IPackageManager` through `AppGlobals`.
 *
 * <p>It is not a `Context`: no `LoadedApk`, no `Resources`, no idmap helper, no
 * `setgid`. `getPackageInfo(name, flags, userId)` takes the user explicitly, so the
 * reader also works for a secondary-user Manager instead of silently asking user 0.
 * Each read derives its user from the target full UID; managerUid scopes only the legacy overload.
 */
internal class SystemPackageSnapshotSource(private val managerUid: Int) : PackageSnapshotSource {
    private val manager: Any? by lazy { PackageManagerBridge.packageManager() }
    private val packagesMethod by lazy {
        manager?.javaClass?.methods?.firstOrNull {
            it.name == "getPackagesForUid" &&
                it.parameterTypes.size == 1 &&
                it.parameterTypes[0] == Int::class.javaPrimitiveType
        }
    }
    private val packageInfoMethod by lazy {
        manager?.javaClass?.methods?.firstOrNull {
            it.name == "getPackageInfo" &&
                it.parameterTypes.size == 3 &&
                it.parameterTypes[0] == String::class.java &&
                it.parameterTypes[2] == Int::class.javaPrimitiveType
        }
    }

    override fun packagesForUid(uid: Int): List<String>? {
        val packageManager = manager ?: return null
        val method = packagesMethod ?: return null
        val names = runCatching { method.invoke(packageManager, uid) }.getOrNull() as? Array<*>
            ?: return null
        if (names.any { it !is String }) return null
        return names.map { it as String }
    }

    override fun packageInfo(packageName: String): PackageInfo? = packageInfo(packageName, managerUid)

    override fun packageInfo(packageName: String, uid: Int): PackageInfo? {
        val packageManager = manager ?: return null
        val method = packageInfoMethod ?: return null
        // The AIDL signature widened from int flags to long flags on API 33. Both are
        // accepted here so the same APK works on the minSdk 31 baseline and on this
        // device; the selected method's own parameter type decides which box we pass.
        val flags = when (method.parameterTypes[1]) {
            Long::class.javaPrimitiveType -> PackageManager.GET_SIGNING_CERTIFICATES.toLong()
            Int::class.javaPrimitiveType -> PackageManager.GET_SIGNING_CERTIFICATES
            else -> return null
        }
        return runCatching { method.invoke(packageManager, packageName, flags, userIdOf(uid)) }
            .getOrNull() as? PackageInfo
    }

    companion object {
        /** Pure and host-tested; the Android user is encoded in the high UID digits. */
        fun userIdOf(managerUid: Int): Int = managerUid / 100_000
    }
}

/** One complete full-UID installation rule, shared by App and root-side sources. */
internal class PackageIdentityReader(
    private val source: PackageSnapshotSource,
) : AuthorizationPolicy.TrustedIdentityProvider {

    override fun read(callingUid: Int): ApplicationIdentity? {
        if (callingUid < 0 || callingUid % 100_000 !in 10_000..19_999) return null
        return try {
            val names = packageNames(callingUid) ?: return null
            val first = installations(callingUid, names) ?: return null
            if (packageNames(callingUid) != names) return null
            val second = installations(callingUid, names) ?: return null
            if (first != second || packageNames(callingUid) != names) return null
            ApplicationIdentity(callingUid, first)
        } catch (_: Exception) {
            // Preserve the existing unavailable-identity result; never admit partial facts.
            null
        }
    }

    private fun packageNames(uid: Int): List<String>? {
        val names = source.packagesForUid(uid) ?: return null
        if (names.isEmpty() || names.size > ApplicationIdentity.MAX_PACKAGES ||
            names.any { it.isBlank() } || names.toSet().size != names.size) return null
        return names.sorted()
    }

    private fun installations(uid: Int, names: List<String>): List<ApplicationIdentity.Installation>? {
        val result = ArrayList<ApplicationIdentity.Installation>(names.size)
        for (name in names) {
            val info = source.packageInfo(name, uid) ?: return null
            val app = info.applicationInfo ?: return null
            if (app.uid != uid || info.packageName != name) return null
            val certificates = info.signingInfo?.apkContentsSigners ?: return null
            if (certificates.isEmpty()) return null
            val signers = certificates.map { certificate ->
                MessageDigest.getInstance("SHA-256").digest(certificate.toByteArray())
                    .joinToString("") { "%02x".format(Locale.ROOT, it.toInt() and 255) }
            }.toSet()
            result += ApplicationIdentity.Installation(name, signers,
                info.firstInstallTime, info.lastUpdateTime, app.sourceDir)
        }
        return result
    }

    /** Revocation's informational representative; null remains a valid tombstone target. */
    fun packageNameForUid(uid: Int): String? = packageNames(uid)?.firstOrNull()
}

/**
 * Resolve `IPackageManager` without a `Context`.
 *
 * <p>`AppGlobals.getPackageManager()` is the framework's own context-free accessor; it
 * reaches `ActivityThread.getPackageManager()`, which is a static binder lookup and
 * never creates `Resources`. A bare `app_process` normally has hidden-API enforcement
 * disabled, but the LSPosed bypass is applied as a fallback so a stricter runtime cannot
 * turn this into a silent "identity unavailable".
 */
private object PackageManagerBridge {
    private const val APP_GLOBALS = "android.app.AppGlobals"
    private const val APP_GLOBALS_DESCRIPTOR = "Landroid/app/AppGlobals;"
    private const val PACKAGE_MANAGER_DESCRIPTOR = "Landroid/content/pm/IPackageManager;"

    fun packageManager(): Any? {
        direct()?.let { return it }
        runCatching {
            val bypass = Class.forName("org.lsposed.hiddenapibypass.HiddenApiBypass")
            bypass.getDeclaredMethod("addHiddenApiExemptions", Array<String>::class.java)
                .invoke(null, arrayOf(APP_GLOBALS_DESCRIPTOR, PACKAGE_MANAGER_DESCRIPTOR))
        }
        return direct()
    }

    private fun direct(): Any? = runCatching {
        Class.forName(APP_GLOBALS).getDeclaredMethod("getPackageManager").invoke(null)
    }.getOrNull()
}
