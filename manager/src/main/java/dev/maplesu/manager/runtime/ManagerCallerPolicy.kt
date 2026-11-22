package dev.maplesu.manager.runtime

/** Snapshot from the service's PackageManager, never from a client parcel. */
internal class ManagerIdentity(
    val uid: Int,
    val packageName: String,
    signers: Set<String>,
    val firstInstallTime: Long,
    val lastUpdateTime: Long,
    val apkPath: String,
) {
    val signers: Set<String> = java.util.Collections.unmodifiableSet(HashSet(signers))

    init {
        require(uid >= 0 && uid % 100_000 in 10_000..19_999)
        require(packageName.isNotBlank() && apkPath.startsWith('/'))
        require(firstInstallTime > 0 && lastUpdateTime >= firstInstallTime)
        require(this.signers.isNotEmpty() && this.signers.all { it.matches(Regex("[0-9a-f]{64}")) })
    }

    fun matches(other: ManagerIdentity): Boolean =
        uid == other.uid && packageName == other.packageName && signers == other.signers &&
            firstInstallTime == other.firstInstallTime && lastUpdateTime == other.lastUpdateTime &&
            apkPath == other.apkPath
}

/** Each service belongs to one full Android UID, including its user ID. */
internal class ManagerCallerPolicy(private val expected: ManagerIdentity) {
    fun enforce(callerUid: Int, packagesForUid: List<String>?, current: ManagerIdentity?) {
        if (callerUid != expected.uid || packagesForUid != listOf(expected.packageName) ||
            current == null || !expected.matches(current)) {
            throw SecurityException("Manager caller identity changed or is not permitted")
        }
    }
}
