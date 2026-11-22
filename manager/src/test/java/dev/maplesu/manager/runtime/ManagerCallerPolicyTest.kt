package dev.maplesu.manager.runtime

import org.junit.Assert.*
import org.junit.Test

class ManagerCallerPolicyTest {
    private val name = "dev.maplesu.manager"
    private val certificate = "a".repeat(64)
    private fun identity(uid: Int = 10123, packageName: String = name,
        signers: Set<String> = setOf(certificate), installed: Long = 100,
        updated: Long = 200, path: String = "/data/app/old/base.apk") =
        ManagerIdentity(uid, packageName, signers, installed, updated, path)

    private fun reject(uid: Int = 10123, packages: List<String>? = listOf(name),
        current: ManagerIdentity? = identity()) {
        assertThrows(SecurityException::class.java) {
            ManagerCallerPolicy(identity()).enforce(uid, packages, current)
        }
    }

    @Test fun acceptsOnlyTheExactInstalledManager() {
        ManagerCallerPolicy(identity()).enforce(10123, listOf(name), identity())
    }

    @Test fun rejectsAnotherUserWithTheSameAppId() = reject(uid = 110123)
    @Test fun rejectsAnotherApplicationUid() = reject(uid = 10124)
    @Test fun rejectsRootAndShellAsManagerCallers() {
        reject(uid = 0)
        reject(uid = 2000)
    }
    @Test fun rejectsUnresolvedOrEmptyPackages() {
        reject(packages = null)
        reject(packages = emptyList())
    }
    @Test fun rejectsSharedUidAndDuplicatePackageResults() {
        reject(packages = listOf(name, "other.package"))
        reject(packages = listOf(name, name))
    }
    @Test fun rejectsPackageSpoofingAndMissingInstallation() {
        reject(packages = listOf("other.package"))
        reject(current = null)
        reject(current = identity(packageName = "other.package"))
    }
    @Test fun rejectsUidReuseReinstallAndUpdate() {
        reject(current = identity(uid = 10124))
        reject(current = identity(installed = 101))
        reject(current = identity(updated = 201))
        reject(current = identity(path = "/data/app/new/base.apk"))
    }
    @Test fun rejectsSignerRotationAndAddedOrRemovedSigners() {
        reject(current = identity(signers = setOf("b".repeat(64))))
        reject(current = identity(signers = setOf(certificate, "b".repeat(64))))
        val multiple = identity(signers = setOf(certificate, "b".repeat(64)))
        assertThrows(SecurityException::class.java) {
            ManagerCallerPolicy(multiple).enforce(10123, listOf(name), identity())
        }
    }
    @Test fun acceptsMatchingMultiSignerSetsInAnyOrder() {
        val other = "b".repeat(64)
        ManagerCallerPolicy(identity(signers = linkedSetOf(certificate, other))).enforce(
            10123, listOf(name), identity(signers = linkedSetOf(other, certificate)))
    }
    @Test fun keepsIndependentServicesForDifferentUsers() {
        val secondary = identity(uid = 110123)
        val policy = ManagerCallerPolicy(secondary)
        policy.enforce(110123, listOf(name), secondary)
        assertThrows(SecurityException::class.java) { policy.enforce(10123, listOf(name), identity()) }
    }
    @Test fun snapshotsSignerInputAndDoesNotExposeAMutableSet() {
        val signers = mutableSetOf(certificate)
        val original = identity(signers = signers)
        signers.clear()
        assertEquals(setOf(certificate), original.signers)
        assertThrows(UnsupportedOperationException::class.java) {
            (original.signers as MutableSet<String>).clear()
        }
    }
    @Test fun rejectsIncompleteTrustAnchors() {
        for (uid in listOf(-1, 0, 2000, 99000, 1099000)) {
            assertThrows(IllegalArgumentException::class.java) { identity(uid = uid) }
        }
        assertThrows(IllegalArgumentException::class.java) { identity(signers = emptySet()) }
        assertThrows(IllegalArgumentException::class.java) { identity(signers = setOf("certificate")) }
        assertThrows(IllegalArgumentException::class.java) { identity(installed = 0) }
        assertThrows(IllegalArgumentException::class.java) { identity(updated = 99) }
        assertThrows(IllegalArgumentException::class.java) { identity(path = "relative.apk") }
    }
}
