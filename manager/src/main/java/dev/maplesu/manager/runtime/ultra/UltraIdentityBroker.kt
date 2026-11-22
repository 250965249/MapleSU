package dev.maplesu.manager.runtime.ultra

import android.net.LocalServerSocket
import android.net.LocalSocket
import android.os.Process
import android.system.Os
import android.system.OsConstants
import dev.maplesu.manager.runtime.authorization.PackageIdentityReader
import dev.maplesu.manager.runtime.authorization.SystemPackageSnapshotSource
import dev.maplesu.manager.runtime.authorization.ApplicationIdentity
import dev.maplesu.manager.runtime.authorization.AuthorizationSnapshot
import dev.maplesu.manager.runtime.authorization.AuthorizationsSnapshot
import dev.maplesu.manager.runtime.authorization.ManagerSuperuserPolicy
import dev.maplesu.manager.runtime.authorization.RootAuthorizationStore
import dev.maplesu.manager.runtime.authorization.SuperuserJournalStore
import dev.maplesu.manager.workmode.storage.MoveSet
import java.io.File
import java.io.FileInputStream
import org.json.JSONObject

/** Root-only environment service. It serves one fixed credential operation, never shell requests. */
object UltraIdentityBroker {
    internal const val DIRECTORY = MoveSet.ULTRA_IDENTITY_ROOT
    internal const val CONFIG = "$DIRECTORY/identity.json"
    internal const val APK = "$DIRECTORY/pairing.apk"
    internal const val DISABLED = "$DIRECTORY/disabled"
    internal const val LEGACY_MODULE_ID = "d4481c55c9544fd3acf6defc01369bd1"
    internal const val VERSION = UltraIdentityHandshake.VERSION
    internal fun socketName(userId: Int) = "maplesu.ultra.identity.v1.$userId"

    private val selectedDirectory: String by lazy {
        val generation = System.getProperty("maplesu.ultra.boot.generation") ?: return@lazy DIRECTORY
        require(generation.matches(Regex("[0-9a-f]{32}")))
        "$DIRECTORY/generation-$generation"
    }

    private fun readConfig(): JSONObject {
        for (path in listOf("/data/adb", "/data/adb/maplesu", DIRECTORY, selectedDirectory).distinct()) {
            val stat = Os.lstat(path)
            check(OsConstants.S_ISDIR(stat.st_mode) && stat.st_uid == 0 && stat.st_mode and 0x12 == 0)
        }
        check(!File(DISABLED).exists())
        val fd = Os.open("$selectedDirectory/identity.json", OsConstants.O_RDONLY or OsConstants.O_NOFOLLOW or OsConstants.O_CLOEXEC, 0)
        return FileInputStream(fd).use { input ->
            val stat = Os.fstat(fd)
            check(OsConstants.S_ISREG(stat.st_mode) && stat.st_uid == 0 && stat.st_mode and 0x1ff == 0x180 &&
                stat.st_nlink == 1L && stat.st_size in 1..8192)
            JSONObject(input.readBytes().toString(Charsets.UTF_8)).also { check(it.getInt("schema") == VERSION) }
        }
    }

    private fun managerIdentity(trust: UltraReinstallTrust): ApplicationIdentity? {
        val source = SystemPackageSnapshotSource(trust.userId * 100_000)
        val uid = source.packageInfo(trust.packageName)?.applicationInfo?.uid ?: return null
        return PackageIdentityReader(source).read(uid)
    }

    private fun restoreAuthorization(trust: UltraReinstallTrust,
                                     authorization: UltraManagerSignatureAuthorization.Session,
                                     client: UltraRuntimeClient): UltraAuthorizationRestoreResult {
        // The immutable locator selects by Android user; this selector asserts no
        // installed UID and never creates/imports/enables an authority.
        val directory = RootAuthorizationStore.authorityDirectory(trust.userId * 100_000 + 10_000)
        fun snapshot() = AuthorizationsSnapshot.load(directory.resolve("authorizations.bin"),
            directory.resolve(SuperuserJournalStore.FILE).toFile()).also {
                check(!it.corrupt) { "AUTHORITY_UNREADABLE" }
            }
        var observed: AuthorizationSnapshot? = null
        var currentIdentity: ApplicationIdentity? = null
        var synchronizedRevision: Long? = null
        var decisionCode: String? = null
        val state = UltraAuthorizationState(currentUserId = trust.userId)
        val port = UltraSelfWhitelist.clientPort(client)
        val result = authorization.refreshAttempt(identity = {
            if (File(DISABLED).exists()) null else {
                val authority = snapshot()
                val identity = managerIdentity(trust)
                observed = authority
                currentIdentity = identity
                decisionCode = when {
                    identity == null -> UltraManagerSignatureAuthorization.IDENTITY_PENDING
                    !trust.allows(identity.uid, identity) -> "MANAGER_IDENTITY_CHANGED"
                    else -> ManagerSuperuserPolicy.decide(authority, identity.uid, identity).reason
                }
                currentBrokerManagerIdentity(trust, authority, identity)
                    ?.takeIf { synchronizedRevision == null || synchronizedRevision == authority.rev }
            }
        }, packages = {
            if (File(DISABLED).exists()) null else port.uidProfiles()?.filter {
                it.allow && it.uid / 100_000 == trust.userId
            }?.map { it.packageName }
        }, grant = {
            val identity = currentIdentity
            when {
                File(DISABLED).exists() -> UltraAuthorizationAttempt.local("SUSPENDED")
                identity == null || observed == null -> UltraAuthorizationAttempt.local("MANAGER_IDENTITY_PENDING")
                snapshot() != observed -> UltraAuthorizationAttempt.local("SU_AUTH_REVISION_CHANGED")
                else -> {
                    synchronizedRevision = observed?.rev
                    state.setUidGranted(port, identity.uid, trust.packageName, true,
                        current = { !File(DISABLED).exists() }, durableDecisionCommitted = true)
                }
            }
        }, revoke = {
            val profiles = port.uidProfiles()
            if (File(DISABLED).exists()) UltraAuthorizationAttempt.local("SUSPENDED")
            else if (profiles == null) UltraAuthorizationAttempt.local("MANAGER_AUTH_LIST_UNREADABLE")
            else {
                var last = UltraAuthorizationAttempt.local()
                for (profile in profiles.filter { it.allow && it.uid / 100_000 == trust.userId && it.packageName == trust.packageName }) {
                    last = state.setUidGranted(port, profile.uid, trust.packageName, false,
                        current = { !File(DISABLED).exists() }, durableDecisionCommitted = true)
                    if (!last.succeeded) break
                }
                last
            }
        })
        return if (result.status == UltraManagerSignatureAuthorization.IDENTITY_PENDING &&
            decisionCode != null && decisionCode != "ALLOW") result.withStatus(requireNotNull(decisionCode)) else result
    }

    @JvmStatic
    fun main(args: Array<String>) {
        check(Process.myUid() == 0)
        val config = readConfig()
        val user = config.getInt("userId")
        // Freeze the launched APK/config identity; rereading a replacement config is not a restart.
        val deployment = config.optString("deploymentId")
        // A second start leaves the listener's owner intact. No peer-controlled socket paths.
        val server = runCatching { LocalServerSocket(socketName(user)) }.getOrNull() ?: return
        server.use {
            // start.sh waits for boot_completed and carries the repaired SDK.
            // The old embedded bootstrap may have built an empty early UID map.
            Thread({
                Process.setThreadPriority(Process.THREAD_PRIORITY_BACKGROUND)
                runCatching {
                    val key = UltraRecoveryKey.open(config.getString("payload"), config.getString("androidId"),
                        config.getString("packageName")) ?: return@runCatching
                    if (File(DISABLED).exists()) return@runCatching
                    val client = UltraRuntimeClient { key }
                    val trust = UltraReinstallTrust.fromConfig(config.toString())
                        ?.withSigningLineage(UltraSigningLineage(SystemPackageSnapshotSource(user * 100_000))::read)
                        ?: return@runCatching
                    val authorization = UltraManagerSignatureAuthorization.Session(trust)
                    val result = UltraBootAuthorizationRestore().maintainAttempt(
                        suspended = { File(DISABLED).exists() },
                        restore = { restoreAuthorization(trust, authorization, client) },
                        onResult = { android.util.Log.i("MapleSUUltraIdentity", "authorization=${it.diagnosticSummary}") })
                    android.util.Log.i("MapleSUUltraIdentity", "boot authorization=$result")
                }.onFailure {
                    if (it is java.util.concurrent.CancellationException) throw it
                    if (it is InterruptedException) Thread.currentThread().interrupt()
                    android.util.Log.w("MapleSUUltraIdentity", "boot authorization refresh failed", it)
                }
            }, "maplesu-ultra-auth-restore").apply { isDaemon = true }.start()
            while (true) {
                val peer = server.accept()
                peer.use { runCatching { reply(it, user, deployment) } }
            }
        }
    }

    private fun reply(peer: LocalSocket, userId: Int, deployment: String) {
        peer.soTimeout = 2000
        val peerUid = peer.peerCredentials.uid
        val config = readConfig()
        val trust = UltraReinstallTrust.fromConfig(config.toString())
            ?.withSigningLineage(UltraSigningLineage(SystemPackageSnapshotSource(userId * 100_000))::read) ?: return
        check(trust.userId == userId)
        UltraIdentityHandshake.serve(trust, peerUid,
            identity = { uid -> if (File(DISABLED).exists()) null else
                PackageIdentityReader(SystemPackageSnapshotSource(uid)).read(uid) },
            input = peer.inputStream, output = peer.outputStream,
            readKey = { if (File(DISABLED).exists()) null else
                UltraRecoveryKey.open(config.getString("payload"), config.getString("androidId"), trust.packageName) },
            buildIdentity = {
                val receipt = UltraRuntimeClient().sdkBuildIdentity()
                UltraSdkBuild.BUILD_ID.takeIf {
                    receipt.succeeded && receipt.string("buildId") == it &&
                        receipt.string("sdkSha256") == UltraSdkBuild.SDK_SHA256 &&
                        receipt.string("sdkVersion") == UltraSdkBuild.SDK_VERSION
                }
            }, deploymentIdentity = { deployment })
    }
}

/** Environment signer trust grants credential recovery; the sole authority grants standard su. */
internal fun currentBrokerManagerIdentity(trust: UltraReinstallTrust, snapshot: AuthorizationSnapshot,
                                          identity: ApplicationIdentity?): ApplicationIdentity? =
    identity?.takeIf { trust.allows(it.uid, it) && ManagerSuperuserPolicy.decide(snapshot, it.uid, it).allowed }
