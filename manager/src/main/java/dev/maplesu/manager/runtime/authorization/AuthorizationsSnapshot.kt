package dev.maplesu.manager.runtime.authorization

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.io.File
import java.nio.file.Path
import java.nio.file.Paths
import java.util.Base64

/**
 * Where the one authority lives (design §1.1).
 *
 * <p>A root-only immutable `user-<userId>.authority` locator selects the original
 * numeric directory, independently of Manager reinstall/appId. It is validated by
 * [RootAuthorizationStore]: root-owned, mode 0700, files 0600, so an app process can
 * neither write nor read it. That is the whole point of putting the authority there -
 * a same-uid process cannot forge its own grant. The journal is a sibling in the same
 * directory, so it inherits the same protection.
 */
object SuperuserPaths {
    const val ROOT = "/data/adb/maplesu/authorization"

    @JvmStatic
    fun directory(managerUid: Int): File = RootAuthorizationStore.authorityDirectory(managerUid).toFile()

    @JvmStatic
    fun store(managerUid: Int): Path =
        directory(managerUid).toPath().resolve("authorizations.bin")

    @JvmStatic
    fun journal(managerUid: Int): File =
        File(directory(managerUid), SuperuserJournalStore.FILE)

    @JvmStatic
    fun legacyImportMarker(managerUid: Int): File =
        File(directory(managerUid), "import-complete")
}

/**
 * Reads the authority once, for one decision.
 *
 * <p>Both files are read on every decision, with two matching journal samples around
 * the binary read and at most one retry. Nothing is cached across a request. That is the
 * mechanism behind the design's "撤销即失效": a revoke written by another process is
 * visible to the next request without any invalidation channel, because there is no
 * cache to invalidate.
 *
 * <p>Failure semantics: an unreadable binary store produces
 * [AuthorizationSnapshot.unreadable] (every decision refuses). A missing
 * journal is legacy history; an existing malformed or unreadable journal denies every
 * decision because it may contain a newer revocation than the binary store.
 */
object AuthorizationsSnapshot {
    @JvmStatic
    fun load(store: Path, journalFile: File): AuthorizationSnapshot {
        return try {
            repeat(2) {
                val before = SuperuserJournalStore.read(journalFile) ?: SuperuserJournal.fresh()
                val state = FileAuthorizationStore(store).load()
                val after = SuperuserJournalStore.read(journalFile) ?: SuperuserJournal.fresh()
                if (before == after) return from(state.enabled, state.grants, after, state.profiles)
            }
            AuthorizationSnapshot.unreadable()
        } catch (_: Throwable) {
            AuthorizationSnapshot.unreadable()
        }
    }

    /** The same read from a directory layout; used by tests and the one-shot tool. */
    @JvmStatic
    fun load(managerUid: Int): AuthorizationSnapshot =
        load(SuperuserPaths.store(managerUid), SuperuserPaths.journal(managerUid))

    @JvmStatic
    @JvmOverloads
    fun from(
        enabled: Boolean,
        grants: Map<Int, ApplicationIdentity>,
        journal: SuperuserJournal,
        profiles: Map<Int, StoredSuProfile> = emptyMap(),
    ): AuthorizationSnapshot {
        require(journal.profileRev.keys.map { it.toInt() }.toSet() == profiles.keys) { "AUTH_STORE_PROFILE_MISSING" }
        return AuthorizationSnapshot(
        enabled = enabled && journal.pendingSwitch == null,
        grants = grants,
        rev = journal.pendingSwitch?.let { it.rev - 1 } ?: journal.rev,
        uidRev = journal.uidRev.mapNotNull { (key, value) ->
            key.toIntOrNull()?.let { it to value }
        }.toMap(),
        tombs = journal.tombs,
        applied = journal.applied,
        migrated = journal.migrated,
        unresolved = journal.unresolved,
        switchPending = journal.pendingSwitch != null,
        pendingApplyRev = journal.pendingApplyRev,
        profiles = profiles,
        profileRev = journal.profileRev.mapKeys { it.key.toInt() },
    )
    }

    /** The snapshot a root-side caller with no authority files yet sees: switch off. */
    @JvmStatic
    fun empty(): AuthorizationSnapshot = AuthorizationSnapshot.empty()
}

/**
 * The wire form the one-shot root tool prints (`OK <base64>`).
 *
 * <p>Why a wire form at all: in the Ultra (hook) route the endpoint runs in the app
 * process, which cannot read `/data/adb/maplesu/authorization` (root 0600). The only
 * way to decide without weakening the store is to ask a short-lived root child for the
 * snapshot. The format is base64(JSON) so a stdout line cannot be confused by package
 * names or APK paths.
 *
 * <p>The wire form carries the stored identities - not a fresh PackageManager read - so
 * the decision compares the caller's **current** identity against the **recorded** one
 * in the same code path on both modes.
 */
object SuperuserWire {
    const val SCHEMA = 3
    private const val IDENTITY_SCHEMA = 2

    private val json = Json {
        ignoreUnknownKeys = true
        encodeDefaults = true
        explicitNulls = false
    }

    @Serializable
    data class WireIdentity(
        val uid: Int,
        val packageName: String,
        val signers: List<String>,
        val firstInstallTime: Long,
        val lastUpdateTime: Long,
        val apkPath: String,
        val members: List<WireInstallation> = emptyList(),
    )

    @Serializable
    data class WireInstallation(
        val packageName: String,
        val signers: List<String>,
        val firstInstallTime: Long,
        val lastUpdateTime: Long,
        val apkPath: String,
    )

    private fun toWireIdentity(identity: ApplicationIdentity) = WireIdentity(
        identity.uid, identity.packageName, identity.signers.sorted(),
        identity.firstInstallTime, identity.lastUpdateTime, identity.apkPath,
        identity.members.values.map { member ->
            WireInstallation(member.packageName, member.signers.sorted(),
                member.firstInstallTime, member.lastUpdateTime, member.apkPath)
        },
    )

    private fun fromWireIdentity(wire: WireIdentity, schema: Int): ApplicationIdentity {
        if (schema == 1) {
            require(wire.members.isEmpty()) { "AUTH_IDENTITY_INVALID" }
            return ApplicationIdentity(wire.uid, wire.packageName, listOf(wire.packageName),
                wire.signers.toSet(), wire.firstInstallTime, wire.lastUpdateTime, wire.apkPath)
        }
        require(schema in IDENTITY_SCHEMA..SCHEMA && wire.members.isNotEmpty()) { "AUTH_IDENTITY_INVALID" }
        val identity = ApplicationIdentity(wire.uid, wire.members.map { member ->
            ApplicationIdentity.Installation(member.packageName, member.signers.toSet(),
                member.firstInstallTime, member.lastUpdateTime, member.apkPath)
        })
        require(identity.packageName == wire.packageName && identity.signers == wire.signers.toSet() &&
            identity.firstInstallTime == wire.firstInstallTime && identity.lastUpdateTime == wire.lastUpdateTime &&
            identity.apkPath == wire.apkPath) { "AUTH_IDENTITY_INVALID" }
        return identity
    }

    @Serializable
    data class WireProfile(val identity: WireIdentity, val profile: SuProfile)

    @Serializable
    data class WireSnapshot(
        val schema: Int = SCHEMA,
        val enabled: Boolean = false,
        val corrupt: Boolean = false,
        val rev: Long = 0,
        val grants: List<WireIdentity> = emptyList(),
        val uidRev: Map<String, Long> = emptyMap(),
        val tombs: List<SuperuserTomb> = emptyList(),
        val applied: List<SuperuserApplied> = emptyList(),
        val migrated: Map<String, Long> = emptyMap(),
        val unresolved: List<SuperuserUnresolved> = emptyList(),
        val switchPending: Boolean = false,
        val pendingApplyRev: Long? = null,
        val profiles: List<WireProfile> = emptyList(),
        val profileRev: Map<String, Long> = emptyMap(),
    )

    /** Base64(JSON) of [snapshot]; never throws for a well-formed snapshot. */
    @JvmStatic
    fun encode(snapshot: AuthorizationSnapshot): String {
        val wire = WireSnapshot(
            schema = if (snapshot.profiles.isEmpty() && snapshot.profileRev.isEmpty()) IDENTITY_SCHEMA else SCHEMA,
            enabled = snapshot.enabled,
            corrupt = snapshot.corrupt,
            rev = snapshot.rev,
            grants = snapshot.grants.values.sortedBy { it.uid }.map { toWireIdentity(it) },
            uidRev = snapshot.uidRev.mapKeys { it.key.toString() },
            tombs = snapshot.tombs,
            applied = snapshot.applied,
            migrated = snapshot.migrated,
            unresolved = snapshot.unresolved,
            switchPending = snapshot.switchPending,
            pendingApplyRev = snapshot.pendingApplyRev,
            profiles = snapshot.profiles.values.sortedBy { it.identity.uid }.map { WireProfile(toWireIdentity(it.identity), it.profile) },
            profileRev = snapshot.profileRev.mapKeys { it.key.toString() },
        )
        val bytes = json.encodeToString(WireSnapshot.serializer(), wire).toByteArray(Charsets.UTF_8)
        return Base64.getEncoder().encodeToString(bytes)
    }

    /** Decodes a tool line; null when it is not a valid snapshot (the caller fails closed). */
    @JvmStatic
    fun decode(encoded: String): AuthorizationSnapshot? = try {
        val bytes = Base64.getDecoder().decode(encoded.trim())
        val wire = json.decodeFromString(WireSnapshot.serializer(), String(bytes, Charsets.UTF_8))
        require(wire.schema in 1..SCHEMA) { "AUTH_STORE_VERSION" }
        require(wire.rev >= 0 && (!wire.switchPending || wire.rev < Long.MAX_VALUE)) { "AUTH_STORE_VERSION" }
        require(!wire.switchPending || wire.pendingApplyRev == wire.rev + 1) { "AUTH_STORE_VERSION" }
        val publishedLimit = if (wire.switchPending) wire.rev + 1 else wire.rev
        require(wire.pendingApplyRev?.let { it > 0 && it <= publishedLimit } != false) { "AUTH_STORE_VERSION" }
        val grants = wire.grants.map { fromWireIdentity(it, wire.schema) }
        require(grants.map { it.uid }.toSet().size == grants.size) { "AUTH_STORE_DUPLICATE_UID" }
        require(wire.schema == SCHEMA || (wire.profiles.isEmpty() && wire.profileRev.isEmpty())) { "AUTH_STORE_PROFILE_VERSION" }
        val profiles = wire.profiles.map { StoredSuProfile(fromWireIdentity(it.identity, wire.schema), it.profile.frozen()) }
        require(profiles.map { it.identity.uid }.distinct().size == profiles.size) { "AUTH_STORE_DUPLICATE_PROFILE" }
        val profileMap = profiles.associateBy { it.identity.uid }
        require(wire.profileRev.keys.map { it.toInt() }.toSet() == profileMap.keys) { "AUTH_STORE_PROFILE_MISSING" }
        require(wire.profileRev.all { (key, value) -> key.toIntOrNull()?.let { it.toString() == key && it in profileMap } == true &&
            value > 0 && value <= publishedLimit }) { "AUTH_STORE_PROFILE_MISSING" }
        require(profiles.all { record -> if (record.profile.allowSu) grants.any { it == record.identity }
            else grants.none { it.uid == record.identity.uid } }) { "AUTH_STORE_PROFILE_IDENTITY" }
        AuthorizationSnapshot(
            enabled = wire.enabled && !wire.switchPending,
            grants = grants.associateBy { it.uid },
            rev = wire.rev,
            uidRev = wire.uidRev.mapNotNull { (key, value) -> key.toIntOrNull()?.let { it to value } }
                .toMap(),
            tombs = wire.tombs,
            applied = wire.applied,
            migrated = wire.migrated,
            unresolved = wire.unresolved,
            corrupt = wire.corrupt,
            switchPending = wire.switchPending,
            pendingApplyRev = wire.pendingApplyRev,
            profiles = profileMap,
            profileRev = wire.profileRev.mapKeys { it.key.toInt() },
        )
    } catch (_: Throwable) {
        null
    }

    /** The import plan as one argv-safe token (design §3.1: the app side enumerates). */
    @Serializable
    data class WirePlan(
        val schema: Int = 1,
        val sources: List<String> = emptyList(),
        val grants: List<WireIdentity> = emptyList(),
        val unresolved: List<SuperuserUnresolved> = emptyList(),
    )

    @JvmStatic
    fun encodePlan(plan: SuperuserMigrationPlan): String? = try {
        val wire = WirePlan(
            schema = IDENTITY_SCHEMA,
            sources = plan.sources,
            grants = plan.grants.sortedBy { it.uid }.map { toWireIdentity(it) },
            unresolved = plan.unresolved,
        )
        Base64.getEncoder().encodeToString(
            json.encodeToString(WirePlan.serializer(), wire).toByteArray(Charsets.UTF_8),
        )
    } catch (_: Throwable) {
        null
    }

    /** A malformed plan is `null`: the tool refuses rather than importing a partial list. */
    @JvmStatic
    fun decodePlan(encoded: String): SuperuserMigrationPlan? = try {
        val wire = json.decodeFromString(
            WirePlan.serializer(),
            String(Base64.getDecoder().decode(encoded.trim()), Charsets.UTF_8),
        )
        require(wire.schema == 1 || wire.schema == IDENTITY_SCHEMA) { "AUTH_STORE_VERSION" }
        val grants = wire.grants.map { fromWireIdentity(it, wire.schema) }
        require(grants.map { it.uid }.toSet().size == grants.size) { "AUTH_STORE_DUPLICATE_UID" }
        SuperuserMigrationPlan(
            sources = wire.sources,
            grants = grants,
            unresolved = wire.unresolved,
        )
    } catch (_: Throwable) {
        null
    }
}
