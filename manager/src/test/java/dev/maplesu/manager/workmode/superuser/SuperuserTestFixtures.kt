package dev.maplesu.manager.workmode.superuser

import dev.maplesu.manager.workmode.control.ControlRead
import dev.maplesu.manager.workmode.control.FileControlPlane
import dev.maplesu.manager.workmode.control.schema.AppliedMark
import dev.maplesu.manager.workmode.control.schema.GrantIntent
import dev.maplesu.manager.workmode.control.schema.PendingOp
import dev.maplesu.manager.workmode.control.schema.SharedPolicy
import dev.maplesu.manager.workmode.control.schema.SharedSuperuserFile
import dev.maplesu.manager.workmode.control.schema.Tomb
import dev.maplesu.manager.workmode.detect.BootIdSource
import dev.maplesu.manager.workmode.detect.Clock
import java.io.File
import java.nio.file.Files

internal class TestClock(var now: Long = 1_000L) : Clock {
    override fun nowMillis(): Long = now
}

internal object Fixtures {
    const val MANAGER = "dev.maplesu.manager"
    const val APP = "com.example.app"
    const val OTHER = "com.example.other"
    const val UID = 10_200
    const val UID_OTHER_USER = 1_010_200

    fun hash(char: Char): String = char.toString().repeat(64)

    fun identity(
        uid: Int = UID,
        packageName: String = APP,
        signers: List<String> = listOf(hash('a'), hash('b')),
        firstInstallTime: Long = 100L,
        lastUpdateTime: Long = 200L,
        apkPath: String = "/data/app/$APP/base.apk",
    ): IdentitySnapshot = IdentityRules.snapshotOf(
        uid, packageName, signers, firstInstallTime, lastUpdateTime, apkPath,
    )

    fun intent(
        uid: Int = UID,
        userId: Int = uid / 100_000,
        packageName: String = APP,
        decision: String = GrantIntent.ALLOW,
        decidedAt: Long = 1_000L,
        signers: List<String> = listOf(hash('a'), hash('b')),
        firstInstallTime: Long = 100L,
        lastUpdateTime: Long = 200L,
        apkPathHash: String = IdentityRules.apkPathHash("/data/app/$APP/base.apk"),
        origin: String = "A",
        applied: List<AppliedMark> = emptyList(),
        pending: PendingOp? = null,
        identityStale: Boolean = false,
        degraded: List<String> = emptyList(),
    ): GrantIntent = GrantIntent(
        uid = uid, userId = userId, packageName = packageName, signerSha256 = signers,
        firstInstallTime = firstInstallTime, lastUpdateTime = lastUpdateTime,
        apkPathHash = apkPathHash, decision = decision, origin = origin, decidedAt = decidedAt,
        applied = applied, pending = pending, identityStale = identityStale, degraded = degraded,
    )

    fun intentFrom(identity: IdentitySnapshot, decision: String = GrantIntent.ALLOW,
                   decidedAt: Long = 1_000L): GrantIntent = intent(
        uid = identity.uid, userId = identity.userId, packageName = identity.packageName,
        decision = decision, decidedAt = decidedAt, signers = identity.signerSha256,
        firstInstallTime = identity.firstInstallTime, lastUpdateTime = identity.lastUpdateTime,
        apkPathHash = identity.apkPathHash,
    )

    fun tomb(
        uid: Int = UID,
        userId: Int = uid / 100_000,
        packageName: String = APP,
        signers: List<String> = listOf(hash('a'), hash('b')),
        revokedAt: Long = 2_000L,
        rev: Long = 2L,
    ): Tomb = Tomb(uid, userId, packageName, signers, revokedAt, rev)

    fun shared(
        revision: Long = 1L,
        entries: List<GrantIntent> = emptyList(),
        tombs: List<Tomb> = emptyList(),
        lastWriter: String = "A",
        updatedAt: Long = 1_000L,
        lastExportRev: Long = 0L,
    ): SharedSuperuserFile = SharedSuperuserFile(
        revision = revision, updatedAt = updatedAt, lastWriter = lastWriter,
        entries = entries, tombs = tombs,
        policy = SharedPolicy(lastExportRev = lastExportRev),
    )

    fun view(
        uid: Int = UID,
        packageName: String = APP,
        allow: Boolean = true,
        granularity: Granularity = Granularity.UID_PACKAGE_PROFILE,
        identity: IdentitySnapshot? = identity(uid = uid, packageName = packageName),
    ): GrantView = GrantView(uid, packageName, allow, granularity, identity)
}

internal class TestControl private constructor(val root: File, val clock: TestClock) : AutoCloseable {
    val plane = FileControlPlane(
        root = root,
        clock = clock,
        bootIdSource = BootIdSource { "boot-1" },
        onDiagnostic = {},
    )

    fun write(file: SharedSuperuserFile): SharedSuperuserFile {
        val result = plane.writeSharedSuperuser { file }
        check(result is dev.maplesu.manager.workmode.control.ControlWrite.Ok) {
            "control write rejected: $result"
        }
        return result.value
    }

    fun read(): SharedSuperuserFile = when (val read = plane.readSharedSuperuser()) {
        is ControlRead.Ok -> read.value
        else -> throw AssertionError("shared superuser unreadable: $read")
    }

    fun readRaw(): String = File(root, "shared/superuser.json").readText()

    fun writeRaw(text: String) {
        val file = File(root, "shared/superuser.json")
        file.parentFile.mkdirs()
        file.writeText(text)
        File(root, "shared/superuser.json.sha256").delete()
    }

    fun sharedFile(): File = File(root, "shared/superuser.json")

    override fun close() {
        root.deleteRecursively()
    }

    companion object {
        fun create(now: Long = 1_000L): TestControl {
            val root = Files.createTempDirectory("maplesu-superuser-test-").toFile()
            return TestControl(root, TestClock(now))
        }
    }
}

/** 可注入故障的后端替身：状态即“内核/策略侧”的 allow 集合。 */
internal class FakeBackend(
    override val id: BackendId,
    private val granularity: Granularity = Granularity.UID_PACKAGE_PROFILE,
) : SuperuserBackend {
    var available: Boolean = true
    var enumerateFailure: Boolean = false
    var applyFailure: Boolean = false
    var failRevokes: Boolean = false
    var verifyOverride: List<GrantView>? = null

    /** 真实状态变化次数，用于幂等断言。 */
    var mutations: Int = 0
    /** "grant:pkg" / "revoke:pkg" 调用序列（仅真实差异）。 */
    val operations: MutableList<String> = mutableListOf()
    private val state = LinkedHashMap<String, Pair<Int, Boolean>>()
    private val identityByUid = mutableMapOf<Int, IdentitySnapshot>()
    val packagesByUid = mutableMapOf<Int, List<String>>()

    fun seed(identity: IdentitySnapshot, allow: Boolean = true) {
        state[identity.packageName] = identity.uid to allow
        identityByUid[identity.uid] = identity
        packagesByUid[identity.uid] = packagesByUid[identity.uid].orEmpty() + identity.packageName
    }

    fun allowState(packageName: String): Boolean? = state[packageName]?.second

    override fun available(): Boolean = available

    override fun enumerate(): List<GrantView> {
        if (enumerateFailure) throw java.io.IOException("TEST_ENUMERATE_FAILED")
        return state.entries.filter { it.value.second }.map { (packageName, value) ->
            GrantView(value.first, packageName, true, granularity,
                identityByUid[value.first] ?: Fixtures.identity(value.first, packageName))
        }
    }

    override fun apply(desired: List<GrantView>, tombs: List<Tomb>, rev: Long): ApplyReport {
        if (!available) {
            return ApplyReport.reject(id, desired, rev, "${id.wire}_UNAVAILABLE", "unavailable")
        }
        val failures = ArrayList<ApplyFailure>()
        for (tomb in tombs) {
            if (ProtectedIdentities.isProtected(tomb.uid, tomb.packageName)) continue
            change(tomb.uid, tomb.packageName, false, ApplyReport.OP_REVOKE, failRevokes)?.let(failures::add)
        }
        for (view in desired.filter { !it.allow }) {
            if (ProtectedIdentities.isProtected(view.uid, view.packageName)) continue
            change(view.uid, view.packageName, false, ApplyReport.OP_REVOKE, failRevokes)?.let(failures::add)
        }
        for (view in desired.filter { it.allow }) {
            if (ProtectedIdentities.isProtected(view.uid, view.packageName)) continue
            change(view.uid, view.packageName, true, ApplyReport.OP_GRANT, applyFailure)?.let(failures::add)
        }
        return if (failures.isEmpty()) ApplyReport.success(id, rev)
        else ApplyReport(emptyList(), failures, rev)
    }

    override fun verify(): List<GrantView> = verifyOverride ?: enumerate()

    override fun packageNamesForUid(uid: Int): List<String> =
        packagesByUid[uid] ?: state.filter { it.value.first == uid }.map { it.key }

    private fun change(
        uid: Int,
        packageName: String,
        allow: Boolean,
        op: String,
        forcedFailure: Boolean,
    ): ApplyFailure? {
        val current = state[packageName]?.second ?: false
        if (current == allow) return null
        operations.add("$op:$packageName")
        if (forcedFailure) {
            return ApplyFailure(uid, packageName, op, "TEST_${op.uppercase()}_FAILED")
        }
        mutations++
        state[packageName] = uid to allow
        return null
    }
}
