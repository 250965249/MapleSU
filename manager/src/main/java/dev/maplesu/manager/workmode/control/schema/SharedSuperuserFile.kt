package dev.maplesu.manager.workmode.control.schema

import kotlinx.serialization.Serializable

/**
 * `shared/superuser.json`：唯一跨模式共享的**授权意图**。
 *
 * 本包只定义 schema 与 canonical 形态；后端枚举/同步状态机归 `workmode/superuser` 子包（W14）。
 * `signerSha256` 必须是**排序后的 List**：源 `ApplicationIdentity.signers` 是无序 Set，
 * 直接序列化会破坏 canonical sha256。
 */
@Serializable
data class SharedSuperuserFile(
    val schema: Int = SCHEMA,
    val revision: Long,
    val updatedAt: Long,
    /** "A" | "B"。 */
    val lastWriter: String,
    /** 按 (userId, uid, packageName) 排序。 */
    val entries: List<GrantIntent>,
    val tombs: List<Tomb>,
    val policy: SharedPolicy,
) {
    companion object { const val SCHEMA = 1 }

    fun entryFor(userId: Int, uid: Int, packageName: String): GrantIntent? =
        entries.firstOrNull { it.userId == userId && it.uid == uid && it.packageName == packageName }

    /** 指定 uid 的全部意图（多用户按 userId 分开存，禁止跨用户回退）。 */
    fun entriesForUid(uid: Int): List<GrantIntent> = entries.filter { it.uid == uid }
}

@Serializable
data class GrantIntent(
    val uid: Int,
    val userId: Int,
    val packageName: String,
    /** 排序；多签名=全部当前签名。 */
    val signerSha256: List<String>,
    val firstInstallTime: Long,
    val lastUpdateTime: Long,
    /** sha256(apkPath) 前 32 hex（不落原路径）。 */
    val apkPathHash: String,
    /** "allow" | "deny"。 */
    val decision: String,
    /** 该决策最后由哪个模式写入。 */
    val origin: String,
    val decidedAt: Long,
    /** 各后端兑现水位（缺 = 未兑现）。 */
    val applied: List<AppliedMark>,
    val pending: PendingOp? = null,
    val identityStale: Boolean = false,
    /** 例如 ["A_ULTRA:multi-package-uid"]。 */
    val degraded: List<String> = emptyList(),
) {
    companion object {
        const val ALLOW = "allow"
        const val DENY = "deny"
        val DECISIONS: Set<String> = setOf(ALLOW, DENY)
    }
}

@Serializable
data class AppliedMark(val backend: String, val rev: Long, val at: Long, val ok: Boolean)

@Serializable
data class PendingOp(
    val backend: String,
    /** 例如 "grant" | "revoke"。 */
    val op: String,
    val attempts: Int,
    val lastError: String,
    val since: Long,
)

@Serializable
data class Tomb(
    val uid: Int,
    val userId: Int,
    val packageName: String,
    val signerSha256: List<String>,
    val revokedAt: Long,
    /** 撤销发生的 revision；用于"旧水位不得复活"。 */
    val rev: Long,
)

@Serializable
data class SharedPolicy(
    val granularity: String = "uid+package",
    val multiPackageUidRule: String = "all-or-none",
    val conflictRule: String = "latest-writer-wins-with-tombstone",
    val lastExportRev: Long = 0,
)

/** 唯一 canonical 形态：排序所有集合与签名列表，写盘前必须调用。 */
fun SharedSuperuserFile.canonicalized(): SharedSuperuserFile = copy(
    entries = entries.sortedWith(compareBy({ it.userId }, { it.uid }, { it.packageName })).map {
        it.copy(
            signerSha256 = it.signerSha256.sorted(),
            applied = it.applied.sortedWith(compareBy({ it.backend }, { it.rev }, { it.at })),
            degraded = it.degraded.distinct().sorted(),
        )
    },
    tombs = tombs.sortedWith(compareBy({ it.userId }, { it.uid }, { it.packageName }, { it.rev })).map {
        it.copy(signerSha256 = it.signerSha256.sorted())
    },
)

/** 供 apply 前判定"墓碑是否覆盖某后端水位"（撤销不复活 G1/G3；纯函数）。 */
fun Tomb.coversWatermark(backend: String, marks: List<AppliedMark>): Boolean {
    val mark = marks.firstOrNull { it.backend == backend } ?: return true
    return !(mark.ok && mark.rev >= rev)
}
