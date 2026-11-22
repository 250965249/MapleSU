package dev.maplesu.manager.workmode.superuser

import dev.maplesu.manager.workmode.WorkMode
import dev.maplesu.manager.workmode.control.schema.AppliedMark
import dev.maplesu.manager.workmode.control.schema.GrantIntent
import dev.maplesu.manager.workmode.control.schema.PendingOp
import dev.maplesu.manager.workmode.control.schema.SharedSuperuserFile
import dev.maplesu.manager.workmode.control.schema.Tomb

/**
 * 导出合并：把各后端“按当前身份裁决后”的枚举结果合入 `shared/superuser.json`（01 §6.5.1）。
 *
 * 规则优先级（高→低）：
 * 1) 墓碑：`tomb.revokedAt >= 当前 allow 的 decidedAt` → deny 定型，不允许被枚举 allow 覆盖；
 * 2) 最新 decidedAt 胜（保留 shared 中更晚的决策，不因一次枚举把它抹掉）；
 * 3) 枚举到 allow 但 shared 无条目 → 新建 allow（origin=当前模式）；
 * 4) shared 有 allow 但后端未枚举到 → **不自动 deny**，先 pending；连续两轮仍缺失才 deny + 立墓碑；
 * 5) ROTATED_SOFT → 保留意图、标记待确认（`identity:rotated-soft`），不更新身份快照；
 * 6) STALE_HARD → `identityStale=true`，目标模式跳过自动兑现。
 *
 * 已知保守裁决：后端 `GrantView` 不带 decidedAt，无法与本地 deny 比较新旧，因此 **deny 粘滞**
 * （只有墓碑早于本地 deny 才能证明 deny 是更新决策；枚举到 allow 不会翻转 deny，防 E5 复活）。
 */
object GrantMerge {
    const val MISSING_OP = "missing-verify"
    const val ROTATED_MARKER = "identity:rotated-soft"
    const val MISSING_EXPORTS_BEFORE_DENY = 2

    fun merge(
        current: SharedSuperuserFile,
        observed: Map<BackendId, List<GrantView>>,
        now: Long,
        writer: WorkMode,
    ): SharedSuperuserFile {
        val nextRevision = current.revision + 1
        val currentByKey = current.entries.associateBy { GrantKey.of(it) }
        val observedByKey = LinkedHashMap<GrantKey, MutableList<GrantView>>()
        for ((_, views) in observed) {
            for (view in views) observedByKey.getOrPut(GrantKey.of(view)) { mutableListOf() }.add(view)
        }
        val keys = LinkedHashSet<GrantKey>()
        keys.addAll(currentByKey.keys)
        keys.addAll(observedByKey.keys)
        val entries = ArrayList<GrantIntent>()
        val tombs = current.tombs.toMutableList()
        for (key in keys.sortedWith(compareBy({ it.userId }, { it.uid }, { it.packageName }))) {
            val existing = currentByKey[key]
            val views = observedByKey[key].orEmpty()
            val observedAllow = views.any { it.allow }
            val identity = views.firstNotNullOfOrNull { it.identity }
            val tomb = latestTomb(current.tombs, key)
            val merged = when {
                existing == null ->
                    if (!observedAllow) null
                    else if (tomb != null) denyFromTomb(key, tomb, writer)
                    else identity?.let { allowFrom(key, it, now, writer) }
                existing.decision == GrantIntent.ALLOW ->
                    mergeAllow(existing, observedAllow, identity, tomb, now, nextRevision, writer, tombs)
                else -> existing.copy(pending = null)
            }
            if (merged != null) entries.add(merged)
        }
        return current.copy(
            revision = nextRevision,
            updatedAt = now,
            lastWriter = writer.suffix,
            entries = entries.sortedWith(compareBy({ it.userId }, { it.uid }, { it.packageName })),
            tombs = tombs.sortedWith(compareBy({ it.userId }, { it.uid }, { it.packageName }, { it.revokedAt })),
        )
    }

    private fun latestTomb(tombs: List<Tomb>, key: GrantKey): Tomb? =
        tombs.filter {
            it.userId == key.userId && it.uid == key.uid && it.packageName == key.packageName
        }.maxByOrNull { it.revokedAt }

    private fun mergeAllow(
        current: GrantIntent,
        observedAllow: Boolean,
        identity: IdentitySnapshot?,
        tomb: Tomb?,
        now: Long,
        nextRevision: Long,
        writer: WorkMode,
        tombs: MutableList<Tomb>,
    ): GrantIntent {
        // 1) 墓碑晚于本地 allow → deny 定型（旧 allow 不得复活）。
        if (tomb != null && tomb.revokedAt >= current.decidedAt) {
            return denyFromTomb(GrantKey.of(current), tomb, writer)
        }
        // 4) 后端未枚举到：先 pending，连续 MISSING_EXPORTS_BEFORE_DENY 轮才 deny + 立墓碑。
        if (!observedAllow) {
            if (tomb != null) return denyFromTomb(GrantKey.of(current), tomb, writer)
            val previous = current.pending?.takeIf { it.op == MISSING_OP }
            val attempts = (previous?.attempts ?: 0) + 1
            if (attempts >= MISSING_EXPORTS_BEFORE_DENY) {
                tombs.add(
                    Tomb(
                        uid = current.uid, userId = current.userId, packageName = current.packageName,
                        signerSha256 = current.signerSha256.sorted(), revokedAt = now, rev = nextRevision,
                    ),
                )
                return denyFrom(current, now, writer, current.applied)
            }
            return current.copy(
                pending = PendingOp(
                    backend = "EXPORT", op = MISSING_OP, attempts = attempts,
                    lastError = "not-observed", since = previous?.since ?: now,
                ),
            )
        }
        if (identity == null) return current.copy(pending = null)
        // 2) 最新 decidedAt 胜：这里 current 就是 shared 的现有决策，枚举没有更晚的显式 decidedAt。
        return when (IdentityRules.verdict(current, identity)) {
            IdentityVerdict.MATCH -> current.copy(
                signerSha256 = identity.signerSha256.sorted(),
                firstInstallTime = identity.firstInstallTime,
                lastUpdateTime = identity.lastUpdateTime,
                apkPathHash = identity.apkPathHash,
                pending = null,
                identityStale = false,
                degraded = current.degraded.filter { it != ROTATED_MARKER },
            )
            // 5) 同签名正常升级：保留意图与旧身份快照，标记待确认，A 后端不自动放行。
            IdentityVerdict.ROTATED_SOFT -> current.copy(
                pending = null,
                degraded = (current.degraded + ROTATED_MARKER).distinct().sorted(),
            )
            // 6) 硬失效：保留意图但标记 identityStale，目标模式跳过兑现。
            IdentityVerdict.STALE_HARD -> current.copy(identityStale = true, pending = null)
            IdentityVerdict.UNKNOWN -> current.copy(pending = null)
        }
    }

    private fun allowFrom(
        key: GrantKey,
        identity: IdentitySnapshot,
        now: Long,
        writer: WorkMode,
    ): GrantIntent = GrantIntent(
        uid = key.uid, userId = key.userId, packageName = key.packageName,
        signerSha256 = identity.signerSha256.sorted(),
        firstInstallTime = identity.firstInstallTime,
        lastUpdateTime = identity.lastUpdateTime,
        apkPathHash = identity.apkPathHash,
        decision = GrantIntent.ALLOW, origin = writer.suffix, decidedAt = now,
        applied = emptyList(), pending = null, identityStale = false, degraded = emptyList(),
    )

    private fun denyFromTomb(key: GrantKey, tomb: Tomb, writer: WorkMode): GrantIntent = GrantIntent(
        uid = key.uid, userId = key.userId, packageName = key.packageName,
        signerSha256 = tomb.signerSha256.sorted(),
        firstInstallTime = 0, lastUpdateTime = 0, apkPathHash = "",
        decision = GrantIntent.DENY, origin = writer.suffix, decidedAt = tomb.revokedAt,
        applied = emptyList(), pending = null, identityStale = false, degraded = emptyList(),
    )

    private fun denyFrom(
        current: GrantIntent,
        now: Long,
        writer: WorkMode,
        applied: List<AppliedMark>,
    ): GrantIntent = current.copy(
        decision = GrantIntent.DENY, origin = writer.suffix, decidedAt = now,
        applied = applied, pending = null,
    )
}
