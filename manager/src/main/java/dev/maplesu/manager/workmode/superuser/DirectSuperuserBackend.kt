package dev.maplesu.manager.workmode.superuser

import dev.maplesu.manager.workmode.control.schema.Tomb
import java.io.IOException

/**
 * `A_DIRECT` 后端的可注入端口（01 §6.3）。生产实现包 `DirectPolicy`/`AndroidApplicationIdentities`
 * 的一次性 root 工具语义；主机测试用假端口注入故障，不依赖 Android。
 */
interface DirectSuperuserPort {
    /** `DirectPolicy.isEnabled` 的结论；null/不可读 → false。 */
    fun enabled(): Boolean

    /** 持久记录的 uid 集合（可能包含身份已变的死授权）。 */
    fun grantedUids(): Set<Int>

    /** `DirectPolicy.hasGrantStrict` 的“按当前身份裁决”结果；null = 无法裁决。 */
    fun hasCurrentGrant(uid: Int): Boolean?

    /** 当前身份快照；读不到返回 null。 */
    fun identity(uid: Int): IdentitySnapshot?

    fun grant(uid: Int): Boolean
    fun revoke(uid: Int): Boolean
}

/**
 * `A_DIRECT`：uid 粒度，且该 uid 必须恰好一个包（`ApplicationIdentity` 合同）。
 * enumerate 用 [DirectSuperuserPort.hasCurrentGrant] 逐 uid 复核，**不导出死授权**（G2）。
 */
class DirectSuperuserBackend(private val port: DirectSuperuserPort) : SuperuserBackend {
    override val id: BackendId = BackendId.A_DIRECT
    private var unrepresentable = 0

    override fun available(): Boolean = runCatching { port.enabled() }.getOrDefault(false)

    override fun enumerate(): List<GrantView> {
        if (!available()) return emptyList()
        val views = ArrayList<GrantView>()
        unrepresentable = 0
        for (uid in port.grantedUids().sorted()) {
            if (ProtectedIdentities.isProtected(uid)) continue
            val current = port.hasCurrentGrant(uid)
                ?: throw IOException("A_DIRECT_IDENTITY_CHECK_FAILED: uid=$uid")
            if (!current) {
                unrepresentable++
                continue
            }
            val identity = port.identity(uid)
            if (identity == null || identity.uid != uid) {
                unrepresentable++
                continue
            }
            views.add(GrantView(uid, identity.packageName, true, Granularity.UID, identity))
        }
        return views
    }

    override fun apply(desired: List<GrantView>, tombs: List<Tomb>, rev: Long): ApplyReport {
        if (!available()) {
            return ApplyReport.reject(id, desired, rev, "A_DIRECT_UNAVAILABLE", "direct policy disabled")
        }
        val currentAllow = runCatching { enumerate().map { it.uid }.toSet() }.getOrElse { emptySet() }
        val failures = ArrayList<ApplyFailure>()
        val revokeUids = LinkedHashSet<Int>()
        for (tomb in tombs) if (!ProtectedIdentities.isProtected(tomb.uid)) revokeUids.add(tomb.uid)
        for (view in desired) {
            if (ProtectedIdentities.isProtected(view.uid)) continue
            if (!view.allow) revokeUids.add(view.uid)
        }
        for (uid in revokeUids) {
            if (uid !in currentAllow && port.hasCurrentGrant(uid) != true) continue
            if (!port.revoke(uid)) {
                failures.add(ApplyFailure(uid, "", ApplyReport.OP_REVOKE, "A_DIRECT_REVOKE_FAILED"))
            }
        }
        val grantUids = LinkedHashSet<Int>()
        for (view in desired) {
            if (ProtectedIdentities.isProtected(view.uid)) continue
            if (view.allow) grantUids.add(view.uid)
        }
        for (uid in grantUids) {
            if (uid in currentAllow) continue
            if (!port.grant(uid)) {
                failures.add(ApplyFailure(uid, "", ApplyReport.OP_GRANT, "A_DIRECT_GRANT_FAILED"))
            }
        }
        return if (failures.isEmpty()) ApplyReport.success(id, rev)
        else ApplyReport(emptyList(), failures, rev)
    }

    override fun verify(): List<GrantView> = enumerate()

    override fun packageNamesForUid(uid: Int): List<String> =
        port.identity(uid)?.let { listOf(it.packageName) } ?: emptyList()

    override fun unrepresentableCount(): Int = unrepresentable
}
