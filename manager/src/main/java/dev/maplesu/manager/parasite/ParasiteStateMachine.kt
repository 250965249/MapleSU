package dev.maplesu.manager.parasite

/**
 * 寄生承载状态机（N0–N6）。
 *
 * 规则：
 * - 只允许相邻前进（N0→N1→…→N5→N6）与"回到 N0"的显式 reset；
 * - **N6（卸载原管理器）必须从 N5（可恢复）进入**，且 N5 需要恢复备份校验通过；
 * - 证据不足的状态跃迁被拒绝（四结果独立，不允许拿"某一步成功"顶替）；
 * - 非法跃迁返回结构化失败码，调用方不得乐观推进。
 */
object ParasiteStateMachine {
    const val ILLEGAL_TRANSITION = "PARASITE_ILLEGAL_TRANSITION"
    const val UNINSTALL_REQUIRES_RECOVERABLE = "PARASITE_UNINSTALL_REQUIRES_N5"
    const val EVIDENCE_MISSING = "PARASITE_EVIDENCE_MISSING"
    const val INVALID_RECORD = "PARASITE_RECORD_INVALID"

    private val ALLOWED: Map<ParasiteState, Set<ParasiteState>> = mapOf(
        ParasiteState.N0_IDLE to setOf(ParasiteState.N1_PRECHECKED),
        ParasiteState.N1_PRECHECKED to setOf(ParasiteState.N2_IMPLANTED, ParasiteState.N0_IDLE),
        ParasiteState.N2_IMPLANTED to setOf(ParasiteState.N3_HOST_LAUNCHED, ParasiteState.N0_IDLE),
        ParasiteState.N3_HOST_LAUNCHED to setOf(ParasiteState.N4_WEB_SERVING, ParasiteState.N0_IDLE),
        ParasiteState.N4_WEB_SERVING to setOf(ParasiteState.N5_RECOVERABLE, ParasiteState.N0_IDLE),
        ParasiteState.N5_RECOVERABLE to setOf(ParasiteState.N6_UNINSTALLED, ParasiteState.N0_IDLE),
        ParasiteState.N6_UNINSTALLED to emptySet(),
    )

    fun canTransition(from: ParasiteState, to: ParasiteState): Boolean = to in ALLOWED.getValue(from)

    data class Transition(
        val ok: Boolean,
        val from: ParasiteState,
        val to: ParasiteState,
        val code: String = "",
        val detail: String = "",
    )

    /**
     * 校验一次状态跃迁。证据要求：
     * - →N2：`capabilities.soLoaded`（植入且实际加载成功）；
     * - →N4：`capabilities.webReachable && capabilities.serviceEstablished`（网页+服务，不含 root）；
     * - →N5：`recoveryVerified`（恢复备份清单+逐文件 sha 校验通过）；
     * - →N6：必须 from==N5（**卸载前必须可恢复**）。
     */
    fun transition(
        from: ParasiteState,
        to: ParasiteState,
        capabilities: ParasiteCapabilities = ParasiteCapabilities(),
        recoveryVerified: Boolean = false,
    ): Transition {
        if (from == to) return Transition(false, from, to, ILLEGAL_TRANSITION, "already in ${from.name}")
        if (!canTransition(from, to)) {
            val detail = if (to == ParasiteState.N6_UNINSTALLED && from != ParasiteState.N5_RECOVERABLE) {
                "uninstall requires recoverable state N5"
            } else {
                "illegal transition ${from.name} -> ${to.name}"
            }
            val code = if (to == ParasiteState.N6_UNINSTALLED && from != ParasiteState.N5_RECOVERABLE) {
                UNINSTALL_REQUIRES_RECOVERABLE
            } else {
                ILLEGAL_TRANSITION
            }
            return Transition(false, from, to, code, detail)
        }
        val evidenceFailure = when (to) {
            ParasiteState.N2_IMPLANTED -> if (!capabilities.soLoaded) "soLoaded=false" else null
            ParasiteState.N4_WEB_SERVING ->
                if (!capabilities.webReachable) "webReachable=false"
                else if (!capabilities.serviceEstablished) "serviceEstablished=false"
                else null
            ParasiteState.N5_RECOVERABLE -> if (!recoveryVerified) "recovery backup not verified" else null
            else -> null
        }
        if (evidenceFailure != null) {
            return Transition(false, from, to, EVIDENCE_MISSING, evidenceFailure)
        }
        return Transition(true, from, to)
    }

    /** 卸载（N6）前置：当前必须是 N5。 */
    fun uninstallBlockedReason(state: ParasiteState): String? =
        if (state == ParasiteState.N5_RECOVERABLE) null else UNINSTALL_REQUIRES_RECOVERABLE

    /** 供记录读取时校验：未知 state wire → 结构化失败（不得默认 N0）。 */
    fun stateOf(record: ParasiteHostRecord): ParasiteState? = record.stateEnum()
}
