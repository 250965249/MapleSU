package dev.maplesu.manager.workmode.switch

/**
 * `switch.json` / journal 的 wire 常量。
 *
 * 为什么在这里声明字符串而不是复制枚举：写侧状态机与 `SwitchState`/`SwitchStep` 枚举
 * 由切换服务负责。App 侧只读门面需要 (a) 判断 pending、
 * (b) 解析未来版本未知 state，因此这里只保留**wire 字符串集合**，不定义状态转移。
 * 若写侧枚举迁入同一模块，应改为直接引用其 `PENDING_STATES`，
 * 本对象届时删除（见 01 §10 C10）。
 */
object SwitchStateNames {
    const val BEGIN = "BEGIN"
    const val SNAPSHOT = "SNAPSHOT"
    const val PRODUCE = "PRODUCE"
    const val COMMIT = "COMMIT"
    const val REBOOT_REQUIRED = "REBOOT_REQUIRED"
    const val VERIFYING = "VERIFYING"
    const val VERIFIED = "VERIFIED"
    const val ROLLING_BACK = "ROLLING_BACK"
    const val ROLLED_BACK = "ROLLED_BACK"
    const val FAILED_PRE_WRITE = "FAILED_PRE_WRITE"
    const val RECOVERY_REQUIRED = "RECOVERY_REQUIRED"
    const val CANCELLED = "CANCELLED"

    val ALL: List<String> = listOf(
        BEGIN, SNAPSHOT, PRODUCE, COMMIT, REBOOT_REQUIRED, VERIFYING, VERIFIED,
        ROLLING_BACK, ROLLED_BACK, FAILED_PRE_WRITE, RECOVERY_REQUIRED, CANCELLED,
    )

    /** 持久 pending = 阻断普通写入的状态（02 §3.2：DOC:745"所有非终态"）。 */
    val PENDING: Set<String> = setOf(
        BEGIN, SNAPSHOT, PRODUCE, COMMIT, REBOOT_REQUIRED, VERIFYING, ROLLING_BACK,
        RECOVERY_REQUIRED,
    )

    /** 终态：不再阻断普通写入。 */
    val TERMINAL: Set<String> = setOf(VERIFIED, ROLLED_BACK, FAILED_PRE_WRITE, CANCELLED)

    fun isKnown(state: String?): Boolean = state != null && state in ALL

    /**
     * 是否按 pending 处理：**未知 state 保守按 pending=true**（01 §4.5 第 3 条）。
     */
    fun isPending(state: String?): Boolean = state !in TERMINAL
}
