package dev.maplesu.manager.runtime.ultra

/**
 * 「Ultra 白名单条目数」的进程内缓存。
 *
 * 存在的唯一理由是让 `Natives.getSuperuserCount()`（底部导航角标）在 Ultra 环境下有一个
 * 不碰 root 的答案：它绝不能走 `DirectPolicy` → `DirectRoot` → `libmaplesu_runtime.so`，
 * 那条路径在 Ultra 内核上不稳。真正的数据源是 Ultra 超级用户页每次成功读取
 * `get_su_auth_list` 之后调用的 [publish]。
 *
 * 因此这里的数字是「上一次成功读取到的条数」：没有读过就是 0，而不是猜出来的值。
 */
object UltraSuAuthCache {
    @Volatile
    private var count: Int = 0

    /** 最近一次成功读取的条数；未读取过为 0。 */
    fun current(): Int = count

    fun publish(value: Int) {
        count = if (value < 0) 0 else value
    }
}
