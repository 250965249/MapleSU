package com.maplesu.core.ui.security

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update

/**
 * 「隐藏/隐身事实变了」的进程内信号。
 *
 * 首页入口的可见性放在 ViewModel 的 StateFlow 里（组合期不读 prefs/JNI）。这样一来，
 * 事实一变就必须主动通知，否则入口要等到下一次切页/回前台才收起——这正是
 * 「隐藏刚生效那几帧仍露出入口」的真机缺陷。
 *
 * 只携带修订号，不携带事实本身：收到信号的一方重新读取，来源始终只有一份。
 */
object HiddenFactsSignal {
    private val mutableRevision = MutableStateFlow(0L)

    val revision: StateFlow<Long> = mutableRevision.asStateFlow()

    fun notifyChanged() {
        mutableRevision.update { it + 1 }
    }
}
