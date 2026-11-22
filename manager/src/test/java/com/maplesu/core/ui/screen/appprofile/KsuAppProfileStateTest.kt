// SPDX-License-Identifier: GPL-3.0-or-later
package com.maplesu.core.ui.screen.appprofile

import dev.maplesu.manager.runtime.State
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * AppProfile 在 Normal（KSU）下的授权语义（2026-11-01 收尾）。
 *
 * 审计 §9：KSU 模式仍在调 `DirectPolicy.grantedUids/stateFor`（Lite 的"投递/接线"模型），
 * 既会起一个必然失败的 root 探测进程，又会把状态误报成 `PENDING_WIRING`。
 *
 * KSU 的事实：内核在应用发起 `su` 请求时直接按 allowlist 判定 —— 在白名单就是生效。
 */
class KsuAppProfileStateTest {

    @Test
    fun grantedProfileIsWired() {
        assertEquals(State.WIRED, ksuSuState(granted = true))
    }

    @Test
    fun missingGrantIsNotAuthorized() {
        assertEquals(State.NOT_AUTHORIZED, ksuSuState(granted = false))
    }

    @Test
    fun ksuNeverReportsDeliveryIntermediateStates() {
        // WIRED / NOT_AUTHORIZED 是 KSU 唯一可能的两个结论：DELIVERED / PENDING_WIRING
        // 描述的是"su 客户端是否投递到位"，Normal 下不存在这个环节。
        val states = setOf(ksuSuState(true), ksuSuState(false))
        assertEquals(setOf(State.WIRED, State.NOT_AUTHORIZED), states)
    }
}
