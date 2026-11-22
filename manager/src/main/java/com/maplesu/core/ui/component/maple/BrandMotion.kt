package com.maplesu.core.ui.component.maple

import android.animation.ValueAnimator
import androidx.compose.runtime.Composable
import androidx.compose.runtime.MutableFloatState
import androidx.compose.runtime.Stable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.runtime.withFrameNanos
import androidx.lifecycle.compose.LifecycleResumeEffect

/**
 * 系统「动画时长」是否开启（`ANIMATOR_DURATION_SCALE != 0`）。
 *
 * 用 [ValueAnimator.areAnimatorsEnabled] 读进程内缓存值，不走 Settings 查询，
 * 组合期调用没有 IO；回前台时再核对一次，覆盖用户在系统设置里改动的情况。
 */
@Composable
fun rememberMotionEnabled(): Boolean {
    var enabled by remember { mutableStateOf(ValueAnimator.areAnimatorsEnabled()) }
    LifecycleResumeEffect(Unit) {
        enabled = ValueAnimator.areAnimatorsEnabled()
        onPauseOrDispose { }
    }
    return enabled
}

/**
 * 把逐帧累计的秒数写进 [time]，直到协程取消。
 *
 * 单帧增量封顶：页面暂停后回来接着流动，不会跳变。
 */
internal suspend fun runBrandClock(time: MutableFloatState) {
    var last = 0L
    var seconds = time.floatValue
    while (true) {
        withFrameNanos { now ->
            if (last != 0L) {
                seconds += ((now - last) / 1_000_000_000f).coerceIn(0f, 0.05f)
                time.floatValue = seconds
            }
            last = now
        }
    }
}

/**
 * 只活在一次"打开管理器"里的品牌状态。
 *
 * 由 Activity ViewModel 持有：跨皮肤和配置重建仍是同一次打开，开场只播一次。
 * 页面自身可离开再回来；Activity 真正结束后状态丢弃，下次打开重新播放。
 */
@Stable
class BrandSession(introPlayed: Boolean = false, onboardingEntered: Boolean = false) {
    var introPlayed: Boolean by mutableStateOf(introPlayed)
    var onboardingEntered: Boolean by mutableStateOf(onboardingEntered)

}

internal class BrandSessionViewModel : androidx.lifecycle.ViewModel() {
    val session = BrandSession()
}

@Composable
fun rememberBrandSession(): BrandSession = androidx.lifecycle.viewmodel.compose.viewModel<BrandSessionViewModel>().session

val LocalBrandSession = staticCompositionLocalOf { BrandSession() }
