package dev.maplesu.manager.workmode.switch

import dev.maplesu.manager.workmode.control.ControlPlane
import dev.maplesu.manager.workmode.control.ControlRead
import dev.maplesu.manager.workmode.control.ControlWrite
import dev.maplesu.manager.workmode.detect.Clock
import dev.maplesu.manager.workmode.detect.WallClock
import java.io.IOException

/**
 * S6 通过后把 `modes.json.current=to` 提交（01 §4.3）。
 *
 * 生产 App 进程通常不能直接写 `/data/adb`；失败由调用方（`ModeSwitchFacade`）降级为
 * 告警而**不**把已验证的切换回滚（分区事实已由服务端 verify 证明）。root 适配器可复用
 * 同一实现（`FileControlPlane`）。
 */
class ControlPlaneModeCommitSink(
    private val control: ControlPlane,
    private val clock: Clock = WallClock,
) : ModeCommitSink {

    override fun commit(mode: dev.maplesu.manager.workmode.WorkMode, bootId: String,
                        bootSha256: String, initBootSha256: String) {
        val current = when (val read = control.readModes()) {
            is ControlRead.Ok -> read.value
            is ControlRead.Missing -> throw IOException("CONTROL_MODES_CORRUPT:missing")
            is ControlRead.Corrupt -> throw IOException("${read.code}:${read.detail}")
            is ControlRead.Unreadable -> throw IOException("${read.code}:${read.path}")
        }
        val updated = control.writeModes { modes ->
            modes.copy(
                revision = modes.revision + 1,
                updatedAt = clock.nowMillis(),
                bootId = bootId,
                current = mode.suffix,
                last = if (modes.current != mode.suffix) modes.current else modes.last,
                boot = modes.boot.copy(
                    bootSha256 = bootSha256.ifEmpty { modes.boot.bootSha256 },
                    initBootSha256 = initBootSha256.ifEmpty { modes.boot.initBootSha256 },
                    activeMode = mode.suffix,
                    verifiedBootId = bootId,
                ),
            )
        }
        if (updated is ControlWrite.Rejected) throw IOException(updated.code)
    }
}
