package dev.maplesu.manager.workmode.detect.probes

import dev.maplesu.manager.workmode.detect.BootIdSource
import dev.maplesu.manager.workmode.detect.ProcBootIdSource

/**
 * bootId 适配器（`/proc/sys/kernel/random/boot_id`）。
 * 读不到返回空串 = 未知；调用方不得把它当成某个具体 boot。
 */
object BootIdSourceAdapter : BootIdSource {
    override fun read(): String = ProcBootIdSource.read()
}
