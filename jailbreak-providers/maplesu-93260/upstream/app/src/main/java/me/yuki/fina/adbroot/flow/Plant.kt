package me.yuki.fina.adbroot.flow

import kotlinx.coroutines.delay
import me.yuki.fina.adbroot.core.ExecResult
import me.yuki.fina.adbroot.core.KernelMap
import me.yuki.fina.adbroot.core.Shell
import java.io.File

/**
 * 8 字节写原语（由 louise 的 plant server 执行）。
 *
 * 协议：把 "%x %d"（目标地址 + 模式）写成 chan/plant_req，
 * plant server 处理完写 chan/plant_res（成功是 "1 ..."）。
 * 每次尝试前都清掉旧的 req/done/res，避免读到上一次的结果。
 */
class Plant(
    private val sh: Shell,
    private val cacheDir: File,
    private val log: (String) -> Unit,
) {
    suspend fun zero(target: Long): Boolean = write(target, mode = 0)

    private suspend fun write(target: Long, mode: Int): Boolean {
        for (attempt in 1..6) {
            sh.exec("rm -f ${Device.CHAN}/plant_res ${Device.CHAN}/plant_done ${Device.CHAN}/plant_req", 10_000)
            val req = File(cacheDir, "plant_req")
            req.writeText("%x %d\n".format(target, mode))
            if (!sh.push(req, "${Device.CHAN}/plant_req")) {
        // 立刻叫醒 dispatcher（否则要等它的 1 秒心跳）
        sh.exec("echo x > ${Device.CHAN}/wake 2>/dev/null", 5_000)
                log("    [plant] 推送请求失败")
                continue
            }
            var res = ""
            var waited = 0
            while (waited < 24) {
                delay(400)
                waited++
                res = sh.exec("cat ${Device.CHAN}/plant_res 2>/dev/null", 10_000).stdout.trim()
                if (res.isNotEmpty()) break
            }
            log("    [plant] ${KernelMap.hex(target)} 第 $attempt 次 → ${res.ifEmpty { "超时" }}")
            if (res.startsWith("1 ")) return true
        }
        return false
    }
}
