package dev.maplesu.manager.liteweb

import android.content.Context

/**
 * liteweb daemon 的 base URL（含 token），只用于「A 模式下 Ultra 模块 WebUI 兜底代理」。
 *
 * 为什么放在 liteweb 包里：token/端口的读取规则属于 liteweb，不应该让模块层再实现一份。
 * 拿不到（没 root、配置没生成、模式不对）就返回 null —— 调用方会明确报
 * `PROXY_UNAVAILABLE`，而不是拼一个猜出来的地址。
 */
object LiteWebProxyBase {
    fun current(context: Context): String? = runCatching {
        LiteWebAdminController(context.applicationContext).previewUrlOrNull()
    }.getOrNull()
}
