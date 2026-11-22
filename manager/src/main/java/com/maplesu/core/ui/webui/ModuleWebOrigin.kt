package com.maplesu.core.ui.webui

import java.net.URI

/** Exact document origin: a different loopback port is a different module host. */
internal data class ModuleWebOrigin private constructor(val value: String) {
    fun contains(url: String?): Boolean = from(url) == this

    companion object {
        fun from(url: String?): ModuleWebOrigin? {
            val uri = runCatching { URI(url ?: return null) }.getOrNull() ?: return null
            if (!uri.scheme.equals("http", true) || uri.rawUserInfo != null) return null
            val host = uri.host?.lowercase() ?: return null
            if (host != "127.0.0.1" && host != "localhost") return null
            val port = if (uri.port == -1) 80 else uri.port
            if (port !in 1..65535) return null
            return ModuleWebOrigin("http://$host:$port")
        }
    }
}
