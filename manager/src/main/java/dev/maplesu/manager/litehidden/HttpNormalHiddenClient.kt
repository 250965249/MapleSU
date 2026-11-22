package dev.maplesu.manager.litehidden

import java.net.HttpURLConnection
import java.net.URI

class HttpNormalHiddenClient {
    fun ready(port: Int, token: String): Boolean =
        request(ParasitePaths.webUiUrl(port, token), "ready", false) == """{"ok":true,"mode":"KSU"}"""

    fun activate(url: String): NormalHiddenResult =
        if (request(url, "activate", true) == """{"ok":true,"state":"absent","data":"retained"}""") {
            NormalHiddenResult(true, recoveryUrl = url)
        } else NormalHiddenResult(false, "NORMAL_ACTIVATION_UNVERIFIED", url)

    private fun request(url: String, operation: String, post: Boolean): String? = runCatching {
        val uri = URI(url)
        if (uri.scheme != "http" || uri.host != "127.0.0.1" || uri.port !in 1..65535 ||
            uri.userInfo != null || uri.query != null || uri.fragment != null ||
            !Regex("^/x7k9f/[a-zA-Z0-9]{16,}/$").matches(uri.path)) return null
        val connection = URI(url + "api/normal/$operation").toURL().openConnection() as HttpURLConnection
        try {
            connection.connectTimeout = 3_000
            connection.readTimeout = if (post) 60_000 else 10_000
            connection.instanceFollowRedirects = false
            if (post) {
                connection.requestMethod = "POST"
                connection.doOutput = true
                connection.setRequestProperty("Content-Type", "application/json")
                connection.outputStream.use { it.write("{}".toByteArray()) }
            }
            if (connection.responseCode == 200) connection.inputStream.bufferedReader().use { it.readText().trim() } else null
        } finally {
            connection.disconnect()
        }
    }.getOrNull()
}
