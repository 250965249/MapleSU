package dev.maplesu.manager.workmode.service

/** Startup arguments contain public paths and uid only. Credentials travel in the socket. */
internal data class ModeSwitchRootLaunch(
    val managerUid: Int,
    val apk: String,
    val nativeDirectory: String,
    val tokenFile: String,
) {
    val socketName: String get() = "maplesu-mode-switch-" + managerUid + "-v" + ModeSwitchRootProtocol.VERSION

    fun validate() {
        require(managerUid >= 10_000 && managerUid % 100_000 in 10_000..99_999)
        val user = managerUid / 100_000
        // Android's Java canonical path may use /data/data for the primary user's CE data.
        val tokenSuffix = "/" + PACKAGE + "/files/" + TOKEN_FILE
        require(tokenFile == "/data/user/" + user + tokenSuffix ||
            (user == 0 && tokenFile == "/data/data" + tokenSuffix))
        require(validPath(apk) && validPath(nativeDirectory))
        require(apk.startsWith("/data/app/") || apk.matches(Regex("/mnt/expand/[A-Za-z0-9-]+/app/.*")))
        require(apk.endsWith("/base.apk"))
        val appDirectory = apk.substringBeforeLast('/')
        require(appDirectory.substringAfterLast('/').startsWith(PACKAGE + "-"))
        require(nativeDirectory.substringBeforeLast('/') == appDirectory + "/lib")
        require(nativeDirectory.substringAfterLast('/') in setOf("arm64", "arm", "x86", "x86_64"))
    }

    fun script(): String {
        validate()
        return "[ \"\$(/system/bin/id -u)\" = 0 ] || exit 1\n" +
            "CLASSPATH=" + quote(apk) + " LD_LIBRARY_PATH=" + quote(nativeDirectory) +
            " nohup /system/bin/app_process /system/bin --nice-name=maplesu-mode-switch " + MAIN +
            " " + quote(socketName) + " " + quote(managerUid.toString()) + " " + quote(tokenFile) +
            " " + quote(nativeDirectory) + " </dev/null >/dev/null 2>&1 &\n"
    }

    companion object {
        const val PACKAGE = "dev.maplesu.manager"
        const val TOKEN_FILE = "mode-switch-root.token"
        const val MAIN = "dev.maplesu.manager.workmode.service.ModeSwitchRootMain"

        private fun validPath(path: String): Boolean = path.length in 1..4096 &&
            path.matches(Regex("/[A-Za-z0-9_./=+~-]+")) && path.split('/').none { it == ".." || it == "." }

        private fun quote(text: String): String = "'" + text.replace("'", "'\\''") + "'"
    }
}
