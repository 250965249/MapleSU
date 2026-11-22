package me.yuki.fina.adbroot.core

/**
 * root 管理器目录。
 *
 * 原则：**只收录 GitHub 上的正式版（release）**，不收 CI / nightly 产物。
 * url / sha256 / bytes 全部取自 GitHub Releases API 的资产信息，下载时逐镜像试、
 * 下完必须 sha256 对得上才用。
 *
 * uapi 是「管理器自己带的 ksud 报出来的版本」，内核模块也是它自带的，
 * 所以只要 uapi 一致就能配上；官方正式版 v3.3.1 是 uapi 5，装到 uapi 6 的模块上会红条。
 */
data class Manager(
    val id: String,
    val name: String,
    val pkg: String,
    val uapi: Int,
    val versionName: String,
    val versionCode: Long,
    val url: String,
    val sha256: String,
    val bytes: Long,
    val recommended: Boolean = false,
    val note: String = "",
    val zipEntry: String? = null,
    val uapiFloor: Long? = null,
    val stack: String = "",
    /**
     * 只认自己编译的内核模块（实测：kernel 里跑的是 FinaSU 的 ko 时，这类管理器会显示「未安装」）。
     * YukiSU 就是这种——uapi 对得上也没用，它的界面直接判定内核模块没装。
     */
    val ownModuleOnly: Boolean = false,
    /** 高风险：装它前先弹一次确认（FinaSU 既是管理器又是当前内核模块来源）。 */
    val highRisk: Boolean = false,
) {
    val fileName: String get() = url.substringAfterLast('/')
    val isZip: Boolean get() = !zipEntry.isNullOrBlank()
}

object Managers {

    const val KERNEL_UAPI = 6

    val ALL: List<Manager> = listOf(
                Manager(
            id = "official",
            name = "官方 KernelSU",
            pkg = "me.weishu.kernelsu",
            uapi = 5,
            versionName = "v3.3.1",
            versionCode = 32680,
            url = "https://github.com/tiann/KernelSU/releases/download/v3.3.1/KernelSU_v3.3.1_32680-release.apk",
            sha256 = "b4a059ace71de2fa65cc7f12b1c58d55fc23ab25e057ee4230ce779742abe450",
            bytes = 13_637_206,
            note = "官方正式版，uapi 5：配 uapi 6 的模块会红条（要 uapi 6 得等官方新 release）",
            stack = "official",
        ),
        Manager(
            id = "finasu",
            name = "FinaSU",
            pkg = "me.yuki.fina",
            uapi = 6,
            versionName = "v1.3.2",
            versionCode = 33090,
            url = "https://github.com/LyraVoid/FinaSU/releases/download/v1.3.2/FinaSU_v1.3.2_33090-release.apk",
            sha256 = "367e28a646d4f448218ea1fa5d1228fcdd5fb20623c5e22eecb3ea3462fb19e1",
            bytes = 28_129_308,
            recommended = true,
            note = "uapi 6，同时也是当前内核模块的来源",
            stack = "fina",
        ),
        Manager(
            id = "sukisu",
            name = "SukiSU-Ultra",
            pkg = "com.sukisu.ultra",
            uapi = 6,
            versionName = "v4.3.0",
            versionCode = 41100,
            url = "https://github.com/SukiSU-Ultra/SukiSU-Ultra/releases/download/v4.3.0/SukiSU_v4.3.0_41100-release.apk",
            sha256 = "a928eb57ad34b105233f92dcd55e54dd883482e417970276329a7d0f0979e212",
            bytes = 19_219_289,
            note = "uapi 6，自带 ksud 6,093,280 B",
            stack = "sukisu",
        ),
        Manager(
            id = "next",
            name = "KernelSU-Next",
            pkg = "com.rifsxd.ksunext",
            uapi = 6,
            versionName = "v3.4.2",
            versionCode = 33355,
            url = "https://github.com/KernelSU-Next/KernelSU-Next/releases/download/v3.4.2/KernelSU_Next_v3.4.2_33355-release.apk",
            sha256 = "774a5511f7034a4930e881114e202319cbdc34c5aaaa5c7c6b6d2902364e4c58",
            bytes = 16_682_167,
            note = "uapi 6，自带 ksud 7,620,040 B",
            stack = "next",
        ),
        Manager(
            id = "baka",
            name = "BakaSU (ReSukiSU)",
            pkg = "com.resukisu.resukisu",
            uapi = 6,
            versionName = "v4.2.0-rc3",
            versionCode = 35171,
            url = "https://github.com/Baka-SU/BakaSU/releases/download/v4.2.0-rc3/ReSukiSU_v4.2.0-rc3_35171-arm64-v8a-release.apk",
            sha256 = "25657bc449439687608fffa04b4b586de90fc405e3dc6217bd997fc71ba0a0a1",
            bytes = 9_379_362,
            note = "uapi 6，自带 ksud 5,953,680 B（这家只发 rc 版，rc3 就是它最新正式版）",
            stack = "baka",
        ),
    )

    fun byId(id: String): Manager = ALL.firstOrNull { it.id == id } ?: ALL.first()
}

/** 设备上实际装了什么。uapi = -1 表示读不到，versionCode = -1 表示未知。 */
data class Installed(val present: Boolean, val uapi: Int = -1, val versionCode: Long = -1, val raw: String = "")

object ManagerProbe {

    /**
     * 直接问设备：包名有没有装、APK 里的 ksud 版本串带不带 uapi。
     *
     * 只认带括号的 `(uapi: N)`：裸匹配 `uapi: N` 会命中内核那一侧的字符串，
     * 把 Next(5)/BakaSU(4) 误报成 6。
     */
    suspend fun probe(sh: Shell, pkg: String): Installed {
        val cmd = """
            export PATH=/system/bin:/system/xbin:/sbin:${'$'}PATH
            export ANDROID_DATA=/data ANDROID_ROOT=/system ANDROID_RUNTIME_ROOT=/apex/com.android.runtime
            APK=${'$'}(cmd package path $pkg 2>/dev/null | head -1 | sed 's/^package://')
            if [ -z "${'$'}APK" ]; then APK=${'$'}(pm path $pkg 2>/dev/null | head -1 | sed 's/^package://'); fi
            if [ -z "${'$'}APK" ]; then echo MEOW_ABSENT_TAG; exit 0; fi
            echo MEOW_PRESENT_TAG
            echo "MEOW_APK=${'$'}APK"
            unzip -p "${'$'}APK" 'lib/arm64-v8a/*' 2>/dev/null | grep -aEo '\(uapi: [0-9]+\)' | head -1
            VC=${'$'}(dumpsys package $pkg 2>/dev/null | grep -m1 versionCode)
            if [ -z "${'$'}VC" ]; then VC=${'$'}(cmd package dump $pkg 2>/dev/null | grep -m1 versionCode); fi
            echo "${'$'}VC"
        """.trimIndent()
        val text = sh.exec(cmd, 40_000).text
        if (!text.lineSequence().any { it.trim() == "MEOW_PRESENT_TAG" }) return Installed(false, raw = text.take(200))
        val uapi = text.lineSequence()
            .firstOrNull { it.trimStart().startsWith("(uapi:") }
            ?.let { Regex("[0-9]+").find(it)?.value?.toIntOrNull() } ?: -1
        val vc = text.lineSequence()
            .firstOrNull { it.contains("versionCode=") }
            ?.let { Regex("versionCode=([0-9]+)").find(it)?.groupValues?.get(1)?.toLongOrNull() } ?: -1
        return Installed(true, uapi, vc, text.take(200))
    }

    /** 实测值优先；读不到时用 versionCode 门槛；再不行退回目录值。 */
    fun effectiveUapi(m: Manager, d: Installed?): Int {
        if (d == null || !d.present) return m.uapi
        if (d.uapi >= 0) return d.uapi
        val floor = m.uapiFloor
        if (floor != null && d.versionCode >= floor) return Managers.KERNEL_UAPI
        return m.uapi
    }
}
