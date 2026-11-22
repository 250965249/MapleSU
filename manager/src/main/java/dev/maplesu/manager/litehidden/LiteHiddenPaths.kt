package dev.maplesu.manager.litehidden

/**
 * Lite 隐藏模式的持久化路径（A 模式专属，**不碰 KSU 的 `/data/adb/ksu/`**）。
 * 纯常量，主机可测。
 */
object LiteHiddenPaths {
    const val DATA_DIR = "/data/adb/maplesu"
    const val STATE_PATH = "$DATA_DIR/lite_hidden"
    const val CODE_PATH = "$DATA_DIR/lite_hidden_code"
    const val DIR_MODE = "700"
    const val FILE_MODE = "600"
    const val OWNER = "0:0"

    /** app 侧私有痕迹根（只允许删这里面白名单子目录）。 */
    const val FILES_DIR = "files"

    /** App prefs（经 SettingsPrefsRouter，模式感知）里的键。 */
    const val PREF_CODE = "lite_hidden_code"
    const val PREF_TRACE = "lite_hidden_trace"

    /** 隐藏模式恢复端口（仅保存；开启时交给后端应用）。 */
    const val PREF_PORT = "lite_hidden_port"

    /** 已选寄生宿主包名（仅 UI 记忆；宿主真实状态由后端 so/记录决定）。 */
    const val PREF_HOST = "lite_hidden_host"

    /** Missing is OFF only after a real root read; inspecting state never prepares directories. */
    fun stateReadScript(): String = """
        [ "${'$'}(id -u)" = 0 ] || exit 1
        if [ -e '$STATE_PATH' ] || [ -L '$STATE_PATH' ]; then
          cat '$STATE_PATH'
        else
          for D in /data /data/adb '$DATA_DIR'; do
            if [ -e "${'$'}D" ]; then
              [ -d "${'$'}D" ] && [ -r "${'$'}D" ] && [ -x "${'$'}D" ] || exit 1
            fi
          done
          echo LITE_MISSING
        fi
    """.trimIndent()

    fun stateScript(write: Boolean? = null, value: String? = null): String {
        if (write != true) return stateReadScript()
        return buildString {
            append("mkdir -p ")
            append(DATA_DIR)
            append(" 2>/dev/null; chmod ")
            append(DIR_MODE)
            append(" ")
            append(DATA_DIR)
            append(" 2>/dev/null; ")
            append("echo '")
            append(value.orEmpty().filter { it == '0' || it == '1' }.take(1))
            append("' > ")
            append(STATE_PATH)
            append(" && chmod ")
            append(FILE_MODE)
            append(" ")
            append(STATE_PATH)
            append(" && chown ")
            append(OWNER)
            append(" ")
            append(STATE_PATH)
            append(" 2>/dev/null && echo LITE_OK")
        }
    }

    fun codeScript(write: Boolean, code: String = ""): String = buildString {
        append("mkdir -p ")
        append(DATA_DIR)
        append(" 2>/dev/null; ")
        if (write) {
            append("printf '%s' '")
            append(code.filter { it.isDigit() }.take(12))
            append("' > ")
            append(CODE_PATH)
            append(" && chmod ")
            append(FILE_MODE)
            append(" ")
            append(CODE_PATH)
            append(" && chown ")
            append(OWNER)
            append(" ")
            append(CODE_PATH)
            append(" 2>/dev/null && echo LITE_OK")
        } else {
            append("cat ")
            append(CODE_PATH)
            append(" 2>/dev/null")
        }
    }
}
