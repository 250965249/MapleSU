package dev.maplesu.manager.litehidden

/** Runs from the existing Ultra native boot module, independently of any installed app. */
object UltraRecoveryBoot {
    fun content(): String = """
        (
          R='${ParasitePaths.RECOVERY}'
          N=0
          while [ "${'$'}N" -lt 5 ]; do
            [ ! -e '${dev.maplesu.manager.runtime.ultra.UltraIdentityBroker.DISABLED}' ] || exit 0
            if [ "${'$'}(cat '${ParasitePaths.DATA_DIR}/lite_hidden' 2>/dev/null)" != 1 ]; then
              grep -qE '^pending:[a-f0-9-]{36}${'$'}' '${dev.maplesu.manager.recovery.ManagerRestoreHandover.PATH}' 2>/dev/null || exit 0
            fi
            [ "${'$'}(sed -n 's/^workMode=//p' "${'$'}R/webui.conf" 2>/dev/null)" = LITE ] || exit 0
            [ ! -e "${'$'}R/webui.paused" ] && [ -f "${'$'}R/parasite-start.sh" ] || exit 0
            /system/bin/sh "${'$'}R/parasite-start.sh" && exit 0
            N=${'$'}((N+1))
            sleep 2
          done
          exit 1
        ) </dev/null >> '${ParasitePaths.RECOVERY}/boot.log' 2>&1 &
    """.trimIndent() + "\n"
}
