package dev.maplesu.manager.litehidden

import java.security.MessageDigest

/** A fixed KSU service.d entry keeps the recovery link available after reboot without a host app. */
object NormalRecoveryBoot {
    const val PATH = "/data/adb/service.d/maplesu-normal-recovery.sh"
    const val INSTALLED = "MAPLESU_NORMAL_BOOT_OK"
    const val REMOVED = "MAPLESU_NORMAL_BOOT_GONE"
    // Previous releases stored the full daemon script here. Accept only these exact owned hashes
    // when updating/removing it; arbitrary user scripts at the same path are left intact.
    private val legacyHashes = setOf("367c7117130341c29b875e80242d5a2c1b38b44014a684b7ab7c5aa08f392dbb")

    fun content(): String = """
        #!/system/bin/sh
        # MapleSU Normal recovery v1
        R='/data/adb/maplesu/recovery'
        [ "${'$'}(sed -n 's/^workMode=//p' "${'$'}R/webui.conf" 2>/dev/null)" = 'KSU' ] || exit 0
        [ "${'$'}(cat '/data/adb/maplesu/lite_hidden' 2>/dev/null)" = '1' ] || exit 0
        [ ! -e "${'$'}R/webui.paused" ] || exit 0
    """.trimIndent() + "\n" + ParasiteScripts.daemonStart().removePrefix("#!/system/bin/sh\n")

    fun installScript(): String {
        val body = content()
        val prefix = """
            set -eu
            P='$PATH'
            [ ! -L "${'$'}P" ] && [ ! -L "${'$'}P.tmp" ] || exit 1
            EXPECTED='${sha(body)}'
            if [ -e "${'$'}P" ]; then
              case "${'$'}(sha256sum "${'$'}P" | awk '{print ${'$'}1}')" in $KNOWN_HASHES) ;; *) exit 1;; esac
            fi
              mkdir -p '/data/adb/service.d'
              umask 077
              cat > "${'$'}P.tmp" <<'MAPLESU_NORMAL_BOOT_EOF'
        """.trimIndent()
        return prefix + "\n" + body + "MAPLESU_NORMAL_BOOT_EOF\n" + """
              chmod 700 "${'$'}P.tmp" && mv -f "${'$'}P.tmp" "${'$'}P"
            [ "${'$'}(sha256sum "${'$'}P" | awk '{print ${'$'}1}')" = "${'$'}EXPECTED" ] && [ -x "${'$'}P" ] && echo $INSTALLED
        """.trimIndent()
    }

    fun removeScript(): String = """
        set -eu
        P='$PATH'
        [ ! -L "${'$'}P" ] || exit 1
        if [ -e "${'$'}P" ]; then
          case "${'$'}(sha256sum "${'$'}P" | awk '{print ${'$'}1}')" in $KNOWN_HASHES) ;; *) exit 1;; esac
          rm -f "${'$'}P"
        fi
        [ ! -e "${'$'}P" ] && echo $REMOVED
    """.trimIndent()

    private val KNOWN_HASHES: String get() = (legacyHashes + sha(content())).joinToString("|")

    private fun sha(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.toByteArray()).joinToString("") { "%02x".format(it.toInt() and 0xff) }
}
