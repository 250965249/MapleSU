package dev.maplesu.manager.litehidden

import dev.maplesu.manager.liteweb.LiteWebToken

/** Kept outside the replaceable bundle so a failed backup never invalidates a saved recovery link. */
internal class NormalHiddenSessionToken(
    private val root: HiddenRootRunner,
    private val factory: () -> String = LiteWebToken::generate,
) {
    private var remembered: String? = null

    @Synchronized
    fun resolve(configToken: String?): String? {
        val read = root.run("if [ -e '$PATH' ]; then cat '$PATH'; else echo MAPLESU_TOKEN_ABSENT; fi")
        if (read.code != 0) return null
        val saved = read.output.trim().takeIf { it != "MAPLESU_TOKEN_ABSENT" }
        if (saved != null && !valid(saved)) return null
        val token = configToken?.takeIf(::valid) ?: remembered ?: saved ?: factory().takeIf(::valid) ?: return null
        remembered = token
        val retained = root.run(
            "umask 077; mkdir -p '/data/adb/maplesu' && printf '%s' '$token' > '$PATH.tmp' && " +
                "chmod 600 '$PATH.tmp' && mv -f '$PATH.tmp' '$PATH' && " +
                "[ \"\$(cat '$PATH')\" = '$token' ] && echo NORMAL_SESSION_RETAINED",
        )
        return token.takeIf { retained.code == 0 && retained.output.lineSequence().count { it.trim() == "NORMAL_SESSION_RETAINED" } == 1 }
    }

    private fun valid(token: String): Boolean = token.length >= 16 && token.all(Char::isLetterOrDigit)
    private companion object { const val PATH = "/data/adb/maplesu/normal-webui-token" }
}
