package dev.maplesu.manager.runtime

/** Preserve the caller's cwd/environment; only the final, admitted child consumes them. */
internal object HookSuCommand {
    fun argv(request: NativeSuRequest, argv: List<String>): Array<String> = arrayOf(
        NativeSu.SHELL, "-c", RootServiceBootstrap.command(script(request, argv)),
    )

    internal fun script(request: NativeSuRequest, argv: List<String>): String =
        "cd " + quote(request.directory) + " || exit 71\nexec /system/bin/env -i -- " +
            (request.environment + argv).joinToString(" ", transform = ::quote)

    private fun quote(value: String): String = "'" + value.replace("'", "'\\''") + "'"
}
