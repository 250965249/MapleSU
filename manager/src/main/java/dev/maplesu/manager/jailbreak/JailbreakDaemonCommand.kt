package dev.maplesu.manager.jailbreak

/**
 * Builds the command line that starts the MapleSU Root executor inside the leased
 * shell.
 *
 * DEV-10/DEV-11: libsu's task layer is silently discarded on the lease shell while
 * a direct lease command is answered, so the launcher writes this command itself.
 *
 * The launcher shell *replaces itself* with the executor (`exec`): the lease
 * stdin/stdout then have exactly one owner, which is what makes a line protocol on
 * that transport possible at all - a backgrounded child would leave the shell and
 * the daemon both reading the same descriptor.
 *
 * Only absolute, separator-free, quote-free values are accepted: this string is
 * written into a shell's stdin, so an injected separator or quote would be a
 * command injection, not a path.
 */
object JailbreakDaemonCommand {
    /** Main class of the executor image. */
    const val MAIN_CLASS = "dev.maplesu.manager.runtime.JailbreakDaemonMain"

    /**
     * The launch line. `CLASSPATH` is exported because app_process builds its boot
     * classpath from that environment variable (a `-Djava.class.path` argument made
     * ART abort in AndroidRuntime::startReg - DEV-12), `LD_LIBRARY_PATH` from the
     * consumer's child is measured to be fatal for this binary, and `-Xnoimage-dex2oat`
     * plus the 64-bit name mirror the vendored libsu recipe.
     */
    fun launch(apkPath: String, processName: String, managerUid: Int): String {
        requireSafe(apkPath, "JAILBREAK_DAEMON_APK_PATH_INVALID")
        requireProcessName(processName)
        require(managerUid > 0) { "JAILBREAK_DAEMON_MANAGER_UID_INVALID" }
        return "unset LD_LIBRARY_PATH; export CLASSPATH=" + apkPath + "; exec app_process64" +
            " -Xnoimage-dex2oat /system/bin --nice-name=" + processName + " " + MAIN_CLASS +
            " " + managerUid
    }

    fun launch(apkPath: String, processName: String, managerUid: Int,
               nativeLibraryDir: String, legacyAuthorityFile: String): String {
        requireSafe(nativeLibraryDir, "JAILBREAK_DAEMON_NATIVE_PATH_INVALID")
        requireSafe(legacyAuthorityFile, "JAILBREAK_DAEMON_AUTHORITY_PATH_INVALID")
        fun encoded(value: String) = java.util.Base64.getEncoder()
            .encodeToString(value.toByteArray(Charsets.UTF_8))
        return launch(apkPath, processName, managerUid) +
            " --su-native=" + encoded(nativeLibraryDir) + " --su-legacy=" + encoded(legacyAuthorityFile)
    }

    private fun requireProcessName(processName: String) {
        require(processName.isNotBlank() && processName.all { character ->
            character.isLetterOrDigit() || character in "._:-"
        }) { "JAILBREAK_DAEMON_NAME_INVALID" }
    }

    /**
     * Allowlist, not a denylist: only characters that cannot separate, quote,
     * expand or redirect a command are accepted. Every path this product builds is
     * an APK path, so the set is sufficient in practice.
     */
    private fun requireSafe(value: String, reason: String) {
        require(value.startsWith("/") && value.length < 4096 && value.all { character ->
            character.isLetterOrDigit() || character in "/._:+-=,@~"
        }) { reason }
    }
}
