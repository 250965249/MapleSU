package dev.maplesu.manager.workmode.service

import dev.maplesu.manager.installer.RootScriptResult
import dev.maplesu.manager.installer.InstallerPending
import dev.maplesu.manager.workmode.WorkMode
import dev.maplesu.manager.workmode.storage.MoveEntry
import dev.maplesu.manager.workmode.storage.MoveSet
import dev.maplesu.manager.workmode.switch.HookResult
import dev.maplesu.manager.workmode.switch.ModeSwitchRequest

/** Source teardown is separate from partition writes; its archive survives an aborted transaction. */
interface ModeSwitchEnvironmentLifecycle {
    fun prepare(): HookResult
    fun withdraw(request: ModeSwitchRequest): HookResult
    /** Final operation after both images and inbound data are durable. The root helper requests reboot. */
    fun complete(request: ModeSwitchRequest): HookResult = HookResult.OK
    fun restoreAfterFailure(request: ModeSwitchRequest): HookResult
}

/**
 * Archive source data before moving it out. SDK removal is deferred to the reboot action,
 * after the partition journal and target data are durable. The independent root helper requests
 * reboot after SDK removal. Rollback restores the archive without invoking the SDK.
 */
class RootModeSwitchEnvironmentLifecycle(
    private val ready: () -> HookResult,
    private val runner: (String) -> RootScriptResult,
    private val dynamicPaths: (WorkMode) -> List<MoveEntry>,
    private val uninstallUltra: () -> HookResult,
    private val archiveRoot: String = "$RECOVERY_ROOT/environment-archives",
    private val originalsRoot: String = "$RECOVERY_ROOT/originals",
) : ModeSwitchEnvironmentLifecycle {
    override fun prepare(): HookResult = ready()

    override fun withdraw(request: ModeSwitchRequest): HookResult {
        // Normal is removed by restoring its verified stock init_boot in the partition transaction.
        // The upstream uninstaller also deletes modules and reboots, so it is not a switch primitive.
        if (request.fromMode != WorkMode.LITE) return HookResult.OK
        val paths = paths(request.fromMode) ?: return HookResult.failed(ARCHIVE_FAILED)
        return execute(archiveScript(request, paths), ARCHIVE_FAILED)
    }

    override fun complete(request: ModeSwitchRequest): HookResult {
        if (request.fromMode != WorkMode.LITE) return HookResult.OK
        return runCatching { uninstallUltra() }.getOrElse {
            HookResult.failed(UNINSTALL_FAILED, it.javaClass.simpleName)
        }
    }

    override fun restoreAfterFailure(request: ModeSwitchRequest): HookResult {
        if (request.fromMode != WorkMode.LITE) return HookResult.OK
        val paths = paths(request.fromMode) ?: return HookResult.failed(RESTORE_FAILED)
        return execute(restoreScript(request, paths), RESTORE_FAILED)
    }

    private fun paths(mode: WorkMode): List<MoveEntry>? = runCatching {
        val entries = MoveSet.moveSetFor(mode) + dynamicPaths(mode)
        require(MoveSet.validate(entries, emptyMap()).isEmpty())
        require(entries.none { a -> entries.any { b -> a != b && a.livePath.startsWith(b.livePath + "/") } })
        entries
    }.getOrNull()

    internal fun archiveScript(request: ModeSwitchRequest, paths: List<MoveEntry>): String = buildString {
        append(header(request))
        append("[ ! -e \"\$A\" ] || { echo ARCHIVE_ALREADY_EXISTS; exit 61; }\n")
        append("mkdir -p \"\$A\" || exit 62\nchmod 700 \"\$A\" || exit 62\n")
        append("if [ -e \"\$B\" ] || [ -L \"\$B\" ]; then\n")
        append(" [ -d \"\$B\" ] && [ ! -L \"\$B\" ] || exit 63\n")
        append(" cp -a \"\$B\" \"\$A/baseline\" || exit 63\n same \"\$B\" \"\$A/baseline\" || exit 64\n")
        append(" digest \"\$A/baseline\" > \"\$A/inventory\" || exit 64\n")
        append(" sha256sum \"\$A/inventory\" > \"\$A/baseline.sha256\" || exit 64\n")
        // Mirrors survive transaction cleanup and are never replaced by a newer capture.
        append(" for p in \"\$B\"/*; do\n")
        append("  [ -e \"\$p\" ] || [ -L \"\$p\" ] || continue\n")
        append("  [ -d \"\$p\" ] && [ ! -L \"\$p\" ] || exit 64\n")
        append("  M=\"\$O/\${p##*/}\"\n")
        append("  if [ -e \"\$M\" ] || [ -L \"\$M\" ]; then\n")
        append("   [ ! -L \"\$M\" ] && same \"\$p\" \"\$M\" || exit 64\n")
        append("  else\n T=\"\$O/.\${p##*/}.${request.switchId}.tmp\"\n")
        append("   [ ! -e \"\$T\" ] && [ ! -L \"\$T\" ] || exit 64\n")
        append("   cp -a \"\$p\" \"\$T\" || exit 63\n same \"\$p\" \"\$T\" || exit 64\n")
        append("   sync\n mv \"\$T\" \"\$M\" || exit 63\n fi\n done\n")
        append(" touch \"\$A/baseline.present\" || exit 62\nfi\n")
        protectedIdentities(paths).forEachIndexed { i, protected ->
            append("if [ -e ").append(q(protected)).append(" ]; then\n")
            append(" stat -c '%d:%i' ").append(q(protected)).append(" > \"\$A/protected-$i\" || exit 62\nfi\n")
        }
        paths.forEachIndexed { i, entry ->
            append("L=").append(q(entry.livePath)).append("\nS=\"\$A/$i\"\n")
            append("if [ -e \"\$L\" ] || [ -L \"\$L\" ]; then\n")
            append(" cp -a \"\$L\" \"\$S\" || exit 63\n")
            MoveSet.preservedPathsUnder(entry.livePath).forEach { protected ->
                val relative = protected.removePrefix(entry.livePath + "/")
                append(" rm -rf \"\$S\"/").append(q(relative)).append(" || exit 63\n")
            }
            append(" same \"\$L\" \"\$S\" || exit 64\n")
            append(" digest \"\$S\" > \"\$A/inventory\" || exit 64\n")
            append(" sha256sum \"\$A/inventory\" > \"\$A/$i.sha256\" || exit 64\n")
            append(" touch \"\$A/$i.present\" || exit 62\nfi\n")
        }
        append("sync\ntouch \"\$A/ready\" || exit 62\nsync\necho MODE_ENV_OK\n")
    }

    internal fun restoreScript(request: ModeSwitchRequest, paths: List<MoveEntry>): String = buildString {
        append(header(request))
        // An unsuccessful/never-started archive has not licensed an uninstall.
        append("[ -f \"\$A/ready\" ] || { echo MODE_ENV_OK; exit 0; }\n")
        // Restore original images first, even if SDK teardown replaced the held installer inode.
        append("if [ -f \"\$A/baseline.present\" ]; then\n")
        append(" digest \"\$A/baseline\" > \"\$A/inventory\" || exit 68\n")
        append(" x=\$(sha256sum \"\$A/inventory\") || exit 68\n y=\$(cat \"\$A/baseline.sha256\") || exit 68\n")
        append(" [ \"\${x%% *}\" = \"\${y%% *}\" ] || exit 68\n")
        append(" if ! same \"\$A/baseline\" \"\$B\"; then\n")
        append("  rm -rf \"\$B\" || exit 65\n mkdir -p \"\$(dirname \"\$B\")\" || exit 65\n")
        append("  cp -a \"\$A/baseline\" \"\$B\" || exit 65\n fi\n")
        append(" same \"\$A/baseline\" \"\$B\" || exit 66\n sync\nfi\n")
        protectedIdentities(paths).forEachIndexed { i, protected ->
            append("if [ -f \"\$A/protected-$i\" ]; then\n")
            append(" [ \"\$(stat -c '%d:%i' ").append(q(protected)).append(")\" = \"\$(cat \"\$A/protected-$i\")\" ] || exit 67\nfi\n")
        }
        // Validate every saved tree before restoring any of them.
        paths.forEachIndexed { i, _ ->
            append("if [ -f \"\$A/$i.present\" ]; then\n")
            append(" digest \"\$A/$i\" > \"\$A/inventory\" || exit 68\n")
            append(" x=\$(sha256sum \"\$A/inventory\") || exit 68\n y=\$(cat \"\$A/$i.sha256\") || exit 68\n")
            append(" [ \"\${x%% *}\" = \"\${y%% *}\" ] || exit 68\nfi\n")
        }
        paths.forEachIndexed { i, entry ->
            append("L=").append(q(entry.livePath)).append("\nS=\"\$A/$i\"\n")
            append("if [ -f \"\$A/$i.present\" ]; then\n")
            val preserved = MoveSet.preservedPathsUnder(entry.livePath)
            if (preserved.isEmpty()) {
                append(" if ! same \"\$S\" \"\$L\"; then\n")
                append("  rm -rf \"\$L\" || exit 65\n mkdir -p \"\$(dirname \"\$L\")\" || exit 65\n")
                append("  cp -a \"\$S\" \"\$L\" || exit 65\n fi\n")
            } else {
                append(" [ ! -L \"\$L\" ] || exit 65\n mkdir -p \"\$L\" || exit 65\n")
                append(" for p in \"\$L\"/* \"\$L\"/.[!.]* \"\$L\"/..?*; do\n")
                append("  [ -e \"\$p\" ] || [ -L \"\$p\" ] || continue\n  skip \"\$p\" && continue\n")
                append("  rm -rf \"\$p\" || exit 65\n done\n")
                append(" cp -a \"\$S/.\" \"\$L/\" || exit 65\n")
            }
            append(" same \"\$S\" \"\$L\" || exit 66\nfi\n")
        }
        append("sync\necho MODE_ENV_OK\n")
    }

    private fun header(request: ModeSwitchRequest): String {
        require(Regex("[A-Za-z0-9_-]{1,64}").matches(request.switchId))
        require(archiveRoot.startsWith("/") && archiveRoot.split('/').none { it == ".." })
        require(originalsRoot.startsWith("/") && originalsRoot.split('/').none { it == ".." })
        return "umask 077\nA=${q("$archiveRoot/${request.switchId}")}\n" +
            "R=${q(archiveRoot)}\nO=${q(originalsRoot)}\nB=${q(BASELINE_ROOT)}\n" + COMPARE +
            (if (archiveRoot.startsWith("$RECOVERY_ROOT/") || originalsRoot.startsWith("$RECOVERY_ROOT/")) {
                "private_root ${q(RECOVERY_ROOT)} || exit 62\n"
            } else "") + "private_root \"\$R\" && private_root \"\$O\" || exit 62\n"
    }

    private fun protectedIdentities(paths: List<MoveEntry>): List<String> {
        val protected = paths.flatMap { MoveSet.preservedPathsUnder(it.livePath) }.distinct()
            .sortedBy { it == MoveSet.NORMAL_RECOVERY_TOKEN }
        // Append the shared token last to preserve identity indices in existing archives.
        return protected.flatMap { path ->
            if (path == MoveSet.INSTALLER_ROOT) listOf(path, "$path/install.lock") else listOf(path)
        }
    }

    private fun execute(script: String, code: String): HookResult = runCatching {
        val result = runner(script)
        if (result.error.contains(ModeSwitchRootProtocol.UNCERTAIN) || result.output.contains(ModeSwitchRootProtocol.UNCERTAIN)) {
            HookResult.failed(ModeSwitchRootProtocol.UNCERTAIN)
        } else if (result.ok && result.output.lineSequence().any { it == "MODE_ENV_OK" }) HookResult.OK
        else HookResult.failed(code, "exit=${result.code}")
    }.getOrElse { HookResult.failed(code, it.javaClass.simpleName) }

    companion object {
        const val ARCHIVE_FAILED = "SWITCH_ENV_ARCHIVE_FAILED"
        const val UNINSTALL_FAILED = "SWITCH_ENV_UNINSTALL_FAILED"
        const val RESTORE_FAILED = "SWITCH_ENV_RECOVERY_REQUIRED"
        const val RECOVERY_ROOT = InstallerPending.MODE_SWITCH_RECOVERY_ROOT
        const val BASELINE_ROOT = "${MoveSet.CONTROL_ROOT}/boot/baseline"
        private fun q(value: String) = "'" + value.replace("'", "'\\''") + "'"

        // Compare names, type, ownership, permissions, timestamps, file bytes and symlink targets.
        // Globs preserve whitespace, and symlinks are never traversed. No path is printed.
        private val COMPARE = """
            private_root() (
              p=${'$'}1
              while [ "${'$'}p" != / ]; do
                [ ! -L "${'$'}p" ] || return 1
                [ ! -e "${'$'}p" ] || [ -d "${'$'}p" ] || return 1
                n=${'$'}{p%/*}; [ "${'$'}n" != "${'$'}p" ] || break
                p=${'$'}n; [ -n "${'$'}p" ] || p=/
              done
              mkdir -p "${'$'}1" && chmod 700 "${'$'}1"
            )
            skip() {
              case "${'$'}1" in
                ${MoveSet.NEVER_MOVE.filter { it != MoveSet.ADB_ROOT }.joinToString("|") { q(it) }}) return 0 ;;
              esac
              return 1
            }
            digest() (
              a=${'$'}1
              stat -c '%a:%u:%g' "${'$'}a" || return 1
              if [ -L "${'$'}a" ]; then
                printf 'L'; readlink "${'$'}a"; return ${'$'}?
              elif [ -f "${'$'}a" ]; then
                printf 'F'; stat -c '%Y' "${'$'}a" || return 1
                h=${'$'}(sha256sum "${'$'}a") || return 1
                printf '%s\000' "${'$'}{h%% *}"
              elif [ -d "${'$'}a" ]; then
                printf 'D'
                for p in "${'$'}a"/* "${'$'}a"/.[!.]* "${'$'}a"/..?*; do
                  [ -e "${'$'}p" ] || [ -L "${'$'}p" ] || continue
                  printf '%s\000' "${'$'}{p##*/}"
                  digest "${'$'}p" || return 1
                done
              else return 1; fi
            )
            same() (
              a=${'$'}1; b=${'$'}2
              [ -e "${'$'}a" ] || [ -L "${'$'}a" ] || return 1
              [ -e "${'$'}b" ] || [ -L "${'$'}b" ] || return 1
              [ "${'$'}(stat -c '%a:%u:%g' "${'$'}a")" = "${'$'}(stat -c '%a:%u:%g' "${'$'}b")" ] || return 1
              if [ -L "${'$'}a" ]; then
                [ -L "${'$'}b" ] && [ "${'$'}(readlink "${'$'}a")" = "${'$'}(readlink "${'$'}b")" ]; return ${'$'}?
              fi
              [ ! -L "${'$'}b" ] || return 1
              if [ -f "${'$'}a" ]; then
                [ -f "${'$'}b" ] || return 1
                [ "${'$'}(stat -c '%Y' "${'$'}a")" = "${'$'}(stat -c '%Y' "${'$'}b")" ] || return 1
                x=${'$'}(sha256sum "${'$'}a") || return 1; y=${'$'}(sha256sum "${'$'}b") || return 1
                [ "${'$'}{x%% *}" = "${'$'}{y%% *}" ]; return ${'$'}?
              fi
              [ -d "${'$'}a" ] && [ -d "${'$'}b" ] || return 1
              for p in "${'$'}a"/* "${'$'}a"/.[!.]* "${'$'}a"/..?*; do
                [ -e "${'$'}p" ] || [ -L "${'$'}p" ] || continue
                skip "${'$'}p" && continue
                same "${'$'}p" "${'$'}b/${'$'}{p##*/}" || return 1
              done
              for p in "${'$'}b"/* "${'$'}b"/.[!.]* "${'$'}b"/..?*; do
                [ -e "${'$'}p" ] || [ -L "${'$'}p" ] || continue
                skip "${'$'}p" && continue
                [ -e "${'$'}a/${'$'}{p##*/}" ] || [ -L "${'$'}a/${'$'}{p##*/}" ] || return 1
              done
            )
        """.trimIndent() + "\n"
    }
}
