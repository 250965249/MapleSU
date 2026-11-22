package dev.maplesu.manager.modules

import dev.maplesu.manager.modules.webui.ModuleWebUiSessions
import java.util.UUID

/** Root owns executable KSU trees; app-private storage owns only archives and receipts. */
internal class RootModuleTree(
    private val runner: ModuleScriptRunner,
    private val root: String = ModuleTree.ROOT,
    private val transactions: String = "/data/adb/maplesu/module-transactions",
) {
    data class Snapshot(
        val directory: Boolean = false,
        val files: Set<String> = emptySet(),
        val directories: Set<String> = emptySet(),
        val zygisk: Boolean = false,
        val revision: String = "",
        val legacyTarget: String = "",
        val metadata: String? = null,
        val identity: String = "",
        val pendingTransaction: Boolean = false,
        val pending: Snapshot? = null,
    ) {
        val enabled get() = "disable" !in files
        val removed get() = "remove" in files
    }

    fun path(id: String): String {
        require(id.matches(Regex("[a-zA-Z][a-zA-Z0-9._-]+")))
        return "$root/$id"
    }

    @JvmOverloads
    fun snapshot(ids: Collection<String>, discover: Boolean = false): Map<String, Snapshot> {
        if (ids.isEmpty() && !discover) return emptyMap()
        ids.forEach(::path)
        val script = buildString {
            appendLine("set -eu")
            // Android mksh's printf is external. Keep row emission inside the shell.
            appendLine("if [ -n \"\${KSH_VERSION:-}\" ]; then")
            appendLine("  snapshot_line() { print -r -- \"\$1\"; }")
            appendLine("else")
            appendLine("  snapshot_line() { printf '%s\\n' \"\$1\"; }")
            appendLine("fi")
            appendLine("set --")
            appendLine("read_module() {")
            appendLine("d=\$1; id=\${d##*/}; metadata_path=; i=\$2; tag=")
            appendLine("case \$d in ${q(root + "_update")}/*) tag=P ;; esac")
            appendLine("if [ -d \"\$d\" ]; then snapshot_line \"\${tag}D\t\$id\"; snapshot_line \"\${tag}I\t\$id\t\$i\"; fi")
            appendLine("if [ -L \"\$d\" ]; then snapshot_line \"\${tag}L\t\$id\t\$(readlink \"\$d\")\"; fi")
            val files = listOf("module.prop", "install.sh", "customize.sh", "action.sh", "uninstall.sh",
                "post-fs-data.sh", "post-mount.sh", "service.sh", "boot-completed.sh", "metamount.sh",
                "metainstall.sh", "metauninstall.sh",
                "system.prop", "sepolicy.rule", "webroot/index.html", "disable", "remove", "skip_mount", "update")
            appendLine("for f in ${files.joinToString(" ", transform = ::q)}; do")
            appendLine("  if [ -f \"\$d/\$f\" ] && [ ! -L \"\$d/\$f\" ]; then snapshot_line \"\${tag}F\t\$id\t\$f\"; fi")
            appendLine("done")
            appendLine("for f in system vendor product system_ext odm oem webroot initrc.d; do")
            appendLine("  if [ -d \"\$d/\$f\" ]; then snapshot_line \"\${tag}S\t\$id\t\$f\"; fi")
            appendLine("done")
            appendLine("for f in \"\$d\"/zygisk/*.so; do")
            appendLine("  if [ -f \"\$f\" ] && [ ! -L \"\$f\" ]; then snapshot_line \"\${tag}Z\t\$id\"; break; fi")
            appendLine("done")
            appendLine("o=\"\$d/$OWNER\"")
            appendLine("if [ -n \"\$i\" ]; then")
            appendLine("  f=${q("$root/$OWNER")}/\${i%:*}-\${i##*:}")
            appendLine("  if [ -e \"\$f\" ] || [ -L \"\$f\" ]; then o=\$f; fi")
            appendLine("fi")
            appendLine("if [ -e \"\$o\" ] || [ -L \"\$o\" ]; then")
            appendLine("  r=INVALID_OWNER")
            appendLine("  if [ -f \"\$o\" ] && [ ! -L \"\$o\" ] && [ \"\$(wc -c < \"\$o\")\" -eq 65 ]; then")
            appendLine("    v=\$(cat \"\$o\"); case \"\$v\" in *[!0-9a-f]*) ;; *) if [ \"\${#v}\" -eq 64 ]; then r=\$v; fi ;; esac")
            appendLine("  fi")
            appendLine("  snapshot_line \"\${tag}R\t\$id\t\$r\"")
            appendLine("fi")
            appendLine("if [ -f \"\$d/module.prop\" ] && [ ! -L \"\$d/module.prop\" ]; then metadata_path=\"\$d/module.prop\"; fi")
            appendLine("}")
            val queueDirectory = "if [ -f \"\$d/module.prop\" ] && [ ! -L \"\$d/module.prop\" ]; then set -- \"\$@\" \"\$d\" \"\$d/module.prop\"; else set -- \"\$@\" \"\$d\"; fi"
            ids.distinct().forEach {
                appendLine("d=${q(path(it))}; if [ -d \"\$d\" ]; then $queueDirectory; else read_module \"\$d\" ''; fi")
            }
            if (discover) {
                appendLine("for d in ${q(root)}/*; do")
                appendLine("  [ -d \"\$d\" ] && [ ! -L \"\$d\" ] && [ -f \"\$d/module.prop\" ] || continue")
                appendLine("  id=\${d##*/}; case \"\$id\" in [a-zA-Z][a-zA-Z0-9._-]*) ;; *) continue ;; esac")
                appendLine("  case \"\$id\" in *[!a-zA-Z0-9._-]*) continue ;; esac")
                if (ids.isNotEmpty()) appendLine("  case \"\$id\" in ${ids.distinct().joinToString("|", transform = ::q)}) continue ;; esac")
                appendLine("  $queueDirectory")
                appendLine("done")
            }
            val pendingIds = ids.distinct()
            pendingIds.forEach {
                appendLine("d=${q("${root}_update/$it")}; if [ -d \"\$d\" ] && [ ! -L \"\$d\" ]; then $queueDirectory; fi")
            }
            if (discover) {
                appendLine("for d in ${q(root + "_update")}/*; do")
                appendLine("  [ -d \"\$d\" ] && [ ! -L \"\$d\" ] || continue")
                appendLine("  id=\${d##*/}; case \"\$id\" in [a-zA-Z][a-zA-Z0-9._-]*) ;; *) continue ;; esac")
                appendLine("  case \"\$id\" in *[!a-zA-Z0-9._-]*) continue ;; esac")
                if (pendingIds.isNotEmpty()) appendLine("  case \"\$id\" in ${pendingIds.joinToString("|", transform = ::q)}) continue ;; esac")
                appendLine("  $queueDirectory")
                appendLine("done")
            }
            if (!discover) {
                ids.distinct().forEach {
                    appendLine("t=${q("$transactions/$it")}")
                    appendLine("if [ -d \"\$t\" ] && [ ! -L \"\$t\" ]; then snapshot_line \"T\t$it\"; fi")
                }
            }
            if (discover) {
                appendLine("for t in ${q(transactions)}/*; do")
                appendLine("  [ -d \"\$t\" ] && [ ! -L \"\$t\" ] || continue")
                appendLine("  id=\${t##*/}; snapshot_line \"T\t\$id\"")
                appendLine("done")
            }
            appendLine("if [ \"\$#\" -gt 0 ]; then")
            appendLine("  inventory=\$(stat -c '%d:%i:%s:%n' \"\$@\")")
            appendLine("  printf '%s\\n' \"\$inventory\" | {")
            appendLine("    set --; metadata_path=")
            appendLine("    while IFS=: read -r dev ino size d; do")
            appendLine("      if [ \"\$d\" = \"\$metadata_path\" ]; then")
            appendLine("        if [ \"\$size\" -le 65536 ]; then set -- \"\$@\" \"\$d\"; snapshot_line \"\${tag}B\t\$id\t\$size\"; fi")
            appendLine("      else read_module \"\$d\" \"\$dev:\$ino\"; fi")
            appendLine("    done")
            appendLine("    if [ \"\$#\" -gt 0 ]; then printf 'H\\t'; od -An -v -tx1 \"\$@\" | tr -d ' \\n'; printf '\\n'; fi")
            appendLine("  }")
            appendLine("fi")
            appendLine("printf 'MAPLESU_SNAPSHOT_OK\\n'")
        }
        val output = run(script, readOnly = true)
        check(output.lineSequence().any { it == "MAPLESU_SNAPSHOT_OK" }) { "MODULE_SNAPSHOT_INCOMPLETE" }
        val result = ids.associateWith { Snapshot() }.toMutableMap()
        val metadata = mutableListOf<Triple<String, Boolean, Int>>()
        var metadataHex: String? = null
        output.lineSequence().forEach { line ->
            if (line.startsWith("H\t")) {
                check(metadataHex == null) { "MODULE_SNAPSHOT_INCOMPLETE" }
                metadataHex = line.removePrefix("H\t")
                return@forEach
            }
            val fields = line.split('\t', limit = 3)
            val id = fields.getOrNull(1) ?: return@forEach
            val value = fields.getOrNull(2).orEmpty()
            if (!id.matches(Regex("[a-zA-Z][a-zA-Z0-9._-]+"))) return@forEach
            val outer = result[id] ?: if (discover) Snapshot() else return@forEach
            val pending = fields[0].startsWith("P")
            val current = if (pending) outer.pending ?: Snapshot() else outer
            val updated = when (fields[0].removePrefix("P")) {
                "D" -> current.copy(directory = true)
                "F" -> current.copy(files = current.files + value)
                "S" -> current.copy(directories = current.directories + value)
                "Z" -> current.copy(zygisk = true)
                "R" -> current.copy(revision = value)
                "L" -> current.copy(legacyTarget = value)
                "M" -> current.copy(metadata = decodeHex(value))
                "B" -> {
                    val size = value.toIntOrNull()
                    check(size != null && size in 0..65536) { "MODULE_SNAPSHOT_INCOMPLETE" }
                    metadata += Triple(id, pending, size)
                    current
                }
                "I" -> current.copy(identity = value)
                "T" -> current.copy(pendingTransaction = true)
                else -> current
            }
            result[id] = if (pending) outer.copy(pending = updated) else updated
        }
        if (metadata.isNotEmpty()) {
            val hex = metadataHex
            check(hex != null && hex.length.toLong() == metadata.sumOf { it.third.toLong() * 2 }) {
                "MODULE_SNAPSHOT_INCOMPLETE"
            }
            var offset = 0
            metadata.forEach { (id, pending, size) ->
                val decoded = decodeHex(hex.substring(offset, offset + size * 2))
                check(decoded != null) { "MODULE_SNAPSHOT_INCOMPLETE" }
                val current = result.getValue(id)
                result[id] = if (pending) current.copy(pending = requireNotNull(current.pending).copy(metadata = decoded))
                    else current.copy(metadata = decoded)
                offset += size * 2
            }
        }
        return result
    }

    /** The catalog chooses commit/rollback for the existing publication journal. */
    @JvmOverloads
    fun recover(id: String, committedRevision: String, committedToken: String? = null) {
        require(committedToken == null || committedToken.matches(Regex("[0-9a-f]{32}")))
        run(recoveryScript(id, committedRevision, committedToken))
    }

    private fun recoveryScript(id: String, committedRevision: String?, committedToken: String? = null): String {
        path(id)
        return """
            set -eu
            d=${q(path(id))}
            p=${q("${root}_update/$id")}
            t=${q("$transactions/$id")}
            if [ ! -d "${'$'}t" ]; then exit 0; fi
            case "${'$'}(cat "${'$'}t/layout" 2>/dev/null || :)" in
                pending-v2|pending-merge-v2) ${pendingCommand("recover-pending", listOf(id))}; exit "${'$'}?" ;;
                '') case "${'$'}(cat "${'$'}t/origin" 2>/dev/null || :)" in
                    pending|merge) ${pendingCommand("recover-pending", listOf(id))}; exit "${'$'}?" ;;
                esac ;;
            esac
            next="${'$'}(cat "${'$'}t/next" 2>/dev/null || :)"
            committed=${committedRevision?.let(::q) ?: "\"\${next}\""}
            if [ -f "${'$'}t/layout" ]; then
                test "${'$'}(cat "${'$'}t/layout")" = modules-update-v1
                token_committed=1
                if [ -f "${'$'}t/catalog-token" ]; then
                    token="${'$'}(cat "${'$'}t/catalog-token")"
                    case "${'$'}token" in ''|*[!0-9a-f]*) exit 73 ;; esac
                    test "${'$'}{#token}" = 32
                    if [ ${if (committedRevision == null) "commit" else "recover"} != commit ] &&
                        [ "${'$'}token" != ${q(committedToken.orEmpty())} ]; then token_committed=0; fi
                fi
                candidate="${'$'}(cat "${'$'}t/candidate")"
                previous="${'$'}(cat "${'$'}t/live")"
                pending="${'$'}(cat "${'$'}t/pending")"
                current="${'$'}(tree_identity "${'$'}d")"
                update="${'$'}(tree_identity "${'$'}p")"
                backup="${'$'}(tree_identity "${'$'}t/previous")"
                old_update="${'$'}(tree_identity "${'$'}t/previous-update")"
                staged="${'$'}(tree_identity "${'$'}t/new")"
                test -z "${'$'}backup" || test "${'$'}backup" = "${'$'}previous"
                test -z "${'$'}old_update" || test "${'$'}old_update" = "${'$'}pending"
                test -z "${'$'}staged" || test "${'$'}staged" = "${'$'}candidate"
                if [ "${'$'}token_committed" = 1 ] && [ "${'$'}committed" = "${'$'}next" ] && [ "${'$'}current" = "${'$'}candidate" ] &&
                    [ "${'$'}(cat "${'$'}(owner_file "${'$'}d")" 2>/dev/null || :)" = "${'$'}next" ]; then
                    persist_publication
                    drop_owner "${'$'}t/previous"
                    drop_owner "${'$'}t/previous-update"
                    remove_tree "${'$'}t"
                    exit 0
                fi
                test ${if (committedRevision == null) "commit" else "recover"} != commit
                case "${'$'}current" in ''|"${'$'}previous"|"${'$'}candidate") ;; *) exit 73 ;; esac
                case "${'$'}update" in ''|"${'$'}pending"|"${'$'}candidate") ;; *) exit 73 ;; esac
                if [ -n "${'$'}previous" ] && [ "${'$'}current" != "${'$'}previous" ]; then test "${'$'}backup" = "${'$'}previous"; fi
                if [ -n "${'$'}pending" ] && [ "${'$'}update" != "${'$'}pending" ]; then test "${'$'}old_update" = "${'$'}pending"; fi
                test -z "${'$'}backup" || test "${'$'}current" != "${'$'}previous"
                test -z "${'$'}old_update" || test "${'$'}update" != "${'$'}pending"
                owner=${q(root)}/$OWNER/"${'$'}{candidate%:*}-${'$'}{candidate##*:}"
                test ! -L "${'$'}owner"
                if [ -e "${'$'}owner" ]; then test "${'$'}(cat "${'$'}owner")" = "${'$'}next"; fi
                state_sync --tree "${'$'}t"
                sync_parent "${'$'}t"
                if [ "${'$'}current" = "${'$'}candidate" ]; then remove_tree "${'$'}d"; fi
                if [ "${'$'}update" = "${'$'}candidate" ]; then remove_tree "${'$'}p"; fi
                if [ -n "${'$'}backup" ]; then move_tree "${'$'}t/previous" "${'$'}d"; fi
                if [ -n "${'$'}old_update" ]; then move_tree "${'$'}t/previous-update" "${'$'}p"; fi
                persist_publication
                rm -f -- "${'$'}owner"
                sync_parent "${'$'}owner"
                remove_tree "${'$'}t"
                exit 0
            fi
            current="${'$'}(cat "${'$'}(owner_file "${'$'}d")" 2>/dev/null || :)"
            if [ ${if (committedRevision == null) "commit" else "recover"} = commit ] || { [ "${'$'}current" = "${'$'}committed" ] && [ "${'$'}next" = "${'$'}committed" ]; }; then
                persist_publication
                drop_owner "${'$'}t/previous"
                remove_tree "${'$'}t"
            else
                state_sync --tree "${'$'}t"
                sync_parent "${'$'}t"
                if [ "${'$'}current" = "${'$'}next" ] && [ ! -d "${'$'}t/new" ] &&
                    { [ -e "${'$'}t/previous" ] || [ -L "${'$'}t/previous" ] || [ -f "${'$'}t/ready" ]; }; then
                    drop_owner "${'$'}d"
                    remove_tree "${'$'}d"
                fi
                if [ -e "${'$'}t/previous" ] || [ -L "${'$'}t/previous" ]; then move_tree "${'$'}t/previous" "${'$'}d"; fi
                persist_publication
                drop_owner "${'$'}t/new"
                remove_tree "${'$'}t"
            fi
        """.trimIndent()
    }

    /** Default KSU installs keep the complete candidate pending until the real boot event. */
    fun preparePendingInstall(id: String, source: String, revision: String, previousRevision: String?,
                              legacyPaths: List<String>, enabled: Boolean, previousMetadata: String?, catalogToken: String): String {
        path(id)
        require(revision.matches(Regex("[0-9a-f]{64}")))
        require(catalogToken.matches(Regex("[0-9a-f]{32}")))
        run(pendingCommand("prepare-pending", listOf(id, source, revision, previousRevision.orEmpty(),
            previousMetadata.orEmpty(), enabled.toString(), catalogToken) + legacyPaths))
        return "${root}_update/$id"
    }

    class PendingCommitRejected(cause: Throwable) : IllegalStateException(cause.message, cause)

    /** One atomic root ready marker commits; a lost reply is read back without replay. */
    fun commitPendingInstall(id: String, revision: String, catalogToken: String, metamodule: Boolean = false) {
        path(id)
        require(revision.matches(Regex("[0-9a-f]{64}")))
        require(catalogToken.matches(Regex("[0-9a-f]{32}")))
        val result = runCatching { run(pendingCommand("commit-pending", listOf(id, revision, catalogToken, metamodule.toString()))) }
        if (result.isFailure && !pendingCommitted(id, revision, catalogToken))
            throw PendingCommitRejected(requireNotNull(result.exceptionOrNull()))
    }

    fun pendingCommitted(id: String, revision: String, catalogToken: String): Boolean {
        path(id)
        require(revision.matches(Regex("[0-9a-f]{64}")))
        require(catalogToken.matches(Regex("[0-9a-f]{32}")))
        val command = pendingCommand("state-pending", listOf(id, revision, catalogToken))
        return run("if $command; then :; else c=\$?; [ \"\$c\" = 1 ] || exit \"\$c\"; fi", readOnly = true)
            .lineSequence().any { it == "MAPLESU_PENDING_COMMITTED" }
    }

    data class HotInstallResult(val requested: Boolean, val applied: Boolean, val status: String, val code: Int?)

    /** A lost hot reply is read back, never submitted a second time. */
    fun hotInstall(id: String, revision: String, catalogToken: String, metamodule: Boolean, safeMode: Boolean,
                   stdout: (String) -> Unit, stderr: (String) -> Unit): HotInstallResult {
        path(id)
        require(revision.matches(Regex("[0-9a-f]{64}")))
        require(catalogToken.matches(Regex("[0-9a-f]{32}")))
        val arguments = listOf(id, revision, catalogToken)
        val attempted = runCatching {
            run(pendingCommand("hot-pending", arguments + listOf(metamodule.toString(), safeMode.toString())),
                stdout = { if (!it.startsWith("MAPLESU_HOT_RESULT:")) stdout(it) }, stderr = stderr)
        }
        val output = attempted.getOrElse { original ->
            if (original is InterruptedException || Thread.currentThread().isInterrupted) throw original
            runCatching { run(pendingCommand("state-hot", arguments), readOnly = true) }
                .getOrElse { throw original }
        }
        val fields = output.lineSequence().lastOrNull { it.startsWith("MAPLESU_HOT_RESULT:") }
            ?.split(':') ?: error("MODULE_HOT_RESULT_UNKNOWN")
        check(fields.size == 5 && fields[1] in setOf("true", "false") && fields[2] in setOf("true", "false")) {
            "MODULE_HOT_RESULT_UNKNOWN"
        }
        val status = fields[3]
        check(status in setOf("none", "skipped", "applied", "started", "ok", "failed")) { "MODULE_HOT_RESULT_UNKNOWN" }
        val code = fields[4].takeUnless { it == "-" }?.toInt()
        check(code == null || code in 0..255) { "MODULE_HOT_RESULT_UNKNOWN" }
        return HotInstallResult(fields[1] == "true", fields[2] == "true", status, code)
    }

    private fun pendingCommand(command: String, arguments: List<String>): String {
        val bin = "${root.substringBeforeLast('/')}/maplesu/bin"
        return (listOf("$bin/busybox", "sh", "$bin/module-boot.sh", command) + arguments).joinToString(" ", transform = ::q)
    }

    /** Migration uses the same transaction without executing an installer. */
    @JvmOverloads
    fun publish(id: String, source: String, revision: String, previousRevision: String?,
                legacyPaths: List<String>, enabled: Boolean, previousMetadata: String? = null, catalogToken: String? = null) {
        prepareInstall(id, source, revision, previousRevision, legacyPaths, enabled, previousMetadata, catalogToken)
        activateInstall(id, revision)
    }

    /** Keep live and any older pending update intact until customize succeeds. */
    @JvmOverloads
    fun prepareInstall(id: String, source: String, revision: String, previousRevision: String?,
                       legacyPaths: List<String>, enabled: Boolean, previousMetadata: String? = null, catalogToken: String? = null): String {
        require(revision.matches(Regex("[0-9a-f]{64}")))
        require(catalogToken == null || catalogToken.matches(Regex("[0-9a-f]{32}")))
        val allowedLinks = legacyPaths.joinToString("|") { q(it) }.ifEmpty { "''" }
        run("""
            set -eu
            test "${'$'}(id -u)" = 0
            root=${q(root)}
            updates=${q(root + "_update")}
            d=${q(path(id))}
            p=${q("${root}_update/$id")}
            t=${q("$transactions/$id")}
            test ! -L "${'$'}root" && test ! -L "${'$'}updates" && test ! -L ${q(transactions)}
            mkdir -p "${'$'}root" "${'$'}updates" ${q(transactions)}
            state_sync "${'$'}root" "${'$'}updates" ${q(transactions)}
            sync_parent "${'$'}root"
            sync_parent ${q(transactions)}
            test ! -e "${'$'}t" && test ! -L "${'$'}t"
            if [ -L "${'$'}d" ]; then
                case "${'$'}(readlink "${'$'}d")" in $allowedLinks) ;; *) exit 73 ;; esac
            elif [ -e "${'$'}d" ]; then
                test -d "${'$'}d"
                test ! -L "${'$'}(owner_file "${'$'}d")"
                if [ -n ${q(previousRevision.orEmpty())} ]; then
                    test "${'$'}(cat "${'$'}(owner_file "${'$'}d")" 2>/dev/null || :)" = ${q(previousRevision.orEmpty())}
                else
                    test ! -e "${'$'}(owner_file "${'$'}d")"
                    test -n ${q(previousMetadata.orEmpty())}
                    test ! -L "${'$'}d/module.prop"
                    test "${'$'}(sha256sum "${'$'}d/module.prop" | cut -d' ' -f1)" = ${q(previousMetadata.orEmpty())}
                fi
            fi
            test ! -L "${'$'}p"
            if [ -e "${'$'}p" ]; then test -d "${'$'}p"; fi
            previous="${'$'}(tree_identity "${'$'}d")"
            pending="${'$'}(tree_identity "${'$'}p")"
            mkdir "${'$'}t"
            state_sync "${'$'}t"
            sync_parent "${'$'}t"
            put "${'$'}t/next" ${q(revision)}
            put "${'$'}t/live" "${'$'}previous"
            cat "${'$'}(owner_file "${'$'}d")" > "${'$'}t/live-owner.tmp" 2>/dev/null || :
            publish_file "${'$'}t/live-owner.tmp" "${'$'}t/live-owner"
            put "${'$'}t/pending" "${'$'}pending"
            mkdir "${'$'}t/new"
            candidate="${'$'}(tree_identity "${'$'}t/new")"
            put "${'$'}t/candidate" "${'$'}candidate"
            ${catalogToken?.let { "put \"\${t}/catalog-token\" ${q(it)}" }.orEmpty()}
            put "${'$'}t/layout" modules-update-v1
            cp -a ${q("$source/.")} "${'$'}t/new/"
            rm -f "${'$'}t/new/$OWNER"
            mkdir -p "${'$'}root/$OWNER"
            chmod 0700 "${'$'}root/$OWNER"
            state_sync "${'$'}root/$OWNER" "${'$'}root"
            o="${'$'}(owner_key "${'$'}t/new")"
            printf '%s\n' ${q(revision)} > "${'$'}o.tmp"
            chown 0:0 "${'$'}t/new" "${'$'}o.tmp"
            chmod 0755 "${'$'}t/new"
            chmod 0600 "${'$'}o.tmp"
            publish_file "${'$'}o.tmp" "${'$'}o"
            test "${'$'}(tree_identity "${'$'}p")" = "${'$'}pending"
            if [ -n "${'$'}pending" ]; then move_tree "${'$'}p" "${'$'}t/previous-update"; fi
            move_tree "${'$'}t/new" "${'$'}p"
            if [ -e "${'$'}d" ] || [ -L "${'$'}d" ]; then
                if [ -e "${'$'}d/disable" ]; then : > "${'$'}p/disable"; else rm -f "${'$'}p/disable"; fi
                if [ -e "${'$'}d/remove" ]; then : > "${'$'}p/remove"; else rm -f "${'$'}p/remove"; fi
            else
                ${if (enabled) "rm -f \"\${p}/disable\"" else ": > \"\${p}/disable\""}
            fi
            test -f "${'$'}p/module.prop" && test ! -L "${'$'}p/module.prop"
        """.trimIndent())
        return "${root}_update/$id"
    }

    /** Publish only the exact candidate and live inodes recorded by prepareInstall. */
    fun activateInstall(id: String, revision: String) {
        require(revision.matches(Regex("[0-9a-f]{64}")))
        run("""
            set -eu
            d=${q(path(id))}
            p=${q("${root}_update/$id")}
            t=${q("$transactions/$id")}
            test "${'$'}(cat "${'$'}t/layout")" = modules-update-v1
            test "${'$'}(cat "${'$'}t/next")" = ${q(revision)}
            test ! -L "${'$'}p" && test -d "${'$'}p"
            test "${'$'}(tree_identity "${'$'}p")" = "${'$'}(cat "${'$'}t/candidate")"
            test ! -L "${'$'}(owner_file "${'$'}p")"
            test "${'$'}(cat "${'$'}(owner_file "${'$'}p")")" = ${q(revision)}
            test "${'$'}(tree_identity "${'$'}d")" = "${'$'}(cat "${'$'}t/live")"
            test "${'$'}(cat "${'$'}(owner_file "${'$'}d")" 2>/dev/null || :)" = "${'$'}(cat "${'$'}t/live-owner")"
            if [ -e "${'$'}d" ] || [ -L "${'$'}d" ]; then
                if [ -e "${'$'}d/disable" ]; then : > "${'$'}p/disable"; else rm -f "${'$'}p/disable"; fi
                if [ -e "${'$'}d/remove" ]; then : > "${'$'}p/remove"; else rm -f "${'$'}p/remove"; fi
                persist_tree "${'$'}p"
                move_tree "${'$'}d" "${'$'}t/previous"
            else
                persist_tree "${'$'}p"
            fi
            move_tree "${'$'}p" "${'$'}d"
            test "${'$'}(tree_identity "${'$'}d")" = "${'$'}(cat "${'$'}t/candidate")"
        """.trimIndent())
    }

    fun seal(id: String, revision: String) {
        require(revision.matches(Regex("[0-9a-f]{64}")))
        val directory = q(path(id))
        run("set -eu\ntest -d $directory\ntest ! -L $directory\n" +
            "mkdir -p ${q("$root/$OWNER")}\nchmod 0700 ${q("$root/$OWNER")}\n" +
            "state_sync ${q("$root/$OWNER")} ${q(root)}\n" +
            "o=\$(owner_key $directory)\nprintf '%s\\n' ${q(revision)} > \"\$o.tmp\"\n" +
            "chown 0:0 \"\$o.tmp\"\nchmod 0600 \"\$o.tmp\"\npublish_file \"\$o.tmp\" \"\$o\"\n" +
            "rm -f $directory/$OWNER\nstate_sync $directory")
    }

    fun commit(id: String) { run(recoveryScript(id, null)) }

    @JvmOverloads
    fun marker(id: String, name: String, present: Boolean, identity: String? = null) {
        require(name in setOf("disable", "remove"))
        require(identity == null || identity.matches(Regex("[0-9]+:[0-9]+")))
        val directory = q(path(id))
        val file = q("${path(id)}/$name")
        val working = "${root.substringBeforeLast('/')}/maplesu"
        val state = "$working/module-boot/events"
        val busybox = q("$working/bin/busybox")
        // Boot merge copies markers before renaming the live tree. Hold its lock
        // across the inode check and mutation so a successful write stays live.
        run("set -eu\nfor parent in ${q(root)} ${q(working)} ${q("$working/module-boot")} ${q(state)}; do\n" +
            "test ! -L \"\$parent\" || exit 73\ndone\ntest -x $busybox || exit 69\n" +
            "mkdir -p ${q(state)}\nchmod 0700 ${q("$working/module-boot")} ${q(state)}\n" +
            "test ! -L ${q("$state/lock")} || exit 73\n(\n$busybox flock 9 || exit 73\n" +
            "test -d $directory\ntest ! -L $directory\ntest ! -L $file\ncd $directory\n" +
            (identity?.let { "test \"\$(stat -c '%d:%i' .)\" = ${q(it)}\n" } ?: "") +
            (if (present) ": > ${q(name)}\ntest -f ${q(name)}" else "rm -f -- ${q(name)}\ntest ! -e ${q(name)}") +
            "\n) 9> ${q("$state/lock")}")
    }

    @JvmOverloads
    fun remove(id: String, revision: String, metadataSha256: String? = null, identity: String? = null) {
        require(identity == null || identity.matches(Regex("[0-9]+:[0-9]+")))
        val directory = q(path(id))
        val pending = q("${root}_update/$id")
        val configRoot = q("${root.substringBeforeLast('/')}/ksu")
        val config = q("${root.substringBeforeLast('/')}/ksu/module_configs/$id")
        run("set -eu\nt=${q("$transactions/$id")}\n" +
            "case \"\$(cat \"\$t/layout\" 2>/dev/null || :)\" in pending-v2|pending-merge-v2) " +
            pendingCommand("recover-pending", listOf(id)) + ";; esac\n" +
            "test ! -L $directory\ntest ! -L ${q(root)}\ntest ! -L ${q(root + "_update")}\n" +
            "test ! -L $configRoot\ntest ! -L $configRoot/module_configs\n" +
            (identity?.let { "test \"\$(stat -c '%d:%i' $directory)\" = ${q(it)}\n" } ?: "") +
            (if (revision.isNotEmpty()) "o=\$(owner_file $directory)\ntest ! -L \"\$o\"\n" +
                "test \"\$(cat \"\$o\")\" = ${q(revision)}\n"
            else "test ! -e \"\$(owner_file $directory)\"\ntest ! -L $directory/module.prop\n" +
                "test \"\$(sha256sum $directory/module.prop | cut -d' ' -f1)\" = ${q(requireNotNull(metadataSha256))}\n") +
            // KSU updates use a second tree; leaving it can reinstall this id after reboot.
            "owner=\$(owner_key $directory)\ndrop_owner $pending\nremove_tree $pending\nremove_tree $config\n" +
            "test ! -e $pending\ntest ! -L $pending\ntest ! -e $config\ntest ! -L $config\n" +
            "remove_tree $directory\ntest ! -e $directory\ntest ! -L $directory\n" +
            "rm -f -- \"\$owner\"\nsync_parent \"\$owner\"")
    }

    fun read(id: String, name: String): String {
        require(name == "system.prop")
        return run("cat ${q("${path(id)}/$name")}", readOnly = true)
    }

    /** A real SDK event owns this boot; a page must never replay missed early stages. */
    fun sdkOwnsBoot(boot: String): Boolean {
        require(boot.matches(Regex("[0-9a-fA-F-]{36}")))
        val state = "${root.substringBeforeLast('/')}/maplesu/module-boot/events"
        val output = run("""
            for stage in post-fs-data post-mount service boot-completed; do
                file=${q(state)}/"${'$'}stage"
                test ! -L "${'$'}file" || exit 73
                if [ -f "${'$'}file" ]; then
                    saved_boot=; read -r saved_boot ignored < "${'$'}file" || :
                    if [ "${'$'}saved_boot" = ${q(boot)} ]; then printf 'SDK_BOOT_OWNER\n'; break; fi
                fi
            done
        """.trimIndent(), readOnly = true)
        return output.lineSequence().any { it == "SDK_BOOT_OWNER" }
    }

    private fun run(script: String, readOnly: Boolean = false, stdout: (String) -> Unit = {},
                    stderr: (String) -> Unit = {}): String {
        // Ownership follows the directory inode across publication/rollback, while
        // module contents remain exactly what their own installer produced.
        val owners = q("$root/$OWNER")
        val syncTool = q("${root.substringBeforeLast('/')}/maplesu/bin/maplesu-tools")
        val changedPrefix = "MAPLESU_TREE_CHANGED:${UUID.randomUUID()}:"
        // As in the pinned KSU mutate paths, an auxiliary next-boot refresh
        // reports its own error and never reverses an already committed module
        // operation or causes the original operation to be submitted twice.
        val refresh = if (readOnly) "" else """
            refresh_module_initrc() {
                module_code=${'$'}?; trap - 0; set +e
                $syncTool module-initrc
                initrc_code=${'$'}?
                if [ "${'$'}initrc_code" -ne 0 ]; then
                    printf "MODULE_INITRC_REFRESH_FAILED:%s\n" "${'$'}initrc_code" >&2
                fi
                exit "${'$'}module_code"
            }
            trap refresh_module_initrc 0
        """.trimIndent() + "\n"
        val command = """
            export MAPLESU_TREE_CHANGED_PREFIX=${q(changedPrefix)}
            live_changed() {
                local id
                [ "${'$'}{1%/*}" = ${q(root)} ] || return 0
                id="${'$'}{1##*/}"
                case "${'$'}id" in ''|*/*|*[!a-zA-Z0-9._-]*) return 0 ;; esac
                printf '%s%s\n' ${q(changedPrefix)} "${'$'}id"
            }
            state_sync() { $syncTool module-sync "${'$'}@"; }
            sync_parent() {
                local parent="${'$'}{1%/*}"
                while [ ! -e "${'$'}parent" ] && [ ! -L "${'$'}parent" ]; do
                    [ -n "${'$'}parent" ] && [ "${'$'}parent" != / ] || return 73
                    parent="${'$'}{parent%/*}"; [ -n "${'$'}parent" ] || parent=/
                done
                state_sync "${'$'}parent"
            }
            publish_file() {
                state_sync "${'$'}1" || return
                mv -f -- "${'$'}1" "${'$'}2" || return
                sync_parent "${'$'}1" || return
                if [ "${'$'}{1%/*}" != "${'$'}{2%/*}" ]; then sync_parent "${'$'}2"; fi
            }
            put() { printf '%s\n' "${'$'}2" > "${'$'}1.tmp" && publish_file "${'$'}1.tmp" "${'$'}1"; }
            remove_tree() {
                local existed=0
                if [ -e "${'$'}1" ] || [ -L "${'$'}1" ]; then existed=1; fi
                rm -rf -- "${'$'}1" || return
                if [ "${'$'}existed" = 1 ]; then live_changed "${'$'}1"; fi
                sync_parent "${'$'}1"
            }
            tree_identity() {
                if [ -e "${'$'}1" ] || [ -L "${'$'}1" ]; then stat -c '%d:%i' "${'$'}1"; fi
            }
            move_tree() {
                test ! -e "${'$'}2" && test ! -L "${'$'}2" || return 73
                mv -Tn -- "${'$'}1" "${'$'}2" || return
                test ! -e "${'$'}1" && test ! -L "${'$'}1" || return 73
                live_changed "${'$'}1"
                live_changed "${'$'}2"
                sync_parent "${'$'}1" || return
                if [ "${'$'}{1%/*}" != "${'$'}{2%/*}" ]; then sync_parent "${'$'}2"; fi
            }
            owner_key() { i="${'$'}(stat -c '%d-%i' "${'$'}1")" || return 1; printf '%s/%s\n' $owners "${'$'}i"; }
            owner_file() {
                f="${'$'}(owner_key "${'$'}1" 2>/dev/null)" || f="${'$'}1/$OWNER"
                if [ ! -e "${'$'}f" ] && [ ! -L "${'$'}f" ]; then f="${'$'}1/$OWNER"; fi
                printf '%s\n' "${'$'}f"
            }
            drop_owner() {
                if [ -d "${'$'}1" ] && [ ! -L "${'$'}1" ]; then
                    local owner
                    owner="${'$'}(owner_key "${'$'}1")" || return
                    rm -f -- "${'$'}owner" && sync_parent "${'$'}owner"
                fi
            }
            persist_tree() {
                if [ -d "${'$'}1" ] && [ ! -L "${'$'}1" ]; then
                    state_sync --tree "${'$'}1" || return
                    local owner
                    owner="${'$'}(owner_file "${'$'}1")" || return
                    if [ -f "${'$'}owner" ] && [ ! -L "${'$'}owner" ]; then
                        state_sync "${'$'}owner" || return
                        sync_parent "${'$'}owner" || return
                    fi
                fi
                sync_parent "${'$'}1"
            }
            persist_publication() { persist_tree "${'$'}d" && persist_tree "${'$'}p"; }
        """.trimIndent() + "\n" + refresh + script
        val result = if (readOnly) runner.readSnapshot(command) else runner.run(command)
        val output = result.out.lineSequence().filterNot { it.startsWith(changedPrefix) }.joinToString("\n")
        // A rename may have happened even when its later fsync or cleanup failed.
        // Retire only pages whose live tree changed, preserving the original failure.
        if (!readOnly) result.out.lineSequence().filter { it.startsWith(changedPrefix) }
            .map { it.removePrefix(changedPrefix) }.filter { it.matches(Regex("[a-zA-Z][a-zA-Z0-9._-]+")) }
            .toSet().forEach(ModuleWebUiSessions::committed)
        output.lineSequence().filter { it.isNotEmpty() }.forEach(stdout)
        result.err.lineSequence().filter { it.isNotEmpty() }.forEach(stderr)
        check(result.isSuccess) { "MODULE_TREE_ROOT_FAILED exit=${result.code}: ${result.err.ifBlank { output }.take(512)}" }
        return output
    }

    companion object {
        const val OWNER = ".maplesu-ultra"
        private fun q(value: String) = "'" + value.replace("'", "'\\''") + "'"
        private fun decodeHex(value: String): String? {
            if (value.length > 131072 || value.length % 2 != 0) return null
            val bytes = ByteArray(value.length / 2)
            for (index in bytes.indices) {
                val high = hexDigit(value[index * 2])
                val low = hexDigit(value[index * 2 + 1])
                if (high < 0 || low < 0) return null
                bytes[index] = ((high shl 4) or low).toByte()
            }
            return bytes.toString(Charsets.UTF_8)
        }
        private fun hexDigit(value: Char): Int = when (value) {
            in '0'..'9' -> value - '0'
            in 'a'..'f' -> value - 'a' + 10
            else -> -1
        }
    }
}
