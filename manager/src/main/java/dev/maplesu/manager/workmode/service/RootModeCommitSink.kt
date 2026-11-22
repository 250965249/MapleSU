package dev.maplesu.manager.workmode.service

import dev.maplesu.manager.runtime.RootExecResult
import dev.maplesu.manager.workmode.Hashes
import dev.maplesu.manager.workmode.WorkMode
import dev.maplesu.manager.workmode.control.ControlJsonCodec
import dev.maplesu.manager.workmode.control.ControlPaths
import dev.maplesu.manager.workmode.control.schema.ModesFile
import dev.maplesu.manager.workmode.control.schema.canonicalized
import dev.maplesu.manager.workmode.control.schema.validateSemantics
import dev.maplesu.manager.workmode.superuser.LiteImplantScripts
import dev.maplesu.manager.workmode.switch.ModeCommitSink
import java.util.Base64
import java.util.UUID

/** Publishes verified mode facts through the pinned root channel, while its device lease is held. */
internal class RootModeCommitSink(
    private val execute: (String) -> RootExecResult,
    private val clock: () -> Long = System::currentTimeMillis,
    private val root: String = ControlPaths.CONTROL,
    private val initial: (() -> ModesFile)? = null,
) : ModeCommitSink {
    override fun commit(mode: WorkMode, bootId: String, bootSha256: String, initBootSha256: String) {
        require(UUID.fromString(bootId).toString() == bootId)
        val target = "$root/modes.json"
        val observed = execute(buildString {
            appendLine("set -eu")
            appendLine("if [ ! -e ${q(target)} ] && [ ! -L ${q(target)} ] && [ ! -e ${q("$target.sha256")} ]; then echo MODES_MISSING; exit 0; fi")
            appendLine("if [ -f ${q("$target.sha256")} ]; then")
            appendLine("  [ \"\$(/system/bin/sha256sum ${q(target)} | /system/bin/cut -d' ' -f1)\" = \"\$(/system/bin/cat ${q("$target.sha256")})\" ] || exit 2")
            appendLine("fi")
            appendLine("/system/bin/base64 ${q(target)}")
        })
        check(observed.ok) { "SWITCH_MODE_PUBLICATION_FAILED" }
        val missing = observed.output.trim() == "MODES_MISSING"
        val bytes = if (missing) null else Base64.getMimeDecoder().decode(observed.output)
        check(bytes == null || bytes.size in 1..262144) { "CONTROL_MODES_CORRUPT" }
        val before = bytes?.let(Hashes::sha256)
        val current = if (missing) initial?.invoke() ?: error("CONTROL_MODES_MISSING")
            else ControlJsonCodec.decodeOrNull(requireNotNull(bytes).toString(Charsets.UTF_8), ModesFile.serializer())
                ?: error("CONTROL_MODES_CORRUPT")
        check(current.validateSemantics().isEmpty()) { "CONTROL_MODES_CORRUPT" }
        val next = current.copy(
            revision = current.revision + 1,
            updatedAt = clock(),
            bootId = bootId,
            current = mode.suffix,
            last = if (current.current != mode.suffix) current.current.takeIf { WorkMode.fromSuffix(it) != null } else current.last,
            pending = null,
            boot = current.boot.copy(
                bootSha256 = bootSha256.ifEmpty { current.boot.bootSha256 },
                initBootSha256 = initBootSha256.ifEmpty { current.boot.initBootSha256 },
                activeMode = mode.suffix,
                verifiedBootId = bootId,
            ),
        ).canonicalized()
        check(next.validateSemantics().isEmpty()) { "CONTROL_MODES_CORRUPT" }
        val json = ControlJsonCodec.encode(next, ModesFile.serializer())
        val digest = Hashes.sha256(json.toByteArray(Charsets.UTF_8))
        val temporary = "$target.${UUID.randomUUID()}.new"
        val result = execute(buildString {
            appendLine("set -eu")
            appendLine("trap ${q("/system/bin/rm -f ${q(temporary)} ${q("$temporary.sha256")}")} EXIT")
            if (before == null) {
                appendLine("[ ! -e ${q(target)} ] && [ ! -L ${q(target)} ] && [ ! -e ${q("$target.sha256")} ] || exit 2")
            } else {
                appendLine("[ \"\$(/system/bin/sha256sum ${q(target)} | /system/bin/cut -d' ' -f1)\" = ${q(before)} ] || exit 2")
            }
            // Carry bytes through the authenticated root channel; SELinux need not grant
            // the root shell access to the manager's app-private staging directory.
            appendLine("/system/bin/printf '%s' ${q(Base64.getEncoder().encodeToString(json.toByteArray(Charsets.UTF_8)))} | /system/bin/base64 -d > ${q(temporary)}")
            appendLine("/system/bin/chown 0:0 ${q(temporary)}; /system/bin/chmod 0600 ${q(temporary)}")
            appendLine("[ \"\$(/system/bin/sha256sum ${q(temporary)} | /system/bin/cut -d' ' -f1)\" = ${q(digest)} ] || exit 3")
            appendLine("/system/bin/mv ${q(temporary)} ${q(target)}")
            appendLine("/system/bin/printf '%s' ${q(digest)} > ${q("$temporary.sha256")}")
            appendLine("/system/bin/chown 0:0 ${q("$temporary.sha256")}; /system/bin/chmod 0600 ${q("$temporary.sha256")}")
            appendLine("/system/bin/mv ${q("$temporary.sha256")} ${q("$target.sha256")}")
            appendLine("/system/bin/sync")
            appendLine("[ \"\$(/system/bin/sha256sum ${q(target)} | /system/bin/cut -d' ' -f1)\" = \"\$(/system/bin/cat ${q("$target.sha256")})\" ]")
        })
        check(result.ok) { "SWITCH_MODE_PUBLICATION_FAILED" }
    }

    private fun q(value: String) = LiteImplantScripts.quote(value)
}
