package dev.maplesu.manager.workmode.detect.probes

import dev.maplesu.manager.workmode.control.ControlPaths
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.util.Base64
import java.util.UUID

/** One UID-verified, read-only SDK snapshot per detection; no process or cross-session cache. */
internal class UltraRootShellSession private constructor(
    running: () -> Boolean,
    samples: Map<String, RootCommandResult>,
) : RootShellSession {
    private val results = samples.toMutableMap()
    private var closed = false
    override val runner = RootShellRunner { command ->
        check(!closed && running()) { "ULTRA_EVIDENCE_NOT_RUNNING" }
        results[command] ?: error("ULTRA_EVIDENCE_NOT_SAMPLED")
    }

    override fun close() {
        closed = true
        results.clear()
    }

    companion object {
        fun open(
            running: () -> Boolean,
            sdk: RootShellRunner,
            marker: () -> String = { "MAPLESU_ULTRA_EVIDENCE_${UUID.randomUUID().toString().replace("-", "")}" },
        ): RootShellSession? {
            if (!running()) return null
            return runCatching {
                val tag = marker()
                require(tag.matches(Regex("[A-Za-z0-9_]+")))
                val result = sdk.run(snapshotScript(tag))
                check(result.ok && running()) { "ULTRA_EVIDENCE_SDK_FAILED" }
                UltraRootShellSession(running, parseSnapshot(tag, result.out))
            }.getOrNull()
        }

        private data class Read(
            val command: String,
            val dependsOn: Int? = null,
            val requireSuccess: Boolean = true,
            val unlessNonblank: Int? = null,
        ) {
            fun enabled(samples: List<RootCommandResult?>): Boolean =
                (dependsOn == null || samples[dependsOn]?.ok == requireSuccess) &&
                    (unlessNonblank == null || samples[unlessNonblank]?.let {
                        it.ok && it.out.any(String::isNotBlank)
                    } != true)
        }

        // Same order and short-circuits as DefaultModeDetector.readRootFacts / ShellRootEvidenceSession.
        private val reads = buildList {
            add(Read("/system/bin/id -u"))
            listOf("modes.json", "installed.json", "switch.json").forEach {
                add(Read("cat ${ShellRootEvidenceSession.quote("${ControlPaths.CONTROL}/$it")}"))
            }
            fun directory(path: String, unlessNonblank: Int? = null): Int {
                val quoted = ShellRootEvidenceSession.quote(path)
                val directory = size
                add(Read("test -d $quoted", unlessNonblank = unlessNonblank))
                val link = size
                add(Read("test -L $quoted", dependsOn = directory))
                val entries = size
                add(Read("ls -A $quoted", dependsOn = link, requireSuccess = false))
                return entries
            }
            directory("/data/adb/maplesu/authorization")
            directory("/data/adb/maplesu/installer")
            directory("/data/adb/maplesu/published-directory")
            directory("/data/adb/ksu")
            add(Read("test -x '/data/adb/ksud'"))
            add(Read("test -e '/data/adb/ksu/.kmi-writable'"))
            val magisk = directory("/data/adb/magisk")
            directory("/data/adb/ksu/.allowlist", unlessNonblank = magisk)
            add(Read("/system/bin/getenforce"))
        }

        private fun snapshotScript(tag: String): String = buildString {
            appendLine("__ms_read() {")
            appendLine("  __ms_id=\"\$1\"; shift")
            // Encode before shell substitution: a damaged control file's NUL must not disappear.
            appendLine("  __ms_encoded=\"\$({ \"\$@\" 2>/dev/null; __ms_status=\$?; printf '$tag:RC:%s' \"\$__ms_status\"; } | base64)\"; __ms_encoding=\$?")
            appendLine("  printf '$tag:ITEM:%s:%s\\n%s\\n$tag:ITEM_END:%s\\n' \"\$__ms_id\" \"\$__ms_encoding\" \"\$__ms_encoded\" \"\$__ms_id\"")
            appendLine("  [ \"\$__ms_encoding\" -eq 0 ]")
            appendLine("}")
            // Only UID/test/directory short-circuits need shell text; never decode a control file here.
            appendLine("__ms_unpack() {")
            appendLine("  __ms_capture=\"\$(printf '%s' \"\$__ms_encoded\" | base64 -d)\" || return 1")
            appendLine("  __ms_rc=\"\${__ms_capture##*$tag:RC:}\"")
            appendLine("  __ms_text=\"\${__ms_capture%$tag:RC:*}\"")
            appendLine("}")
            // Match Kotlin isNotBlank, including Unicode whitespace, without locale-sensitive tr.
            appendLine("__ms_has_nonblank() {")
            appendLine("  while [ -n \"\$1\" ]; do")
            appendLine("    case \"\$1\" in")
            ('\u0009'..'\u3000').filter(Char::isWhitespace).forEach { whitespace ->
                val quoted = ShellRootEvidenceSession.quote(whitespace.toString())
                appendLine("      $quoted*) set -- \"\${1#$quoted}\" ;;")
            }
            appendLine("      *) return 0 ;;")
            appendLine("    esac")
            appendLine("  done")
            appendLine("  return 1")
            appendLine("}")
            appendLine("printf '$tag:BEGIN:2\\n'")
            reads.forEachIndexed { index, read ->
                val dependency = read.dependsOn
                val unless = read.unlessNonblank
                val condition = when {
                    dependency != null && read.requireSuccess ->
                        "[ \"\${__ms_rc_$dependency:-SKIP}\" = 0 ]"
                    dependency != null ->
                        "[ \"\${__ms_rc_$dependency:-SKIP}\" != SKIP ] && [ \"\$__ms_rc_$dependency\" -ne 0 ]"
                    unless != null -> "[ \"\${__ms_any_$unless:-0}\" != 1 ]"
                    else -> null
                }
                if (condition != null) appendLine("if $condition; then")
                appendLine("__ms_read $index ${read.command} || exit 1")
                if (index == 0 || reads.any { it.dependsOn == index || it.unlessNonblank == index }) {
                    appendLine("__ms_unpack || exit 1")
                    appendLine("__ms_rc_$index=\"\$__ms_rc\"")
                }
                if (index == 0) {
                    appendLine("[ \"\$__ms_rc\" -eq 0 ] || exit 1")
                    appendLine("case \"\$__ms_text\" in '0'|'0\n') ;; *) exit 1 ;; esac")
                }
                if (reads.any { it.unlessNonblank == index }) {
                    appendLine("__ms_any_$index=0")
                    appendLine("if [ \"\$__ms_rc\" -eq 0 ] && __ms_has_nonblank \"\$__ms_text\"; then __ms_any_$index=1; fi")
                }
                if (condition != null) {
                    appendLine("else")
                    appendLine("printf '$tag:SKIP:$index\\n'")
                    appendLine("fi")
                }
            }
            appendLine("printf '$tag:END\\n'")
        }

        private fun parseSnapshot(tag: String, output: List<String>): Map<String, RootCommandResult> {
            val lines = output.dropLastWhile(String::isEmpty)
            check(lines.firstOrNull() == "$tag:BEGIN:2")
            val samples = mutableListOf<RootCommandResult?>()
            var cursor = 1
            reads.forEachIndexed { index, read ->
                if (!read.enabled(samples)) {
                    check(lines[cursor++] == "$tag:SKIP:$index")
                    samples += null
                } else {
                    val prefix = "$tag:ITEM:$index:"
                    check(lines[cursor].startsWith(prefix))
                    val header = lines[cursor++].removePrefix(prefix)
                    check(header == "0")
                    val encoded = StringBuilder()
                    do {
                        val chunk = lines[cursor++]
                        check(chunk.matches(Regex("[A-Za-z0-9+/]*={0,2}")))
                        if (chunk.isEmpty()) check(lines[cursor] == "$tag:ITEM_END:$index")
                        encoded.append(chunk)
                    } while (lines[cursor] != "$tag:ITEM_END:$index")
                    cursor++
                    val bytes = Base64.getDecoder().decode(encoded.toString())
                    check(Base64.getEncoder().encodeToString(bytes) == encoded.toString())
                    val framed = Charsets.UTF_8.newDecoder()
                        .onMalformedInput(CodingErrorAction.REPORT)
                        .onUnmappableCharacter(CodingErrorAction.REPORT)
                        .decode(ByteBuffer.wrap(bytes)).toString()
                    check('\u0000' !in framed)
                    val suffix = "$tag:RC:"
                    val separator = framed.lastIndexOf(suffix)
                    check(separator >= 0)
                    val status = framed.substring(separator + suffix.length)
                    check(status.matches(Regex("[0-9]{1,3}")))
                    val exit = status.toInt()
                    check(exit in 0..255)
                    val textLines = framed.substring(0, separator).lines().toMutableList()
                    if (textLines.lastOrNull() == "") textLines.removeAt(textLines.lastIndex)
                    val sample = RootCommandResult(exit == 0, textLines)
                    if (index == 0) check(sample.ok && sample.out.singleOrNull()?.trim() == "0")
                    samples += sample
                }
            }
            check(lines.getOrNull(cursor) == "$tag:END" && cursor == lines.lastIndex)
            return reads.mapIndexedNotNull { index, read -> samples[index]?.let { read.command to it } }.toMap()
        }
    }
}
