package com.ghostlock.app.data

/**
 * MapleSU replacement for the upstream `HoconSupport` (which depends on
 * `com.typesafe:config`). The vendored profile-core has to run inside the App
 * with no extra dependency, so this file implements the subset of HOCON the
 * pinned Ghostlock profiles actually use:
 *
 *  - `key = value` and `key: value`, quoted or bare keys
 *  - nested objects: `key { ... }` and `key = { ... }`
 *  - arrays: `[ a, b ]` (used by `index.conf`)
 *  - quoted strings with `\"`/`\\`/`\n` escapes, bare strings, integers,
 *    `true`/`false`, `null`
 *  - `#` and `//` comments outside quoted strings, commas as separators
 *
 * It deliberately does **not** implement `${}` substitution or `include`
 * directives: the caller expands `include` first (with byte identity and digest
 * checks) and a profile that still needs substitution is rejected instead of
 * being silently mis-resolved.
 */
object HoconSupport {
    fun parseValue(text: String): Any? {
        val trimmed = text.trimStart()
        val isArray = trimmed.startsWith("[")
        return Parser(if (isArray) "value = $text" else text).parseDocument()
            .let { if (isArray) (it as? Map<*, *>)?.get("value") else it }
    }

    /** Upstream-compatible name; used by the exporter CLI only. */
    fun render(value: Any?): String = renderValue(value, 0)

    private fun renderValue(value: Any?, depth: Int): String = when (value) {
        null -> "null"
        is String -> "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\""
        is Map<*, *> -> value.entries.joinToString(", ", "{", "}") { (key, child) ->
            key.toString() + " = " + renderValue(child, depth + 1)
        }
        is List<*> -> value.joinToString(", ", "[", "]") { renderValue(it, depth + 1) }
        else -> value.toString()
    }

    private class Parser(private val text: String) {
        private var at = 0

        fun parseDocument(): Any? {
            skipSpaceAndComments()
            if (at >= text.length) fail("empty document")
            // A HOCON document is an object body without the surrounding braces,
            // unless it is a single array (wrapped by the caller as `value = [...]`).
            val value = if (text[at] == '{' || text[at] == '[') parseValue()
                        else parseObjectBody(terminator = null)
            skipSpaceAndComments()
            if (at < text.length) fail("trailing input")
            return value
        }

        private fun fail(message: String): Nothing =
            throw IllegalArgumentException("HOCON parse error at " + at + ": " + message)

        private fun skipSpaceAndComments() {
            while (at < text.length) {
                val ch = text[at]
                when {
                    ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n' || ch == ',' -> at++
                    ch == '#' -> skipLine()
                    ch == '/' && at + 1 < text.length && text[at + 1] == '/' -> skipLine()
                    else -> return
                }
            }
        }

        private fun skipLine() {
            while (at < text.length && text[at] != '\n') at++
        }

        private fun parseValue(): Any? {
            skipSpaceAndComments()
            if (at >= text.length) fail("value expected")
            return when (text[at]) {
                '{' -> parseObject()
                '[' -> parseArray()
                '"' -> parseQuoted()
                else -> parseBare()
            }
        }

        private fun parseObject(): Map<String, Any?> {
            expect('{')
            return parseObjectBody(terminator = '}')
        }

        private fun parseObjectBody(terminator: Char?): Map<String, Any?> {
            val result = LinkedHashMap<String, Any?>()
            while (true) {
                skipSpaceAndComments()
                if (at >= text.length) {
                    if (terminator == null) return result
                    fail("unterminated object")
                }
                if (terminator != null && text[at] == terminator) { at++; return result }
                val key = parseKey()
                skipSpaceAndComments()
                val value = if (at < text.length && text[at] == '{') parseObject() else {
                    if (at < text.length && (text[at] == '=' || text[at] == ':')) at++
                    parseValue()
                }
                // HOCON lets a later definition win; includes commonly re-state
                // a key the profile also sets.
                result[key] = value
            }
        }

        private fun parseArray(): List<Any?> {
            expect('[')
            val result = ArrayList<Any?>()
            while (true) {
                skipSpaceAndComments()
                if (at >= text.length) fail("unterminated array")
                if (text[at] == ']') { at++; return result }
                result.add(parseValue())
            }
        }

        private fun parseKey(): String {
            skipSpaceAndComments()
            if (at >= text.length) fail("key expected")
            return if (text[at] == '"') parseQuoted() else {
                val start = at
                while (at < text.length && (text[at].isLetterOrDigit() || text[at] == '_' ||
                        text[at] == '-' || text[at] == '.' || text[at] == '+')) at++
                if (at == start) fail("key expected")
                text.substring(start, at)
            }
        }

        private fun parseQuoted(): String {
            expect('"')
            val builder = StringBuilder()
            while (true) {
                if (at >= text.length) fail("unterminated string")
                when (val ch = text[at]) {
                    '"' -> { at++; return builder.toString() }
                    '\\' -> {
                        at++
                        if (at >= text.length) fail("unterminated escape")
                        when (val escape = text[at]) {
                            'n' -> builder.append('\n')
                            't' -> builder.append('\t')
                            'r' -> builder.append('\r')
                            '"' -> builder.append('"')
                            '\\' -> builder.append('\\')
                            else -> builder.append(escape)
                        }
                        at++
                    }
                    else -> { builder.append(ch); at++ }
                }
            }
        }

        private fun parseBare(): Any? {
            val start = at
            while (at < text.length) {
                val ch = text[at]
                if (ch == '\n' || ch == ',' || ch == '}' || ch == ']' || ch == '#') break
                if (ch == '/' && at + 1 < text.length && text[at + 1] == '/') break
                at++
            }
            val raw = text.substring(start, at).trim()
            if (raw.isEmpty()) fail("value expected")
            return when {
                raw == "true" -> true
                raw == "false" -> false
                raw == "null" -> null
                raw.matches(Regex("-?[0-9]+")) -> raw.toLongOrNull() ?: fail("integer overflow")
                raw.contains("\${") -> fail("substitutions are not supported")
                else -> raw
            }
        }

        private fun expect(ch: Char) {
            if (at >= text.length || text[at] != ch) fail("expected " + ch)
            at++
        }
    }
}
