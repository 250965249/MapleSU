package dev.maplesu.ghostlock.extract

/**
 * Kernel symbol table: name -> addresses (a name may legitimately appear twice)
 * and name -> symbol types.
 *
 * This is the shape the reference uses (`Kallsyms` in
 * `tools/extract_rs/src/kallsyms.rs`), so every later lookup ("unique address or
 * nothing") is the same decision the reference makes.
 */
class Kallsyms(
    val symbols: Map<String, Set<Long>>,
    val types: Map<String, Set<Char>>,
) {
    /** The address of [name] when it is unique, else null. */
    fun unique(name: String): Long? {
        val values = symbols[name] ?: return null
        return if (values.size == 1) values.first() else null
    }

    /**
     * The unique address of an exact symbol, else the unique address among all
     * symbols containing every [fragments] entry (case-insensitive) - the
     * reference's `find_function` heuristic.
     */
    fun findFunction(exact: String, fragments: List<String> = emptyList()): Long? {
        unique(exact)?.let { return it }
        val matches = LinkedHashSet<Long>()
        for ((name, values) in symbols) {
            if (fragments.isEmpty()) continue
            if (!fragments.all { name.lowercase().contains(it.lowercase()) }) continue
            matches.addAll(values)
        }
        return if (matches.size == 1) matches.first() else null
    }

    /** Same as [findFunction] but only over data symbols (`dDbB`), like `find_data_symbol`. */
    fun findDataSymbol(exact: String, fragments: List<String> = emptyList()): Long? {
        unique(exact)?.let { return it }
        val matches = LinkedHashSet<Long>()
        for ((name, values) in symbols) {
            if (fragments.isEmpty()) continue
            if (!fragments.all { name.lowercase().contains(it.lowercase()) }) continue
            val isData = types[name]?.any { it in "dDbB" } == true
            if (!isData) continue
            matches.addAll(values)
        }
        return if (matches.size == 1) matches.first() else null
    }

    companion object {
        /**
         * Parse `/proc/kallsyms` text. Zeroed addresses (kptr_restrict) are
         * dropped, and a table without `_text`/`_head` is rejected - the same
         * two rules the reference applies.
         */
        fun parse(text: String): Kallsyms {
            val pattern = Regex("^([0-9a-fA-F]{8,16})\\s+(\\S)\\s+(.+?)\\s*$")
            val symbols = LinkedHashMap<String, MutableSet<Long>>()
            val types = LinkedHashMap<String, MutableSet<Char>>()
            for (line in text.lineSequence()) {
                val captures = pattern.find(line) ?: continue
                val value = captures.groupValues[1].toLongOrNull(16) ?: continue
                if (value == 0L) continue
                val symbolType = captures.groupValues[2].first()
                val name = captures.groupValues[3]
                symbols.getOrPut(name) { LinkedHashSet() }.add(value)
                types.getOrPut(name) { LinkedHashSet() }.add(symbolType)
            }
            if (!symbols.containsKey("_text") && !symbols.containsKey("_head")) {
                throw ExtractionException(
                    FailureKind.KALLSYMS, "kallsyms has no _text or _head symbol")
            }
            return Kallsyms(symbols, types)
        }
    }
}
