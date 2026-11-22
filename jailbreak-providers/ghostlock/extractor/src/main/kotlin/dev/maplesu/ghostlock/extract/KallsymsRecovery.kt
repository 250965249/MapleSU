package dev.maplesu.ghostlock.extract

/**
 * In-image kallsyms recovery: rebuild the kernel's embedded symbol table from
 * the uncompressed arm64 Image alone (no root, no `/proc/kallsyms`).
 *
 * Field-for-field port of GhostLock-App `tools/extract_rs/src/kallsyms_finder.rs`
 * (Apache-2.0, commit 437b3b2). The format is the kernel's
 * (`kernel/kallsyms.c`, `scripts/kallsyms.c`): a 256-entry token table with a
 * u16 index, length-prefixed compressed names (u8 or uleb128 since v4.20), u32
 * markers every 256 names, and 32-bit addresses relative to a base (since
 * v4.6). Pre-6.4 the offsets sit before the names; 6.4+ moved them after the
 * token index. Both layouts are tried, exactly like the reference.
 *
 * All bounds, candidate counts and the ambiguity rule are kept: several
 * surviving candidates are an error unless the embedded BTF blob's
 * `__start_BTF`/`__stop_BTF` symbols delimit exactly one of them.
 */
object KallsymsRecovery {
    private const val ALIGN = 8
    private const val TOKEN_COUNT = 256
    private const val TOKEN_INDEX_SIZE = TOKEN_COUNT * 2
    private const val MAX_TOKEN_LEN = 256
    private const val MARKER_SEARCH_WINDOW = 4 * 1024 * 1024
    private const val NAME_TAIL_SEARCH = 0x40000
    private const val MIN_MARKERS = 8
    private const val MAX_MARKERS = 4096
    private const val SYMBOL_TYPES = "aAbBcCdDeEfFgGiInNpPrRsStTuUvVwW?-"
    private val REQUIRED_SYMBOLS = listOf("_text", "_end", "load_module")

    /** Image size from the arm64 header at offset 0x10, when present. */
    fun arm64ImageSize(image: ByteArray): Int? {
        if (image.size < 64 || !image.copyOfRange(0x38, 0x3C).contentEquals("ARM\u0064".toByteArray()))
            return null
        val size = readU64(image, 0x10)
        if (size <= 0 || size > Int.MAX_VALUE) return null
        return size.toInt().takeIf { it != 0 }
    }

    private class TokenTable(
        val tokens: List<ByteArray>,
        val tableOffset: Int,
        val indexOffset: Int,
    )

    private fun alignUp(value: Int, alignment: Int): Int = (value + alignment - 1) and (alignment - 1).inv()

    private fun readU16(data: ByteArray, offset: Int): Int =
        (data[offset].toInt() and 0xFF) or ((data[offset + 1].toInt() and 0xFF) shl 8)

    private fun readU32(data: ByteArray, offset: Int): Int =
        (data[offset].toInt() and 0xFF) or
            ((data[offset + 1].toInt() and 0xFF) shl 8) or
            ((data[offset + 2].toInt() and 0xFF) shl 16) or
            ((data[offset + 3].toInt() and 0xFF) shl 24)

    private fun readU64(data: ByteArray, offset: Int): Long {
        var value = 0L
        for (i in 0 until 8) value = value or ((data[offset + i].toLong() and 0xFF) shl (8 * i))
        return value
    }

    /** Validate the 256-token table starting at [start] with `'0'` at [digitOffset]. */
    private fun parseTokenTableAt(image: ByteArray, start: Int, digitOffset: Int): TokenTable? {
        if (start % ALIGN != 0 || start < 0) return null
        val tokens = ArrayList<ByteArray>(TOKEN_COUNT)
        val tokenOffsets = ArrayList<Int>(TOKEN_COUNT)
        val tokenStarts = ArrayList<Int>(TOKEN_COUNT)
        var position = start
        for (index in 0 until TOKEN_COUNT) {
            tokenStarts.add(position)
            val searchEnd = minOf(position.toLong() + MAX_TOKEN_LEN + 1, image.size.toLong()).toInt()
            if (position >= searchEnd) return null
            var length = 0
            var found = false
            while (position + length < searchEnd) {
                if (image[position + length].toInt() == 0) {
                    found = true
                    break
                }
                length++
            }
            if (!found || length == 0) return null
            val end = position + length
            for (i in position until end) {
                val b = image[i].toInt() and 0xFF
                if (b < 0x20 || b > 0x7E) return null
            }
            tokenOffsets.add(position - start)
            tokens.add(image.copyOfRange(position, end))
            position = end + 1
        }
        if (tokenStarts.getOrNull('0'.code) != digitOffset) return null
        for (value in "0123456789_abcdefghijklmnopqrstuvwxyzT") {
            val token = tokens.getOrNull(value.code) ?: return null
            if (token.size != 1 || token[0].toInt() != value.code) return null
        }
        val indexOffset = alignUp(position, ALIGN)
        for (i in position until indexOffset) if (image[i].toInt() != 0) return null
        val indexEnd = indexOffset.toLong() + TOKEN_INDEX_SIZE
        if (indexEnd > image.size || tokenOffsets.last() > 0xFFFF) return null
        for (index in 0 until TOKEN_COUNT) {
            if (readU16(image, indexOffset + index * 2) != tokenOffsets[index]) return null
        }
        return TokenTable(tokens, start, indexOffset)
    }

    /** Scan for token tables: find the `0\0..9\0` digit run, try each 8-aligned start. */
    private fun findTokenTables(image: ByteArray): List<TokenTable> {
        val digitNeedle = ByteArray(20)
        for (value in '0'..'9') {
            digitNeedle[(value - '0') * 2] = value.code.toByte()
            digitNeedle[(value - '0') * 2 + 1] = 0
        }
        val tables = ArrayList<TokenTable>()
        var searchFrom = 0
        while (true) {
            val digitOffset = BootImage.findSubslice(image, digitNeedle, searchFrom) ?: break
            val earliest = (digitOffset - '0'.code * (MAX_TOKEN_LEN + 1)).coerceAtLeast(0)
            var start = alignUp(earliest, ALIGN)
            while (start <= digitOffset) {
                parseTokenTableAt(image, start, digitOffset)?.let(tables::add)
                start += ALIGN
            }
            searchFrom = digitOffset + 1
            if (searchFrom >= image.size) break
        }
        return tables
    }

    /**
     * Read `kallsyms_markers` at [start]: first entry 0, every following delta
     * within one name block (0x200..=0x40000), bounded by [limit].
     */
    private fun readMarkers(image: ByteArray, start: Int, limit: Int): List<Int> {
        if (start % ALIGN != 0 || start.toLong() + 8 > limit) return emptyList()
        if (start + 8 > image.size) return emptyList()
        val first = readU32(image, start)
        val second = readU32(image, start + 4)
        if (first != 0 || second < 0x200 || second > 0x40000) return emptyList()
        val markers = ArrayList<Int>()
        markers.add(first)
        markers.add(second)
        var position = start + 8
        while (markers.size < MAX_MARKERS && position.toLong() + 4 <= limit) {
            if (position + 4 > image.size) break
            val value = readU32(image, position)
            val delta = value - markers.last()
            if (delta < 0x200 || delta > 0x40000) break
            markers.add(value)
            position += 4
        }
        return if (markers.size < MIN_MARKERS) emptyList() else markers
    }

    /**
     * Walk `count` length-prefixed name entries; every 256th must match the
     * corresponding marker and the block must end exactly at [markersOffset].
     */
    private fun parseNameSpans(
        image: ByteArray,
        namesOffset: Int,
        count: Int,
        markersOffset: Int,
        markers: List<Int>,
        uleb128Lengths: Boolean,
    ): List<IntArray>? {
        if (count == 0 || markers.size != (count + 255) / 256) return null
        val spans = ArrayList<IntArray>(count)
        var position = namesOffset
        for (index in 0 until count) {
            if (index % 256 == 0 && position - namesOffset != markers[index / 256]) return null
            if (position >= markersOffset || position >= image.size) return null
            var length = image[position].toInt() and 0xFF
            position += 1
            if (uleb128Lengths && length and 0x80 != 0) {
                if (position >= markersOffset || position >= image.size) return null
                val high = image[position].toInt() and 0xFF
                if (high and 0x80 != 0) return null
                length = (length and 0x7F) or (high shl 7)
                position += 1
            }
            if (length == 0 || length > 0x3FFF) return null
            if (position.toLong() + length > markersOffset) return null
            spans.add(intArrayOf(position, length))
            position += length
        }
        if (alignUp(position, ALIGN) != markersOffset) return null
        for (i in position until markersOffset) if (image[i].toInt() != 0) return null
        return spans
    }

    /** Expand token runs into `(type, name)` and require the anchor symbols. */
    private fun decodeNames(
        image: ByteArray,
        spans: List<IntArray>,
        tokens: List<ByteArray>,
    ): List<Pair<Char, String>>? {
        val decoded = ArrayList<Pair<Char, String>>(spans.size)
        for (span in spans) {
            val position = span[0]
            val length = span[1]
            if (position < 0 || position.toLong() + length > image.size) return null
            var expandedLength = 0
            for (i in 0 until length) {
                val tokenIndex = image[position + i].toInt() and 0xFF
                expandedLength += tokens.getOrNull(tokenIndex)?.size ?: return null
                if (expandedLength > 4096) return null
            }
            val expanded = ByteArray(expandedLength)
            var offset = 0
            for (i in 0 until length) {
                val token = tokens[image[position + i].toInt() and 0xFF]
                System.arraycopy(token, 0, expanded, offset, token.size)
                offset += token.size
            }
            if (expanded.isEmpty()) return null
            val kind = (expanded[0].toInt() and 0xFF).toChar()
            if (expanded.size == 1 || kind !in SYMBOL_TYPES) return null
            for (i in 1 until expanded.size) {
                val b = expanded[i].toInt() and 0xFF
                if (b < 0x21 || b > 0x7E) return null
            }
            decoded.add(kind to String(expanded, 1, expanded.size - 1, Charsets.US_ASCII))
        }
        val names = decoded.mapTo(HashSet()) { it.second }
        for (required in REQUIRED_SYMBOLS) if (required !in names) return null
        return decoded
    }

    private class NameTable(
        val numSymsOffset: Int,
        val namesOffset: Int,
        val markersOffset: Int,
        val names: List<Pair<Char, String>>,
    )

    private class Candidate(val entries: List<Triple<Long, Char, String>>) {
        fun resolve(name: String): Long? {
            var found: Long? = null
            for ((address, _, candidate) in entries) {
                if (candidate != name) continue
                if (found != null && found != address) return null
                found = address
            }
            return found
        }
    }

    /** Recover the names block: markers before the token table, then `num_syms`. */
    private fun findNameTables(
        image: ByteArray,
        tokens: List<ByteArray>,
        tokenTableOffset: Int,
    ): List<NameTable> {
        val lower = (tokenTableOffset - MARKER_SEARCH_WINDOW).coerceAtLeast(0)
        val markerCandidates = ArrayList<Pair<Int, List<Int>>>()
        var position = alignUp(lower, ALIGN)
        while (position.toLong() + 8 <= tokenTableOffset) {
            val markers = readMarkers(image, position, tokenTableOffset)
            if (markers.isNotEmpty()) markerCandidates.add(position to markers)
            position += ALIGN
        }
        val recovered = ArrayList<NameTable>()
        for ((markersOffset, markers) in markerCandidates) {
            val minimumCount = (markers.size - 1) * 256 + 1
            val maximumCount = markers.size * 256
            val approximateNames = markersOffset.toLong() - markers.last().toLong()
            if (approximateNames < 0) continue
            val searchStart = (approximateNames - NAME_TAIL_SEARCH).coerceAtLeast(0)
            var numSymsOffset = (approximateNames - approximateNames % ALIGN).toInt()
            while (true) {
                if (numSymsOffset >= 0 && numSymsOffset.toLong() + 8 <= image.size) {
                    val count = readU32(image, numSymsOffset)
                    val paddingIsZero = image[numSymsOffset + 4].toInt() == 0 &&
                        image[numSymsOffset + 5].toInt() == 0 &&
                        image[numSymsOffset + 6].toInt() == 0 &&
                        image[numSymsOffset + 7].toInt() == 0
                    if (count in minimumCount..maximumCount && paddingIsZero) {
                        val namesOffset = numSymsOffset + ALIGN
                        val seenSpans = ArrayList<List<IntArray>>()
                        for (uleb128 in listOf(true, false)) {
                            val spans = parseNameSpans(
                                image, namesOffset, count, markersOffset, markers, uleb128) ?: continue
                            if (seenSpans.any { sameSpans(it, spans) }) continue
                            seenSpans.add(spans)
                            val decoded = decodeNames(image, spans, tokens) ?: continue
                            recovered.add(NameTable(numSymsOffset, namesOffset, markersOffset, decoded))
                        }
                    }
                }
                if (numSymsOffset < searchStart + ALIGN) break
                numSymsOffset -= ALIGN
            }
        }
        return recovered
    }

    private fun sameSpans(left: List<IntArray>, right: List<IntArray>): Boolean {
        if (left.size != right.size) return false
        for (i in left.indices) {
            if (left[i][0] != right[i][0] || left[i][1] != right[i][1]) return false
        }
        return true
    }

    private fun isArm64KernelAddress(address: Long): Boolean =
        (address ushr 48) == 0xFFFFL && address and 0xFFFL == 0L

    /** Decode offsets + relative base into absolute addresses, requiring a sorted span. */
    private fun decodeAddresses(
        image: ByteArray,
        imageSize: Int,
        names: List<Pair<Char, String>>,
        offsetsOffset: Int,
        relativeBaseOffset: Int,
    ): List<Triple<Long, Char, String>>? {
        val count = names.size
        val offsetsEnd = offsetsOffset.toLong() + count.toLong() * 4
        if (offsetsOffset < 0 || offsetsEnd > image.size) return null
        if (relativeBaseOffset < offsetsEnd) return null
        if (relativeBaseOffset.toLong() + 8 > image.size) return null
        for (i in offsetsEnd.toInt() until relativeBaseOffset) {
            if (image[i].toInt() != 0) return null
        }
        val relativeBase = readU64(image, relativeBaseOffset)
        if (!isArm64KernelAddress(relativeBase)) return null
        val signedOffsets = IntArray(count) { readU32(image, offsetsOffset + it * 4) }
        val negativeCount = signedOffsets.count { it < 0 }
        val addresses = LongArray(count)
        if (negativeCount * 2 >= count) {
            for (index in 0 until count) {
                val offset = signedOffsets[index]
                val address = if (offset < 0) {
                    relativeBase - 1L - offset.toLong()
                } else {
                    offset.toLong()
                }
                if (address < 0) return null
                addresses[index] = address
            }
        } else {
            for (index in 0 until count) {
                val unsigned = (signedOffsets[index].toLong() and 0xFFFFFFFFL)
                addresses[index] = relativeBase + unsigned
            }
        }
        for (index in 1 until count) if (addresses[index - 1] > addresses[index]) return null
        var textAddress: Long? = null
        var endAddress: Long? = null
        for (index in 0 until count) {
            when (names[index].second) {
                "_text" -> {
                    if (textAddress != null) return null
                    textAddress = addresses[index]
                }
                "_end" -> {
                    if (endAddress != null) return null
                    endAddress = addresses[index]
                }
            }
        }
        val text = textAddress ?: return null
        val end = endAddress ?: return null
        if (text != relativeBase) return null
        if (end - text != imageSize.toLong()) return null
        var ordinary = 0
        var inImage = 0
        for (index in 0 until count) {
            val kind = names[index].first
            if (kind in "Aa") continue
            if (addresses[index] == 0L) continue
            ordinary++
            if (addresses[index] in text..end) inImage++
        }
        if (ordinary == 0 || inImage * 100 < ordinary * 90) return null
        return (0 until count).map { Triple(addresses[it], names[it].first, names[it].second) }
    }

    /**
     * Recover the full kallsyms table from an uncompressed arm64 Image.
     *
     * [btf] optionally carries the embedded BTF blob's `(file offset, size)`;
     * when several candidates survive, the one whose `__start_BTF`/`__stop_BTF`
     * delimit that blob wins.
     */
    fun recover(image: ByteArray, btf: BootImage.BtfBlob? = null): Kallsyms {
        val imageSize = arm64ImageSize(image) ?: image.size
        val tokenTables = findTokenTables(image)
        val candidates = ArrayList<Candidate>()
        var nameBlocks = 0
        for (table in tokenTables) {
            for (nameTable in findNameTables(image, table.tokens, table.tableOffset)) {
                nameBlocks++
                val count = nameTable.names.size
                val oldRelativeBase = nameTable.numSymsOffset - ALIGN
                val oldOffsets = oldRelativeBase - alignUp(count * 4, ALIGN)
                val newOffsets = alignUp(table.indexOffset + TOKEN_INDEX_SIZE, ALIGN)
                val newRelativeBase = alignUp(newOffsets + count * 4, ALIGN)
                for ((offsetsOffset, relativeBaseOffset) in listOf(
                    oldOffsets to oldRelativeBase,
                    newOffsets to newRelativeBase,
                )) {
                    if (offsetsOffset < 0) continue
                    val entries = decodeAddresses(
                        image, imageSize, nameTable.names, offsetsOffset, relativeBaseOffset)
                    if (entries != null) candidates.add(Candidate(entries))
                }
            }
        }
        if (candidates.isEmpty()) {
            throw ExtractionException(
                FailureKind.KALLSYMS,
                "no kallsyms table found in the kernel image " +
                    "(${tokenTables.size} token tables, $nameBlocks name blocks, " +
                    "image_size=0x${imageSize.toString(16)})",
            )
        }
        val boundaryMatches = ArrayList<Int>()
        if (btf != null) {
            for ((index, candidate) in candidates.withIndex()) {
                val base = candidate.resolve("_text") ?: continue
                val btfStart = candidate.resolve("__start_BTF") ?: continue
                val btfStop = candidate.resolve("__stop_BTF") ?: continue
                val recoveredOffset = btfStart - base
                val recoveredSize = btfStop - btfStart
                if (recoveredOffset == btf.offset.toLong() && recoveredSize == btf.bytes.size.toLong()) {
                    boundaryMatches.add(index)
                }
            }
        }
        val selected = when {
            boundaryMatches.size == 1 -> candidates[boundaryMatches[0]]
            boundaryMatches.isEmpty() && candidates.size == 1 -> candidates[0]
            else -> throw ExtractionException(
                FailureKind.KALLSYMS,
                "ambiguous kallsyms recovery in the kernel image " +
                    "(${tokenTables.size} token tables, ${candidates.size} complete candidates, " +
                    "${boundaryMatches.size} BTF boundary matches)",
            )
        }
        val symbols = LinkedHashMap<String, MutableSet<Long>>()
        val types = LinkedHashMap<String, MutableSet<Char>>()
        for ((address, kind, name) in selected.entries) {
            symbols.getOrPut(name) { LinkedHashSet() }.add(address)
            types.getOrPut(name) { LinkedHashSet() }.add(kind)
        }
        return Kallsyms(symbols, types)
    }
}
