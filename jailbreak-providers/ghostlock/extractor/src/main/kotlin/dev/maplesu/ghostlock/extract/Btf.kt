package dev.maplesu.ghostlock.extract

/**
 * Minimal BTF (BPF Type Format) parser used for struct-offset derivation.
 *
 * Port of GhostLock-App `tools/extract_rs/src/btf.rs` (Apache-2.0, commit
 * 437b3b2). Only what the profile derivation reads is implemented, but the
 * decision rules are the reference's:
 * - `named_struct` picks the struct/union with the **most members** when a name
 *   appears several times;
 * - a field search descends into anonymous members and accumulates their bit
 *   offsets, bounded by the same depth/cycle guards;
 * - the strings table is the declared range, extended to the blob end when the
 *   extractor extended it past a vendor-short `str_len`.
 */
class Btf private constructor(
    private val strings: ByteArray,
    private val types: Map<Int, BtfType>,
    private val byName: Map<String, List<Int>>,
) {
    class BtfMember(val name: String, val typeId: Int, val bitOffset: Int)

    class BtfType(
        val typeId: Int,
        val name: String,
        val kind: Int,
        val sizeOrType: Int,
        val members: List<BtfMember>,
        val enumValues: List<Pair<String, Long>>,
    )

    private fun string(offset: Int): String? {
        if (offset == 0) return ""
        if (offset < 0 || offset >= strings.size) return null
        var end = offset
        while (end < strings.size && strings[end].toInt() != 0) end++
        return String(strings, offset, end - offset, Charsets.UTF_8)
    }

    /** Largest struct/union with this name, or null. */
    fun namedStruct(name: String): BtfType? =
        byName[name]?.asSequence()
            ?.mapNotNull { types[it] }
            ?.filter { it.kind == KIND_STRUCT || it.kind == KIND_UNION }
            ?.maxByOrNull { it.members.size }

    fun typeOf(typeId: Int): BtfType? = types[typeId]

    /** Resolve typedef/qualifier chains to the real type. */
    fun resolve(typeId: Int): BtfType? {
        var current = typeId
        val seen = HashSet<Int>()
        while (current != 0 && !seen.contains(current)) {
            seen.add(current)
            val item = types[current] ?: return null
            if (item.kind !in QUALIFIER_KINDS) return item
            current = item.sizeOrType
        }
        return null
    }

    /** Byte offset of [field] inside [structName], or null. */
    fun field(structName: String, fieldName: String): Int? {
        val item = namedStruct(structName) ?: return null
        return findMember(item, fieldName, 0, 0, HashSet())
    }

    /** Declared byte size of [structName] (struct/union size), or null. */
    fun size(structName: String): Int? = namedStruct(structName)?.sizeOrType

    fun enumValue(enumName: String, memberName: String): Long? {
        val candidates = byName[enumName]?.asSequence()
            ?.mapNotNull { types[it] }
            ?.filter { it.kind == KIND_ENUM || it.kind == KIND_ENUM64 }
            ?.toList() ?: return null
        val item = candidates.maxByOrNull { it.enumValues.size } ?: return null
        val values = item.enumValues.filter { it.first == memberName }.map { it.second }
        return if (values.size == 1) values[0] else null
    }

    /** Value of an enum member that appears exactly once in the whole BTF. */
    fun uniqueEnumMemberValue(memberName: String): Long? {
        val matches = ArrayList<Long>()
        for (item in types.values) {
            if (item.kind != KIND_ENUM && item.kind != KIND_ENUM64) continue
            for ((name, value) in item.enumValues) if (name == memberName) matches.add(value)
        }
        return if (matches.size == 1) matches[0] else null
    }

    /** Byte size of a type id, resolving qualifiers, pointers and arrays. */
    fun typeSize(typeId: Int): Int? {
        val resolved = resolve(typeId) ?: return null
        if (resolved.kind == KIND_PTR) return 8
        if (resolved.kind == KIND_ARRAY) return null
        if (resolved.kind in SIZED_KINDS) return resolved.sizeOrType
        return null
    }

    /** Byte size of a direct (non-anonymous) struct member's type, or null. */
    fun directFieldSize(structName: String, fieldName: String): Int? {
        val item = namedStruct(structName) ?: return null
        val matches = item.members.filter { it.name == fieldName }
        if (matches.size != 1) return null
        return typeSize(matches[0].typeId)
    }

    private fun findMember(
        item: BtfType,
        name: String,
        base: Int,
        depth: Int,
        seen: MutableSet<Int>,
    ): Int? {
        if (depth > 64 || seen.contains(item.typeId)) return null
        seen.add(item.typeId)
        for (member in item.members) {
            val offset = base + member.bitOffset
            if (member.name == name) return offset / 8
            if (member.name.isEmpty()) {
                val child = resolve(member.typeId) ?: continue
                if (child.kind == KIND_STRUCT || child.kind == KIND_UNION) {
                    val found = findMember(child, name, offset, depth + 1, seen)
                    if (found != null) return found
                }
            }
        }
        return null
    }

    companion object {
        const val KIND_INT = 1
        const val KIND_PTR = 2
        const val KIND_ARRAY = 3
        const val KIND_STRUCT = 4
        const val KIND_UNION = 5
        const val KIND_ENUM = 6
        const val KIND_FWD = 7
        const val KIND_TYPEDEF = 8
        const val KIND_VOLATILE = 9
        const val KIND_CONST = 10
        const val KIND_RESTRICT = 11
        const val KIND_FUNC = 12
        const val KIND_FUNC_PROTO = 13
        const val KIND_VAR = 14
        const val KIND_DATASEC = 15
        const val KIND_FLOAT = 16
        const val KIND_DECL_TAG = 17
        const val KIND_TYPE_TAG = 18
        const val KIND_ENUM64 = 19

        private val QUALIFIER_KINDS = setOf(
            KIND_TYPEDEF, KIND_VOLATILE, KIND_CONST, KIND_RESTRICT, KIND_TYPE_TAG)
        private val SIZED_KINDS = setOf(
            KIND_INT, KIND_STRUCT, KIND_UNION, KIND_ENUM, KIND_ENUM64, KIND_FLOAT)

        private val FIXED_SIZES = mapOf(
            KIND_INT to 4,
            KIND_PTR to 0,
            KIND_ARRAY to 12,
            KIND_ENUM to 8,
            KIND_FWD to 0,
            KIND_TYPEDEF to 0,
            KIND_VOLATILE to 0,
            KIND_CONST to 0,
            KIND_RESTRICT to 0,
            KIND_FUNC to 0,
            KIND_FUNC_PROTO to 8,
            KIND_VAR to 4,
            KIND_DATASEC to 12,
            KIND_FLOAT to 0,
            KIND_DECL_TAG to 8,
            KIND_TYPE_TAG to 0,
            KIND_ENUM64 to 12,
        )

        /** Parse a BTF blob; malformed input is a [FailureKind.GENERIC] failure. */
        fun parse(raw: ByteArray): Btf {
            if (raw.size < 24) throw ExtractionException(FailureKind.GENERIC, "truncated BTF header")
            val magic = BootImage.readU16(raw, 0)
            val version = raw[2].toInt() and 0xFF
            val headerLength = BootImage.readU32(raw, 4)
            val typeOffset = BootImage.readU32(raw, 8)
            val typeLength = BootImage.readU32(raw, 12)
            val stringOffset = BootImage.readU32(raw, 16)
            val stringLength = BootImage.readU32(raw, 20)
            if (magic != BootImage.BTF_MAGIC || version != 1 || headerLength < 24) {
                throw ExtractionException(FailureKind.GENERIC, "invalid BTF header")
            }
            val typesStart = headerLength.toLong() + typeOffset
            val typesEnd = typesStart + typeLength
            if (typesStart < 0 || typesEnd > raw.size) {
                throw ExtractionException(FailureKind.GENERIC, "truncated BTF types")
            }
            val declared = headerLength.toLong() +
                maxOf(typeOffset.toLong() + typeLength, stringOffset.toLong() + stringLength)
            val stringsStart = headerLength.toLong() + stringOffset
            if (stringsStart < 0 || stringsStart > raw.size) {
                throw ExtractionException(FailureKind.GENERIC, "invalid BTF string offset")
            }
            val strings = if (raw.size > declared) {
                raw.copyOfRange(stringsStart.toInt(), raw.size)
            } else {
                val end = minOf(stringsStart + stringLength, raw.size.toLong())
                raw.copyOfRange(stringsStart.toInt(), end.toInt())
            }
            val builder = Builder(strings)
            builder.parse(raw.copyOfRange(typesStart.toInt(), typesEnd.toInt()))
            return Btf(strings, builder.types, builder.byName)
        }
    }

    private class Builder(private val strings: ByteArray) {
        val types = LinkedHashMap<Int, BtfType>()
        val byName = LinkedHashMap<String, MutableList<Int>>()

        private fun string(offset: Int): String? {
            if (offset == 0) return ""
            if (offset < 0 || offset >= strings.size) return null
            var end = offset
            while (end < strings.size && strings[end].toInt() != 0) end++
            return String(strings, offset, end - offset, Charsets.UTF_8)
        }

        private fun readU32(data: ByteArray, offset: Int): Int =
            (data[offset].toInt() and 0xFF) or
                ((data[offset + 1].toInt() and 0xFF) shl 8) or
                ((data[offset + 2].toInt() and 0xFF) shl 16) or
                ((data[offset + 3].toInt() and 0xFF) shl 24)

        fun parse(typesRaw: ByteArray) {
            var cursor = 0
            var typeId = 1
            while (cursor < typesRaw.size) {
                if (cursor + 12 > typesRaw.size) {
                    throw ExtractionException(FailureKind.GENERIC, "truncated BTF type record")
                }
                val nameOffset = readU32(typesRaw, cursor)
                val info = readU32(typesRaw, cursor + 4)
                val sizeOrType = readU32(typesRaw, cursor + 8)
                cursor += 12
                val kind = (info ushr 24) and 0x1F
                val vlen = info and 0xFFFF
                val name = string(nameOffset)
                    ?: throw ExtractionException(
                        FailureKind.GENERIC, "invalid BTF string offset $nameOffset")
                val members = ArrayList<BtfMember>()
                val enumValues = ArrayList<Pair<String, Long>>()
                when (kind) {
                    KIND_STRUCT, KIND_UNION -> {
                        val extra = vlen.toLong() * 12
                        if (cursor.toLong() + extra > typesRaw.size) {
                            throw ExtractionException(FailureKind.GENERIC, "truncated BTF members")
                        }
                        for (index in 0 until vlen) {
                            val base = cursor + index * 12
                            val memberName = string(readU32(typesRaw, base))
                                ?: throw ExtractionException(
                                    FailureKind.GENERIC, "invalid BTF member name offset")
                            members.add(BtfMember(
                                memberName,
                                readU32(typesRaw, base + 4),
                                readU32(typesRaw, base + 8) and 0xFF_FFFF,
                            ))
                        }
                        cursor += extra.toInt()
                    }

                    KIND_ENUM -> {
                        val extra = vlen.toLong() * 8
                        if (cursor.toLong() + extra > typesRaw.size) {
                            throw ExtractionException(FailureKind.GENERIC, "truncated BTF enum members")
                        }
                        val kflag = info and (1 shl 31) != 0
                        for (index in 0 until vlen) {
                            val base = cursor + index * 8
                            val enumName = string(readU32(typesRaw, base))
                                ?: throw ExtractionException(
                                    FailureKind.GENERIC, "invalid BTF enum name offset")
                            val rawValue = readU32(typesRaw, base + 4)
                            val value = if (kflag) rawValue.toLong() else rawValue.toLong() and 0xFFFFFFFFL
                            enumValues.add(enumName to value)
                        }
                        cursor += extra.toInt()
                    }

                    KIND_ENUM64 -> {
                        val extra = vlen.toLong() * 12
                        if (cursor.toLong() + extra > typesRaw.size) {
                            throw ExtractionException(FailureKind.GENERIC, "truncated BTF enum64 members")
                        }
                        for (index in 0 until vlen) {
                            val base = cursor + index * 12
                            val enumName = string(readU32(typesRaw, base))
                                ?: throw ExtractionException(
                                    FailureKind.GENERIC, "invalid BTF enum64 name offset")
                            val low = readU32(typesRaw, base + 4).toLong() and 0xFFFFFFFFL
                            val high = readU32(typesRaw, base + 8).toLong() and 0xFFFFFFFFL
                            enumValues.add(enumName to (low or (high shl 32)))
                        }
                        cursor += extra.toInt()
                    }

                    else -> {
                        val unit = FIXED_SIZES[kind]
                            ?: throw ExtractionException(
                                FailureKind.GENERIC, "unsupported BTF kind $kind")
                        cursor += if (kind == KIND_FUNC_PROTO || kind == KIND_DATASEC) unit * vlen else unit
                    }
                }
                val item = BtfType(typeId, name, kind, sizeOrType, members, enumValues)
                byName.getOrPut(name) { ArrayList() }.add(typeId)
                types[typeId] = item
                typeId += 1
            }
        }
    }
}
