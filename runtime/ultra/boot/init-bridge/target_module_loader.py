"""Prove the inlined vermagic/CRC and empty protection predicates from a target Image.

This recognizes native instruction semantics, BTF fields and exported-table pointers.
It has no release, model, Image hash or device-offset allowlist. Other code shapes
retain a contract failure; no module, trusted signature or runtime acceptance is inferred.
"""
import hashlib
import re
import struct

POLICY = "skip-release-word-only-with-actual-crcs"


def target_release(image, table):
    """Read actual named kernel objects, not the first generic banner-format string."""
    def value(name, maximum):
        offsets = set(table.all_offsets(name))
        if len(offsets) != 1:
            fail("RELEASE_SYMBOL:" + name)
        at = offsets.pop()
        limit = min((row[0] for row in table.rows if row[0] > at), default=len(image))
        limit = min(limit, at + maximum, len(image))
        if not 0 <= at < limit:
            fail("RELEASE_SYMBOL_BOUNDS:" + name)
        stop = image.find(b"\0", at, limit)
        if stop < 0:
            fail("RELEASE_SYMBOL_STRING:" + name)
        raw = image[at:stop + 1]
        return raw[:-1].decode("ascii"), dict(symbol=name, offset=at, bytes=len(raw),
            sha256=hashlib.sha256(raw).hexdigest())
    banner, banner_proof = value("linux_banner", 4096)
    found = re.fullmatch(r"Linux version ([0-9]+\.[0-9]+\.[^ \t\r\n%]+) [^\0]+\n", banner)
    if found is None:
        fail("ACTUAL_LINUX_BANNER")
    release = found[1]
    magic, magic_proof = value("vermagic", 512)
    if (not magic.startswith(release + " ") or not magic.endswith(" aarch64") or
            " modversions " not in magic or any(char in magic for char in "\r\n%")):
        fail("ACTUAL_VERMAGIC_RELEASE")
    return dict(schema="maplesu-target-symbol-release-proof/1", release=release,
        vermagic=magic, linuxBanner=banner_proof, targetVermagic=magic_proof)


def fail(label):
    raise ValueError("ULTRA_BRIDGE_KMI_INLINE_LOADER:" + label)


def capture(image, table, btf, vermagic, exports):
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)

    def unique(name):
        values = set(table.all_offsets(name))
        if len(values) != 1:
            fail("SYMBOL:" + name)
        return values.pop()

    def text(name):
        start = unique(name)
        end = min((row[0] for row in table.rows if row[0] > start), default=len(image))
        if start % 4 or not 0 <= start < end <= len(image) or end - start > 65536 or (end - start) % 4:
            fail("TEXT_BOUNDS:" + name)
        instructions = list(decoder.disasm(image[start:end], start))
        if len(instructions) * 4 != end - start:
            fail("TEXT_DECODE:" + name)
        return instructions

    def cstring(at):
        if not 0 <= at < len(image):
            fail("STRING_BOUNDS")
        end = image.find(b"\0", at, min(at + 512, len(image)))
        if end < 0:
            fail("STRING_END")
        return image[at:end].decode("ascii")

    def pairs(instructions):
        return [(row.mnemonic, row.op_str) for row in instructions]

    def branch(row, name):
        return row.mnemonic == "bl" and row.op_str == "#" + hex(unique(name))

    def literal(left, right, register):
        first = re.fullmatch(re.escape(register) + r", #(0x[0-9a-f]+|[0-9]+)", left.op_str)
        second = re.fullmatch(re.escape(register) + r", " + re.escape(register) + r", #(0x[0-9a-f]+|[0-9]+)", right.op_str)
        if left.mnemonic != "adrp" or right.mnemonic != "add" or not first or not second:
            fail("LITERAL_ADDRESS")
        at = int(first[1], 0) + int(second[1], 0)
        if not 0 <= at < len(image):
            fail("LITERAL_BOUNDS")
        return at

    def field(owner, *path):
        indexes = [i for i, row in enumerate(btf.types) if row and row[1] == 4 and btf.name(row[0]) == owner]
        values = []
        for root in indexes:
            at, index = 0, root
            for label in path:
                row = btf.types[btf.resolve(index)]
                if row[1] != 4:
                    fail("BTF_AGGREGATE:" + owner)
                matches = []
                for number in range(row[2]):
                    member = row[5] + number * 12
                    if btf.name(btf.u32(member)) == label:
                        raw = btf.u32(member + 8)
                        if (row[4] and raw >> 24) or raw % 8:
                            fail("BTF_BITFIELD:" + label)
                        matches.append((btf.u32(member + 4), raw // 8))
                if len(matches) != 1:
                    fail("BTF_FIELD:" + label)
                index, offset = matches[0]
                at += offset
            values.append((at, btf.type_size(index)))
        if not values or len(set(values)) != 1:
            fail("BTF_FIELD_AMBIGUOUS:" + owner)
        return values[0]

    def memory(register, offset):
        return "[" + register + (", #" + hex(offset) if offset else "") + "]"

    def exact(actual, expected, label):
        if pairs(actual) != expected:
            fail(label)

    def proof(instructions):
        raw = b"".join(row.bytes for row in instructions)
        return dict(offset=instructions[0].address, bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())

    vers, vers_bytes = field("load_info", "index", "vers")
    if vers_bytes != 4:
        fail("VERS_INDEX_WIDTH")
    predicates = []
    for name in ("gki_is_module_protected_symbol", "gki_is_module_exported_symbol"):
        rows = text(name)
        if btf.function(name) != "fi1:67108872(*i1:8;)":
            fail("PROTECTION_PROTOTYPE:" + name)
        exact(rows, [("paciasp", ""), ("mov", "w0, wzr"), ("autiasp", ""), ("ret", "")],
            "PROTECTION_PREDICATE:" + name)
        predicates.append(dict(symbol=name, result=False, **proof(rows)))

    info = text("check_modinfo")
    candidates = []
    for at, instruction in enumerate(info):
        if instruction.mnemonic != "ldr" or instruction.op_str != "w8, " + memory("x20", vers):
            continue
        block = info[at:at + 15]
        if len(block) != 15:
            continue
        exact(block[:2], [("ldr", "w8, " + memory("x20", vers)),
            ("cbz", "w8, #" + hex(block[10].address))], "VERMAGIC_VERS_BRANCH")
        space = literal(block[2], block[4], "x1")
        suffix = literal(block[6], block[8], "x1")
        full = literal(block[10], block[12], "x1")
        if cstring(space) != " " or cstring(full) != vermagic or cstring(suffix) != vermagic[vermagic.find(" "):]:
            fail("VERMAGIC_LITERAL_CONTENT")
        if suffix != full + vermagic.index(" "):
            fail("VERMAGIC_SUFFIX_POINTER")
        expected = [("ldr", "w8, " + memory("x20", vers)),
            ("cbz", "w8, #" + hex(block[10].address)),
            pairs(block[2:3])[0], ("mov", "x0, x22"), pairs(block[4:5])[0],
            ("bl", "#" + hex(unique("strcspn"))), pairs(block[6:7])[0],
            ("add", "x0, x22, x0"), pairs(block[8:9])[0],
            ("b", "#" + hex(block[13].address)), pairs(block[10:11])[0],
            ("mov", "x0, x22"), pairs(block[12:13])[0],
            ("bl", "#" + hex(unique("strcmp"))), pairs(block[14:15])[0]]
        exact(block, expected, "VERMAGIC_COMPARE_FLOW")
        error = re.fullmatch(r"w0, #(0x[0-9a-f]+)", block[14].op_str)
        if block[14].mnemonic != "cbnz" or not error:
            fail("VERMAGIC_REJECT_BRANCH")
        error_at = int(error[1], 0)
        error_index = next((i for i, row in enumerate(info) if row.address == error_at), None)
        if error_index is None:
            fail("VERMAGIC_REJECT_BOUNDS")
        reject = info[error_index:]
        first_ret = next((i for i, row in enumerate(reject) if row.mnemonic == "ret"), None)
        if first_ret is None:
            fail("VERMAGIC_REJECT_RETURN")
        reject = reject[:first_ret + 1]
        minus = [i for i, row in enumerate(reject) if (row.mnemonic, row.op_str) == ("mov", "w0, #-8")]
        if len(minus) != 1 or not any(branch(row, "_printk") for row in reject[:minus[0]]):
            fail("VERMAGIC_REJECT_ERRNO")
        if any(row.mnemonic not in ("ldp", "ldr", "autiasp", "ret") for row in reject[minus[0] + 1:]):
            fail("VERMAGIC_REJECT_EPILOGUE")
        prefix = info[:at]
        if not any((row.mnemonic, row.op_str) == ("mov", "x20, x1") for row in prefix):
            fail("VERMAGIC_LOAD_INFO_ARGUMENT")
        input_name = [i for i, row in enumerate(prefix) if (row.mnemonic, row.op_str) == ("add", "x22, x24, #9")]
        if len(input_name) != 1:
            fail("VERMAGIC_NAME_VALUE")
        searches = []
        for i in range(input_name[0]):
            if branch(prefix[i], "strncmp") and i >= 3:
                sequence = prefix[i - 3:i + 5]
                if (pairs(sequence[:3]) == [("mov", "x0, x24"), ("mov", "x1, x23"), ("mov", "w2, #8")] and
                        any((row.mnemonic, row.op_str) == ("cmp", "w8, #0x3d") for row in sequence)):
                    searches.append(i)
        if len(searches) != 1:
            fail("VERMAGIC_MODINFO_KEY")
        constants = [(prefix[i], prefix[j]) for i in range(searches[0]) for j in range(i + 1, searches[0])
            if prefix[i].mnemonic == "adrp" and prefix[j].mnemonic == "add" and
            prefix[i].op_str.startswith("x23, #") and prefix[j].op_str.startswith("x23, x23, #")]
        if not any(cstring(literal(left, right, "x23")) == "vermagic" for left, right in constants):
            fail("VERMAGIC_KEY_STRING")
        candidates.append(dict(block=proof(block), reject=proof(reject), fullMagicOffset=full,
            suffixMagicOffset=suffix, versionIndexOffset=vers))
    if len(candidates) != 1:
        fail("ONE_INLINED_VERMAGIC_FLOW")
    magic = dict(policy=POLICY, implementation="inlined-check_modinfo-actual-version-index",
        **candidates[0]["block"], versionIndexOffset=vers,
        fullMagicOffset=candidates[0]["fullMagicOffset"], suffixMagicOffset=candidates[0]["suffixMagicOffset"])

    resolve = text("resolve_symbol")
    crc, crc_bytes = field("modversion_info", "crc")
    name, _ = field("modversion_info", "name")
    record_size = btf.named_structure_members("modversion_info")["bytes"]
    section_size, _ = field("elf64_shdr", "sh_size")
    section_address, _ = field("elf64_shdr", "sh_addr")
    section_record = btf.named_structure_members("elf64_shdr")["bytes"]
    if (crc, crc_bytes, name, record_size, section_size, section_address, section_record) != (0, 8, 8, 64, 32, 16, 64):
        fail("ACTUAL_MODVERSION_RECORD_LAYOUT")
    locations = [i for i in range(len(resolve) - 3) if pairs(resolve[i:i + 4]) ==
        [("ldr", "w8, [x25]"), ("ldur", "x9, [x23, #-8]"), ("cmp", "x9, x8"),
         ("b.ne", resolve[i + 3].op_str)]]
    if len(locations) != 1:
        fail("ONE_UNSIGNED32_TO_ULONG_CRC_COMPARE")
    ci = locations[0]
    crc_error = int(resolve[ci + 3].op_str.lstrip("#"), 0)
    error_index = next((i for i, row in enumerate(resolve) if row.address == crc_error), None)
    if error_index is None:
        fail("CRC_REJECT_BOUNDS")
    reject = resolve[error_index:error_index + 6]
    if len(reject) != 6 or not branch(reject[4], "_printk") or reject[5].mnemonic != "b":
        fail("CRC_REJECT_DIAGNOSTIC")
    rejected_at = int(reject[5].op_str.lstrip("#"), 0)
    rejected = [row for row in resolve if row.address == rejected_at]
    if len(rejected) != 1 or (rejected[0].mnemonic, rejected[0].op_str) != ("mov", "x22, #-0x16"):
        fail("CRC_REJECT_EINVAL")
    vi = [i for i, row in enumerate(resolve[:ci]) if (row.mnemonic, row.op_str) ==
        ("ldr", "w8, " + memory("x24", vers))]
    if len(vi) != 1:
        fail("CRC_VERS_INDEX")
    vi = vi[0]
    exact(resolve[vi:vi + 17], [("ldr", "w8, " + memory("x24", vers)),
        ("cbz", "w8, #" + hex(rejected_at)), ("ldr", "x9, [x24, #0x20]"),
        ("add", "x8, x9, x8, lsl #6"), ("ldr", "x9, [x8, #0x20]"),
        ("lsr", "x10, x9, #6"), ("cbz", "w10, #" + hex(resolve[vi + 17].address)),
        ("ldr", "x8, [x8, #0x10]"), ("ubfx", "x26, x9, #6, #0x20"),
        ("add", "x23, x8, #8"), ("mov", "x0, x23"), ("mov", "x1, x22"),
        ("bl", "#" + hex(unique("strcmp"))), ("cbz", "w0, #" + hex(resolve[ci].address)),
        ("add", "x23, x23, #0x40"), ("subs", "x26, x26, #1"),
        ("b.ne", "#" + hex(resolve[vi + 10].address))], "CRC_VERSION_NAME_LOOP")
    if not all(any((row.mnemonic, row.op_str) == pair for row in resolve[:vi]) for pair in
            (("mov", "x24, x1"), ("mov", "x22, x2"), ("ldr", "x25, [sp, #0x20]"))):
        fail("CRC_ARGUMENT_FLOW")
    find_calls = [i for i, row in enumerate(resolve) if branch(row, "find_symbol")]
    if len(find_calls) != 1 or pairs(resolve[find_calls[0] - 1:find_calls[0]]) != [("add", "x0, sp, #8")]:
        fail("ACTUAL_FIND_SYMBOL_ARGUMENT")
    sig_ok, _ = field("module", "sig_ok")
    if any(row.mnemonic.startswith(("ldrb", "ldur")) and
            re.search(r"\[x(?:20|21), #" + hex(sig_ok) + r"\]", row.op_str) for row in resolve):
        fail("UNPROVED_INLINE_SIGNATURE_GATE")
    if any(row.mnemonic in ("br", "blr") for row in resolve):
        fail("UNPROVED_INDIRECT_RESOLVER")

    find = text("find_symbol")
    search = [i for i in range(len(find) - 3) if pairs(find[i:i + 4])[:2] ==
        [("adrp", find[i].op_str), ("sub", "x11, x19, x8")] and
        find[i].op_str.startswith("x10, #") and find[i + 2].mnemonic == "add" and
        find[i + 2].op_str.startswith("x10, x10, #")]
    if len(search) != 1:
        fail("ONE_NATIVE_SYMSEARCH_TABLE")
    si = search[0]
    address = literal(find[si], find[si + 2], "x10")
    expected_tables = []
    base = table.text_base
    for number, suffix in enumerate(("", "_gpl")):
        start, stop = unique("__start___ksymtab" + suffix), unique("__stop___ksymtab" + suffix)
        crcs, crc_stop = unique("__start___kcrctab" + suffix), unique("__stop___kcrctab" + suffix)
        actual = struct.unpack_from("<3QI4x", image, address + number * 32)
        if actual != (base + start, base + stop, base + crcs, number) or (stop - start) // 12 * 4 != crc_stop - crcs:
            fail("SYMSEARCH_ACTUAL_EXPORT_CRC_POINTER:" + suffix)
        expected_tables.append(dict(exportClass="EXPORT_SYMBOL_GPL" if number else "EXPORT_SYMBOL",
            tableOffset=address + number * 32, symbolStart=start, symbolStop=stop, crcStart=crcs, crcStop=crc_stop))
    exact(find[si + 3:si + 16], [("mov", "w12, #0xc"), ("add", "x9, x10, x9, lsl #5"),
        ("lsr", "x10, x11, #2"), ("mov", "w11, #0xaaab"), ("movk", "w11, #0xaaaa, lsl #16"),
        ("mul", "w10, w10, w11"), ("ldr", "x11, [x9, #0x10]"),
        ("add", "x11, x11, w10, uxtw #2"), ("umaddl", "x10, w10, w12, x8"),
        ("ldr", "w8, [x9, #0x18]"), ("stp", "xzr, x11, [x25, #0x10]"),
        ("str", "x10, [x25, #0x20]"), ("b", find[si + 15].op_str)], "SYMSEARCH_CRC_RESULT_FLOW")
    if field("find_symbol_arg", "crc") != (24, 8) or field("find_symbol_arg", "owner") != (16, 8):
        fail("FIND_SYMBOL_CRC_BTF")
    actual_exports = []
    for entry in expected_tables:
        for number, at in enumerate(range(entry["symbolStart"], entry["symbolStop"], 12)):
            _, label, namespace = struct.unpack_from("<iii", image, at)
            name = cstring(at + 4 + label)
            if unique("__ksymtab_" + name) != at:
                fail("ACTUAL_EXPORT_NAME:" + name)
            value = struct.unpack_from("<I", image, entry["crcStart"] + number * 4)[0]
            actual_exports.append((name, value, entry["exportClass"], cstring(at + 8 + namespace)))
    if actual_exports != exports:
        fail("ACTUAL_IMAGE_EXPORT_CRC_SET")
    allowed = sorted({row[0] for row in actual_exports})
    if not allowed or len(allowed) != len(exports):
        fail("UNIQUE_EXPORTED_SYMBOLS_REQUIRED")
    record = dict(schema="maplesu-target-inlined-module-loader-proof/1",
        implementation="native-inlined-vermagic-crc-and-constant-false-gki-predicates",
        imageSha256=hashlib.sha256(image).hexdigest(),
        sameMagic=candidates[0], signatureProtection=dict(policy="both-native-predicates-proven-false",
            predicates=predicates, resolver=proof(resolve), moduleSigOkOffset=sig_ok,
            unprotectedScope="actual-vmlinux-exported-symbols-only;GPL-namespace-CRC-checks-retained"),
        crc=dict(compareOffset=resolve[ci].address, errorOffset=rejected_at,
            versionIndexOffset=vers, recordBytes=record_size, sourceWidth=4, moduleWidth=8,
            comparison="unsigned32-native-export-CRC-zero-extended-to-module-unsigned-long",
            resolver=proof(resolve)),
        findSymbol=dict(symsearchOffset=address, symsearchTables=expected_tables, body=proof(find)),
        acceptedExportedNamesSha256=hashlib.sha256("\n".join(allowed).encode("ascii")).hexdigest(),
        targetQualified=False, deviceQualified=False)
    return magic, allowed, record
