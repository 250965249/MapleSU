package dev.maplesu.image;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Edits one caller-owned root file in decoded CPIO, preserving every other entry byte.
 * The caller supplies a canonical ASCII basename and a decoded-byte budget. An existing owned
 * file must be root-owned, regular 0600 and have one link; these are shape checks, not authentication.
 * No decompression, filesystem I/O, executable content or recovery-record interpretation occurs.
 */
public final class RamdiskEntryEditor {
    public static final int MAX_ENTRY_BYTES = 1024 * 1024;
    private RamdiskEntryEditor() {}

    /** Returns an independent content copy, or null when the owned file is absent. */
    public static byte[] read(byte[] decodedCpio, String ownedPath, int maxBytes) throws IOException {
        Archive archive = inspect(decodedCpio, ownedPath, maxBytes);
        RamdiskInspector.Entry entry = archive.owned;
        return entry == null ? null : Arrays.copyOfRange(archive.bytes, (int) entry.offset,
                (int) (entry.offset + entry.size));
    }

    /** Inserts before the original trailer, or replaces the unique owned file in place. */
    public static byte[] put(byte[] decodedCpio, String ownedPath, byte[] content,
                             int maxBytes) throws IOException {
        if (content == null) throw error("CONTENT");
        if (content.length > MAX_ENTRY_BYTES) throw error("ENTRY_SIZE");
        Archive archive = inspect(decodedCpio, ownedPath, maxBytes);
        RamdiskInspector.Entry entry = archive.owned;
        if (entry != null && entry.size == content.length &&
                Arrays.equals(archive.bytes, (int) entry.offset, (int) (entry.offset + entry.size),
                        content, 0, content.length)) return archive.bytes;
        if (entry == null && archive.report.entries.size() >= RamdiskInspector.DEFAULT_MAX_ENTRIES) {
            throw error("ENTRY_COUNT");
        }
        byte[] path = ownedPath.getBytes(StandardCharsets.US_ASCII);
        int dataOffset = align4(110 + path.length + 1);
        int entrySize = dataOffset + align4(content.length);
        int start = entry == null ? archive.report.trailerOffset : entry.headerOffset;
        int end = entry == null ? start : entry.endOffset;
        long outputSize = (long) archive.bytes.length - (end - start) + entrySize;
        if (outputSize > maxBytes) throw error("OUTPUT_SIZE");
        byte[] data = content.clone();
        byte[] replacement = new byte[entrySize];
        boolean crc = entry == null ? archive.report.trailerCrc : entry.crc;
        byte[] magic = (crc ? "070702" : "070701").getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(magic, 0, replacement, 0, magic.length);
        long sum = 0; if (crc) for (byte value : data) sum += value & 255;
        long[] fields = {0, 0100600, 0, 0, 1, 0, data.length, 0, 0, 0, 0, path.length + 1, sum};
        for (int field = 0; field < fields.length; field++) hex8(replacement, 6 + field * 8, fields[field]);
        System.arraycopy(path, 0, replacement, 110, path.length);
        System.arraycopy(data, 0, replacement, dataOffset, data.length);
        return splice(archive.bytes, start, end, replacement);
    }

    /** Removes only the unique owned file; absent removal returns an exact independent copy. */
    public static byte[] remove(byte[] decodedCpio, String ownedPath, int maxBytes) throws IOException {
        Archive archive = inspect(decodedCpio, ownedPath, maxBytes);
        return archive.owned == null ? archive.bytes : splice(archive.bytes,
                archive.owned.headerOffset, archive.owned.endOffset, new byte[0]);
    }

    private static Archive inspect(byte[] input, String path, int maxBytes) throws IOException {
        if (path == null || path.isEmpty() || path.length() > 255 || path.equals(".") ||
                path.equals("..") || path.equals("TRAILER!!!")) throw error("PATH");
        for (int index = 0; index < path.length(); index++) {
            char value = path.charAt(index);
            if (!(value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' ||
                    value >= '0' && value <= '9' || value == '.' || value == '_' || value == '-')) {
                throw error("PATH");
            }
        }
        if (maxBytes <= 0 || maxBytes > RamdiskInspector.DEFAULT_MAX_BYTES) throw error("BUDGET");
        if (input == null || input.length == 0) throw error("INPUT");
        if (input.length > maxBytes) throw error("INPUT_SIZE");
        byte[] bytes = input.clone();
        if (bytes.length < 6 || !new String(bytes, 0, 6, StandardCharsets.US_ASCII).matches("07070[12]")) {
            throw error("NOT_DECODED_CPIO");
        }
        RamdiskInspector.Report report = RamdiskInspector.inspectRamdisk(bytes,
                RamdiskInspector.DEFAULT_MAX_ENTRIES, maxBytes);
        if (report.malformed) throw error("ARCHIVE:" + report.errorCode);
        if (!report.trailerSeen || report.trailerOffset < 0) throw error("ARCHIVE:MISSING_TRAILER");
        RamdiskInspector.Entry owned = null;
        for (RamdiskInspector.Entry entry : report.entries) {
            if (!alias(entry.path, path)) continue;
            if (owned != null) throw error("DUPLICATE_OWNED_ENTRY");
            owned = entry;
        }
        if (owned != null) {
            if (!owned.path.equals(path)) throw error("OWNED_ENTRY_ALIAS");
            if (!owned.isRegularFile()) throw error("OWNED_ENTRY_TYPE");
            if (owned.mode != 0100600 || owned.uid != 0 || owned.gid != 0 || owned.links != 1) {
                throw error("OWNED_ENTRY_METADATA");
            }
            if (owned.size > MAX_ENTRY_BYTES) throw error("ENTRY_SIZE");
        }
        return new Archive(bytes, report, owned);
    }

    private static boolean alias(String candidate, String path) {
        String found = null;
        for (String component : candidate.split("/", -1)) {
            if (component.isEmpty() || component.equals(".")) continue;
            if (found != null) return false;
            found = component;
        }
        return path.equals(found);
    }

    private static byte[] splice(byte[] bytes, int start, int end, byte[] replacement) {
        byte[] output = new byte[bytes.length - (end - start) + replacement.length];
        System.arraycopy(bytes, 0, output, 0, start);
        System.arraycopy(replacement, 0, output, start, replacement.length);
        System.arraycopy(bytes, end, output, start + replacement.length, bytes.length - end);
        return output;
    }

    private static int align4(int value) { return (value + 3) & ~3; }
    private static void hex8(byte[] bytes, int offset, long value) {
        for (int index = 7; index >= 0; index--) {
            bytes[offset + index] = (byte) "0123456789abcdef".charAt((int) (value & 15));
            value >>>= 4;
        }
    }
    private static IOException error(String code) { return new IOException("CPIO_EDIT_" + code); }
    private static final class Archive {
        final byte[] bytes;
        final RamdiskInspector.Report report;
        final RamdiskInspector.Entry owned;
        Archive(byte[] bytes, RamdiskInspector.Report report, RamdiskInspector.Entry owned) {
            this.bytes = bytes; this.report = report; this.owned = owned;
        }
    }
}
