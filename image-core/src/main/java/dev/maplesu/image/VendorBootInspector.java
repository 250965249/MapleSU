package dev.maplesu.image;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Locale;

/** Structural gate for VNDRBOOT v3/v4, separate from Android boot targets. */
public final class VendorBootInspector {
    private VendorBootInspector() {}
    public static final class Report {
        public final int headerVersion;
        public final long fileSize, ramdiskSize, fragmentCount;
        public final String sha256;
        private Report(int version, long size, long ramdisk, long fragments, String hash) {
            headerVersion = version; fileSize = size; ramdiskSize = ramdisk; fragmentCount = fragments; sha256 = hash;
        }
    }
    public static Report inspect(File file) throws IOException {
        try (RandomAccessFile input = new RandomAccessFile(file, "r")) {
            long length = input.length();
            if (length < 2112 || length > 512L * 1024 * 1024) throw invalid();
            byte[] header = new byte[2112]; input.readFully(header);
            if (!new String(header, 0, 8, java.nio.charset.StandardCharsets.US_ASCII).equals("VNDRBOOT")) throw invalid();
            long version = u32(header, 8), page = u32(header, 12), size = u32(header, 2096);
            if ((version != 3 && version != 4) || (page != 2048 && page != 4096 && page != 8192 && page != 16384) ||
                size < (version == 3 ? 2112 : 2128) || size > 65536) throw invalid();
            long ramdisk = u32(header, 24), dtb = u32(header, 2100);
            long ramdiskOffset = align(size, page), dtbOffset = ramdiskOffset + align(ramdisk, page);
            region(ramdiskOffset, ramdisk, length); region(dtbOffset, dtb, length);
            long fragments = 1;
            if (version == 4) {
                byte[] extension = new byte[16]; input.seek(2112); input.readFully(extension);
                long tableSize = u32(extension, 0), count = u32(extension, 4), entrySize = u32(extension, 8);
                long tableOffset = dtbOffset + align(dtb, page);
                if (count == 0 || count > 4096 || entrySize < 108 || count * entrySize != tableSize) throw invalid();
                region(tableOffset, tableSize, length);
                region(tableOffset + align(tableSize, page), u32(extension, 12), length);
                long previousEnd = 0;
                for (long i = 0; i < count; i++) {
                    input.seek(tableOffset + i * entrySize); byte[] entry = new byte[108]; input.readFully(entry);
                    long bytes = u32(entry, 0), offset = u32(entry, 4);
                    if (offset != previousEnd || offset > ramdisk || bytes > ramdisk - offset) throw invalid();
                    previousEnd = offset + bytes;
                }
                if (previousEnd != ramdisk) throw invalid();
                fragments = count;
            }
            MessageDigest digest;
            try { digest = MessageDigest.getInstance("SHA-256"); }
            catch (NoSuchAlgorithmException e) { throw new IllegalStateException(e); }
            input.seek(0); byte[] buffer = new byte[65536]; int n;
            while ((n = input.read(buffer)) != -1) {
                if (Thread.currentThread().isInterrupted()) throw new IOException("INSTALLER_CANCELLED");
                digest.update(buffer, 0, n);
            }
            if (input.length() != length) throw invalid();
            StringBuilder hash = new StringBuilder(64);
            for (byte b : digest.digest()) hash.append(String.format(Locale.ROOT, "%02x", b & 255));
            return new Report((int) version, length, ramdisk, fragments, hash.toString());
        }
    }
    private static long u32(byte[] b, int at) {
        return (b[at] & 255L) | ((b[at + 1] & 255L) << 8) | ((b[at + 2] & 255L) << 16) | ((b[at + 3] & 255L) << 24);
    }
    private static long align(long size, long page) { return (size + page - 1) / page * page; }
    private static void region(long at, long size, long length) throws IOException {
        if (at > length || size > length - at) throw invalid();
    }
    private static IOException invalid() { return new IOException("INSTALLER_VENDOR_BOOT_INVALID"); }
}
