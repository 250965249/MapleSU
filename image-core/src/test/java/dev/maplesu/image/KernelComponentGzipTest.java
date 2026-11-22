package dev.maplesu.image;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.zip.CRC32;
import java.util.zip.GZIPOutputStream;

/** Exercises the production kernel-component path without native tools or fixture files. */
public final class KernelComponentGzipTest {
    private static int checks;

    public static void main(String[] args) throws Exception {
        byte[] raw = "kernel payload".repeat(7000).getBytes(StandardCharsets.US_ASCII);
        byte[] changed = raw.clone();
        changed[140] ^= 42;
        byte[] gzip = KernelCompression.encode(raw, "GZIP");
        byte[] tail = {(byte) 0xd0, 0x0d, (byte) 0xfe, (byte) 0xed, 0, 0, 0, 12, 9, 4, 0, 0};
        roundTrip(raw, changed, gzip, new byte[0]);
        roundTrip(raw, changed, gzip, tail);
        // Tail recognition depends on stream consumption, rather than DTB magic or alignment.
        roundTrip(raw, changed, gzip, new byte[]{1, 5, 9, 0, 31});
        roundTrip(raw, changed, gzip, new byte[]{31});
        byte[] optional = optionalHeader(gzip);
        roundTrip(raw, changed, optional, tail);
        byte[] first = Arrays.copyOfRange(raw, 0, 1);
        byte[] second = Arrays.copyOfRange(raw, 1, raw.length);
        roundTrip(raw, changed, join(KernelCompression.encode(first, "GZIP"),
                KernelCompression.encode(second, "GZIP")), tail);
        for (int offset : new int[]{gzip.length - 8, gzip.length - 4}) {
            byte[] broken = gzip.clone(); broken[offset] ^= 1;
            fails(join(broken, tail), "INVALID_GZIP_TRAILER");
        }
        byte[] badHeaderCrc = optional.clone(); badHeaderCrc[25] ^= 1;
        fails(badHeaderCrc, "INVALID_GZIP_HEADER_CRC");
        byte[] reserved = gzip.clone(); reserved[3] |= (byte) 0xe0;
        fails(reserved, "INVALID_GZIP_HEADER");
        byte[] method = gzip.clone(); method[2] = 7;
        fails(method, "INVALID_GZIP_HEADER");
        for (int length : new int[]{0, 1, 9}) fails(Arrays.copyOf(gzip, length), "TRUNCATED_GZIP_HEADER");
        fails(Arrays.copyOf(optional, 11), "TRUNCATED_GZIP_HEADER");
        byte[] noNameEnd = join(Arrays.copyOf(gzip, 10), new byte[]{65, 66}); noNameEnd[3] = 8;
        fails(noNameEnd, "TRUNCATED_GZIP_HEADER");
        fails(Arrays.copyOf(gzip, 12), "TRUNCATED_GZIP_DATA");
        fails(Arrays.copyOf(gzip, gzip.length - 1), "TRUNCATED_GZIP_TRAILER");
        fails(join(gzip, Arrays.copyOf(gzip, 9)), "TRUNCATED_GZIP_HEADER");
        byte[] badSecond = gzip.clone(); badSecond[badSecond.length - 8] ^= 1;
        fails(join(gzip, badSecond), "INVALID_GZIP_TRAILER");
        byte[] badDeflate = gzip.clone(); badDeflate[10] = 7;
        fails(badDeflate, "INVALID_GZIP_DATA");
        ByteArrayOutputStream empty = new ByteArrayOutputStream();
        try (GZIPOutputStream stream = new GZIPOutputStream(empty)) { }
        fails(empty.toByteArray(), "EMPTY_KERNEL");
        roundTrip(raw, changed, join(empty.toByteArray(), gzip), tail);
        ByteArrayOutputStream oversized = new ByteArrayOutputStream();
        try (GZIPOutputStream stream = new GZIPOutputStream(oversized)) {
            byte[] block = new byte[1024 * 1024];
            for (int index = 0; index < 128; index++) stream.write(block);
            stream.write(1);
        }
        fails(oversized.toByteArray(), "DECOMPRESSION_LIMIT");
        try {
            KernelCompression.decode(join(gzip, tail), "GZIP", raw.length - 1);
            throw new AssertionError("decode limit was ignored");
        } catch (IOException error) { same("DECOMPRESSION_LIMIT", error.getMessage()); }
        Thread.currentThread().interrupt();
        try {
            KernelCompression.encodeKernelComponent(changed, join(gzip, tail), "GZIP");
            throw new AssertionError("cancellation was ignored");
        } catch (IOException error) { same("CANCELLED", error.getMessage()); }
        finally { Thread.interrupted(); }
        // This API keeps the existing non-gzip codec behavior.
        for (String format : new String[]{"RAW_ARM64", "LZ4_LEGACY", "LZ4_FRAME"}) {
            byte[] encoded = KernelCompression.encodeKernelComponent(changed,
                    KernelCompression.encode(raw, format), format);
            equal(KernelCompression.encode(changed, format), encoded);
            equal(changed, KernelCompression.decode(encoded, format, KernelCompression.MAX_KERNEL_BYTES));
        }
        equal(gzip, KernelCompression.encode(raw, "GZIP"));
        System.out.println("PASS " + checks + " kernel-component gzip checks");
    }

    private static void roundTrip(byte[] originalRaw, byte[] changed, byte[] members, byte[] tail) throws Exception {
        byte[] original = join(members, tail);
        byte[] copy = original.clone();
        equal(originalRaw, KernelCompression.decode(original, "GZIP", KernelCompression.MAX_KERNEL_BYTES));
        byte[] rebuilt = KernelCompression.encodeKernelComponent(changed, original, "GZIP");
        equal(changed, KernelCompression.decode(rebuilt, "GZIP", KernelCompression.MAX_KERNEL_BYTES));
        equal(tail, Arrays.copyOfRange(rebuilt, rebuilt.length - tail.length, rebuilt.length));
        equal(join(KernelCompression.encode(changed, "GZIP"), tail), rebuilt);
        equal(copy, original);
    }

    private static byte[] optionalHeader(byte[] gzip) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] header = Arrays.copyOf(gzip, 10); header[3] = 31;
        out.writeBytes(header);
        out.writeBytes(new byte[]{3, 0, 1, 2, 3});
        out.writeBytes(new byte[]{'k', 'e', 'r', 'n', 0, 'n', 'o', 't', 'e', 0});
        CRC32 crc = new CRC32(); crc.update(out.toByteArray());
        out.write((int) crc.getValue() & 255); out.write((int) (crc.getValue() >>> 8) & 255);
        out.writeBytes(Arrays.copyOfRange(gzip, 10, gzip.length));
        return out.toByteArray();
    }

    private static void fails(byte[] original, String expected) throws Exception {
        try {
            KernelCompression.encodeKernelComponent(new byte[]{1}, original, "GZIP");
            throw new AssertionError("invalid source accepted: " + expected);
        } catch (IOException error) { same(expected, error.getMessage()); }
    }

    private static byte[] join(byte[] first, byte[] second) {
        byte[] both = Arrays.copyOf(first, first.length + second.length);
        System.arraycopy(second, 0, both, first.length, second.length);
        return both;
    }

    private static void same(String expected, String actual) {
        if (!expected.equals(actual)) throw new AssertionError(expected + " != " + actual);
        checks++;
    }

    private static void equal(byte[] expected, byte[] actual) {
        if (!Arrays.equals(expected, actual)) throw new AssertionError("byte mismatch");
        checks++;
    }
}
