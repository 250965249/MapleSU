package dev.maplesu.image;

import java.io.IOException;
import java.util.Arrays;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.zip.CRC32;

/** Independent liblzma/liblz4 fixtures cover whole-stream consumption, not only the first frame. */
public final class KernelStreamCompatibilityTest {
    private static int checks, failures;
    private static final String[] FILES = {"arm64-0.xz", "arm64-4096.xz", "arm64-4294967292.xz",
            "arm64-blocks.xz", "delta.xz", "arm64-delta.xz", "four-filters.xz", "arm64-crc64.xz",
            "arm64-sha256.xz", "plain-blocks.xz", "concat.xz", "concat.lz4"};

    private static byte[] fixture(String name) throws IOException {
        try (var input = KernelStreamCompatibilityTest.class.getResourceAsStream("/kernel-streams/" + name)) {
            if (input == null) throw new IOException("MISSING_FIXTURE:" + name);
            return input.readAllBytes();
        }
    }

    private static byte[] join(byte[] first, byte[] second) {
        byte[] bytes = Arrays.copyOf(first, first.length + second.length);
        System.arraycopy(second, 0, bytes, first.length, second.length);
        return bytes;
    }

    private static void equal(byte[] expected, byte[] actual, String label) {
        checks++;
        if (!Arrays.equals(expected, actual)) throw new AssertionError(label);
    }

    private static void valid(String name, byte[] raw) throws Exception {
        String format = name.endsWith("xz") ? "XZ" : "LZ4_FRAME";
        byte[] input = fixture(name), frozen = input.clone();
        equal(raw, KernelCompression.decode(input, format, raw.length), name + " incomplete decoded image");
        byte[] changed = raw.clone(); changed[1024] ^= 42;
        for (byte[] tail : new byte[][]{new byte[0], new byte[]{1},
                new byte[]{(byte) 0xd0,0x0d,(byte) 0xfe,(byte) 0xed,1,2,3}}) {
            byte[] component = join(input, tail);
            byte[] rebuilt = KernelCompression.encodeKernelComponent(changed, component, format);
            equal(join(KernelCompression.encode(changed, format), tail), rebuilt, name + " tail changed");
            equal(changed, KernelCompression.decode(rebuilt, format, raw.length), name + " rebuilt payload");
        }
        try {
            KernelCompression.decode(input, format, raw.length - 1);
            throw new AssertionError(name + " total decode limit ignored");
        } catch (IOException expected) {
            if (!"DECOMPRESSION_LIMIT".equals(expected.getMessage())) throw expected;
            checks++;
        }
        equal(frozen, input, name + " input changed");
        for (int length : new int[]{4,24,input.length / 2,input.length - 1})
            rejects(Arrays.copyOf(input, length), format, null);
    }

    private static void rejects(byte[] input, String format, String code) throws Exception {
        try {
            KernelCompression.decode(input, format, KernelCompression.MAX_KERNEL_BYTES);
            throw new AssertionError("accepted malformed " + format + ": " + code);
        } catch (IOException error) {
            if (code != null && !code.equals(error.getMessage())) throw error;
            checks++;
        }
        try {
            KernelCompression.encodeKernelComponent(new byte[]{1}, input, format);
            throw new AssertionError("rewrote malformed " + format + ": " + code);
        } catch (IOException error) {
            if (code != null && !code.equals(error.getMessage())) throw error;
            checks++;
        }
    }

    private static byte[] badLz4(boolean crossFrame) throws Exception {
        byte[] prior = KernelCompression.encode(new byte[]{65}, "LZ4_FRAME");
        byte[] block = {0,1,0,0x50,66,67,68,69,70};
        byte[] next = Arrays.copyOf(prior, 7 + 4 + block.length + 4);
        ByteBuffer.wrap(next).order(ByteOrder.LITTLE_ENDIAN).putInt(7, block.length);
        System.arraycopy(block, 0, next, 11, block.length);
        Arrays.fill(next, 11 + block.length, next.length, (byte) 0);
        return crossFrame ? join(prior, next) : join(Arrays.copyOf(prior, prior.length - 4),
                Arrays.copyOfRange(next, 7, next.length));
    }

    private static void crc(byte[] data, int start, int checksum) {
        CRC32 crc = new CRC32(); crc.update(data, start, checksum - start);
        ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN).putInt(checksum, (int) crc.getValue());
    }

    private static void malformedXz() throws Exception {
        byte[] input = KernelCompression.encode(new byte[17], "XZ");
        int footer = input.length - 12;
        int index = footer - (ByteBuffer.wrap(input).order(ByteOrder.LITTLE_ENDIAN).getInt(footer + 4) + 1) * 4;
        byte[] broken = input.clone(); broken[index + 3] ^= 1;
        crc(broken, index, footer - 4);
        rejects(broken, "XZ", "INVALID_XZ_INDEX");
        broken = input.clone(); broken[6] = 1; crc(broken, 6, 8);
        rejects(broken, "XZ", "INVALID_XZ_STREAM_FLAGS");
        broken = fixture("arm64-4096.xz"); broken[16] |= 1;
        crc(broken, 12, 12 + ((broken[12] & 255) + 1) * 4 - 4);
        rejects(broken, "XZ", "INVALID_XZ_FILTER_PROPERTIES");
        byte[] first = KernelCompression.encode(new byte[]{1,2,3}, "XZ");
        rejects(join(join(first, new byte[]{0}), input), "XZ", "INVALID_XZ_STREAM_PADDING");
        broken = input.clone(); broken[broken.length - 12] ^= 1;
        rejects(join(first, broken), "XZ", "INVALID_XZ_FOOTER_CHECKSUM");
    }

    private static void checkedLz4() throws Exception {
        byte[] frame;
        try (var stream = KernelStreamCompatibilityTest.class.getResourceAsStream("/ramdisk-codecs/stock-checksums.cpio.lz4")) {
            frame = stream.readAllBytes();
        }
        byte[] raw = KernelCompression.decode(frame, "LZ4_FRAME", 4096);
        equal(join(raw, raw), KernelCompression.decode(join(frame, frame), "LZ4_FRAME", raw.length * 2),
                "each concatenated frame checks its own content");
        byte[] broken = frame.clone(); broken[broken.length - 1] ^= 1;
        rejects(join(frame, broken), "LZ4_FRAME", "INVALID_LZ4_FRAME_CONTENT_CHECKSUM");
        byte[] skip = {0x50,0x2a,0x4d,0x18,3,0,0,0,1};
        rejects(join(frame, skip), "LZ4_FRAME", "TRUNCATED_LZ4_SKIPPABLE_FRAME");
    }

    private static void mutations(byte[] raw) throws Exception {
        java.util.Random random = new java.util.Random(20261116);
        for (String name : FILES) {
            byte[] original = fixture(name);
            String format = name.endsWith("xz") ? "XZ" : "LZ4_FRAME";
            for (int index = 0; index < 36; index++) {
                byte[] changed = original.clone();
                int at = index < 8 ? index : index < 16 ? changed.length - 1 - (index - 8) : random.nextInt(changed.length);
                changed[at] ^= (byte) (1 << random.nextInt(8));
                try {
                    byte[] decoded = KernelCompression.decode(changed, format, raw.length);
                    if ("XZ".equals(format)) equal(raw, decoded, name + " unchecked changed payload");
                    // This external LZ4 vector has no content checksum; a changed payload can be valid.
                    else {
                        if (decoded.length > raw.length) throw new AssertionError("decode limit ignored");
                        checks++;
                    }
                } catch (IOException expected) { checks++; }
            }
        }
    }

    public static void main(String[] args) throws Exception {
        byte[] raw = fixture("arm64.raw");
        for (String name : FILES) {
            try { valid(name, raw); }
            catch (Exception | AssertionError error) {
                failures++; System.err.println("FAIL " + name + ": " + error);
            }
        }
        for (boolean crossFrame : new boolean[]{true, false}) {
            try { rejects(badLz4(crossFrame), "LZ4_FRAME", "INVALID_LZ4_FRAME_OFFSET"); }
            catch (Exception | AssertionError error) {
                failures++; System.err.println("FAIL lz4 history boundary " + crossFrame + ": " + error);
            }
        }
        malformedXz();
        checkedLz4();
        mutations(raw);
        System.out.println("KernelStreamCompatibilityTest: " + checks + " checks, " + failures + " failures");
        if (failures != 0) throw new AssertionError("compressed stream compatibility regression");
    }
}
