package dev.maplesu.image;

import java.io.IOException;
import java.util.Arrays;
import java.util.Random;

/** Independent native-libzstd compressed-block fixtures through the actual component writer. */
public final class ZstdCompressedTest {
    private static int checks, failures;
    private static final String[] FILES = {"kernel-1.zst", "kernel-3.zst", "kernel-19.zst",
            "kernel-unknown.zst", "kernel-window27.zst", "kernel-concat.zst",
            "multi.zst", "multi-unknown.zst", "text.zst", "rle-literals.zst"};

    private static byte[] fixture(String name) throws Exception {
        try (var input = ZstdCompressedTest.class.getResourceAsStream("/zstd-compressed/" + name)) {
            if (input == null) throw new IOException("MISSING_FIXTURE:" + name);
            return input.readAllBytes();
        }
    }

    private static byte[] join(byte[] first, byte[] second) {
        byte[] both = Arrays.copyOf(first, first.length + second.length);
        System.arraycopy(second, 0, both, first.length, second.length);
        return both;
    }

    private static void equal(byte[] expected, byte[] actual, String label) {
        checks++;
        if (!Arrays.equals(expected, actual)) throw new AssertionError(label);
    }

    private static void valid(String name) throws Exception {
        String rawName = name.startsWith("multi") ? "multi.raw" : name.startsWith("text") ? "text.raw"
                : name.startsWith("rle-literals") ? "rle-literals.raw" : "kernel.raw";
        byte[] raw = fixture(rawName), input = fixture(name), original = input.clone();
        equal(raw, KernelCompression.decode(input, "ZSTD", raw.length), name + " incomplete decoded payload");
        byte[] changed = raw.clone(); changed[Math.min(1024, raw.length - 1)] ^= 42;
        for (byte[] tail : new byte[][]{new byte[0], new byte[]{1}, new byte[]{(byte)0xd0,0x0d,(byte)0xfe,(byte)0xed,1,2,3}}) {
            byte[] component = KernelCompression.encodeKernelComponent(changed, join(input, tail), "ZSTD");
            equal(join(KernelCompression.encode(changed, "ZSTD"), tail), component, name + " component tail");
            equal(changed, KernelCompression.decode(component, "ZSTD", raw.length), name + " changed payload");
        }
        try {
            KernelCompression.decode(input, "ZSTD", raw.length - 1);
            throw new AssertionError(name + " output limit ignored");
        } catch (IOException error) {
            if (!"DECOMPRESSION_LIMIT".equals(error.getMessage())) throw error;
            checks++;
        }
        equal(original, input, name + " input changed");
        // Every original has a checksum; accepted mutations must preserve the complete payload.
        Random random = new Random(name.hashCode());
        for (int index = 0; index < 96; index++) {
            byte[] mutated = input.clone();
            int at = index < 12 ? Math.min(index, input.length - 1)
                    : index < 20 ? input.length - 1 - (index - 12) : random.nextInt(input.length);
            mutated[at] ^= (byte) (1 << random.nextInt(8));
            try { equal(raw, KernelCompression.decode(mutated, "ZSTD", raw.length), name + " unchecked corruption at " + at); }
            catch (IOException expected) { checks++; }
        }
        for (int size : new int[]{0,1,4,8,input.length / 2,input.length - 1})
            rejects(Arrays.copyOf(input, size), null);
        for (int index = 0; index < 32; index++) {
            byte[] mutated = input.clone();
            mutated[input.length - 4 + index / 8] ^= (byte)(1 << (index % 8));
            rejects(mutated, "INVALID_ZSTD_CONTENT_CHECKSUM");
        }
    }

    private static void rejects(byte[] input, String code) throws Exception {
        try {
            KernelCompression.decode(input, "ZSTD", KernelCompression.MAX_KERNEL_BYTES);
            throw new AssertionError("accepted invalid compressed input " + code);
        } catch (IOException error) {
            if (code != null && !code.equals(error.getMessage())) throw error;
            checks++;
        }
        try {
            KernelCompression.encodeKernelComponent(new byte[]{1}, input, "ZSTD");
            throw new AssertionError("rewrote invalid compressed input " + code);
        } catch (IOException error) {
            if (code != null && !code.equals(error.getMessage())) throw error;
            checks++;
        }
    }

    public static void main(String[] args) throws Exception {
        for (String name : FILES) {
            try { valid(name); }
            catch (Exception | AssertionError error) {
                failures++; System.err.println("FAIL " + name + ": " + error);
            }
        }
        byte[] oversizedWindow = fixture("kernel-window27.zst"); oversizedWindow[5] = (byte)((28 - 10) << 3);
        rejects(oversizedWindow, "ZSTD_WINDOW_LIMIT");
        byte[] missingTable = {0x28,(byte)0xb5,0x2f,(byte)0xfd,0x20,64,29,0,0,3,0,0};
        rejects(missingTable, "INVALID_ZSTD_COMPRESSED_BLOCK");
        byte[] valid = fixture("kernel-3.zst");
        rejects(join(valid, missingTable), "INVALID_ZSTD_COMPRESSED_BLOCK");
        Random random = new Random(20261116);
        for (int index = 0; index < 500; index++) {
            byte[] body = new byte[3 + random.nextInt(64)]; random.nextBytes(body);
            byte[] frame = Arrays.copyOf(missingTable, 9 + body.length);
            int header = (body.length << 3) | 5;
            for (int i = 0; i < 3; i++) frame[6 + i] = (byte)(header >>> (8 * i));
            frame[5] = (byte)128;
            System.arraycopy(body, 0, frame, 9, body.length);
            try { KernelCompression.decode(frame, "ZSTD", 1024); checks++; }
            catch (IOException expected) { checks++; }
        }
        Thread.currentThread().interrupt();
        try { rejects(fixture("kernel-3.zst"), "CANCELLED"); }
        finally { Thread.interrupted(); }
        System.out.println("ZstdCompressedTest: " + checks + " checks, " + failures + " failures");
        if (failures != 0) throw new AssertionError("zstd compressed block regression");
    }
}
