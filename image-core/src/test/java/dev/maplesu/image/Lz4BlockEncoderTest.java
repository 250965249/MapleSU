package dev.maplesu.image;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Random;

/** Ordinary codec bytes only; optional output fixtures are for independent host decoders. */
public final class Lz4BlockEncoderTest {
    private static int checks;

    private static void check(boolean value, String message) {
        if (!value) throw new AssertionError(message);
        checks++;
    }

    private static int u32(byte[] bytes, int at) {
        return ByteBuffer.wrap(bytes, at, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
    }

    /** Checks format endings and match ranges separately from the production decoder. */
    private static int shape(byte[] bytes, int expected) {
        int in = 0, out = 0, lastMatch = -1, finalLiterals = -1, maxDistance = 0;
        while (in < bytes.length) {
            int token = bytes[in++] & 255;
            int literals = token >>> 4;
            if (literals == 15) {
                int next;
                do { next = bytes[in++] & 255; literals += next; } while (next == 255);
            }
            check(literals <= bytes.length - in, "Literal range remains in encoded block");
            in += literals;
            out += literals;
            if (in == bytes.length) { finalLiterals = literals; break; }
            check(bytes.length - in >= 2, "Match offset is present");
            int distance = (bytes[in] & 255) | ((bytes[in + 1] & 255) << 8);
            in += 2;
            check(distance > 0 && distance <= Math.min(65535, out), "Match uses the block's 64K history");
            maxDistance = Math.max(maxDistance, distance);
            lastMatch = out;
            int match = (token & 15) + 4;
            if ((token & 15) == 15) {
                int next;
                do { next = bytes[in++] & 255; match += next; } while (next == 255);
            }
            out += match;
        }
        check(out == expected && in == bytes.length, "Encoded block produces exactly the input length");
        check(finalLiterals >= 0 && (lastMatch < 0 || finalLiterals >= 5), "Final sequence has five literal bytes after matches");
        check(lastMatch < 0 || expected - lastMatch >= 12, "Last match starts twelve bytes before block end");
        return maxDistance;
    }

    private static byte[] legacy(byte[] block) {
        return ByteBuffer.allocate(8 + block.length).order(ByteOrder.LITTLE_ENDIAN)
                .putInt(0x184c2102).putInt(block.length).put(block).array();
    }

    private static byte[] compressible(int size) {
        byte[] bytes = new byte[size];
        for (int i = 0; i < size; i++) bytes[i] = (byte) (i % 127);
        return bytes;
    }

    private static void blockRoundTrip(byte[] raw) throws Exception {
        byte[] before = raw.clone();
        byte[] block = Lz4BlockEncoder.encode(raw, 0, raw.length);
        shape(block, raw.length);
        check(block.length <= raw.length + raw.length / 255 + 16, "Compression stays within block bound");
        if (raw.length > 0) check(Arrays.equals(raw,
                KernelCompression.decode(legacy(block), "LZ4_LEGACY", raw.length)), "Block roundtrip");
        check(Arrays.equals(before, raw), "Encoding preserves source bytes");
    }

    private static void containerRoundTrip(byte[] raw) throws Exception {
        for (String format : new String[]{"LZ4_LEGACY", "LZ4_FRAME"}) {
            byte[] encoded = KernelCompression.encode(raw, format);
            check(Arrays.equals(raw, KernelCompression.decode(encoded, format, raw.length)), format + " roundtrip");
        }
    }

    private static void rejects(int start, int length) throws Exception {
        try {
            Lz4BlockEncoder.encode(new byte[32], start, length);
            throw new AssertionError("Invalid source range accepted");
        } catch (IOException expected) {
            check("INVALID_LZ4_BLOCK_SIZE".equals(expected.getMessage()), "Invalid source range reported");
        }
    }

    private static void fixtures(Path directory) throws Exception {
        Files.createDirectories(directory);
        for (int size : new int[]{1, 15, 270, 65536, 8388625}) {
            byte[] raw = compressible(size);
            String name = "repeated-" + size;
            Files.write(directory.resolve(name + ".raw"), raw);
            if (size <= 8 * 1024 * 1024)
                Files.write(directory.resolve(name + ".block"), Lz4BlockEncoder.encode(raw, 0, raw.length));
            Files.write(directory.resolve(name + ".legacy"), KernelCompression.encode(raw, "LZ4_LEGACY"));
            Files.write(directory.resolve(name + ".frame"), KernelCompression.encode(raw, "LZ4_FRAME"));
        }
        byte[] random = new byte[100003];
        new Random(515).nextBytes(random);
        Files.write(directory.resolve("random.raw"), random);
        Files.write(directory.resolve("random.block"), Lz4BlockEncoder.encode(random, 0, random.length));
        Files.write(directory.resolve("random.legacy"), KernelCompression.encode(random, "LZ4_LEGACY"));
        Files.write(directory.resolve("random.frame"), KernelCompression.encode(random, "LZ4_FRAME"));
    }

    public static void main(String[] args) throws Exception {
        for (int size : new int[]{0, 1, 4, 11, 12, 13, 14, 15, 16, 19, 20, 269, 270, 271,
                65534, 65535, 65536, 65537, 131073, 4 * 1024 * 1024, 8 * 1024 * 1024}) {
            blockRoundTrip(compressible(size));
            blockRoundTrip(new byte[size]);
            byte[] random = new byte[size]; new Random(size).nextBytes(random); blockRoundTrip(random);
        }
        byte[] withEdges = new byte[65577];
        for (int i = 0; i < 24; i++) withEdges[i] = (byte) (i + 1);
        System.arraycopy(withEdges, 0, withEdges, 65535, 24);
        blockRoundTrip(withEdges);
        check(shape(Lz4BlockEncoder.encode(withEdges, 0, withEdges.length), withEdges.length) == 65535,
                "Maximum nonzero 16-bit match offset is represented");
        byte[] region = compressible(70000);
        byte[] block = Lz4BlockEncoder.encode(region, 17, region.length - 37);
        shape(block, region.length - 37);
        check(Arrays.equals(Arrays.copyOfRange(region, 17, region.length - 20),
                KernelCompression.decode(legacy(block), "LZ4_LEGACY", region.length)), "Subrange excludes outside bytes");
        for (int size : new int[]{4194303, 4194304, 4194305, 8388607, 8388608, 8388609})
            containerRoundTrip(compressible(size));
        byte[] repeated = compressible(1024 * 1024);
        for (String format : new String[]{"LZ4_LEGACY", "LZ4_FRAME"})
            check(KernelCompression.encode(repeated, format).length < repeated.length / 20, format + " compresses repeated input");
        byte[] random = new byte[100003]; new Random(515).nextBytes(random);
        byte[] frame = KernelCompression.encode(random, "LZ4_FRAME");
        check(u32(frame, 7) < 0, "Incompressible frame block remains stored");
        check(u32(KernelCompression.encode(repeated, "LZ4_FRAME"), 7) > 0, "Compressible frame uses a compressed block");
        byte[] original = KernelCompression.encode(repeated, "LZ4_FRAME"), tail = {1, 7, 9, 11};
        byte[] input = Arrays.copyOf(original, original.length + tail.length);
        System.arraycopy(tail, 0, input, original.length, tail.length);
        repeated[12345] ^= 19;
        byte[] encoded = KernelCompression.encodeKernelComponent(repeated, input, "LZ4_FRAME");
        check(Arrays.equals(tail, Arrays.copyOfRange(encoded, encoded.length - tail.length, encoded.length)), "Component tail retained");
        check(Arrays.equals(repeated, KernelCompression.decode(encoded, "LZ4_FRAME", repeated.length)), "Changed component decodes");
        rejects(-1, 1); rejects(0, -1); rejects(31, 2); rejects(0, 8 * 1024 * 1024 + 1);
        Thread.currentThread().interrupt();
        try {
            Lz4BlockEncoder.encode(new byte[32], 0, 32);
            throw new AssertionError("Cancellation ignored");
        } catch (IOException expected) {
            check("CANCELLED".equals(expected.getMessage()) && Thread.currentThread().isInterrupted(), "Cancellation preserved");
        } finally { Thread.interrupted(); }
        if (args.length == 1) fixtures(Path.of(args[0]));
        else check(args.length == 0, "Only optional reference output directory accepted");
        System.out.println("Lz4BlockEncoder: " + checks + " checks passed");
    }
}
