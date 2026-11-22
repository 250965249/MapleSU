package dev.maplesu.image;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

/** Independent libzstd checksum vectors, consumed through the public kernel decoder. */
public final class ZstdIntegrityTest {
    private static int checks, failures;

    private static byte[] hex(String value) {
        byte[] bytes = new byte[value.length() / 2];
        for (int i = 0; i < bytes.length; i++)
            bytes[i] = (byte) Integer.parseInt(value.substring(i * 2, i * 2 + 2), 16);
        return bytes;
    }

    private static byte[] join(byte[]... values) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        for (byte[] value : values) output.write(value);
        return output.toByteArray();
    }

    private static void check(boolean value, String label) {
        checks++;
        if (!value) {
            failures++;
            System.err.println("FAIL " + label);
        }
    }

    private static void accepts(byte[] input, byte[] expected, String label) {
        try {
            check(Arrays.equals(expected, KernelCompression.decode(input, "ZSTD", 2 * 1024 * 1024)), label);
        } catch (Exception error) {
            check(false, label + ": " + error.getMessage());
        }
    }

    private static void rejects(byte[] input, String code, String label) {
        try {
            KernelCompression.decode(input, "ZSTD", 2 * 1024 * 1024);
            check(false, label + ": accepted");
        } catch (IOException error) {
            check(code.equals(error.getMessage()), label + ": " + error.getMessage());
        }
    }

    public static void main(String[] args) throws Exception {
        byte[] abc = hex("28b52ffd2403190000616263990977ad");
        byte[] sequence = new byte[40];
        for (int i = 0; i < sequence.length; i++) sequence[i] = (byte) i;
        byte[] longFrame = hex("28b52ffd2428410100000102030405060708090a0b0c0d0e0f"
                + "101112131415161718191a1b1c1d1e1f2021222324252627e94117b1");
        byte[] repeated = new byte[64];
        Arrays.fill(repeated, (byte) 'A');
        byte[] rle = hex("28b52ffd244003020041bddeb0ad");
        accepts(abc, new byte[]{'a', 'b', 'c'}, "raw external vector");
        accepts(longFrame, sequence, "XXH64 stripe external vector");
        accepts(rle, repeated, "RLE external checksum");
        accepts(join(abc, longFrame), join(new byte[]{'a', 'b', 'c'}, sequence), "per-frame checksum start");
        accepts(join(hex("502a4d1803000000666f6f"), abc), new byte[]{'a', 'b', 'c'}, "skippable frame");
        byte[] zeroDictionary = join(hex("28b52ffd250003"), Arrays.copyOfRange(abc, 6, abc.length));
        accepts(zeroDictionary, new byte[]{'a', 'b', 'c'}, "explicit zero dictionary ID");
        byte[] nonzeroDictionary = zeroDictionary.clone();
        nonzeroDictionary[5] = 1;
        rejects(nonzeroDictionary, "UNSUPPORTED_ZSTD_DICTIONARY", "nonzero dictionary remains unsupported");
        accepts(join(hex("28b52ffd0400"), Arrays.copyOfRange(abc, 6, abc.length)),
                new byte[]{'a', 'b', 'c'}, "unknown content size");
        int vector = 0;
        for (byte[] frame : new byte[][]{abc, longFrame, rle}) {
            for (int bit = 0; bit < 32; bit++) {
                byte[] bad = frame.clone();
                bad[bad.length - 4 + bit / 8] ^= (byte) (1 << (bit % 8));
                rejects(bad, "INVALID_ZSTD_CONTENT_CHECKSUM", "checksum " + vector + ":" + bit);
            }
            byte[] bad = frame.clone();
            bad[9] ^= 1;
            rejects(bad, "INVALID_ZSTD_CONTENT_CHECKSUM", "content " + vector);
            vector++;
        }
        byte[] secondBad = longFrame.clone();
        secondBad[secondBad.length - 1] ^= 1;
        rejects(join(abc, secondBad), "INVALID_ZSTD_CONTENT_CHECKSUM", "second-frame corruption");
        rejects(Arrays.copyOf(abc, abc.length - 1), "TRUNCATED_ZSTD_CHECKSUM", "short checksum");
        rejects(hex("28b52ffde00100000000000080190000616263"), "DECOMPRESSION_LIMIT", "unsigned FCS high bit");
        byte[] oversized = new byte[131073];
        rejects(join(hex("28b52ffda001000200090010"), oversized),
                "INVALID_ZSTD_BLOCK_SIZE", "raw block over 128 KiB");
        rejects(join(hex("28b52ffd0000092000"), new byte[1025]),
                "INVALID_ZSTD_BLOCK_SIZE", "raw block over window");
        if (args.length != 0) {
            for (String row : Files.readAllLines(Path.of(args[0]))) {
                String[] columns = row.split("\\|");
                byte[] frame = Files.readAllBytes(Path.of(columns[0]));
                byte[] expected = Files.readAllBytes(Path.of(columns[1]));
                accepts(frame, expected, "external " + columns[0]);
                frame[frame.length - 1] ^= 1;
                rejects(frame, "INVALID_ZSTD_CONTENT_CHECKSUM", "external corrupt " + columns[0]);
            }
        }
        System.out.println("ZstdIntegrityTest: " + checks + " checks, " + failures + " failures");
        if (failures != 0) throw new AssertionError("ZSTD integrity regression");
    }
}
