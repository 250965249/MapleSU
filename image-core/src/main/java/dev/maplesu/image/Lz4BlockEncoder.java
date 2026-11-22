package dev.maplesu.image;

import java.io.IOException;
import java.util.Arrays;

/** One independent LZ4 block, shared by the legacy and frame containers. */
final class Lz4BlockEncoder {
    private static final int HASH_BITS = 16;
    private static final int MAX_DISTANCE = 65535;
    private static final int MAX_BLOCK_BYTES = 8 * 1024 * 1024;

    private Lz4BlockEncoder() {}

    static byte[] encode(byte[] input, int start, int length) throws IOException {
        cancelled();
        if (start < 0 || length < 0 || length > MAX_BLOCK_BYTES || start > input.length - length)
            throw new IOException("INVALID_LZ4_BLOCK_SIZE");
        byte[] output = new byte[length + length / 255 + 16];
        int[] table = new int[1 << HASH_BITS];
        Arrays.fill(table, -1);
        int end = start + length, anchor = start, position = start, written = 0, checkpoint = start;
        // LZ4 requires five final literals and the last match to start at least twelve bytes
        // before the block end. These limits also keep every four-byte hash read in bounds.
        while (position <= end - 12) {
            if (position >= checkpoint) { cancelled(); checkpoint = position + 65536; }
            int word = readInt(input, position), slot = hash(word);
            int reference = table[slot];
            table[slot] = position;
            if (reference < start || position - reference > MAX_DISTANCE ||
                    readInt(input, reference) != word) {
                position++;
                continue;
            }
            int match = 4;
            while (position + match < end - 5 && input[reference + match] == input[position + match]) {
                match++;
                if ((match & 65535) == 0) cancelled();
            }
            int literals = position - anchor, extra = match - 4;
            output[written++] = (byte) ((Math.min(literals, 15) << 4) | Math.min(extra, 15));
            written = length(output, written, literals - 15);
            System.arraycopy(input, anchor, output, written, literals);
            written += literals;
            int distance = position - reference;
            output[written++] = (byte) distance;
            output[written++] = (byte) (distance >>> 8);
            written = length(output, written, extra - 15);
            position += match;
            anchor = position;
            if (position <= end - 12) table[hash(readInt(input, position - 2))] = position - 2;
        }
        cancelled();
        int literals = end - anchor;
        output[written++] = (byte) (Math.min(literals, 15) << 4);
        written = length(output, written, literals - 15);
        System.arraycopy(input, anchor, output, written, literals);
        return Arrays.copyOf(output, written + literals);
    }

    private static int length(byte[] output, int position, int remaining) {
        if (remaining < 0) return position;
        while (remaining >= 255) { output[position++] = (byte) 255; remaining -= 255; }
        output[position++] = (byte) remaining;
        return position;
    }

    private static int hash(int word) { return (word * 0x9E3779B1) >>> (32 - HASH_BITS); }

    private static int readInt(byte[] data, int offset) {
        return (data[offset] & 255) | ((data[offset + 1] & 255) << 8) |
                ((data[offset + 2] & 255) << 16) | ((data[offset + 3] & 255) << 24);
    }

    private static void cancelled() throws IOException {
        if (Thread.currentThread().isInterrupted()) throw new IOException("CANCELLED");
    }
}
