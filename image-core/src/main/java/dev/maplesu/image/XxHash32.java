package dev.maplesu.image;

/**
 * XXH32 (seed 0) for the LZ4 frame header checksum. Only the 8..15 bit of the digest is stored by
 * the frame format; the full 32-bit value is used by the encoder self-test.
 *
 * <p>Implemented from the published algorithm; no native code and no dependency.
 */
final class XxHash32 {
    private static final int PRIME1 = 0x9E3779B1;
    private static final int PRIME2 = 0x85EBCA77;
    private static final int PRIME3 = 0xC2B2AE3D;
    private static final int PRIME4 = 0x27D4EB2F;
    private static final int PRIME5 = 0x165667B1;

    private XxHash32() {}

    static int hash(byte[] data, int start, int length) {
        int index = start, end = start + length;
        int result;
        if (length >= 16) {
            int v1 = PRIME1 + PRIME2, v2 = PRIME2, v3 = 0, v4 = -PRIME1;
            int limit = end - 16;
            while (index <= limit) {
                v1 = round(v1, readInt(data, index));
                v2 = round(v2, readInt(data, index + 4));
                v3 = round(v3, readInt(data, index + 8));
                v4 = round(v4, readInt(data, index + 12));
                index += 16;
            }
            result = Integer.rotateLeft(v1, 1) + Integer.rotateLeft(v2, 7)
                    + Integer.rotateLeft(v3, 12) + Integer.rotateLeft(v4, 18);
        } else {
            result = PRIME5;
        }
        result += length;
        while (index + 4 <= end) {
            result = Integer.rotateLeft(result + readInt(data, index) * PRIME3, 17) * PRIME4;
            index += 4;
        }
        while (index < end) {
            result = Integer.rotateLeft(result + (data[index] & 255) * PRIME5, 11) * PRIME1;
            index++;
        }
        result ^= result >>> 15;
        result *= PRIME2;
        result ^= result >>> 13;
        result *= PRIME3;
        result ^= result >>> 16;
        return result;
    }

    /** The single byte an LZ4 frame stores as header checksum. */
    static int frameHeaderChecksum(byte[] descriptor, int start, int length) {
        return (hash(descriptor, start, length) >>> 8) & 255;
    }

    private static int round(int accumulator, int lane) {
        return Integer.rotateLeft(accumulator + lane * PRIME2, 13) * PRIME1;
    }

    private static int readInt(byte[] data, int offset) {
        return (data[offset] & 255) | ((data[offset + 1] & 255) << 8)
                | ((data[offset + 2] & 255) << 16) | ((data[offset + 3] & 255) << 24);
    }
}
