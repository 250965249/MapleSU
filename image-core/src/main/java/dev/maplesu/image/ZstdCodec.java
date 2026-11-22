package dev.maplesu.image;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import dev.maplesu.image.zstd.ZstdBlockDecoder;
import dev.maplesu.image.zstd.MalformedInputException;

/**
 * Zstandard frame decoder plus a stored-block encoder. Pure Java, bounded, no native code.
 *
 * <p>Decoding accepts the standard frame header (window descriptor, optional dictionary id, optional
 * frame content size, optional content checksum), raw and RLE blocks, skippable frames, and several
 * concatenated frames. Compressed blocks use a pinned Apache-2.0 Huffman/FSE decoder with portable
 * byte-array access; the framing, checksums, limits and opaque-tail boundary stay here.
 *
 * <p>Encoding writes raw blocks ({@code Block_Type = 0}), which every zstd decoder accepts: it keeps
 * the rebuild path auditable instead of bundling a second compressor.
 */
final class ZstdCodec {
    private static final int MAGIC = 0xFD2FB528;
    private static final int SKIPPABLE_LOW = 0x184D2A50, SKIPPABLE_HIGH = 0x184D2A5F;
    private static final int BLOCK_MAX = 128 * 1024;
    private static final long PRIME1 = 0x9E3779B185EBCA87L, PRIME2 = 0xC2B2AE3D27D4EB4FL;
    private static final long PRIME3 = 0x165667B19E3779F9L, PRIME4 = 0x85EBCA77C2B2AE63L;
    private static final long PRIME5 = 0x27D4EB2F165667C5L;

    private ZstdCodec() {}

    static boolean matches(byte[] data) {
        return data.length >= 4 && (data[0] & 255) == 40 && (data[1] & 255) == 181
                && (data[2] & 255) == 47 && (data[3] & 255) == 253;
    }

    static byte[] decode(byte[] input, int limit) throws IOException {
        return decode(input, limit, null);
    }

    static byte[] decode(byte[] input, int limit, int[] consumed) throws IOException {
        byte[] output = new byte[Math.min(limit, 1 << 16)];
        int produced = 0, position = 0;
        boolean frame = false;
        while (position < input.length) {
            cancelled();
            if (input.length - position < 4) {
                if (frame) break;
                throw new IOException("TRUNCATED_ZSTD");
            }
            int magic = readInt(input, position);
            if (magic >= SKIPPABLE_LOW && magic <= SKIPPABLE_HIGH) {
                position += 4;
                if (input.length - position < 4) throw new IOException("TRUNCATED_ZSTD");
                long size = readInt(input, position) & 0xFFFFFFFFL;
                position += 4;
                if (size > input.length - position) throw new IOException("TRUNCATED_ZSTD");
                position += (int) size;
                continue;
            }
            if (magic != MAGIC) {
                if (frame) break;                       // trailing non-zstd bytes: stop, do not guess
                throw new IOException("INVALID_ZSTD_MAGIC");
            }
            position += 4;
            frame = true;
            if (position >= input.length) throw new IOException("TRUNCATED_ZSTD_HEADER");
            int descriptor = input[position++] & 255;
            int fcsFlag = descriptor >>> 6;
            boolean singleSegment = (descriptor & 0x20) != 0;
            boolean checksum = (descriptor & 0x04) != 0;
            int dictionaryFlag = descriptor & 3;
            if ((descriptor & 0x08) != 0) throw new IOException("INVALID_ZSTD_HEADER");
            long windowSize = 0;
            if (!singleSegment) {
                if (position >= input.length) throw new IOException("TRUNCATED_ZSTD_HEADER");
                int windowDescriptor = input[position++] & 255;
                long windowBase = 1L << (10 + (windowDescriptor >>> 3));
                windowSize = windowBase + (windowBase >>> 3) * (windowDescriptor & 7);
            }
            int dictionaryBytes = dictionaryFlag == 3 ? 4 : dictionaryFlag;
            if (dictionaryBytes > input.length - position) throw new IOException("TRUNCATED_ZSTD_HEADER");
            if (readLe(input, position, dictionaryBytes) != 0) throw new IOException("UNSUPPORTED_ZSTD_DICTIONARY");
            position += dictionaryBytes;
            int contentSizeBytes = fcsFlag == 0 ? (singleSegment ? 1 : 0)
                    : fcsFlag == 1 ? 2 : fcsFlag == 2 ? 4 : 8;
            long contentSize = -1;
            if (contentSizeBytes > 0) {
                if (input.length - position < contentSizeBytes) throw new IOException("TRUNCATED_ZSTD_HEADER");
                contentSize = readLe(input, position, contentSizeBytes) + (contentSizeBytes == 2 ? 256 : 0);
                position += contentSizeBytes;
                if (contentSize < 0 || contentSize > limit) throw new IOException("DECOMPRESSION_LIMIT");
            }
            int blockLimit = (int) Math.min(BLOCK_MAX, singleSegment ? contentSize : windowSize);
            long effectiveWindow = singleSegment ? contentSize : windowSize;
            int start = produced;
            ZstdBlockDecoder entropy = null;
            while (true) {
                cancelled();
                if (input.length - position < 3) throw new IOException("TRUNCATED_ZSTD_BLOCK");
                int header = (input[position] & 255) | ((input[position + 1] & 255) << 8)
                        | ((input[position + 2] & 255) << 16);
                position += 3;
                boolean last = (header & 1) != 0;
                int type = (header >>> 1) & 3;
                int size = header >>> 3;
                if (type != 3 && size > blockLimit) throw new IOException("INVALID_ZSTD_BLOCK_SIZE");
                if (type == 0) {
                    if (size > input.length - position) throw new IOException("TRUNCATED_ZSTD_BLOCK");
                    if (size > limit - produced) throw new IOException("DECOMPRESSION_LIMIT");
                    output = ensure(output, produced + size, limit);
                    System.arraycopy(input, position, output, produced, size);
                    produced += size;
                    position += size;
                } else if (type == 1) {
                    if (size > limit - produced) throw new IOException("DECOMPRESSION_LIMIT");
                    output = ensure(output, produced + size, limit);
                    if (position >= input.length) throw new IOException("TRUNCATED_ZSTD_BLOCK");
                    Arrays.fill(output, produced, produced + size, input[position]);
                    produced += size;
                    position++;
                } else if (type == 2) {
                    if (size > input.length - position) throw new IOException("TRUNCATED_ZSTD_BLOCK");
                    if (effectiveWindow > MAX_WINDOW_BYTES) throw new IOException("ZSTD_WINDOW_LIMIT");
                    int capacity = Math.min(blockLimit, limit - produced);
                    output = ensure(output, produced + capacity, limit);
                    if (entropy == null) entropy = new ZstdBlockDecoder();
                    try {
                        int decoded = entropy.decodeCompressedBlock(input, position, size, output, produced,
                                produced + capacity, (int) effectiveWindow, start);
                        produced += decoded;
                    } catch (MalformedInputException error) {
                        if (error.getMessage().startsWith("Output buffer too small"))
                            throw new IOException(capacity < blockLimit ? "DECOMPRESSION_LIMIT" : "INVALID_ZSTD_BLOCK_SIZE", error);
                        throw new IOException("INVALID_ZSTD_COMPRESSED_BLOCK", error);
                    } catch (IndexOutOfBoundsException | IllegalArgumentException | ArithmeticException error) {
                        throw new IOException("INVALID_ZSTD_COMPRESSED_BLOCK", error);
                    }
                    position += size;
                } else {
                    throw new IOException("INVALID_ZSTD_BLOCK_TYPE");
                }
                if (last) break;
            }
            if (contentSize >= 0 && produced - start != contentSize) throw new IOException("INVALID_ZSTD_CONTENT_SIZE");
            if (checksum) {
                if (input.length - position < 4) throw new IOException("TRUNCATED_ZSTD_CHECKSUM");
                if ((int) contentHash(output, start, produced - start) != readInt(input, position))
                    throw new IOException("INVALID_ZSTD_CONTENT_CHECKSUM");
                position += 4;
            }
        }
        if (!frame) throw new IOException("INVALID_ZSTD_MAGIC");
        if (produced == 0) throw new IOException("EMPTY_KERNEL");
        if (consumed != null) consumed[0] = position;
        return Arrays.copyOf(output, produced);
    }

    /** Raw-block frame: valid zstd that any decoder accepts, sized within three bytes per 128 KiB. */
    static byte[] encode(byte[] raw) throws IOException {
        if (raw.length == 0) throw new IOException("EMPTY_KERNEL");
        int blocks = (raw.length + BLOCK_MAX - 1) / BLOCK_MAX;
        ByteArrayOutputStream output = new ByteArrayOutputStream(raw.length + blocks * 3 + 12);
        writeInt(output, MAGIC);
        output.write(0xA0);                             // single segment, fcsFlag 2 (4-byte content size), no checksum
        writeLe(output, raw.length, 4);
        for (int offset = 0; offset < raw.length; offset += BLOCK_MAX) {
            int length = Math.min(BLOCK_MAX, raw.length - offset);
            int header = (length << 3) | (offset + length >= raw.length ? 1 : 0);
            output.write(header & 255);
            output.write((header >>> 8) & 255);
            output.write((header >>> 16) & 255);
            output.write(raw, offset, length);
        }
        return output.toByteArray();
    }

    private static byte[] ensure(byte[] buffer, int required, int limit) throws IOException {
        if (required > limit) throw new IOException("DECOMPRESSION_LIMIT");
        if (required <= buffer.length) return buffer;
        int capacity = Math.max(required, (int) Math.min(limit, Math.max(1024L, (long) buffer.length * 2)));
        return Arrays.copyOf(buffer, capacity);
    }

    private static final int MAX_WINDOW_BYTES = KernelCompression.MAX_KERNEL_BYTES;

    private static void cancelled() throws IOException {
        if (Thread.currentThread().isInterrupted()) throw new IOException("CANCELLED");
    }

    /** XXH64 seed 0, over this frame's decoded bytes only. The frame stores its low 32 bits. */
    private static long contentHash(byte[] data, int start, int length) {
        int index = start, end = start + length;
        long hash;
        if (length >= 32) {
            long v1 = PRIME1 + PRIME2, v2 = PRIME2, v3 = 0, v4 = -PRIME1;
            do {
                v1 = hashRound(v1, readLe(data, index, 8));
                v2 = hashRound(v2, readLe(data, index + 8, 8));
                v3 = hashRound(v3, readLe(data, index + 16, 8));
                v4 = hashRound(v4, readLe(data, index + 24, 8));
                index += 32;
            } while (index <= end - 32);
            hash = Long.rotateLeft(v1, 1) + Long.rotateLeft(v2, 7)
                    + Long.rotateLeft(v3, 12) + Long.rotateLeft(v4, 18);
            hash = hashMerge(hash, v1);
            hash = hashMerge(hash, v2);
            hash = hashMerge(hash, v3);
            hash = hashMerge(hash, v4);
        } else {
            hash = PRIME5;
        }
        hash += length;
        while (index <= end - 8) {
            hash = Long.rotateLeft(hash ^ hashRound(0, readLe(data, index, 8)), 27) * PRIME1 + PRIME4;
            index += 8;
        }
        if (index <= end - 4) {
            hash = Long.rotateLeft(hash ^ (readLe(data, index, 4) * PRIME1), 23) * PRIME2 + PRIME3;
            index += 4;
        }
        while (index < end) {
            hash = Long.rotateLeft(hash ^ ((data[index++] & 255L) * PRIME5), 11) * PRIME1;
        }
        hash ^= hash >>> 33;
        hash *= PRIME2;
        hash ^= hash >>> 29;
        hash *= PRIME3;
        return hash ^ (hash >>> 32);
    }

    private static long hashRound(long accumulator, long lane) {
        return Long.rotateLeft(accumulator + lane * PRIME2, 31) * PRIME1;
    }

    private static long hashMerge(long hash, long lane) {
        return (hash ^ hashRound(0, lane)) * PRIME1 + PRIME4;
    }

    private static long readLe(byte[] data, int offset, int bytes) {
        long value = 0;
        for (int index = bytes - 1; index >= 0; index--) value = (value << 8) | (data[offset + index] & 255L);
        return value;
    }

    private static int readInt(byte[] data, int offset) {
        return (data[offset] & 255) | ((data[offset + 1] & 255) << 8)
                | ((data[offset + 2] & 255) << 16) | ((data[offset + 3] & 255) << 24);
    }

    private static void writeInt(ByteArrayOutputStream out, int value) {
        for (int index = 0; index < 4; index++) out.write((value >>> (index * 8)) & 255);
    }

    private static void writeLe(ByteArrayOutputStream out, long value, int bytes) {
        for (int index = 0; index < bytes; index++) out.write((int) (value >>> (index * 8)) & 255);
    }
}
