package dev.maplesu.image;

import java.io.IOException;
import java.util.Arrays;

/**
 * LZ4 frame format (v1.6.x) decoder and independent-block encoder. Pure Java, bounded, no native code.
 *
 * <p>Kernels in the wild use the frame format with independent blocks and (usually) block checksums;
 * this decoder accepts independent and linked blocks, raw and compressed blocks, optional content
 * size fields and optional block/content checksums. Header, block and content checksums are
 * verified; streams requiring an external dictionary are rejected. Encoding shares the independent
 * block compressor with legacy LZ4 and uses stored blocks when compression would not reduce size.
 */
final class Lz4FrameCodec {
    private static final int MAGIC = 0x184D2204;
    private static final int BLOCK_MAX = 4 * 1024 * 1024;
    /** FLG: version 01, block independence, no checksums, no content size, no dictionary. */
    private static final int ENCODE_FLAG = 0x60;
    /** BD: block maximum size code 7 (4 MiB). */
    private static final int ENCODE_BLOCK_DESCRIPTOR = 0x70;

    private Lz4FrameCodec() {}

    static boolean matches(byte[] data) {
        return data.length >= 4 && (data[0] & 255) == 4 && (data[1] & 255) == 34
                && (data[2] & 255) == 77 && (data[3] & 255) == 24;
    }

    static byte[] decode(byte[] input, int limit) throws IOException {
        return decode(input, limit, null);
    }

    static byte[] decode(byte[] input, int limit, int[] consumed) throws IOException {
        Buffer buffer = new Buffer(limit, 0);
        int position = decodeFrame(input, 0, buffer);
        while (input.length - position >= 4) {
            cancelled();
            int magic = readInt(input, position);
            if (magic == MAGIC) position = decodeFrame(input, position, buffer);
            else if (magic >= 0x184D2A50 && magic <= 0x184D2A5F) {
                if (input.length - position < 8) throw new IOException("TRUNCATED_LZ4_SKIPPABLE_FRAME");
                long size = readInt(input, position + 4) & 0xFFFFFFFFL;
                if (size > input.length - position - 8) throw new IOException("TRUNCATED_LZ4_SKIPPABLE_FRAME");
                position += 8 + (int) size;
            } else break;
        }
        if (buffer.size == 0) throw new IOException("EMPTY_KERNEL");
        if (consumed != null) consumed[0] = position;
        return buffer.toArray();
    }

    private static int decodeFrame(byte[] input, int start, Buffer buffer) throws IOException {
        cancelled();
        if (input.length - start < 7) throw new IOException("TRUNCATED_LZ4_FRAME");
        if (readInt(input, start) != MAGIC) throw new IOException("INVALID_LZ4_FRAME_MAGIC");
        int position = start + 4;
        int frameStart = buffer.size;
        int flags = input[position++] & 255;
        if ((flags >>> 6) != 1) throw new IOException("INVALID_LZ4_FRAME_VERSION");
        boolean blockChecksum = (flags & 0x10) != 0;
        boolean contentSizePresent = (flags & 0x08) != 0;
        boolean contentChecksum = (flags & 0x04) != 0;
        boolean dictionary = (flags & 0x01) != 0;
        if (position >= input.length) throw new IOException("TRUNCATED_LZ4_FRAME");
        int descriptor = input[position++] & 255;
        int code = (descriptor >>> 4) & 7;
        int maxBlock = code == 4 ? 64 * 1024 : code == 5 ? 256 * 1024
                : code == 6 ? 1024 * 1024 : code == 7 ? BLOCK_MAX : -1;
        if (maxBlock < 0) throw new IOException("INVALID_LZ4_FRAME_BLOCK_SIZE");
        long contentSize = -1;
        if (contentSizePresent) {
            if (position + 8 > input.length) throw new IOException("TRUNCATED_LZ4_FRAME");
            contentSize = readLong(input, position);
            position += 8;
            if (contentSize < 0) throw new IOException("INVALID_LZ4_FRAME_CONTENT_SIZE");
        }
        if (dictionary) throw new IOException("UNSUPPORTED_LZ4_FRAME_DICTIONARY");
        if (position >= input.length) throw new IOException("TRUNCATED_LZ4_FRAME");
        int expected = input[position++] & 255;
        if (expected != XxHash32.frameHeaderChecksum(input, start + 4, position - start - 5)) {
            throw new IOException("INVALID_LZ4_FRAME_HEADER_CHECKSUM");
        }
        if (contentSize > buffer.limit - buffer.size) throw new IOException("DECOMPRESSION_LIMIT");
        while (true) {
            cancelled();
            if (input.length - position < 4) throw new IOException("TRUNCATED_LZ4_FRAME_BLOCK_HEADER");
            int raw = readInt(input, position);
            position += 4;
            if (raw == 0) break;
            boolean stored = (raw & 0x80000000) != 0;
            int size = raw & 0x7FFFFFFF;
            if (size > maxBlock) throw new IOException("INVALID_LZ4_FRAME_BLOCK_SIZE");
            if (size > input.length - position) throw new IOException("TRUNCATED_LZ4_FRAME_BLOCK");
            if (stored) {
                buffer.put(input, position, size);
                position += size;
            } else {
                int before = buffer.size;
                decodeBlock(input, position, size, buffer, (flags & 0x20) != 0 ? before : frameStart);
                if (buffer.size - before > maxBlock) throw new IOException("INVALID_LZ4_FRAME_BLOCK_SIZE");
                position += size;
            }
            if (blockChecksum) {
                if (input.length - position < 4) throw new IOException("TRUNCATED_LZ4_FRAME_CHECKSUM");
                if (XxHash32.hash(input, position - size, size) != readInt(input, position)) {
                    throw new IOException("INVALID_LZ4_FRAME_BLOCK_CHECKSUM");
                }
                position += 4;
            }
        }
        if (contentChecksum) {
            if (input.length - position < 4) throw new IOException("TRUNCATED_LZ4_FRAME_CHECKSUM");
            if (XxHash32.hash(buffer.data, frameStart, buffer.size - frameStart) != readInt(input, position)) {
                throw new IOException("INVALID_LZ4_FRAME_CONTENT_CHECKSUM");
            }
            position += 4;
        }
        if (contentSize >= 0 && buffer.size - frameStart != contentSize) throw new IOException("INVALID_LZ4_FRAME_CONTENT_SIZE");
        return position;
    }

    /**
     * Decodes one compressed block into {@code buffer}. Matches may reach back into earlier blocks
     * (linked-block streams); independent blocks and new frames reset the permitted history.
     */
    private static void decodeBlock(byte[] input, int start, int size, Buffer buffer, int historyStart) throws IOException {
        int in = start, end = start + size, before = buffer.size;
        while (in < end) {
            int token = input[in++] & 255;
            int literals = token >>> 4;
            if (literals == 15) {
                int next;
                do {
                    if (in == end) throw new IOException("TRUNCATED_LZ4_FRAME_LENGTH");
                    next = input[in++] & 255;
                    literals += next;
                } while (next == 255);
            }
            if (literals > end - in) throw new IOException("TRUNCATED_LZ4_FRAME_LITERALS");
            buffer.put(input, in, literals);
            in += literals;
            if (in == end) break;
            if (end - in < 2) throw new IOException("TRUNCATED_LZ4_FRAME_OFFSET");
            int distance = (input[in] & 255) | ((input[in + 1] & 255) << 8);
            in += 2;
            if (distance == 0 || distance > buffer.size - historyStart) throw new IOException("INVALID_LZ4_FRAME_OFFSET");
            int match = (token & 15) + 4;
            if ((token & 15) == 15) {
                int next;
                do {
                    if (in == end) throw new IOException("TRUNCATED_LZ4_FRAME_LENGTH");
                    next = input[in++] & 255;
                    match += next;
                } while (next == 255);
            }
            buffer.copy(distance, match);
        }
        if (buffer.size == before) throw new IOException("EMPTY_LZ4_FRAME_BLOCK");
    }

    /** Growable output with LZ77 back-references (matches may overlap the current position). */
    private static final class Buffer {
        private final int limit;
        byte[] data;
        int size;

        Buffer(int limit, int hint) {
            this.limit = limit;
            this.data = new byte[Math.max(1, Math.min(limit, hint > 0 ? hint : 1 << 16))];
        }

        void put(byte[] source, int offset, int length) throws IOException {
            ensure(length);
            System.arraycopy(source, offset, data, size, length);
            size += length;
        }

        void copy(int distance, int length) throws IOException {
            if (distance <= 0 || distance > size) throw new IOException("INVALID_LZ4_FRAME_OFFSET");
            ensure(length);
            for (int index = 0; index < length; index++) {
                data[size] = data[size - distance];
                size++;
            }
        }

        private void ensure(int extra) throws IOException {
            if (extra > limit - size || size + extra < 0) throw new IOException("DECOMPRESSION_LIMIT");
            if (size + extra <= data.length) return;
            int capacity = Math.max(size + extra, (int) Math.min(limit, Math.max(1024L, (long) data.length * 2)));
            data = Arrays.copyOf(data, capacity);
        }

        byte[] toArray() { return Arrays.copyOf(data, size); }
    }

    /** Independent blocks, compressed only when smaller than their stored representation. */
    static byte[] encode(byte[] raw) throws IOException {
        if (raw.length == 0) throw new IOException("EMPTY_KERNEL");
        int blocks = (raw.length + BLOCK_MAX - 1) / BLOCK_MAX;
        byte[] output = new byte[7 + raw.length + blocks * 4 + 4];
        output[0] = 4; output[1] = 34; output[2] = 77; output[3] = 24;
        output[4] = (byte) ENCODE_FLAG;
        output[5] = (byte) ENCODE_BLOCK_DESCRIPTOR;
        output[6] = (byte) XxHash32.frameHeaderChecksum(output, 4, 2);
        int position = 7;
        for (int offset = 0; offset < raw.length; offset += BLOCK_MAX) {
            cancelled();
            int length = Math.min(BLOCK_MAX, raw.length - offset);
            byte[] compressed = Lz4BlockEncoder.encode(raw, offset, length);
            boolean smaller = compressed.length < length;
            int size = smaller ? compressed.length : length;
            writeInt(output, position, smaller ? size : size | 0x80000000);
            position += 4;
            System.arraycopy(smaller ? compressed : raw, smaller ? 0 : offset, output, position, size);
            position += size;
        }
        // EndMark (four zero bytes) is the zero-filled tail of the array.
        return position + 4 == output.length ? output : Arrays.copyOf(output, position + 4);
    }

    private static int readInt(byte[] data, int offset) {
        return (data[offset] & 255) | ((data[offset + 1] & 255) << 8)
                | ((data[offset + 2] & 255) << 16) | ((data[offset + 3] & 255) << 24);
    }

    private static long readLong(byte[] data, int offset) {
        long value = 0;
        for (int index = 7; index >= 0; index--) value = (value << 8) | (data[offset + index] & 255L);
        return value;
    }

    private static void writeInt(byte[] data, int offset, int value) {
        for (int index = 0; index < 4; index++) data[offset + index] = (byte) (value >>> (index * 8));
    }

    private static void cancelled() throws IOException {
        if (Thread.currentThread().isInterrupted()) throw new IOException("CANCELLED");
    }
}
