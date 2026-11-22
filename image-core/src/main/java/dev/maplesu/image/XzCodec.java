package dev.maplesu.image;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.zip.CRC32;

/**
 * XZ container decoder (LZMA2 blocks) plus a stored-chunk encoder. Pure Java, bounded, no native code.
 *
 * <p>Decoding follows the XZ file format: concatenated streams, LZMA2 blocks with optional ARM64
 * BCJ and Delta filters, block padding, the selected integrity check, the block index
 * and the stream footer. Chunk controls, state/property/dictionary
 * resets and the LZMA range-coder are implemented per the format, so ordinary {@code xz}-compressed
 * kernels decode verbatim.
 *
 * <p>Encoding deliberately writes <em>uncompressed</em> LZMA2 chunks (control 0x01/0x02), which is
 * the format's own representation for incompressible data: any XZ decoder accepts it, and it keeps
 * the rebuild path auditable instead of shipping a second compressor.
 */
final class XzCodec {
    private static final byte[] MAGIC = {(byte) 0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00};
    private static final int CHECK_NONE = 0, CHECK_CRC32 = 1, CHECK_CRC64 = 4, CHECK_SHA256 = 10;
    private static final int FILTER_LZMA2 = 0x21;
    /** LZMA2 uncompressed chunks carry a 16-bit (size-1) field, so 64 KiB is the maximum. */
    private static final int STORED_CHUNK = 64 * 1024;
    private static final int PROB_INIT = 1024;
    private static final long[] CRC64_TABLE = crc64Table();

    private XzCodec() {}

    static boolean matches(byte[] data) {
        return matches(data, 0);
    }

    private static boolean matches(byte[] data, int offset) {
        if (data.length - offset < MAGIC.length) return false;
        for (int index = 0; index < MAGIC.length; index++) if (data[offset + index] != MAGIC[index]) return false;
        return true;
    }

    static byte[] decode(byte[] input, int limit) throws IOException {
        return decode(input, limit, null);
    }

    static byte[] decode(byte[] input, int limit, int[] consumedStream) throws IOException {
        Sink sink = new Sink(limit);
        int position = 0;
        while (true) {
            position = decodeStream(input, position, sink);
            int next = position;
            while (next < input.length && input[next] == 0) {
                if ((next & 65535) == 0) cancelled();
                next++;
            }
            if (!matches(input, next)) break;
            if (((next - position) & 3) != 0) throw new IOException("INVALID_XZ_STREAM_PADDING");
            position = next;
        }
        if (sink.size == 0) throw new IOException("EMPTY_KERNEL");
        if (consumedStream != null) consumedStream[0] = position;
        return sink.toArray();
    }

    private static int decodeStream(byte[] input, int start, Sink sink) throws IOException {
        cancelled();
        if (input.length - start < 24) throw new IOException("TRUNCATED_XZ");
        if (!matches(input, start)) throw new IOException("INVALID_XZ_MAGIC");
        int checkType = input[start + 7] & 255;
        int checkSize = checkSize(checkType);
        if (crc32(input, start + 6, 2) != readInt(input, start + 8)) throw new IOException("INVALID_XZ_HEADER_CHECKSUM");
        if (input[start + 6] != 0) throw new IOException("INVALID_XZ_STREAM_FLAGS");
        int position = start + 12;
        int indexSize = 0;
        List<long[]> records = new ArrayList<>();
        while (true) {
            cancelled();
            if (position >= input.length) throw new IOException("TRUNCATED_XZ");
            int indicator = input[position] & 255;
            if (indicator == 0) {
                int indexStart = position;
                position = index(input, position, input.length, records);
                indexSize = position - indexStart;
                break;
            }
            int headerSize = (indicator + 1) * 4;
            if (headerSize < 8 || headerSize > input.length - position) throw new IOException("INVALID_XZ_BLOCK_HEADER");
            int flags = input[position + 1] & 255;
            int filters = (flags & 3) + 1;
            if ((flags & 0x3C) != 0) throw new IOException("INVALID_XZ_BLOCK_HEADER");
            int checksumAt = position + headerSize - 4;
            int[] cursor = {position + 2};
            long compressedSize = -1, uncompressedSize = -1;
            if ((flags & 0x40) != 0) compressedSize = readVli(input, cursor, checksumAt);
            if ((flags & 0x80) != 0) uncompressedSize = readVli(input, cursor, checksumAt);
            int[] filterIds = new int[filters - 1], properties = new int[filters - 1];
            for (int filter = 0; filter < filters; filter++) {
                long id = readVli(input, cursor, checksumAt);
                long size = readVli(input, cursor, checksumAt);
                if (size > checksumAt - cursor[0]) throw new IOException("INVALID_XZ_BLOCK_HEADER");
                if (filter == filters - 1) {
                    if (id != FILTER_LZMA2) throw new IOException("UNSUPPORTED_XZ_FILTER:" + id);
                    if (size != 1 || (input[cursor[0]] & 255) > 40) throw new IOException("INVALID_XZ_FILTER_PROPERTIES");
                } else if (id == 0x0A) {
                    if (size != 0 && size != 4) throw new IOException("INVALID_XZ_FILTER_PROPERTIES");
                    properties[filter] = size == 0 ? 0 : readInt(input, cursor[0]);
                    if ((properties[filter] & 3) != 0) throw new IOException("INVALID_XZ_FILTER_PROPERTIES");
                    filterIds[filter] = (int) id;
                } else if (id == 3) {
                    if (size != 1) throw new IOException("INVALID_XZ_FILTER_PROPERTIES");
                    properties[filter] = (input[cursor[0]] & 255) + 1;
                    filterIds[filter] = (int) id;
                } else throw new IOException("UNSUPPORTED_XZ_FILTER:" + id);
                cursor[0] += (int) size;
            }
            if (cursor[0] > checksumAt) throw new IOException("INVALID_XZ_BLOCK_HEADER");
            for (int index = cursor[0]; index < checksumAt; index++) {
                if (input[index] != 0) throw new IOException("INVALID_XZ_BLOCK_HEADER");
            }
            if (crc32(input, position, headerSize - 4) != readInt(input, checksumAt)) {
                throw new IOException("INVALID_XZ_BLOCK_HEADER_CHECKSUM");
            }
            position += headerSize;
            if (uncompressedSize > sink.limit - sink.size) throw new IOException("DECOMPRESSION_LIMIT");
            int before = sink.size;
            int[] consumed = {0};
            Lzma2.decode(input, position, input.length, sink,
                    compressedSize >= 0 ? (int) Math.min(Integer.MAX_VALUE, compressedSize) : -1, consumed);
            if (compressedSize >= 0) {
                if (consumed[0] != compressedSize) throw new IOException("INVALID_XZ_COMPRESSED_SIZE");
            } else {
                compressedSize = consumed[0];
            }
            position += (int) compressedSize;
            int padding = (int) ((4 - (compressedSize & 3)) & 3);
            if (position + padding > input.length) throw new IOException("TRUNCATED_XZ");
            for (int index = 0; index < padding; index++) {
                if (input[position + index] != 0) throw new IOException("INVALID_XZ_BLOCK_PADDING");
            }
            position += padding;
            if (uncompressedSize >= 0 && sink.size - before != uncompressedSize) {
                throw new IOException("INVALID_XZ_UNCOMPRESSED_SIZE");
            }
            for (int filter = filterIds.length - 1; filter >= 0; filter--) {
                if (filterIds[filter] == 0x0A) arm64(sink.data, before, sink.size, properties[filter]);
                else for (int index = before + properties[filter]; index < sink.size; index++) {
                    if ((index & 65535) == 0) cancelled();
                    sink.data[index] += sink.data[index - properties[filter]];
                }
            }
            if (position + checkSize > input.length) throw new IOException("TRUNCATED_XZ");
            if (checkType == CHECK_CRC32 && crc32(sink.data, before, sink.size - before) != readInt(input, position)) {
                throw new IOException("INVALID_XZ_CHECK");
            }
            if (checkType == CHECK_CRC64 && crc64(sink.data, before, sink.size - before) != readLong(input, position)) {
                throw new IOException("INVALID_XZ_CHECK");
            }
            if (checkType == CHECK_SHA256) {
                try {
                    MessageDigest digest = MessageDigest.getInstance("SHA-256");
                    digest.update(sink.data, before, sink.size - before);
                    byte[] actual = digest.digest();
                    for (int index = 0; index < actual.length; index++) {
                        if (actual[index] != input[position + index]) throw new IOException("INVALID_XZ_CHECK");
                    }
                } catch (NoSuchAlgorithmException error) {
                    throw new AssertionError(error);
                }
            }
            position += checkSize;
            if (records.size() == 1 << 20) throw new IOException("INVALID_XZ_INDEX");
            records.add(new long[]{headerSize + compressedSize + checkSize, sink.size - before});
        }
        if (input.length - position < 12) throw new IOException("TRUNCATED_XZ");
        if (input[position + 10] != 'Y' || input[position + 11] != 'Z') throw new IOException("INVALID_XZ_FOOTER");
        if (crc32(input, position + 4, 6) != readInt(input, position)) throw new IOException("INVALID_XZ_FOOTER_CHECKSUM");
        if (input[position + 8] != input[start + 6] || input[position + 9] != input[start + 7]) {
            throw new IOException("INVALID_XZ_STREAM_FLAGS");
        }
        long backward = readInt(input, position + 4) & 0xFFFFFFFFL;
        if ((backward + 1) * 4 != indexSize) throw new IOException("INVALID_XZ_INDEX_SIZE");
        return position + 12;
    }

    /** ARM64 BL/ADRP inverse from XZ Utils arm64.c (0BSD); see META-INF/LICENSE-xz-arm64.txt. */
    private static void arm64(byte[] data, int start, int end, int base) throws IOException {
        for (int at = start; at <= end - 4; at += 4) {
            if (((at - start) & 65535) == 0) cancelled();
            int pc = base + at - start, instruction = readInt(data, at);
            if (instruction >>> 26 == 0x25) {
                instruction = 0x94000000 | ((instruction - (pc >>> 2)) & 0x03FFFFFF);
            } else if ((instruction & 0x9F000000) == 0x90000000) {
                int source = ((instruction >>> 29) & 3) | ((instruction >>> 3) & 0x001FFFFC);
                if (((source + 0x00020000) & 0x001C0000) != 0) continue;
                int dest = source - (pc >>> 12);
                instruction = (instruction & 0x9000001F) | ((dest & 3) << 29)
                        | ((dest & 0x0003FFFC) << 3) | ((-(dest & 0x00020000)) & 0x00E00000);
            } else continue;
            writeInt(data, at, instruction);
        }
    }

    /** Parses the index between blocks and the footer; returns the footer offset. */
    private static int index(byte[] input, int start, int end, List<long[]> records) throws IOException {
        int[] cursor = {start + 1};
        long count = readVli(input, cursor, end);
        if (count != records.size()) throw new IOException("INVALID_XZ_INDEX");
        for (long[] record : records) {
            if (readVli(input, cursor, end) != record[0] || readVli(input, cursor, end) != record[1])
                throw new IOException("INVALID_XZ_INDEX");
        }
        int body = cursor[0] - start;
        int padding = (4 - ((body + 4) & 3)) & 3;
        int checksumAt = cursor[0] + padding;
        if (checksumAt + 4 > end) throw new IOException("TRUNCATED_XZ");
        for (int index = cursor[0]; index < checksumAt; index++) {
            if (input[index] != 0) throw new IOException("INVALID_XZ_INDEX_PADDING");
        }
        if (crc32(input, start, checksumAt - start) != readInt(input, checksumAt)) {
            throw new IOException("INVALID_XZ_INDEX_CHECKSUM");
        }
        return checksumAt + 4;
    }

    /** Stored-block XZ: one block, uncompressed LZMA2 chunks, CRC32 integrity check. */
    static byte[] encode(byte[] raw) throws IOException {
        if (raw.length == 0) throw new IOException("EMPTY_KERNEL");
        ByteArrayOutputStream lzma2 = new ByteArrayOutputStream(raw.length + raw.length / 65536 * 3 + 8);
        for (int offset = 0; offset < raw.length; offset += STORED_CHUNK) {
            int length = Math.min(STORED_CHUNK, raw.length - offset);
            lzma2.write(offset == 0 ? 0x01 : 0x02);
            lzma2.write((length - 1) >>> 8);
            lzma2.write((length - 1) & 255);
            lzma2.write(raw, offset, length);
        }
        lzma2.write(0);
        byte[] data = lzma2.toByteArray();

        ByteArrayOutputStream body = new ByteArrayOutputStream();
        body.write(0xC0);                                   // one filter, compressed + uncompressed size present
        vli(body, data.length);
        vli(body, raw.length);
        vli(body, FILTER_LZMA2);
        vli(body, 1);
        body.write(0x0C);                                   // LZMA2 dictionary property: 256 KiB
        int bodyLength = body.size();
        int padding = (4 - ((bodyLength + 5) & 3)) & 3;
        int headerSize = 1 + bodyLength + padding + 4;
        if (headerSize % 4 != 0) throw new IOException("XZ_ENCODE_MISMATCH");
        byte[] header = new byte[headerSize];
        header[0] = (byte) (headerSize / 4 - 1);
        byte[] fields = body.toByteArray();
        System.arraycopy(fields, 0, header, 1, fields.length);
        writeInt(header, headerSize - 4, crc32(header, 0, headerSize - 4));

        int checkSize = 4;
        int unpadded = headerSize + data.length + checkSize;
        int blockPadding = (4 - (data.length & 3)) & 3;
        ByteArrayOutputStream index = new ByteArrayOutputStream();
        index.write(0);
        vli(index, 1);
        vli(index, unpadded);
        vli(index, raw.length);
        byte[] indexBody = index.toByteArray();
        int indexPadding = (4 - ((indexBody.length + 4) & 3)) & 3;
        byte[] indexBytes = Arrays.copyOf(indexBody, indexBody.length + indexPadding);
        byte[] indexChecksum = new byte[4];
        writeInt(indexChecksum, 0, crc32(indexBytes, 0, indexBytes.length));

        ByteArrayOutputStream output = new ByteArrayOutputStream(12 + unpadded + blockPadding
                + indexBytes.length + indexChecksum.length + 12);
        output.write(MAGIC, 0, MAGIC.length);
        output.write(0x00);
        output.write(CHECK_CRC32);
        byte[] streamFlags = {0x00, (byte) CHECK_CRC32};
        byte[] streamChecksum = new byte[4];
        writeInt(streamChecksum, 0, crc32(streamFlags, 0, 2));
        output.write(streamChecksum, 0, 4);
        output.write(header, 0, header.length);
        output.write(data, 0, data.length);
        output.write(new byte[blockPadding], 0, blockPadding);
        byte[] check = new byte[4];
        writeInt(check, 0, crc32(raw, 0, raw.length));
        output.write(check, 0, 4);
        output.write(indexBytes, 0, indexBytes.length);
        output.write(indexChecksum, 0, 4);
        byte[] footerBody = new byte[6];
        writeInt(footerBody, 0, (indexBytes.length + 4) / 4 - 1);
        footerBody[4] = 0x00;
        footerBody[5] = (byte) CHECK_CRC32;
        byte[] footerChecksum = new byte[4];
        writeInt(footerChecksum, 0, crc32(footerBody, 0, 6));
        output.write(footerChecksum, 0, 4);
        output.write(footerBody, 0, 6);
        output.write('Y');
        output.write('Z');
        return output.toByteArray();
    }

    /** LZMA2 chunk layer: chunk controls, state/property/dictionary resets, LZMA decoder. */
    private static final class Lzma2 {
        static void decode(byte[] input, int start, int end, Sink sink, int expected, int[] consumed)
                throws IOException {
            int position = start, limit = expected >= 0 ? start + expected : end;
            if (limit > end) throw new IOException("TRUNCATED_XZ");
            Model model = null;
            while (true) {
                if (position >= limit) throw new IOException("TRUNCATED_LZMA2");
                int control = input[position++] & 255;
                if (control == 0) break;
                if (control == 0x01 || control == 0x02) {
                    if (limit - position < 2) throw new IOException("TRUNCATED_LZMA2");
                    int size = (((input[position] & 255) << 8) | (input[position + 1] & 255)) + 1;
                    position += 2;
                    if (size > limit - position) throw new IOException("TRUNCATED_LZMA2");
                    // A dictionary reset starts *at* this chunk, so its own bytes stay addressable.
                    if (control == 0x01) sink.dictionaryStart = sink.size;
                    sink.put(input, position, size);
                    position += size;
                    continue;
                }
                if (control < 0x80) throw new IOException("INVALID_LZMA2_CONTROL");
                int reset = (control >>> 5) & 3;
                if (limit - position < 4) throw new IOException("TRUNCATED_LZMA2");
                int unpacked = (((control & 0x1F) << 16)
                        | ((input[position] & 255) << 8) | (input[position + 1] & 255)) + 1;
                int packed = (((input[position + 2] & 255) << 8) | (input[position + 3] & 255)) + 1;
                position += 4;
                if (reset >= 2) {
                    if (position >= limit) throw new IOException("TRUNCATED_LZMA2");
                    model = new Model(input[position++] & 255);
                } else if (model == null) {
                    throw new IOException("INVALID_LZMA2_RESET");
                }
                if (reset >= 3) sink.dictionaryStart = sink.size;
                if (reset >= 1) model.reset();
                if (packed > limit - position) throw new IOException("TRUNCATED_LZMA2");
                Range range = new Range(input, position, position + packed);
                model.decode(range, sink, unpacked);
                position += packed;
            }
            consumed[0] = position - start;
        }
    }

    /** LZMA probability model plus the match/literal state machine. */
    private static final class Model {
        final int lc, lp, pb;
        final int[] isMatch = new int[12 * 16], isRep = new int[12], isRepG0 = new int[12];
        final int[] isRepG1 = new int[12], isRepG2 = new int[12], isRep0Long = new int[12 * 16];
        final int[] posSlot = new int[4 * 64], specPos = new int[114], align = new int[16];
        final int[] len = new int[514], repLen = new int[514], literal;
        int state, rep0, rep1, rep2, rep3;

        Model(int properties) throws IOException {
            if (properties > (4 * 5 + 4) * 9 + 8) throw new IOException("INVALID_LZMA2_PROPERTIES");
            int remainder = properties;
            lc = remainder % 9; remainder /= 9;
            lp = remainder % 5; pb = remainder / 5;
            if (lc + lp > 4) throw new IOException("INVALID_LZMA2_PROPERTIES");
            literal = new int[0x300 << (lc + lp)];
            reset();
        }

        void reset() {
            Arrays.fill(isMatch, PROB_INIT);
            Arrays.fill(isRep, PROB_INIT);
            Arrays.fill(isRepG0, PROB_INIT);
            Arrays.fill(isRepG1, PROB_INIT);
            Arrays.fill(isRepG2, PROB_INIT);
            Arrays.fill(isRep0Long, PROB_INIT);
            Arrays.fill(posSlot, PROB_INIT);
            Arrays.fill(specPos, PROB_INIT);
            Arrays.fill(align, PROB_INIT);
            Arrays.fill(len, PROB_INIT);
            Arrays.fill(repLen, PROB_INIT);
            Arrays.fill(literal, PROB_INIT);
            state = 0; rep0 = 0; rep1 = 0; rep2 = 0; rep3 = 0;
        }

        void decode(Range range, Sink sink, int unpacked) throws IOException {
            int target = sink.size + unpacked;
            while (sink.size < target) {
                int posState = (sink.size - sink.dictionaryStart) & ((1 << pb) - 1);
                if (range.bit(isMatch, (state << 4) + posState) == 0) {
                    literal(range, sink);
                    continue;
                }
                int length;
                if (range.bit(isRep, state) != 0) {
                    if (range.bit(isRepG0, state) == 0) {
                        if (range.bit(isRep0Long, (state << 4) + posState) == 0) {
                            state = state < 7 ? 9 : 11;
                            sink.copy(rep0 + 1, 1);
                            continue;
                        }
                        length = length(range, repLen, posState);
                        state = state < 7 ? 8 : 11;
                    } else {
                        int distance;
                        if (range.bit(isRepG1, state) == 0) {
                            distance = rep1;
                        } else {
                            if (range.bit(isRepG2, state) == 0) {
                                distance = rep2;
                            } else {
                                distance = rep3;
                                rep3 = rep2;
                            }
                            rep2 = rep1;
                        }
                        rep1 = rep0;
                        rep0 = distance;
                        length = length(range, repLen, posState);
                        state = state < 7 ? 8 : 11;
                    }
                } else {
                    rep3 = rep2; rep2 = rep1; rep1 = rep0;
                    length = length(range, len, posState);
                    state = state < 7 ? 7 : 10;
                    int slot = tree(range, posSlot, Math.min(length - 2, 3) * 64, 6);
                    if (slot < 4) {
                        rep0 = slot;
                    } else {
                        int direct = (slot >>> 1) - 1;
                        rep0 = (2 | (slot & 1)) << direct;
                        if (slot < 14) {
                            rep0 += reverse(range, specPos, rep0 - slot - 1, direct);
                        } else {
                            rep0 += (range.direct(direct - 4) << 4) + reverse(range, align, 0, 4);
                        }
                    }
                }
                sink.copy(rep0 + 1, length);
            }
        }

        private void literal(Range range, Sink sink) throws IOException {
            int position = sink.size - sink.dictionaryStart;
            int previous = position == 0 ? 0 : sink.data[sink.size - 1] & 255;
            int base = 0x300 * (((position & ((1 << lp) - 1)) << lc) + (previous >>> (8 - lc)));
            int symbol = 1;
            if (state < 7) {
                while (symbol < 0x100) symbol = (symbol << 1) | range.bit(literal, base + symbol);
            } else {
                if (rep0 + 1 > sink.size - sink.dictionaryStart) throw new IOException("INVALID_LZMA2_DISTANCE");
                int matchByte = sink.data[sink.size - rep0 - 1] & 255;
                while (symbol < 0x100) {
                    int matchBit = (matchByte >>> 7) & 1;
                    matchByte = (matchByte << 1) & 0xFF;
                    int bit = range.bit(literal, base + ((1 + matchBit) << 8) + symbol);
                    symbol = (symbol << 1) | bit;
                    if (matchBit != bit) {
                        while (symbol < 0x100) symbol = (symbol << 1) | range.bit(literal, base + symbol);
                        break;
                    }
                }
            }
            state = state < 4 ? 0 : state < 10 ? state - 3 : state - 6;
            sink.put((byte) symbol);
        }

        private int length(Range range, int[] probs, int posState) throws IOException {
            if (range.bit(probs, 0) == 0) return 2 + tree(range, probs, 2 + posState * 8, 3);
            if (range.bit(probs, 1) == 0) return 10 + tree(range, probs, 130 + posState * 8, 3);
            return 18 + tree(range, probs, 258, 8);
        }

        private static int tree(Range range, int[] probs, int base, int bits) throws IOException {
            int symbol = 1;
            for (int index = 0; index < bits; index++) symbol = (symbol << 1) | range.bit(probs, base + symbol);
            return symbol - (1 << bits);
        }

        private static int reverse(Range range, int[] probs, int base, int bits) throws IOException {
            int symbol = 1, result = 0;
            for (int index = 0; index < bits; index++) {
                int bit = range.bit(probs, base + symbol);
                symbol = (symbol << 1) | bit;
                result |= bit << index;
            }
            return result;
        }
    }

    /** LZMA range decoder with 11-bit probabilities. */
    private static final class Range {
        private final byte[] input;
        private int position, end;
        private int range = 0xFFFFFFFF, code;

        Range(byte[] input, int start, int end) throws IOException {
            this.input = input; this.position = start; this.end = end;
            if (end - start < 5) throw new IOException("TRUNCATED_LZMA2_RANGE");
            if (input[position++] != 0) throw new IOException("INVALID_LZMA2_RANGE");
            for (int index = 0; index < 4; index++) code = (code << 8) | (input[position++] & 255);
            if (code == 0xFFFFFFFF) throw new IOException("INVALID_LZMA2_RANGE");
        }

        int bit(int[] probs, int index) throws IOException {
            int probability = probs[index];
            int bound = (range >>> 11) * probability;
            int result;
            // range/code are uint32: a signed compare flips once code crosses 0x80000000.
            if (Integer.compareUnsigned(code, bound) < 0) {
                range = bound;
                probs[index] = probability + ((2048 - probability) >>> 5);
                result = 0;
            } else {
                range -= bound;
                code -= bound;
                probs[index] = probability - (probability >>> 5);
                result = 1;
            }
            if (needsNormalize()) {
                if (position >= end) throw new IOException("TRUNCATED_LZMA2_RANGE");
                range <<= 8;
                code = (code << 8) | (input[position++] & 255);
            }
            return result;
        }

        /** range is uint32: `range < 0x01000000` as a signed test fires for any range >= 2^31. */
        private boolean needsNormalize() { return (range >>> 24) == 0; }

        int direct(int bits) throws IOException {
            int result = 0;
            for (int index = 0; index < bits; index++) {
                range >>>= 1;
                code -= range;
                int mask = 0 - (code >>> 31);
                code += range & mask;
                result = (result << 1) + mask + 1;
                if (needsNormalize()) {
                    if (position >= end) throw new IOException("TRUNCATED_LZMA2_RANGE");
                    range <<= 8;
                    code = (code << 8) | (input[position++] & 255);
                }
            }
            return result;
        }
    }

    /** Bounded output buffer; matches may overlap (LZ77 semantics). */
    private static final class Sink {
        byte[] data;
        int size, dictionaryStart;
        private final int limit;

        Sink(int limit) {
            this.limit = limit;
            this.data = new byte[Math.min(limit, 1 << 16)];
        }

        void put(byte value) throws IOException {
            ensure(1);
            data[size++] = value;
        }

        void put(byte[] source, int offset, int length) throws IOException {
            ensure(length);
            System.arraycopy(source, offset, data, size, length);
            size += length;
        }

        void copy(int distance, int length) throws IOException {
            if (distance <= 0 || distance > size - dictionaryStart) throw new IOException("INVALID_LZMA2_DISTANCE");
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

    private static int checkSize(int type) throws IOException {
        switch (type) {
            case CHECK_NONE: return 0;
            case CHECK_CRC32: return 4;
            case CHECK_CRC64: return 8;
            case CHECK_SHA256: return 32;
            default: throw new IOException("UNSUPPORTED_XZ_CHECK:" + type);
        }
    }

    private static long readVli(byte[] input, int[] cursor, int end) throws IOException {
        long value = 0;
        int shift = 0;
        while (true) {
            if (cursor[0] >= end) throw new IOException("TRUNCATED_XZ");
            int current = input[cursor[0]++] & 255;
            if (shift > 56) throw new IOException("INVALID_XZ_VLI");
            value |= (long) (current & 0x7F) << shift;
            if ((current & 0x80) == 0) return value;
            shift += 7;
        }
    }

    private static void vli(ByteArrayOutputStream out, long value) {
        while (value >= 0x80) {
            out.write((int) (value & 0x7F) | 0x80);
            value >>>= 7;
        }
        out.write((int) value);
    }

    private static int crc32(byte[] data, int offset, int length) {
        CRC32 crc = new CRC32();
        crc.update(data, offset, length);
        return (int) crc.getValue();
    }

    private static long[] crc64Table() {
        long[] table = new long[256];
        for (int index = 0; index < table.length; index++) {
            long value = index;
            for (int bit = 0; bit < 8; bit++) {
                value = (value >>> 1) ^ ((value & 1) == 0 ? 0 : 0xC96C5795D7870F42L);
            }
            table[index] = value;
        }
        return table;
    }

    private static long crc64(byte[] data, int offset, int length) {
        long value = -1L;
        for (int index = offset; index < offset + length; index++) {
            value = CRC64_TABLE[((int) value ^ data[index]) & 255] ^ (value >>> 8);
        }
        return ~value;
    }

    private static long readLong(byte[] data, int offset) {
        return (readInt(data, offset) & 0xFFFFFFFFL) | ((long) readInt(data, offset + 4) << 32);
    }

    private static int readInt(byte[] data, int offset) {
        return (data[offset] & 255) | ((data[offset + 1] & 255) << 8)
                | ((data[offset + 2] & 255) << 16) | ((data[offset + 3] & 255) << 24);
    }

    private static void writeInt(byte[] data, int offset, int value) {
        for (int index = 0; index < 4; index++) data[offset + index] = (byte) (value >>> (index * 8));
    }

    private static void cancelled() throws IOException {
        if (Thread.currentThread().isInterrupted()) throw new IOException("CANCELLED");
    }
}
