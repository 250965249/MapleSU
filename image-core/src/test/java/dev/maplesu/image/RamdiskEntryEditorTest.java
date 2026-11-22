package dev.maplesu.image;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

/** Independent decoded-CPIO fixtures; no compressor, boot image or device is used. */
public final class RamdiskEntryEditorTest {
    private static final String OWNED = "maplesu.recovery";
    private static final int REG = 0100000, DIR = 0040000, LINK = 0120000;
    private static final int BUDGET = 32 * 1024;
    private static Method read, put, remove;
    private static int passed;

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        passed++;
    }

    private static byte[] invoke(Method method, Object... arguments) throws Exception {
        try { return (byte[]) method.invoke(null, arguments); }
        catch (InvocationTargetException error) {
            if (error.getCause() instanceof Exception) throw (Exception) error.getCause();
            throw error;
        }
    }

    private static byte[] read(byte[] cpio) throws Exception { return invoke(read, cpio, OWNED, BUDGET); }
    private static byte[] put(byte[] cpio, byte[] content) throws Exception {
        return invoke(put, cpio, OWNED, content, BUDGET);
    }
    private static byte[] remove(byte[] cpio) throws Exception { return invoke(remove, cpio, OWNED, BUDGET); }

    private interface Operation { void run() throws Exception; }
    private static void fails(String code, Operation operation) throws Exception {
        try { operation.run(); throw new AssertionError("expected " + code); }
        catch (IOException error) { check(error.getMessage().startsWith(code), error.getMessage()); }
    }

    private static byte[] ascii(String value) { return value.getBytes(StandardCharsets.US_ASCII); }
    private static byte[] concat(byte[]... chunks) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] chunk : chunks) out.write(chunk, 0, chunk.length);
        return out.toByteArray();
    }
    private static void hex(ByteArrayOutputStream out, long value) {
        byte[] text = ascii(String.format(Locale.ROOT, "%08x", value & 0xffffffffL));
        out.write(text, 0, text.length);
    }
    private static byte[] entry(String name, int mode, long uid, long gid, long links,
                                boolean crc, byte[] data, int pad) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] magic = ascii(crc ? "070702" : "070701"); out.write(magic, 0, magic.length);
        byte[] path = name.getBytes(StandardCharsets.ISO_8859_1);
        long sum = 0; for (byte value : data) sum += value & 255;
        for (long field : new long[]{19, mode, uid, gid, links, 1700000001L, data.length,
                12, 34, 56, 78, path.length + 1, crc ? sum : 0}) hex(out, field);
        out.write(path, 0, path.length); out.write(0);
        while (out.size() % 4 != 0) out.write(pad);
        out.write(data, 0, data.length);
        while (out.size() % 4 != 0) out.write(pad);
        return out.toByteArray();
    }
    private static byte[] file(String name, boolean crc, byte[] data) {
        return entry(name, REG | 0600, 0, 0, 1, crc, data, 0x5a);
    }
    private static byte[] trailer(boolean crc) {
        return concat(entry("TRAILER!!!", 0, 0, 0, 1, crc, new byte[0], 0), new byte[19]);
    }
    private static byte[][] stock(boolean crc) {
        return new byte[][]{
                entry("dev", DIR | 0751, 17, 19, 2, crc, new byte[0], 0x37),
                entry("init", REG | 0755, 0, 0, 1, crc, ascii("original-init"), 0x73),
                entry("vendor.\u00e9", REG | 0641, 501, 502, 1, crc, new byte[]{0, -1, 7, 3, 9}, 0x65),
                entry("vendor-link", LINK | 0777, 0, 0, 1, crc, ascii("vendor.\u00e9"), 0x49),
                entry("dev", DIR | 0700, 41, 42, 2, crc, new byte[0], 0x6d),
                trailer(crc),
        };
    }

    private static void sequence(boolean crc) throws Exception {
        byte[][] chunks = stock(crc);
        byte[] baseline = concat(chunks);
        byte[] frozen = baseline.clone();
        byte[] prefix = concat(Arrays.copyOf(chunks, chunks.length - 1));
        check(read(baseline) == null, "absent");
        byte[] absent = remove(baseline);
        check(absent != baseline && Arrays.equals(absent, baseline), "absent removal is an exact copy");
        byte[] payload = {7, 9, -1, 0, 2};
        byte[] inserted = put(baseline, payload);
        check(Arrays.equals(Arrays.copyOf(inserted, prefix.length), prefix), "all original headers/data/order/pad");
        check(Arrays.equals(Arrays.copyOfRange(inserted, inserted.length - chunks[5].length, inserted.length), chunks[5]),
                "original trailer and zero tail");
        check(Arrays.equals(read(inserted), payload), "read inserted payload");
        RamdiskInspector.Report report = RamdiskInspector.inspectRamdisk(inserted);
        check(!report.malformed && report.entries.size() == 6, "unique parser accepts insertion");
        check(report.findings.stream().anyMatch(problem -> problem.code.equals("DUPLICATE_ENTRY")),
                "legitimate duplicate directory remains a finding");
        RamdiskInspector.Entry record = report.entry(OWNED);
        check(record.mode == (REG | 0600), "owned regular 0600");
        int start = prefix.length;
        check(new String(inserted, start, 6, StandardCharsets.US_ASCII).equals(crc ? "070702" : "070701"),
                "new header matches archive CRC variant");
        byte[] same = put(inserted, payload);
        check(same != inserted && Arrays.equals(inserted, same), "identical update independent and byte exact");
        payload[0] = 99;
        check(read(inserted)[0] == 7, "content input is not retained");
        byte[] readCopy = read(inserted); readCopy[0] = 88;
        check(read(inserted)[0] == 7, "read output is independent");
        byte[] grown = put(inserted, new byte[107]);
        check(Arrays.equals(remove(grown), baseline), "grow then remove exact original bytes");
        byte[] shrunk = put(grown, new byte[0]);
        check(read(shrunk).length == 0, "zero-byte owned file");
        check(Arrays.equals(remove(shrunk), baseline), "shrink then remove exact original bytes");
        check(Arrays.equals(baseline, frozen), "source remains unchanged throughout");

        // Replacement in the middle must move the suffix without changing any suffix byte.
        byte[] before = concat(chunks[0], chunks[1]);
        byte[] after = concat(chunks[2], chunks[3], chunks[4], chunks[5]);
        byte[] middle = concat(before, file(OWNED, crc, ascii("old")), after);
        byte[] middleFrozen = middle.clone();
        byte[] replaced = put(middle, ascii("new content of a different length"));
        check(Arrays.equals(Arrays.copyOf(replaced, before.length), before), "middle prefix exact");
        check(Arrays.equals(Arrays.copyOfRange(replaced, replaced.length - after.length, replaced.length), after),
                "middle suffix raw headers/content/order/CRC/pad exact");
        check(Arrays.equals(remove(replaced), baseline), "middle removal exact baseline");
        check(Arrays.equals(middle, middleFrozen), "middle source unchanged");

        if (crc) {
            byte[] bad = inserted.clone(); bad[(int) record.offset] ^= 1;
            fails("CPIO_EDIT_ARCHIVE:CPIO_CHECK_MISMATCH", () -> read(bad));
            check(Arrays.equals(baseline, frozen), "CRC failure leaves unrelated input unchanged");
        }
    }

    private static void ownership() throws Exception {
        byte[] tail = trailer(false), content = ascii("owned");
        for (byte[] archive : List.of(
                concat(file(OWNED, false, content), file(OWNED, false, content), tail),
                concat(file(OWNED, false, content), file("./" + OWNED, false, content), tail),
                concat(file(OWNED, false, content), file(OWNED + "/.", false, content), tail))) {
            byte[] frozen = archive.clone();
            fails("CPIO_EDIT_DUPLICATE_OWNED_ENTRY", () -> read(archive));
            fails("CPIO_EDIT_DUPLICATE_OWNED_ENTRY", () -> put(archive, content));
            fails("CPIO_EDIT_DUPLICATE_OWNED_ENTRY", () -> remove(archive));
            check(Arrays.equals(archive, frozen), "duplicate conflict preserves input");
        }
        for (String alias : List.of("./" + OWNED, "././" + OWNED, OWNED + "/", OWNED + "/./")) {
            byte[] archive = concat(file(alias, false, content), tail);
            fails("CPIO_EDIT_OWNED_ENTRY_ALIAS", () -> read(archive));
        }
        for (int mode : new int[]{DIR | 0600, LINK | 0600}) {
            byte[] archive = concat(entry(OWNED, mode, 0, 0, 1, false, content, 0), tail);
            fails("CPIO_EDIT_OWNED_ENTRY_TYPE", () -> remove(archive));
        }
        for (long[] metadata : new long[][]{{1, 0, 1}, {0, 1, 1}, {0, 0, 2}, {0, 0, 0}}) {
            byte[] archive = concat(entry(OWNED, REG | 0600, metadata[0], metadata[1], metadata[2],
                    false, content, 0), tail);
            fails("CPIO_EDIT_OWNED_ENTRY_METADATA", () -> put(archive, content));
        }
        byte[] wrongMode = concat(entry(OWNED, REG | 0644, 0, 0, 1, false, content, 0), tail);
        fails("CPIO_EDIT_OWNED_ENTRY_METADATA", () -> read(wrongMode));
    }

    private static void boundsAndMalformed() throws Exception {
        byte[] base = concat(stock(false)), frozen = base.clone();
        for (String path : List.of("", ".", "..", "TRAILER!!!", "./x", "/x", "a/b", "x\\y", "x\n", "\u00e9")) {
            fails("CPIO_EDIT_PATH", () -> invoke(read, base, path, BUDGET));
        }
        fails("CPIO_EDIT_PATH", () -> invoke(read, base, null, BUDGET));
        fails("CPIO_EDIT_INPUT", () -> read(null));
        fails("CPIO_EDIT_INPUT", () -> read(new byte[0]));
        fails("CPIO_EDIT_NOT_DECODED_CPIO", () -> read(new byte[]{31, -117, 0, 0, 0, 0}));
        fails("CPIO_EDIT_BUDGET", () -> invoke(read, base, OWNED, 0));
        fails("CPIO_EDIT_BUDGET", () -> invoke(read, base, OWNED, 128 * 1024 * 1024 + 1));
        fails("CPIO_EDIT_INPUT_SIZE", () -> invoke(read, base, OWNED, base.length - 1));
        fails("CPIO_EDIT_OUTPUT_SIZE", () -> invoke(put, base, OWNED, ascii("one"), base.length));
        fails("CPIO_EDIT_CONTENT", () -> put(base, null));
        fails("CPIO_EDIT_ENTRY_SIZE", () -> put(base, new byte[1024 * 1024 + 1]));
        // Every truncation before the trailer completes must be rejected by the shared parser.
        int trailerStart = base.length - trailer(false).length;
        for (int length = 0; length < trailerStart + 121; length++) {
            final byte[] cut = Arrays.copyOf(base, length);
            try { read(cut); throw new AssertionError("accepted truncation " + length); }
            catch (IOException expected) { passed++; }
        }
        byte[] garbage = base.clone(); garbage[garbage.length - 1] = 1;
        fails("CPIO_EDIT_ARCHIVE:TRAILING_DATA", () -> remove(garbage));
        byte[] badSize = base.clone(); Arrays.fill(badSize, 54, 62, (byte) 'f');
        fails("CPIO_EDIT_ARCHIVE:TRUNCATED_CPIO_DATA", () -> read(badSize));
        byte[] noTrailer = Arrays.copyOf(base, trailerStart);
        fails("CPIO_EDIT_ARCHIVE:MISSING_TRAILER", () -> put(noTrailer, ascii("x")));
        check(Arrays.equals(base, frozen), "all malformed/budget cases preserve original input");

        // A tolerated writer variant omits the final trailer-name alignment padding.
        byte[] shortTrailer = Arrays.copyOf(entry("TRAILER!!!", 0, 0, 0, 1, false, new byte[0], 0), 121);
        byte[] shortArchive = concat(file("init", false, ascii("original")), shortTrailer);
        check(!RamdiskInspector.inspectRamdisk(shortArchive).malformed, "unpadded trailer fixture valid");
        check(Arrays.equals(remove(put(shortArchive, ascii("record"))), shortArchive),
                "unpadded trailer roundtrip exact");

        String maximumName = "x".repeat(255);
        byte[] named = invoke(put, base, maximumName, ascii("value"), BUDGET);
        check(Arrays.equals(invoke(read, named, maximumName, BUDGET), ascii("value")), "255-byte basename");
        fails("CPIO_EDIT_PATH", () -> invoke(read, base, maximumName + "x", BUDGET));
        byte[] maximumContent = new byte[1024 * 1024]; Arrays.fill(maximumContent, (byte) 0xff);
        byte[] large = invoke(put, base, OWNED, maximumContent, 2 * 1024 * 1024);
        check(Arrays.equals(invoke(read, large, OWNED, 2 * 1024 * 1024), maximumContent), "exact content budget");
        check(Arrays.equals(invoke(remove, large, OWNED, 2 * 1024 * 1024), base), "maximum content removal");
        byte[] oversizedOwned = concat(file(OWNED, false, new byte[1024 * 1024 + 1]), trailer(false));
        fails("CPIO_EDIT_ENTRY_SIZE", () -> invoke(read, oversizedOwned, OWNED, 2 * 1024 * 1024));

        byte[] directory = entry("dev", DIR | 0755, 0, 0, 2, false, new byte[0], 0);
        byte[][] repeated = new byte[RamdiskInspector.DEFAULT_MAX_ENTRIES + 1][];
        Arrays.fill(repeated, directory); repeated[repeated.length - 1] = trailer(false);
        byte[] atEntryLimit = concat(repeated);
        fails("CPIO_EDIT_ENTRY_COUNT", () -> invoke(put, atEntryLimit, OWNED, ascii("value"), 4 * 1024 * 1024));
        repeated[repeated.length - 2] = file(OWNED, false, ascii("old"));
        byte[] replacingAtLimit = concat(repeated);
        byte[] changed = invoke(put, replacingAtLimit, OWNED, ascii("new"), 4 * 1024 * 1024);
        check(Arrays.equals(invoke(read, changed, OWNED, 4 * 1024 * 1024), ascii("new")),
                "replacement at entry limit does not add an entry");
    }

    public static void main(String[] args) throws Exception {
        Class<?> editor = Class.forName("dev.maplesu.image.RamdiskEntryEditor");
        read = editor.getMethod("read", byte[].class, String.class, int.class);
        put = editor.getMethod("put", byte[].class, String.class, byte[].class, int.class);
        remove = editor.getMethod("remove", byte[].class, String.class, int.class);
        sequence(false);
        sequence(true);
        ownership();
        boundsAndMalformed();
        System.out.println("RamdiskEntryEditorTest: " + passed + " checks passed");
    }
}
