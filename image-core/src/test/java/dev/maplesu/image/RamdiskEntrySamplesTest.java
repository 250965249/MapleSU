package dev.maplesu.image;

import java.io.File;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HexFormat;

/** Read-only real-image harness: decoded CPIO edits exist only in memory and are never written. */
public final class RamdiskEntrySamplesTest {
    private static final String OWNED = "maplesu.entry-test";
    private static int passed;

    private static void check(boolean value, String message) {
        if (!value) throw new AssertionError(message);
        passed++;
    }
    private static String sha(byte[] bytes) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }

    private static void sample(File image) throws Exception {
        String imageBefore = sha(Files.readAllBytes(image.toPath()));
        BootImageInspector.Report container = BootImageInspector.inspect(image);
        check(container.ramdiskSize > 0 && container.ramdiskSize <= RamdiskInspector.MAX_COMPONENT_BYTES,
                "actual ramdisk component");
        byte[] encoded = new byte[(int) container.ramdiskSize];
        try (RandomAccessFile input = new RandomAccessFile(image, "r")) {
            input.seek(container.ramdiskOffset); input.readFully(encoded);
        }
        RamdiskInspector.Report original = RamdiskInspector.inspectRamdisk(encoded);
        check(!original.malformed, "source CPIO parses: " + original.errorCode);
        byte[] cpio = KernelCompression.decode(encoded,
                original.compression.equals("RAW") ? "RAW_ARM64" : original.compression,
                (int) RamdiskInspector.DEFAULT_MAX_BYTES);
        byte[] frozen = cpio.clone();
        check(sha(cpio).equals(original.decompressedSha256), "same decoded archive as unique parser");
        int budget = (int) RamdiskInspector.DEFAULT_MAX_BYTES;
        check(RamdiskEntryEditor.read(cpio, OWNED, budget) == null, "temporary entry absent");
        byte[] data = "inert MapleSU decoded-CPIO fixture".getBytes(StandardCharsets.US_ASCII);
        byte[] inserted = RamdiskEntryEditor.put(cpio, OWNED, data, budget);
        check(Arrays.equals(RamdiskEntryEditor.read(inserted, OWNED, budget), data), "read inserted content");
        check(Arrays.equals(Arrays.copyOf(inserted, original.trailerOffset),
                Arrays.copyOf(cpio, original.trailerOffset)), "all pre-trailer bytes preserved");
        check(Arrays.equals(Arrays.copyOfRange(inserted, inserted.length - (cpio.length - original.trailerOffset),
                        inserted.length), Arrays.copyOfRange(cpio, original.trailerOffset, cpio.length)),
                "entire original trailer and zero tail preserved");
        RamdiskInspector.Report changed = RamdiskInspector.inspectRamdisk(inserted);
        check(!changed.malformed && changed.entries.size() == original.entries.size() + 1,
                "only one new entry");
        for (int index = 0; index < original.entries.size(); index++) {
            RamdiskInspector.Entry before = original.entries.get(index), after = changed.entries.get(index);
            check(before.path.equals(after.path) && before.mode == after.mode && before.size == after.size
                    && before.sha256.equals(after.sha256), "original entry identity " + index);
            check(Arrays.equals(Arrays.copyOfRange(cpio, before.headerOffset, before.endOffset),
                    Arrays.copyOfRange(inserted, after.headerOffset, after.endOffset)),
                    "original entry raw header/name/data/padding " + index);
        }
        check(original.findings.size() == changed.findings.size(), "existing findings unchanged");
        check(original.form() == changed.form(), "existing manager form unchanged");
        byte[] same = RamdiskEntryEditor.put(inserted, OWNED, data, budget);
        check(Arrays.equals(same, inserted), "repeat byte exact");
        byte[] grown = RamdiskEntryEditor.put(inserted, OWNED, new byte[307], budget);
        check(RamdiskEntryEditor.read(grown, OWNED, budget).length == 307, "replacement read");
        byte[] restored = RamdiskEntryEditor.remove(grown, OWNED, budget);
        check(Arrays.equals(restored, frozen), "whole decoded CPIO restored byte-for-byte");
        check(Arrays.equals(cpio, frozen), "caller decoded input unchanged");
        check(sha(Files.readAllBytes(image.toPath())).equals(imageBefore), "original image unchanged");
        System.out.println("{\"image\":\"" + image.getAbsolutePath().replace('\\', '/') +
                "\",\"imageSha256\":\"" + imageBefore + "\",\"headerVersion\":" + container.headerVersion +
                ",\"compression\":\"" + original.compression + "\",\"encodedBytes\":" + encoded.length +
                ",\"decodedBytes\":" + cpio.length + ",\"decodedSha256\":\"" + sha(cpio) +
                "\",\"entries\":" + original.entries.size() + ",\"form\":\"" + original.form() +
                "\",\"roundtripSha256\":\"" + sha(restored) +
                "\",\"wholeDecodedRoundtrip\":true,\"imageUnchanged\":true,\"fileOutput\":false}");
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 2) throw new IllegalArgumentException("at least two real-image inputs required");
        for (String path : args) sample(new File(path));
        System.out.println("RamdiskEntrySamplesTest: " + passed + " checks passed; " + args.length +
                " read-only images; no decoded CPIO or candidate output");
    }
}
