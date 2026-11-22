package dev.maplesu.image;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

/** Runs the actual component writer and container rebuilder, including opaque appended data. */
public final class KernelComponentTailTest {
    private static int checks, failures, containers;

    private static void equal(byte[] expected, byte[] actual, String label) {
        checks++;
        if (!Arrays.equals(expected, actual)) throw new AssertionError(label);
    }

    private static byte[] join(byte[] first, byte[] second) {
        byte[] bytes = Arrays.copyOf(first, first.length + second.length);
        System.arraycopy(second, 0, bytes, first.length, second.length);
        return bytes;
    }

    private static int align(int value, int page) { return (value + page - 1) / page * page; }

    private static byte[] boot(byte[] component, int version, int page) {
        int ramdisk = align(page + component.length, page);
        byte[] image = new byte[align(ramdisk + 71, page)];
        ByteBuffer header = ByteBuffer.wrap(image).order(ByteOrder.LITTLE_ENDIAN);
        header.put(new byte[]{'A','N','D','R','O','I','D','!'});
        header.putInt(8, component.length).putInt(40, version);
        if (version < 3) {
            header.putInt(16, 71).putInt(36, page);
            if (version > 0) header.putInt(1644, version == 1 ? 1648 : 1660);
        } else {
            header.putInt(12, 71).putInt(20, version == 3 ? 1580 : 1584);
        }
        System.arraycopy(component, 0, image, page, component.length);
        Arrays.fill(image, ramdisk, ramdisk + 71, (byte) 0x72);
        return image;
    }

    private static void roundTrip(Path work, byte[] raw, String format, byte[] stream, byte[] tail) throws Exception {
        byte[] original = join(stream, tail), copy = original.clone();
        equal(raw, KernelCompression.decode(original, format, raw.length), format + " original decode");
        byte[] changed = raw.clone(); changed[140] ^= 42;
        byte[] rebuilt = KernelCompression.encodeKernelComponent(changed, original, format);
        equal(join(KernelCompression.encode(changed, format), tail), rebuilt, format + " tail lost");
        equal(changed, KernelCompression.decode(rebuilt, format, raw.length), format + " changed decode");
        equal(copy, original, format + " input mutated");
        Path source = work.resolve("source.img"), kernel = work.resolve("kernel"), output = work.resolve("output.img");
        Files.write(kernel, rebuilt);
        for (int version = 0; version <= 4; version++) {
            for (int page : version < 3 ? new int[]{2048,4096,8192,16384} : new int[]{4096}) {
                byte[] image = boot(original, version, page);
                Files.write(source, image);
                BootImageRebuilder.Report report = BootImageRebuilder.rebuild(source.toFile(), kernel.toFile(), output.toFile());
                byte[] actual = Files.readAllBytes(output);
                byte[] expected = boot(rebuilt, version, page);
                // The legacy header ID is intentionally recomputed; its writer has separate tests.
                if (version < 3) Arrays.fill(actual, 576, 608, (byte) 0);
                equal(expected, actual, format + " whole container mismatch");
                equal(rebuilt, Arrays.copyOfRange(actual, (int) report.image.kernelOffset,
                        (int) (report.image.kernelOffset + report.image.kernelSize)), format + " component mismatch");
                equal(image, Files.readAllBytes(source), format + " source mutated");
                if (!report.equivalence.ok()) throw new AssertionError("undeclared container diff");
                Files.delete(output);
                containers++;
            }
        }
    }

    private static void rejects(byte[] input, String format) throws Exception {
        try {
            KernelCompression.encodeKernelComponent(new byte[]{1}, input, format);
            throw new AssertionError(format + " accepted damaged original stream");
        } catch (IOException expected) { checks++; }
    }

    public static void main(String[] args) throws Exception {
        byte[] raw = new byte[70017];
        new java.util.Random(17).nextBytes(raw);
        System.arraycopy(new byte[]{'A','R','M',100}, 0, raw, 56, 4);
        byte[][] tails = {new byte[0], new byte[]{1}, new byte[]{1,5,9},
                new byte[]{(byte) 0xd0,0x0d,(byte) 0xfe,(byte) 0xed,0,0,0,12,9,4,0,0}};
        Path work = Files.createTempDirectory("maplesu-component-tail-");
        try {
            for (String format : new String[]{"GZIP","LZ4_FRAME","XZ","ZSTD"}) {
                byte[] stream = KernelCompression.encode(raw, format);
                for (byte[] tail : tails) {
                    try { roundTrip(work, raw, format, stream, tail); }
                    catch (Exception | AssertionError error) {
                        failures++;
                        System.err.println("FAIL " + format + " tail=" + tail.length + ": " + error);
                    }
                }
                for (int size : new int[]{0,1,4,stream.length / 2,stream.length - 1})
                    rejects(Arrays.copyOf(stream, size), format);
            }
            // Zstd concatenation and skippable frames are part of the consumed stream, not DTB data.
            byte[] first = Arrays.copyOf(raw, 140), second = Arrays.copyOfRange(raw, 140, raw.length);
            byte[] skip = {0x50,0x2a,0x4d,0x18,3,0,0,0,1,2,3};
            byte[] multi = join(join(KernelCompression.encode(first, "ZSTD"), skip),
                    KernelCompression.encode(second, "ZSTD"));
            roundTrip(work, raw, "ZSTD", multi, tails[3]);
            rejects(join(KernelCompression.encode(raw, "LZ4_LEGACY"), tails[3]), "LZ4_LEGACY");
            // External liblz4/liblzma streams exercise compressed blocks and optional checksums.
            for (String name : new String[]{"stock.cpio.lz4", "stock-checksums.cpio.lz4",
                    "stock-crc32.cpio.xz", "stock-crc64.cpio.xz", "stock-sha256.cpio.xz"}) {
                try (var input = KernelComponentTailTest.class.getResourceAsStream("/ramdisk-codecs/" + name);
                     var reference = KernelComponentTailTest.class.getResourceAsStream("/ramdisk-codecs/stock.cpio")) {
                    String format = name.endsWith("lz4") ? "LZ4_FRAME" : "XZ";
                    try { roundTrip(work, reference.readAllBytes(), format, input.readAllBytes(), tails[3]); }
                    catch (Exception | AssertionError error) {
                        failures++; System.err.println("FAIL external " + name + ": " + error);
                    }
                }
            }
        } finally {
            try (var files = Files.list(work)) { for (Path path : files.toList()) Files.delete(path); }
            Files.delete(work);
        }
        System.out.println("KernelComponentTailTest: " + checks + " checks, " + containers
                + " rebuilt containers, " + failures + " failures");
        if (failures != 0) throw new AssertionError("kernel component tail regression");
    }
}
