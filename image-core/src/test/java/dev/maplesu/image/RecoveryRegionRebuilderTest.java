package dev.maplesu.image;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Arrays;

/** Opaque inverse-data carrier only; no SDK, loader or device-boot claim. */
public final class RecoveryRegionRebuilderTest {
    private static int passed;
    private static void check(boolean value, String message) {
        if (!value) throw new AssertionError(message);
        passed++;
    }
    private static int align(int value, int page) { return (value + page - 1) / page * page; }
    // Independent wire fixture, not the production region encoder.
    private static byte[] withRegion(byte[] boot, byte[] record, int page) throws Exception {
        byte[] bytes = Arrays.copyOf(boot, align(boot.length + 56 + record.length, page));
        ByteBuffer h = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);
        h.position(boot.length);
        h.put(new byte[]{'M','S','U','R','R','E','G',0});
        h.putInt(1).putInt(56).putInt(record.length).putInt(0);
        h.put(MessageDigest.getInstance("SHA-256").digest(record));
        h.put(record);
        return bytes;
    }
    private static byte[] content(int size, int seed) {
        byte[] result = new byte[size];
        for (int index = 0; index < size; index++) result[index] = (byte) (seed + index * 37);
        return result;
    }


    private static byte[] fixture(int version, int page, int ramdiskSize) throws Exception {
        byte[][] parts = {content(71, 31), content(ramdiskSize, 71), content(version < 3 ? 39 : 0, 91),
                content(version == 1 || version == 2 ? 17 : 0, 111), content(version == 2 ? 7 : 0, 131)};
        int count = version < 3 ? version + 3 : 2;
        int length = page;
        for (int index = 0; index < count; index++) length += align(parts[index].length, page);
        byte[] result = new byte[length];
        ByteBuffer fields = ByteBuffer.wrap(result).order(ByteOrder.LITTLE_ENDIAN);
        fields.put(new byte[]{'A','N','D','R','O','I','D','!'}).putInt(8, 71).putInt(40, version);
        if (version >= 3) fields.putInt(12, ramdiskSize).putInt(20, version == 3 ? 1580 : 1584);
        else {
            fields.putInt(16, ramdiskSize).putInt(24, parts[2].length).putInt(36, page);
            if (version > 0) fields.putInt(1632, parts[3].length)
                    .putLong(1636, page + align(71, page) + align(ramdiskSize, page) + align(parts[2].length, page))
                    .putInt(1644, version == 1 ? 1648 : 1660);
            if (version == 2) fields.putInt(1648, parts[4].length);
        }
        int at = page;
        MessageDigest id = MessageDigest.getInstance("SHA-1");
        for (int index = 0; index < count; index++) {
            System.arraycopy(parts[index], 0, result, at, parts[index].length);
            at += align(parts[index].length, page);
            id.update(parts[index]);
            id.update(ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(parts[index].length).array());
        }
        if (version < 3) System.arraycopy(id.digest(), 0, result, 576, 20);
        return result;
    }

    private static byte[] avb(byte[] body, int spare) {
        int vbmeta = align(body.length, 4096);
        byte[] result = Arrays.copyOf(body, align(vbmeta + spare, 4096));
        result[vbmeta] = 'A'; result[vbmeta + 1] = 'V'; result[vbmeta + 2] = 'B'; result[vbmeta + 3] = '0';
        int at = result.length - 64;
        ByteBuffer footer = ByteBuffer.wrap(result).order(ByteOrder.BIG_ENDIAN);
        footer.position(at); footer.put(new byte[]{'A','V','B','f'});
        footer.putInt(at + 4, 1).putLong(at + 12, body.length).putLong(at + 20, vbmeta).putLong(at + 28, 256);
        return result;
    }

    private static void payloads(Path file, byte[] kernel, byte[] ramdisk) throws Exception {
        byte[] bytes = Files.readAllBytes(file);
        BootImageInspector.Report report = BootImageInspector.inspect(file.toFile());
        check(Arrays.equals(kernel, Arrays.copyOfRange(bytes, (int) report.kernelOffset,
                (int) report.kernelOffset + kernel.length)) && report.kernelSize == kernel.length, "Kernel payload retained");
        check(Arrays.equals(ramdisk, Arrays.copyOfRange(bytes, (int) report.ramdiskOffset,
                (int) report.ramdiskOffset + ramdisk.length)) && report.ramdiskSize == ramdisk.length, "Ramdisk payload retained");
        long[][] extras = {{report.secondOffset, report.secondSize, 91},
                {report.recoveryDtboOffset, report.recoveryDtboSize, 111}, {report.dtbOffset, report.dtbSize, 131}};
        for (long[] extra : extras) if (extra[1] > 0)
            check(Arrays.equals(content((int) extra[1], (int) extra[2]), Arrays.copyOfRange(bytes,
                    (int) extra[0], (int) (extra[0] + extra[1]))), "Non-target vendor component retained");
    }

    private static void matrix(Path work) throws Exception {
        byte[] first = {0x12, 0x34, 0x56}, second = content(5001, 67);
        for (int version = 0; version <= 4; version++) for (int page : new int[]{2048,4096,8192,16384}) {
            if (version >= 3 && page != 4096) continue;
            for (int ramdiskSize : new int[]{0, 53}) for (boolean footer : new boolean[]{false,true}) {
                Path dir = Files.createDirectory(work.resolve("v" + version + "p" + page + "r" + ramdiskSize + "a" + footer));
                Path source = dir.resolve("source.img"), kernel = dir.resolve("kernel"), ramdisk = dir.resolve("ramdisk");
                Path a = dir.resolve("a.img"), b = dir.resolve("b.img"), c = dir.resolve("c.img"),
                        d = dir.resolve("d.img"), e = dir.resolve("e.img"), f = dir.resolve("f.img");
                byte[] base = fixture(version, page, ramdiskSize);
                if (footer) base = avb(base, 65536);
                Files.write(source, base);
                check(BootImageRebuilder.readRecoveryRecord(source.toFile()) == null, "Pristine source has no carrier");
                byte[] grown = content(8193, 5), smaller = content(33, 9), newRamdisk = content(8193, 19);
                Files.write(kernel, grown);
                check(BootImageRebuilder.rebuild(source.toFile(), kernel.toFile(), a.toFile(), first).equivalence.ok(), "Insert has declared diffs");
                check(Arrays.equals(first, BootImageRebuilder.readRecoveryRecord(a.toFile())), "Inserted record reads through public API");
                payloads(a, grown, content(ramdiskSize, 71));
                if (footer) {
                    AvbFooter parsed = AvbFooter.parse(a.toFile());
                    check(parsed.originalImageSize > BootImageInspector.inspect(a.toFile()).signatureOffset,
                            "AVB content covers the inverse-data carrier");
                    check(parsed.vbmetaOffset >= parsed.originalImageSize && a.toFile().length() == base.length,
                            "Carrier and vbmeta stay within partition capacity");
                }
                Files.write(kernel, smaller);
                check(BootImageRebuilder.rebuild(a.toFile(), kernel.toFile(), b.toFile()).equivalence.ok(), "Default API preserves carrier while shrinking kernel");
                check(Arrays.equals(first, BootImageRebuilder.readRecoveryRecord(b.toFile())), "Default record preserved");
                check(BootImageRebuilder.rebuild(b.toFile(), kernel.toFile(), c.toFile(), second).equivalence.ok(), "Explicit replacement declared");
                check(Arrays.equals(second, BootImageRebuilder.readRecoveryRecord(c.toFile())), "Replacement record is current");
                byte[] independent = BootImageRebuilder.readRecoveryRecord(c.toFile()); independent[0] ^= 0x55;
                check(Arrays.equals(second, BootImageRebuilder.readRecoveryRecord(c.toFile())), "Reader returns independent bytes");
                byte[] bytes = Files.readAllBytes(c); int magicCount = 0;
                for (int at = 0; at + 8 <= bytes.length; at++)
                    if (Arrays.equals(Arrays.copyOfRange(bytes, at, at + 8), new byte[]{'M','S','U','R','R','E','G',0})) magicCount++;
                check(magicCount == 1, "Two generations leave exactly one owned region");
                Files.write(ramdisk, newRamdisk);
                check(BootImageRebuilder.rebuildRamdisk(c.toFile(), ramdisk.toFile(), d.toFile()).equivalence.ok(), "Ramdisk API preserves carrier");
                check(Arrays.equals(second, BootImageRebuilder.readRecoveryRecord(d.toFile())), "Ramdisk resize retains inverse record");
                payloads(d, smaller, newRamdisk);
                check(BootImageRebuilder.rebuild(d.toFile(), kernel.toFile(), e.toFile(), null).equivalence.ok(), "Explicit removal declared");
                check(BootImageRebuilder.readRecoveryRecord(e.toFile()) == null, "Null explicitly removes carrier");
                payloads(e, smaller, newRamdisk);
                BootImageRebuilder.rebuild(e.toFile(), kernel.toFile(), f.toFile(), null);
                check(Arrays.equals(Files.readAllBytes(e), Files.readAllBytes(f)), "Repeated removal is byte-identical");
                check(Arrays.equals(base, Files.readAllBytes(source)), "Lifecycle preserves original source");
            }
        }
    }

    private static void rejected(Path source, Path kernel, Path output, byte[] bytes, String code) throws Exception {
        Files.write(source, bytes);
        try { BootImageRebuilder.readRecoveryRecord(source.toFile()); throw new AssertionError("Read accepted " + code); }
        catch (java.io.IOException error) { check(code.equals(error.getMessage()), "Reader failure " + error); }
        try { BootImageRebuilder.rebuild(source.toFile(), kernel.toFile(), output.toFile()); throw new AssertionError("Rebuild accepted " + code); }
        catch (java.io.IOException error) { check(code.equals(error.getMessage()), "Writer failure " + error); }
        check(!Files.exists(output), "Malformed carrier does not publish output");
        check(Arrays.equals(bytes, Files.readAllBytes(source)), "Malformed source remains unchanged");
    }

    private static void boundaries(Path work) throws Exception {
        Path source = work.resolve("boundary-source.img"), kernel = work.resolve("boundary-kernel"), output = work.resolve("boundary-output.img");
        byte[] original = BootImageRebuilderTest.fixture(71, 0), record = {1,2,3};
        byte[] carried = withRegion(original, record, 4096);
        Files.write(kernel, content(71, 31));
        for (int[] edit : new int[][]{{8,2},{12,55},{20,1},{16,0},
                {16,(int)BootImageRebuilder.MAX_RECOVERY_FILE_BYTES + 1},{16,-1}}) {
            byte[] bad = carried.clone();
            ByteBuffer.wrap(bad).order(ByteOrder.LITTLE_ENDIAN).putInt(original.length + edit[0], edit[1]);
            rejected(source,kernel,output,bad,edit[0] == 16 ? "RECOVERY_RECORD_SIZE_LIMIT" : "RECOVERY_REGION_HEADER");
        }
        for (int offset : new int[]{24,56}) {
            byte[] bad = carried.clone(); bad[original.length + offset] ^= 1;
            rejected(source,kernel,output,bad,"RECOVERY_REGION_CHECKSUM");
        }
        rejected(source,kernel,output,Arrays.copyOf(carried, original.length + 10),"RECOVERY_REGION_TRUNCATED");
        rejected(source,kernel,output,Arrays.copyOf(carried, original.length + 58),"RECOVERY_REGION_TRUNCATED");
        byte[] duplicate = carried.clone();
        System.arraycopy(carried, original.length, duplicate, original.length + 59, 59);
        rejected(source,kernel,output,duplicate,"UNRECOGNIZED_BOOT_TRAILER");
        byte[] unknown = Arrays.copyOf(original, original.length + 4096); unknown[original.length] = 1;
        rejected(source,kernel,output,unknown,"UNRECOGNIZED_BOOT_TRAILER");
        Files.write(source,original);
        for (int size : new int[]{0,1048577}) {
            try { BootImageRebuilder.rebuild(source.toFile(),kernel.toFile(),output.toFile(),new byte[size]); throw new AssertionError("Bad new record size accepted"); }
            catch (java.io.IOException error) { check("RECOVERY_RECORD_SIZE_LIMIT".equals(error.getMessage()),"New record size checked"); }
            check(!Files.exists(output) && Arrays.equals(original,Files.readAllBytes(source)),"Bad record does not alter source/output");
        }
        byte[] maximum = new byte[1048576];
        BootImageRebuilder.rebuild(source.toFile(),kernel.toFile(),output.toFile(),maximum);
        check(Arrays.equals(maximum,BootImageRebuilder.readRecoveryRecord(output.toFile())),"Maximum opaque record accepted");
        Files.delete(output);
        byte[] partition = avb(original,8192); Files.write(source,partition);
        try { BootImageRebuilder.rebuild(source.toFile(),kernel.toFile(),output.toFile(),maximum); throw new AssertionError("Capacity overflow accepted"); }
        catch (java.io.IOException error) { check("AVB_PARTITION_SIZE_LIMIT".equals(error.getMessage()),"Capacity overflow checked"); }
        check(!Files.exists(output) && Arrays.equals(partition,Files.readAllBytes(source)),"Capacity failure preserves source and removes output");
        byte[] certificates = Arrays.copyOf(original,original.length + 4096 + 16384);
        ByteBuffer.wrap(certificates).order(ByteOrder.LITTLE_ENDIAN).putInt(1580,256);
        for (int at : new int[]{original.length, original.length + 4096, original.length + 4096 + 256}) {
            certificates[at]='A';certificates[at+1]='V';certificates[at+2]='B';certificates[at+3]='0';
        }
        byte[] withCertificates = withRegion(certificates,record,4096); Files.write(source,withCertificates);
        BootImageRebuilder.Report dropped = BootImageRebuilder.rebuild(source.toFile(),kernel.toFile(),output.toFile());
        check(dropped.declaredSignatures == 1 && dropped.trailingGkiCertificates == 2,"Old signature/GKI handling retained");
        check(Arrays.equals(record,BootImageRebuilder.readRecoveryRecord(output.toFile())),"Record after old certificates survives their removal");
        Files.delete(output);
        byte[] init = withRegion(BootImageRebuilderTest.fixture(0,71),record,4096); Files.write(source,init);
        Files.write(kernel,content(8193,7));
        BootImageRebuilder.rebuildRamdisk(source.toFile(),kernel.toFile(),output.toFile());
        check(BootImageInspector.inspect(output.toFile()).kernelSize == 0,"Ramdisk-only init_boot keeps zero kernel");
        check(Arrays.equals(record,BootImageRebuilder.readRecoveryRecord(output.toFile())),"Ramdisk-only init_boot retains inverse record");
        Files.delete(output);
    }

    private static void signer(Path work) throws Exception {
        Path fixtures = Files.createDirectory(work.resolve("signer-fixtures"));
        try (var resource = RecoveryRegionRebuilderTest.class.getResourceAsStream("/lenovo-avb-fixtures.zip");
             var zip = new java.util.zip.ZipInputStream(resource)) {
            for (var entry=zip.getNextEntry();entry!=null;entry=zip.getNextEntry()) {
                Path file=fixtures.resolve(entry.getName()).normalize();
                check(file.getParent().equals(fixtures),"Signer fixture confined");Files.copy(zip,file);
            }
        }
        var keys = new java.util.HashMap<Integer,java.security.PrivateKey>();
        for (int bits:new int[]{2048,4096}) keys.put(bits,LenovoAvbSigner.decodeKey(Files.readAllBytes(fixtures.resolve("testkey_rsa"+bits+".pem"))));
        Path stock=fixtures.resolve("boot.img"), kernel=work.resolve("signed-kernel"), candidate=work.resolve("signed-carrier.img");
        byte[] record={1,2,0,0,0}; Files.write(kernel,content(71,31));
        BootImageRebuilder.rebuild(stock.toFile(),kernel.toFile(),candidate.toFile(),record);
        byte[] before=Files.readAllBytes(candidate);
        var signed=LenovoAvbSigner.sign(LenovoAvbSigner.Mode.CHAINED,"boot",candidate.toFile(),stock.toFile(),
                java.util.Map.of(),work.resolve("signed-out").toFile(),keys::get,message->{});
        LenovoAvbSigner.verifySigned(LenovoAvbSigner.Mode.CHAINED,"boot",signed);
        check(Arrays.equals(record,BootImageRebuilder.readRecoveryRecord(signed.get("boot"))),"Signed footer covers and retains carrier");
        check(Arrays.equals(before,Files.readAllBytes(candidate)),"Signing keeps candidate immutable");
        // Existing footerless full-partition recovery scans the last nonzero byte. A record may end in zeros.
        byte[] compact=withRegion(BootImageRebuilderTest.fixture(71,0),record,4096);
        Files.write(candidate,Arrays.copyOf(compact,(int)stock.toFile().length()));
        var full=LenovoAvbSigner.sign(LenovoAvbSigner.Mode.CHAINED,"boot",candidate.toFile(),stock.toFile(),
                java.util.Map.of(),work.resolve("signed-full-out").toFile(),keys::get,message->{});
        LenovoAvbSigner.verifySigned(LenovoAvbSigner.Mode.CHAINED,"boot",full);
        check(Arrays.equals(record,BootImageRebuilder.readRecoveryRecord(full.get("boot"))),"Signer preserves zero-ending record in a padded footerless image");
    }

    public static void main(String[] args) throws Exception {
        Path work = Files.createTempDirectory("maplesu-recovery-region-");
        Path source = work.resolve("source.img"), kernel = work.resolve("kernel"), output = work.resolve("output.img");
        try {
            byte[] original = BootImageRebuilderTest.fixture(71, 0);
            byte[] record = new byte[]{0x12, 0x34, 0x56};
            byte[] carried = withRegion(original, record, 4096);
            Files.write(source, carried);
            byte[] replacement = new byte[8193];
            Arrays.fill(replacement, (byte) 0x44);
            Files.write(kernel, replacement);
            BootImageRebuilder.Report report = BootImageRebuilder.rebuild(source.toFile(), kernel.toFile(), output.toFile());
            byte[] actual = Files.readAllBytes(output);
            check(Arrays.equals(Arrays.copyOfRange(actual, 16384, 16443),
                    Arrays.copyOfRange(carried, 8192, 8251)), "Existing inverse record survives a kernel resize");
            check(report.equivalence.ok(), "Independent declared diff includes recovery relocation");
            check(Arrays.equals(carried, Files.readAllBytes(source)), "Recovery source stays unchanged");
            matrix(work);
            boundaries(work);
            signer(work);
            System.out.println("PASS " + passed + " recovery-region checks");
        } finally {
            try (var files = Files.walk(work)) {
                for (Path file : files.sorted(java.util.Comparator.reverseOrder()).toList()) Files.deleteIfExists(file);
            }
        }
    }
}
