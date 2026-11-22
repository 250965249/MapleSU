package dev.maplesu.image;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.zip.ZipInputStream;

/** AOSP avbtool-generated ordinary files. No device, root, Python or network is needed. */
public final class LenovoAvbSignerTest {
    private static int passed;
    private static Path fixtures, output;
    private static final Map<Integer, PrivateKey> KEYS = new LinkedHashMap<>();
    private static void check(boolean value, String message) {
        if (!value) throw new AssertionError(message);
        passed++;
    }
    private static File fixture(String name) { return fixtures.resolve(name).toFile(); }
    private static Map<String, File> sign(String name, LenovoAvbSigner.Mode mode, String source, String patch,
                                          Map<String, File> companions) throws Exception {
        return LenovoAvbSigner.sign(mode, "boot", fixture(patch), fixture(source), companions,
                output.resolve(name).toFile(), KEYS::get, message -> {});
    }
    private static long number(byte[] data, int at) { return ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN).getLong(at); }
    private static byte[] descriptor(LenovoAvbSigner.Info info, long tag, String partition) {
        return info.raw.stream().filter(raw -> number(raw, 0) == tag && new String(raw,
                tag == 2 ? 132 : 92, ByteBuffer.wrap(raw).getInt(tag == 2 ? 56 : 20),
                java.nio.charset.StandardCharsets.UTF_8).equals(partition)).findFirst().orElseThrow();
    }
    private static void rejected(String name, String source, Map<String, File> companions, String code) throws Exception {
        try {
            sign(name, LenovoAvbSigner.Mode.AOSP, source, "patched-grow.img", companions);
            throw new AssertionError("Expected " + code);
        } catch (IOException error) { check(error.getMessage().contains(code), error.toString()); }
        check(!Files.exists(output.resolve(name)), "No partial signed output");
    }
    private static void verifyRejected(LenovoAvbSigner.Mode mode, String partition, Map<String, File> images, String code) throws Exception {
        try {
            LenovoAvbSigner.verifySigned(mode, partition, images);
            throw new AssertionError("Expected " + code);
        } catch (IOException error) { check(error.getMessage().contains(code), error.toString()); }
    }
    public static void main(String[] args) throws Exception {
        fixtures = Files.createTempDirectory("lenovo-avb-fixtures-");
        output = Path.of(System.getProperty("maplesu.avb.outputs", fixtures.resolve("outputs").toString()));
        Files.createDirectories(output);
        try {
            try (InputStream resource = LenovoAvbSignerTest.class.getResourceAsStream("/lenovo-avb-fixtures.zip");
                 ZipInputStream zip = new ZipInputStream(resource)) {
                for (var entry = zip.getNextEntry(); entry != null; entry = zip.getNextEntry()) {
                    Path path = fixtures.resolve(entry.getName()).normalize();
                    check(path.getParent().equals(fixtures), "Fixture path confined");
                    Files.copy(zip, path);
                }
            }
            for (int bits : new int[]{2048, 4096}) KEYS.put(bits, LenovoAvbSigner.decodeKey(Files.readAllBytes(fixture("testkey_rsa" + bits + ".pem").toPath())));
            File patched = fixture("patched-grow.img");
            byte[] patchedBefore = Files.readAllBytes(patched.toPath());
            for (String algorithm : new String[]{"SHA256_RSA2048", "SHA256_RSA4096", "SHA512_RSA2048", "SHA512_RSA4096"}) {
                String source = "boot-" + algorithm + ".img";
                byte[] before = Files.readAllBytes(fixture(source).toPath());
                var result = sign(algorithm, LenovoAvbSigner.Mode.CHAINED, source, "patched-grow.img", Map.of());
                File boot = result.get("boot");
                LenovoAvbSigner.Info info = LenovoAvbSigner.read(boot), old = LenovoAvbSigner.read(fixture(source));
                check(info.algorithm == old.algorithm && info.rollback == 123 && info.flags == old.flags && info.minor == old.minor, "Chained header parameters retained");
                check(info.location == 0, "Legacy chained footer uses location zero like Violet");
                check(AvbFooter.parse(boot).originalImageSize == patched.length(), "Footer uses final payload length");
                check(boot.length() == before.length, "Partition length preserved");
                check(Arrays.equals(old.key, info.key), "Original AOSP signing identity retained");
                check(Arrays.equals(before, Files.readAllBytes(fixture(source).toPath())), "Source immutable");
                for (byte[] descriptor : old.raw) if (number(descriptor, 0) == 0)
                    check(info.raw.stream().anyMatch(raw -> Arrays.equals(raw, descriptor)), "Raw build properties preserved");
                byte[] oldHash = old.raw.stream().filter(raw -> number(raw, 0) == 2).findFirst().orElseThrow();
                byte[] newHash = info.raw.stream().filter(raw -> number(raw, 0) == 2).findFirst().orElseThrow();
                check(Arrays.equals(Arrays.copyOfRange(oldHash, 136, 168), Arrays.copyOfRange(newHash, 136, 168)), "Original salt retained");
                LenovoAvbSigner.verify(result);
            }
            var full = sign("full-length", LenovoAvbSigner.Mode.CHAINED, "boot.img", "patched-full-no-footer.img", Map.of());
            check(AvbFooter.parse(full.get("boot")).originalImageSize == patched.length(), "Zero-padded patcher output trimmed to new components");
            Map<String, File> nonchain = Map.of("vbmeta", fixture("vbmeta-nonchained.img"));
            var plain = sign("non-chained", LenovoAvbSigner.Mode.NON_CHAINED, "boot-NONE.img", "patched-grow.img", nonchain);
            check(plain.size() == 2 && LenovoAvbSigner.read(plain.get("boot")).algorithm == 0, "Unsigned footer rebuilt and vbmeta exported");
            check(LenovoAvbSigner.read(plain.get("vbmeta")).algorithm == 5 && LenovoAvbSigner.read(plain.get("vbmeta")).rollback == 555, "Main vbmeta original algorithm and rollback retained");
            File raw = fixture("raw-boot.img");
            byte[] noFooter = new byte[131072];
            System.arraycopy(BootImageRebuilderTest.fixture(8192, 4096), 0, noFooter, 0, 16384);
            Files.write(raw.toPath(), noFooter);
            var rawSigned = sign("raw-non-chained", LenovoAvbSigner.Mode.NON_CHAINED, "raw-boot.img", "patched-grow.img", nonchain);
            LenovoAvbSigner.verify(rawSigned);
            check(rawSigned.size() == 2, "Normal reads hash parameters from main vbmeta when boot lacks footer");
            for (String initSource : new String[]{"init_boot.img", "raw-init_boot.img"}) {
                var init = LenovoAvbSigner.sign(LenovoAvbSigner.Mode.NON_CHAINED, "init_boot",
                        fixture("patched-init_boot-full.img"), fixture(initSource), nonchain,
                        output.resolve("init-" + initSource).toFile(), KEYS::get, message -> {});
                check(init.keySet().equals(java.util.Set.of("init_boot", "vbmeta")), "Non-chained outputs preserve init_boot target");
                check(AvbFooter.parse(init.get("init_boot")).originalImageSize == fixture("patched-init_boot-grow.img").length(), "Init boot grows from final ramdisk header, including source without footer");
                check(LenovoAvbSigner.read(init.get("init_boot")).algorithm == 0, "Init boot uses unsigned hash footer");
                LenovoAvbSigner.verifySigned(LenovoAvbSigner.Mode.NON_CHAINED, "init_boot", init);
            }
            File restoredInit = fixture("restored-init_boot.img");
            byte[] restoredBytes = Files.readAllBytes(fixture("raw-init_boot.img").toPath());
            restoredBytes[4096] ^= 0x55;
            Files.write(restoredInit.toPath(), restoredBytes);
            var restored = LenovoAvbSigner.sign(LenovoAvbSigner.Mode.NON_CHAINED, "boot", patched, fixture("boot-NONE.img"),
                    nonchain, Map.of("init_boot", restoredInit), output.resolve("restored-hash").toFile(), KEYS::get, message -> {});
            Map<String, File> restoredSet = new LinkedHashMap<>(restored);
            restoredSet.put("init_boot", restoredInit);
            LenovoAvbSigner.verify(restoredSet);
            check(!Arrays.equals(descriptor(LenovoAvbSigner.read(fixture("vbmeta-nonchained.img")), 2, "init_boot"),
                    descriptor(LenovoAvbSigner.read(restored.get("vbmeta")), 2, "init_boot")), "Main vbmeta covers restored non-target stock bytes");
            var restoredBoot = LenovoAvbSigner.sign(LenovoAvbSigner.Mode.NON_CHAINED, "init_boot", fixture("patched-init_boot-grow.img"),
                    fixture("init_boot.img"), Map.of("vbmeta", fixture("vbmeta-init-boot4k.img")), Map.of("boot", fixture("boot.img")),
                    output.resolve("restored-boot-chain").toFile(), KEYS::get, message -> {});
            Map<String, File> restoredBootSet = new LinkedHashMap<>(restoredBoot);
            restoredBootSet.put("boot", fixture("boot.img"));
            LenovoAvbSigner.verifySigned(LenovoAvbSigner.Mode.NON_CHAINED, "init_boot", restoredBootSet);
            check(!Arrays.equals(descriptor(LenovoAvbSigner.read(fixture("vbmeta-init-boot4k.img")), 4, "boot"),
                    descriptor(LenovoAvbSigner.read(restoredBoot.get("vbmeta")), 4, "boot")), "Migration rebinds main chain to restored stock boot key after prior AOSP signing");
            var alreadyChained = sign("non-chained-signed-boot", LenovoAvbSigner.Mode.NON_CHAINED, "boot.img", "patched-grow.img", Map.of("vbmeta", fixture("vbmeta.img")));
            check(Arrays.equals(Files.readAllBytes(alreadyChained.get("vbmeta").toPath()), Files.readAllBytes(fixture("vbmeta.img").toPath())), "Non-chained mode preserves main metadata for already chained boot");
            var rebound = sign("legacy-rebind", LenovoAvbSigner.Mode.CHAINED, "boot.img", "patched-grow.img",
                    Map.of("vbmeta", fixture("vbmeta-init-boot4k.img")));
            check(rebound.size() == 2 && LenovoAvbSigner.read(rebound.get("vbmeta")).algorithm == 2,
                    "Legacy signing rebinds a prior AOSP target chain while preserving the main algorithm");
            Map<String, File> chain = Map.of("recovery", fixture("recovery.img"), "vbmeta_system", fixture("vbmeta_system.img"), "vbmeta", fixture("vbmeta.img"));
            var aosp = sign("aosp", LenovoAvbSigner.Mode.AOSP, "boot.img", "patched-grow.img", chain);
            check(aosp.size() == 4, "All four AOSP outputs present");
            for (String name : new String[]{"boot", "recovery", "vbmeta_system", "vbmeta"}) {
                var info = LenovoAvbSigner.read(aosp.get(name));
                check(info.algorithm == 2 && Arrays.equals(info.key, LenovoAvbSigner.publicKey(KEYS.get(4096))), "AOSP forces SHA256 RSA4096: " + name);
                check(aosp.get(name).length() == fixture(name + ".img").length(), "AOSP preserves length: " + name);
            }
            check(LenovoAvbSigner.read(aosp.get("vbmeta_system")).rollback == 777 && LenovoAvbSigner.read(aosp.get("vbmeta")).location == 8, "AOSP standalone header parameters retained");
            for (String name : LenovoAvbSigner.AOSP_PARTITIONS) {
                byte[] oldChain = descriptor(LenovoAvbSigner.read(fixture("vbmeta.img")), 4, name);
                byte[] newChain = descriptor(LenovoAvbSigner.read(aosp.get("vbmeta")), 4, name);
                check(Arrays.equals(Arrays.copyOfRange(oldChain, 16, 24), Arrays.copyOfRange(newChain, 16, 24)) &&
                    Arrays.equals(Arrays.copyOfRange(oldChain, 28, 92), Arrays.copyOfRange(newChain, 28, 92)), "AOSP chain rollback location, flags and reserved bytes retained: " + name);
            }
            var systemBefore = LenovoAvbSigner.read(fixture("vbmeta_system.img"));
            var systemAfter = LenovoAvbSigner.read(aosp.get("vbmeta_system"));
            check(systemBefore.raw.size() == systemAfter.raw.size(), "System descriptor count retained");
            for (int i = 0; i < systemBefore.raw.size(); i++) check(Arrays.equals(systemBefore.raw.get(i), systemAfter.raw.get(i)), "System raw descriptors retained exactly");
            LenovoAvbSigner.verify(aosp);
            verifyRejected(LenovoAvbSigner.Mode.CHAINED, "boot", Map.of("boot", fixture("boot.img"),
                    "vbmeta", fixture("vbmeta_system.img")), "CHAIN_MISSING_boot");
            verifyRejected(LenovoAvbSigner.Mode.NON_CHAINED, "init_boot", Map.of("init_boot", fixture("init_boot.img"),
                    "vbmeta", fixture("vbmeta_system.img")), "VBMETA_REFERENCE_MISSING_init_boot");
            Map<String, File> missingAospChain = new LinkedHashMap<>(aosp);
            missingAospChain.put("vbmeta", aosp.get("vbmeta_system"));
            verifyRejected(LenovoAvbSigner.Mode.AOSP, "boot", missingAospChain, "CHAIN_MISSING_boot");
            byte[] aospBoot = Files.readAllBytes(aosp.get("boot").toPath());
            try (RandomAccessFile tamper = new RandomAccessFile(aosp.get("boot"), "rw")) { tamper.seek(4096); tamper.write(0); }
            try { LenovoAvbSigner.verify(aosp); throw new AssertionError("Tampered hash accepted"); }
            catch (IOException expected) { check(expected.getMessage().contains("HASH_MISMATCH"), expected.toString()); }
            Files.write(aosp.get("boot").toPath(), aospBoot);
            byte[] mainBefore = Files.readAllBytes(aosp.get("vbmeta").toPath());
            try (RandomAccessFile tamper = new RandomAccessFile(aosp.get("vbmeta"), "rw")) {
                tamper.seek(256 + 32); int octet = tamper.read(); tamper.seek(256 + 32); tamper.write(octet ^ 0x80);
            }
            try { LenovoAvbSigner.verify(aosp); throw new AssertionError("Tampered signature accepted"); }
            catch (IOException expected) { check(expected.getMessage().contains("RSA_VERIFY_FAILED"), expected.toString()); }
            Files.write(aosp.get("vbmeta").toPath(), mainBefore);
            rejected("missing", "boot.img", Map.of(), "IMAGE_MISSING_vbmeta");
            rejected("missing-chain", "boot.img", Map.of("vbmeta", fixture("vbmeta-nonchained.img")), "CHAIN_MISSING_boot");
            File malformed = fixture("malformed.img");
            byte[] invalid = Files.readAllBytes(fixture("boot.img").toPath()); invalid[invalid.length - 52] = (byte) 0xff;
            Files.write(malformed.toPath(), invalid);
            rejected("malformed", "malformed.img", chain, "FOOTER_INVALID");
            File small = fixture("small.img");
            Files.write(small.toPath(), Files.readAllBytes(fixture("boot.img").toPath()));
            try (RandomAccessFile file = new RandomAccessFile(small, "rw")) { file.setLength(100); }
            rejected("truncated", "small.img", chain, "HEADER_TRUNCATED");
            File oversized = fixture("oversized.img");
            Files.write(oversized.toPath(), Arrays.copyOf(patchedBefore, 131072 - 4096));
            try { sign("space", LenovoAvbSigner.Mode.CHAINED, "boot.img", "oversized.img", Map.of()); throw new AssertionError("Full partition accepted"); }
            catch (IOException expected) { check(expected.getMessage().contains("PARTITION_SPACE"), expected.toString()); }
            check(!Files.exists(output.resolve("space")), "Insufficient space leaves no partial output");
            check(Arrays.equals(patchedBefore, Files.readAllBytes(patched.toPath())), "Patched source immutable across all attempts");
            System.out.println("LenovoAvbSignerTest: " + passed + " assertions passed; outputs=" + output);
        } finally {
            if (System.getProperty("maplesu.avb.outputs") == null) {
                try (var paths = Files.walk(fixtures)) { for (Path p : paths.sorted(java.util.Comparator.reverseOrder()).toList()) Files.delete(p); }
            }
        }
    }
}
