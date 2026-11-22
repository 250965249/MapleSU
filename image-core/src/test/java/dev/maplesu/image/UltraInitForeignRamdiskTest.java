package dev.maplesu.image;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

/** Narrow actual Producer/CPIO tests; no shim/module/SDK/device execution. Fixed test_owner only. */
public final class UltraInitForeignRamdiskTest {
    private static int checks;
    private static void check(boolean answer, String detail) {
        if (!answer) throw new AssertionError(detail);
        checks++;
    }
    private static byte[] ascii(String value) { return value.getBytes(StandardCharsets.US_ASCII); }
    private static byte[] fixture(String name, Object... args) throws Exception {
        Class<?>[] types = Arrays.stream(args).map(value -> value instanceof Boolean ? boolean.class :
                value instanceof Integer ? int.class : value.getClass()).toArray(Class<?>[]::new);
        Method method = UltraInitBootProducerTest.class.getDeclaredMethod(name, types);
        method.setAccessible(true);
        return (byte[]) method.invoke(null, args);
    }
    private static byte[] entry(String path, int mode, byte[] bytes) throws Exception {
        return fixture("entry", path, mode, bytes, false);
    }
    private static byte[] join(byte[]... arrays) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] bytes : arrays) out.write(bytes);
        return out.toByteArray();
    }
    private static byte[] archive(byte[]... entries) throws Exception {
        return join(join(entries), entry("TRAILER!!!", 0, new byte[0]));
    }
    private static byte[] shim(String module) throws Exception {
        byte[] bytes = Arrays.copyOf(fixture("handoff"), 512);
        byte[] names = ascii("init.real\0/system/bin/init\0" + module + "\0ksu_config\0");
        System.arraycopy(names, 0, bytes, 256, names.length);
        ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).putLong(96, bytes.length).putLong(104, bytes.length);
        return bytes;
    }
    private interface Action { void run() throws Exception; }
    private static void fails(String code, Action action) throws Exception {
        try { action.run(); throw new AssertionError("expected " + code); }
        catch (IOException error) { check(error.getMessage().startsWith(code), "expected " + code + ", got " + error); }
    }
    private static void roundTrip(Path root, String name, byte[] cpio, String expectedInit,
                                  boolean normalizedBackup, boolean symbolic) throws Exception {
        Path work = Files.createDirectory(root.resolve(name));
        byte[] raw = fixture("kernel"), targetBytes = fixture("image", raw, new byte[0]);
        Path target = work.resolve("target.img"), input = work.resolve("input.img"),
                first = work.resolve("first.img"), next = work.resolve("next.img"), inverse = work.resolve("inverse.img");
        Files.write(target, targetBytes);
        byte[] original = fixture("image", new byte[0], cpio);
        Files.write(input, original);
        UltraInitBootProducer.Artifact artifact = new UltraInitBootProducer.Artifact(target.toFile(),
                KernelIdentity.sha256(targetBytes), KernelIdentity.releaseOf(raw), KernelIdentity.sha256(raw),
                KernelIdentity.sha256(ascii("fixture-credential")), fixture("handoff"), ascii("opaque module fixture"));
        UltraInitBootProducer.produce(input.toFile(), first.toFile(), artifact);
        RamdiskInspector.Report report = RamdiskInspector.inspect(first.toFile());
        check(!report.malformed, name + " produced CPIO");
        RamdiskInspector.Entry init = report.entry(UltraInitRamdisk.ORIGINAL);
        check(init != null && init.isSymbolicLink() == symbolic &&
                init.sha256.equals(KernelIdentity.sha256(ascii(expectedInit))), name + " executes preserved Android init");
        if (normalizedBackup) {
            check(!report.has(".backup") && !report.has(".backup/init") && !report.has("overlay.d/new.rc"), name + " restore bookkeeping and added overlay removed");
            if (report.has("fstab.fixture")) check(report.entry("fstab.fixture").sha256.equals(
                    KernelIdentity.sha256(ascii("original-fstab"))), "backup restores modified original entry");
        }
        UltraInitBootProducer.produce(first.toFile(), next.toFile(), artifact);
        check(Arrays.equals(Files.readAllBytes(first), Files.readAllBytes(next)), name + " deterministic owned repatch");
        UltraInitBootProducer.restore(next.toFile(), inverse.toFile());
        check(Arrays.equals(original, Files.readAllBytes(inverse)), name + " exact foreign container inverse");
        check(Arrays.equals(original, Files.readAllBytes(input)) && Arrays.equals(targetBytes, Files.readAllBytes(target)), name + " both inputs immutable");
    }
    public static void main(String[] args) throws Exception {
        if (args.length != 1) throw new IllegalArgumentException("one fixed tester output directory required");
        Path root = Path.of(args[0]);
        Files.createDirectory(root);
        byte[] trueInit = ascii("preserved-android-init");
        for (String module : new String[]{"kernelsu.ko", "sevenk.ko"}) {
            byte[] noReal = archive(entry("init", 0100755, shim(module)), entry(module, 0100600, ascii("opaque prior module")));
            roundTrip(root, module + "-empty-origin", noReal, "/system/bin/init", false, true);
            byte[] withReal = archive(entry("init", 0100755, ascii("prior-shim")), entry("init.real", 0100750, trueInit),
                    entry(module, 0100600, ascii("opaque prior module")));
            roundTrip(root, module + "-retained-init", withReal, "preserved-android-init", false, false);
        }
        byte[] backup = archive(entry("init", 0100755, shim("magisk")),
                entry("fstab.fixture", 0100644, ascii("modified-fstab")),
                entry("overlay.d", 0040755, new byte[0]), entry("overlay.d/new.rc", 0100644, ascii("foreign-overlay")),
                entry(".backup", 0040000, new byte[0]), entry(".backup/.magisk", 0100000, ascii("KEEPVERITY=true\n")),
                entry(".backup/.rmlist", 0100000, ascii("overlay.d\0")),
                entry(".backup/init", 0100750, trueInit), entry(".backup/fstab.fixture", 0100644, ascii("original-fstab")));
        roundTrip(root, "backup-normalization", backup, "preserved-android-init", true, false);
        byte[] empty = archive(entry("init", 0100755, shim("magisk")),
                entry(".backup/.magisk", 0100000, ascii("KEEPVERITY=true\n")),
                entry(".backup/.rmlist", 0100000, ascii("init\0")));
        roundTrip(root, "backup-empty-origin", empty, "/system/bin/init", true, true);
        byte[] badList = archive(entry("init", 0100755, shim("magisk")),
                entry(".backup/.magisk", 0100000, ascii("metadata")),
                entry(".backup/.rmlist", 0100000, ascii("overlay.d")), entry(".backup/init", 0100750, trueInit));
        fails("ULTRA_INIT_FOREIGN_REMOVAL_LIST_FORMAT", () -> UltraInitRamdisk.install(badList, fixture("handoff"), ascii("bridge")));
        byte[] unknown = archive(entry("init", 0100755, ascii("unknown-shim")), entry("magiskinit", 0100755, ascii("marker")));
        fails("ULTRA_INIT_FOREIGN_BACKUP_REQUIRED", () -> UltraInitRamdisk.install(unknown, fixture("handoff"), ascii("bridge")));
        byte[] fakeFallback = archive(entry("init", 0100755, ascii("unproven")), entry("kernelsu.ko", 0100600, ascii("module")));
        fails("ULTRA_INIT_FOREIGN_KSU_FALLBACK_PROOF_REQUIRED", () -> UltraInitRamdisk.install(fakeFallback, fixture("handoff"), ascii("bridge")));
        byte[] conflict = archive(entry("init", 0100755, shim("magisk")), entry(".backup/.magisk", 0100000, ascii("metadata")),
                entry(".backup/.rmlist", 0100000, ascii("init\0")), entry(".backup/init", 0100750, trueInit));
        fails("ULTRA_INIT_FOREIGN_BACKUP_REMOVAL_CONFLICT", () -> UltraInitRamdisk.install(conflict, fixture("handoff"), ascii("bridge")));
        System.out.println("PASS " + checks + " actual Producer/CPIO migration checks; no module or device execution");
    }
}
