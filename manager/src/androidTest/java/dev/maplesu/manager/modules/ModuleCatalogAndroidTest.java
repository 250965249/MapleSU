package dev.maplesu.manager.modules;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;
import dev.maplesu.manager.ModuleArchiveInspector;
import dev.maplesu.manager.ModuleArchiveInspector.ModuleType;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import static org.junit.Assert.*;

/** Ordinary app-UID file tests: packages stay compressed and module code is never loaded or run. */
@RunWith(AndroidJUnit4.class)
public class ModuleCatalogAndroidTest {
    private static final String ID = "abcdef0123456789abcdef0123456789";
    private File directory, catalogDirectory, marker;
    private ModuleCatalog catalog;

    @Before public void prepare() throws Exception {
        assertTrue("Expected ordinary application UID", android.os.Process.myUid() >= 10_000);
        File cache = InstrumentationRegistry.getInstrumentation().getTargetContext().getCacheDir();
        directory = new File(cache, "module-catalog-android-" + System.nanoTime());
        assertTrue(directory.mkdir());
        catalogDirectory = new File(directory, "catalog");
        marker = new File(directory, "module-code-must-not-run");
        catalog = new ModuleCatalog(catalogDirectory);
    }

    @After public void cleanup() throws Exception {
        if (directory != null) delete(directory);
    }

    @Test public void bothFormatsStageCommitReopenDisableEnableAndUninstallAtAppUid() throws Exception {
        File ksu = ksu("ksu.zip", 1);
        File maplesu = zip("maplesu.zip", new String[] { "libmodule.so", "service.sh" },
                new byte[][] { maplesuElf(), script() });
        var ksuReport = ModuleArchiveInspector.inspect(ksu);
        var maplesuReport = ModuleArchiveInspector.inspect(maplesu);
        assertEquals(ModuleType.KERNEL_SU, ksuReport.type);
        assertEquals(ModuleType.MAPLESU, maplesuReport.type);
        byte[] originalKsu = Files.readAllBytes(ksu.toPath());
        byte[] originalMaplesu = Files.readAllBytes(maplesu.toPath());
        var stagedKsu = catalog.stage(ksu, ksuReport.type, ksuReport.sha256);
        var stagedMaplesu = catalog.stage(maplesu, maplesuReport.type, maplesuReport.sha256);
        assertTrue(catalog.list().isEmpty());
        catalog.commit(stagedKsu.token);
        catalog.commit(stagedMaplesu.token);
        assertEquals(2, new ModuleCatalog(catalogDirectory).list().size());
        for (var report : List.of(ksuReport, maplesuReport)) {
            var stored = new ModuleCatalog(catalogDirectory).get(report.type, report.id);
            assertNotNull(stored);
            assertTrue(stored.enabled);
            assertEquals(report.sha256, sha(stored.archive));
            assertTrue(Files.isRegularFile(stored.archive.toPath(), LinkOption.NOFOLLOW_LINKS));
            assertFalse(new File(stored.archive.getParentFile(), "service.sh").exists());
            catalog.setEnabled(report.type, report.id, false);
            assertFalse(new ModuleCatalog(catalogDirectory).get(report.type, report.id).enabled);
            catalog.setEnabled(report.type, report.id, true);
            assertTrue(new ModuleCatalog(catalogDirectory).get(report.type, report.id).enabled);
            catalog.uninstall(report.type, report.id);
            assertNull(new ModuleCatalog(catalogDirectory).get(report.type, report.id));
            assertFalse(stored.archive.exists());
        }
        assertTrue(catalog.list().isEmpty());
        assertArrayEquals(originalKsu, Files.readAllBytes(ksu.toPath()));
        assertArrayEquals(originalMaplesu, Files.readAllBytes(maplesu.toPath()));
        assertFalse(marker.exists());
    }

    @Test public void nativePackageIsRejectedBeforeStagingAndHistoricalDataIsPreserved() throws Exception {
        var context = InstrumentationRegistry.getInstrumentation().getTargetContext();
        var isolated = new android.content.ContextWrapper(context) {
            @Override public android.content.Context getApplicationContext() { return this; }
            @Override public File getFilesDir() { return directory; }
        };
        File source = zip("unsupported.zip", new String[] { "libmodule.so", "service.sh" },
                new byte[][] { maplesuElf(), script() });
        byte[] original = Files.readAllBytes(source.toPath());
        var report = ModuleArchiveInspector.inspect(source);
        assertEquals(ModuleType.MAPLESU, report.type);
        var backend = new LiteScriptModuleBackend(isolated);
        var errors = new java.util.ArrayList<String>();
        var result = backend.install(source, report, ignored -> kotlin.Unit.INSTANCE,
                message -> { errors.add(message); return kotlin.Unit.INSTANCE; });
        assertEquals(1, result.getCode());
        assertFalse(result.getNeedsReboot());
        assertEquals(List.of(context.getString(com.maplesu.core.R.string.module_maplesu_not_supported)), errors);
        var stored = new ModuleCatalog(new File(directory, "module-catalog"));
        assertTrue(stored.list().isEmpty());
        assertEquals(0, new File(directory, "module-catalog/staged").list().length);

        // A previously stored native package stays intact but has no product list entry.
        var old = stored.commit(stored.stage(source, report.type, report.sha256).token);
        assertEquals(0, new org.json.JSONArray(backend.listJson()).length());
        assertNotNull(stored.get(report.type, report.id));
        assertArrayEquals(original, Files.readAllBytes(old.archive.toPath()));
        assertArrayEquals(original, Files.readAllBytes(source.toPath()));
        assertFalse(marker.exists());
    }

    @Test public void changedSourceAndStagedDigestRejectUpdateAndPreserveOldVersion() throws Exception {
        File original = ksu("original.zip", 1);
        var first = catalog.commit(stage(original).token);
        byte[] originalBytes = Files.readAllBytes(original.toPath());
        File changed = ksu("changed.zip", 2);
        var confirmed = ModuleArchiveInspector.inspect(changed);
        ksu("changed.zip", 3);
        assertEquals("MODULE_ARCHIVE_CONFIRMATION_MISMATCH", assertThrows(ModuleCatalog.Failure.class,
                () -> catalog.stage(changed, confirmed.type, confirmed.sha256)).code);
        assertEquals(first.report.sha256, new ModuleCatalog(catalogDirectory).get(ModuleType.KERNEL_SU, ID).report.sha256);

        var pending = stage(ksu("pending.zip", 2));
        File different = ksu("different.zip", 4);
        Files.copy(different.toPath(), new File(catalogDirectory, "staged/" + pending.token + "/archive.zip").toPath(),
                   StandardCopyOption.REPLACE_EXISTING);
        assertEquals("MODULE_ARCHIVE_CONFIRMATION_MISMATCH", assertThrows(ModuleCatalog.Failure.class,
                () -> catalog.commit(pending.token)).code);
        var retained = new ModuleCatalog(catalogDirectory).get(ModuleType.KERNEL_SU, ID);
        assertEquals(1, retained.report.versionCode);
        assertEquals(first.report.sha256, sha(retained.archive));
        assertEquals(1, catalog.list().size());
        assertArrayEquals(originalBytes, Files.readAllBytes(original.toPath()));
        assertFalse(marker.exists());
        catalog.discard(pending.token);
        catalog.uninstall(ModuleType.KERNEL_SU, ID);
    }

    @Test public void traversalArchiveIsRejectedAndInstalledRecordIsPreserved() throws Exception {
        var first = catalog.commit(stage(ksu("original.zip", 1)).token);
        File invalid = zip("traversal.zip", new String[] { "module.prop", "../outside-marker" },
                new byte[][] { ("id=" + ID + "\nversionCode=2\n").getBytes(StandardCharsets.UTF_8),
                               "untrusted archive data".getBytes(StandardCharsets.UTF_8) });
        byte[] original = Files.readAllBytes(invalid.toPath());
        String confirmedHash = sha(invalid);
        assertEquals("INVALID_ARCHIVE_PATH", assertThrows(ModuleArchiveInspector.Failure.class,
                () -> catalog.stage(invalid, ModuleType.KERNEL_SU, confirmedHash)).code);
        assertEquals(first.report.sha256, new ModuleCatalog(catalogDirectory).list().get(0).report.sha256);
        assertArrayEquals(original, Files.readAllBytes(invalid.toPath()));
        assertEquals(0, new File(catalogDirectory, "staged").list().length);
        assertFalse(new File(directory, "outside-marker").exists());
        assertFalse(new File(catalogDirectory, "staged/outside-marker").exists());
        assertFalse(marker.exists());
        catalog.uninstall(ModuleType.KERNEL_SU, ID);
    }

    private ModuleCatalog.Staged stage(File source) throws Exception {
        var report = ModuleArchiveInspector.inspect(source);
        return catalog.stage(source, report.type, report.sha256);
    }

    private File ksu(String name, int version) throws Exception {
        return zip(name, new String[] { "module.prop", "service.sh" }, new byte[][] {
                ("id=" + ID + "\nname=Catalog fixture\nversionCode=" + version + "\n").getBytes(StandardCharsets.UTF_8),
                script() });
    }

    private byte[] script() {
        return ("echo executed > '" + marker.getAbsolutePath() + "'\n").getBytes(StandardCharsets.UTF_8);
    }

    private File zip(String name, String[] names, byte[][] values) throws Exception {
        File file = new File(directory, name);
        try (ZipOutputStream zip = new ZipOutputStream(new FileOutputStream(file))) {
            for (int i = 0; i < names.length; i++) {
                zip.putNextEntry(new ZipEntry(names[i])); zip.write(values[i]); zip.closeEntry();
            }
        }
        return file;
    }

    private static String sha(File file) throws Exception {
        byte[] hash = MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(file.toPath()));
        StringBuilder value = new StringBuilder(64);
        for (byte item : hash) value.append(Character.forDigit((item >>> 4) & 15, 16))
                .append(Character.forDigit(item & 15, 16));
        return value.toString();
    }

    private static void delete(File file) throws Exception {
        if (file.isDirectory()) {
            File[] children = file.listFiles(); assertNotNull(children);
            for (File child : children) delete(child);
        }
        assertTrue("Test file cleanup: " + file, file.delete());
    }

    /** Minimal ELF metadata fixture with a defined dynamic function; its bytes are never executed. */
    static byte[] maplesuElf() {
        String entry = dev.maplesu.manager.compat.NativeModuleAbi.ENTRY;
        String[] tags = {
            "de1f663bcae792d7c9ed1a21cdaeff00331fe11b074f0303e018f43998f8db3e" + "Catalog fixture" + "04429c3f7172e4cce7ac7a5d44b75631ce91777b5f2a5eec076a3a508a76fb17",
            "7dc74a2b86805f2cd0f45c6a82d384fd568e341c6f05af17c7229c9ba6d4318b" + "1.0" + "8dbc019a6e51fe8d4a3db9feaf05535d70879f35626050cd4131bfe323ecefc2",
            "05c62cd446c811e772c94d97fd546738328f7c6b9967ed135190ef37ff06d866" + "Static fixture" + "ed02c95e091c66100d6f2f4554f96392b2951b394ba042278eed8f236f43e1a3",
            "1f39b220291a2fb6e4fec95f179d0faf833ca534ef8ab2ffc4bd893768694451" + "MapleSU tests" + "d409c886fd6cedd694c1b126fd19eccd90e2463e04154c193effc7103ce63f1c",
            "b33dcddd88c07d079a8e0e9ec6ab976f15f2edba46cab91a61234cfbb982111c" + ID + "3020d9a6c07a30e2649dd29a72d7e57121f0c0ca457b6d21dca5a69acbe6c2c4"
        };
        byte[] metadata = String.join("\0", tags).getBytes(StandardCharsets.UTF_8);
        byte[] strings = ("\0" + entry + "\0").getBytes(StandardCharsets.US_ASCII);
        int stringOffset = 512 + metadata.length, symbolOffset = (stringOffset + strings.length + 7) & -8;
        int sectionOffset = symbolOffset + 48;
        ByteBuffer bytes = ByteBuffer.allocate(sectionOffset + 192).order(ByteOrder.LITTLE_ENDIAN);
        bytes.put(new byte[] { 0x7f, 69, 76, 70, 2, 1, 1 });
        bytes.putShort(16, (short) 3); bytes.putShort(18, (short) 183); bytes.putInt(20, 1);
        bytes.putLong(32, 64); bytes.putLong(40, sectionOffset);
        bytes.putShort(52, (short) 64); bytes.putShort(54, (short) 56); bytes.putShort(56, (short) 1);
        bytes.putShort(58, (short) 64); bytes.putShort(60, (short) 3);
        bytes.putInt(64, 1); bytes.putInt(68, 5); bytes.putLong(80, 0x400000);
        bytes.putLong(96, bytes.capacity()); bytes.putLong(104, bytes.capacity()); bytes.putLong(112, 4096);
        bytes.putInt(256, 0xd65f03c0);
        bytes.position(512); bytes.put(metadata); bytes.position(stringOffset); bytes.put(strings);
        bytes.putInt(symbolOffset + 24, 1); bytes.put(symbolOffset + 28, (byte) 0x12);
        bytes.putShort(symbolOffset + 30, (short) 1);
        bytes.putLong(symbolOffset + 32, 0x400100); bytes.putLong(symbolOffset + 40, 4);
        bytes.putInt(sectionOffset + 68, 3); bytes.putLong(sectionOffset + 88, stringOffset);
        bytes.putLong(sectionOffset + 96, strings.length);
        bytes.putInt(sectionOffset + 132, 11); bytes.putLong(sectionOffset + 152, symbolOffset);
        bytes.putLong(sectionOffset + 160, 48); bytes.putInt(sectionOffset + 168, 1);
        bytes.putLong(sectionOffset + 184, 24);
        return bytes.array();
    }
}
