package dev.maplesu.manager.modules;

import dev.maplesu.manager.ModuleArchiveInspector;
import dev.maplesu.manager.ModuleArchiveInspector.ModuleType;
import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryNotEmptyException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.compress.archivers.zip.ZipArchiveOutputStream;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import static org.junit.Assert.*;

public class ModuleCatalogTest {
    @Rule public final TemporaryFolder temporary = new TemporaryFolder();
    private File root;
    private ModuleCatalog catalog;

    @Before public void prepare() throws IOException {
        root = new File(temporary.getRoot(), "catalog");
        catalog = new ModuleCatalog(root);
    }

    private File zip(String... namesAndContents) throws IOException {
        File file = temporary.newFile();
        try (ZipArchiveOutputStream output = new ZipArchiveOutputStream(file)) {
            for (int i = 0; i < namesAndContents.length; i += 2) {
                output.putArchiveEntry(new ZipArchiveEntry(namesAndContents[i]));
                output.write(namesAndContents[i + 1].getBytes(StandardCharsets.UTF_8));
                output.closeArchiveEntry();
            }
        }
        return file;
    }

    private File module(String id, int version) throws IOException {
        return zip("module.prop", "id=" + id + "\nname=Catalog test\nversionCode=" + version + "\n");
    }

    private ModuleCatalog.Staged stage(File file) throws IOException {
        var report = ModuleArchiveInspector.inspect(file);
        return catalog.stage(file, report.type, report.sha256);
    }

    private static String sha(File file) throws Exception {
        byte[] hash = MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(file.toPath()));
        StringBuilder value = new StringBuilder();
        for (byte b : hash) value.append(String.format("%02x", b & 255));
        return value.toString();
    }

    @Test public void stageCommitAndReloadReflectRealFilesWithoutExecutingOrExtracting() throws Exception {
        Path sentinel = temporary.getRoot().toPath().resolve("script-executed");
        File source = zip("module.prop", "id=maple_demo\nversionCode=1\n",
                "service.sh", "echo executed > '" + sentinel + "'\n",
                "sepolicy.rule", "fixture policy text\n", "webroot/index.html", "hello");
        String original = sha(source);
        var pending = stage(source);
        assertTrue(catalog.list().isEmpty());
        assertNull(catalog.get(ModuleType.KERNEL_SU, "maple_demo"));
        assertFalse(Files.exists(sentinel));
        var entry = catalog.commit(pending.token);
        assertTrue(entry.enabled);
        assertEquals(original, entry.report.sha256);
        assertEquals(original, sha(source));
        assertEquals(original, sha(entry.archive));
        assertEquals(1, entry.report.versionCode);
        assertTrue(entry.report.features.contains(ModuleArchiveInspector.Feature.SCRIPT));
        assertTrue(entry.report.features.contains(ModuleArchiveInspector.Feature.SELINUX_POLICY));
        assertEquals(1, new ModuleCatalog(root).list().size());
        assertFalse(Files.exists(sentinel));
        assertFalse(new File(entry.archive.getParentFile(), "service.sh").exists());
    }

    @Test public void hostUninstallWithoutAManagerRecordIsIdempotent() throws Exception {
        catalog.uninstallIfPresent(ModuleType.MAPLESU, "fb044e7a140697bb1a6d1ddb6f15b0b4");
        assertTrue(catalog.list().isEmpty());
        var entry = catalog.commit(stage(module("maple_demo", 1)).token);
        catalog.uninstallIfPresent(ModuleType.KERNEL_SU, "maple_demo");
        catalog.uninstallIfPresent(ModuleType.KERNEL_SU, "maple_demo");
        assertTrue(catalog.list().isEmpty());
        assertFalse(entry.archive.exists());
    }

    @Test public void updatePreservesDisablePreferenceAndRemovesPreviousStoredRevision() throws Exception {
        var first = catalog.commit(stage(module("maple_demo", 1)).token);
        catalog.setEnabled(ModuleType.KERNEL_SU, "maple_demo", false);
        var pending = stage(module("maple_demo", 2));
        assertEquals(1, catalog.get(ModuleType.KERNEL_SU, "maple_demo").report.versionCode);
        var updated = catalog.commit(pending.token);
        assertFalse(updated.enabled);
        assertEquals(2, updated.report.versionCode);
        assertNotEquals(first.report.sha256, updated.report.sha256);
        assertFalse(first.archive.exists());
        assertEquals(1, catalog.list().size());
        assertFalse(new ModuleCatalog(root).get(ModuleType.KERNEL_SU, "maple_demo").enabled);
        long installedAt = updated.installedAtMillis;
        var enabled = catalog.setEnabled(ModuleType.KERNEL_SU, "maple_demo", true);
        assertTrue(enabled.enabled);
        assertEquals(installedAt, enabled.installedAtMillis);
    }

    @Test public void uninstallRemovesRecordAndStoredZipWhilePreservingOriginal() throws Exception {
        File source = module("maple_demo", 1);
        String original = sha(source);
        var installed = catalog.commit(stage(source).token);
        catalog.uninstall(ModuleType.KERNEL_SU, "maple_demo");
        assertTrue(catalog.list().isEmpty());
        assertNull(catalog.get(ModuleType.KERNEL_SU, "maple_demo"));
        assertFalse(installed.archive.exists());
        assertEquals(original, sha(source));
    }

    @Test public void discardOnlyRemovesUncommittedPackage() throws Exception {
        var installed = catalog.commit(stage(module("maple_demo", 1)).token);
        var pending = stage(module("maple_demo", 2));
        catalog.discard(pending.token);
        assertFalse(new File(root, "staged/" + pending.token).exists());
        assertEquals(installed.report.sha256, catalog.list().get(0).report.sha256);
    }

    @Test public void confirmationRequiresMatchingTypeAndOriginalSha256() throws Exception {
        File source = module("maple_demo", 1);
        var report = ModuleArchiveInspector.inspect(source);
        assertEquals("MODULE_TYPE_CONFIRMATION_MISMATCH", assertThrows(ModuleCatalog.Failure.class,
                () -> catalog.stage(source, ModuleType.MAPLESU, report.sha256)).code);
        assertEquals("MODULE_ARCHIVE_CONFIRMATION_MISMATCH", assertThrows(ModuleCatalog.Failure.class,
                () -> catalog.stage(source, report.type, "0".repeat(64))).code);
        assertEquals("INVALID_MODULE_CONFIRMATION", assertThrows(ModuleCatalog.Failure.class,
                () -> catalog.stage(source, report.type, "not-a-sha256")).code);
        assertEquals("INVALID_MODULE_CONFIRMATION", assertThrows(ModuleCatalog.Failure.class,
                () -> catalog.stage(source, null, report.sha256)).code);
        assertTrue(catalog.list().isEmpty());
        assertEquals(0, new File(root, "staged").list().length);
    }

    @Test public void changedStagedZipCannotReplaceInstalledVersion() throws Exception {
        var first = catalog.commit(stage(module("maple_demo", 1)).token);
        var pending = stage(module("maple_demo", 2));
        Files.copy(module("maple_demo", 3).toPath(), new File(root, "staged/" + pending.token + "/archive.zip").toPath(),
                   java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        assertEquals("MODULE_ARCHIVE_CONFIRMATION_MISMATCH", assertThrows(ModuleCatalog.Failure.class,
                () -> catalog.commit(pending.token)).code);
        assertEquals(first.report.sha256, catalog.list().get(0).report.sha256);
    }

    @Test public void changedInstalledBytesFailReadsRatherThanShowingStaleState() throws Exception {
        var installed = catalog.commit(stage(module("maple_demo", 1)).token);
        Files.copy(module("maple_demo", 2).toPath(), installed.archive.toPath(),
                   java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        assertThrows(IOException.class, () -> catalog.get(ModuleType.KERNEL_SU, "maple_demo"));
        assertThrows(IOException.class, catalog::list);
    }

    @Test public void traversalDuplicatesAndFileDirectoryConflictsUseProductionInspector() throws Exception {
        for (File source : List.of(
                zip("module.prop", "id=maple_demo\n", "../outside", "x"),
                zip("module.prop", "id=maple_demo\n", "module.prop", "id=other_module\n"),
                zip("module.prop", "id=maple_demo\n", "node", "file", "node/child", "x"))) {
            String before = sha(source);
            assertThrows(ModuleArchiveInspector.Failure.class,
                    () -> catalog.stage(source, ModuleType.KERNEL_SU, before));
            assertEquals(before, sha(source));
            assertTrue(catalog.list().isEmpty());
        }
        assertFalse(new File(temporary.getRoot(), "outside").exists());
    }

    @Test public void zipSymlinksAreRejectedWithoutExtractingTargets() throws Exception {
        File source = temporary.newFile();
        try (ZipArchiveOutputStream output = new ZipArchiveOutputStream(source)) {
            output.putArchiveEntry(new ZipArchiveEntry("module.prop"));
            output.write("id=maple_demo\n".getBytes(StandardCharsets.UTF_8)); output.closeArchiveEntry();
            ZipArchiveEntry link = new ZipArchiveEntry("link"); link.setUnixMode(0120777);
            output.putArchiveEntry(link); output.write("../target".getBytes(StandardCharsets.UTF_8));
            output.closeArchiveEntry();
        }
        assertEquals("UNSUPPORTED_ARCHIVE_ENTRY", assertThrows(ModuleArchiveInspector.Failure.class,
                () -> catalog.stage(source, ModuleType.KERNEL_SU, sha(source))).code);
    }

    @Test public void declaredOversizedEntryIsRejectedWithoutCreatingLargeFiles() throws Exception {
        File source = module("maple_demo", 1);
        byte[] data = Files.readAllBytes(source.toPath());
        ByteBuffer bytes = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);
        for (int position = 0; position < data.length - 46; position++) {
            if (bytes.getInt(position) == 0x02014b50) {
                bytes.putInt(position + 24, 128 * 1024 * 1024 + 1); break;
            }
        }
        Files.write(source.toPath(), data);
        assertEquals("ARCHIVE_LIMIT_EXCEEDED", assertThrows(ModuleArchiveInspector.Failure.class,
                () -> catalog.stage(source, ModuleType.KERNEL_SU, sha(source))).code);
        assertTrue(source.length() < 1024);
    }

    @Test public void invalidTokensDoNotAddressFilesOutsideTheCatalog() throws Exception {
        for (String token : Arrays.asList("../outside", "", "A".repeat(32), null)) {
            assertThrows(ModuleCatalog.Failure.class, () -> catalog.commit(token));
            assertThrows(ModuleCatalog.Failure.class, () -> catalog.discard(token));
        }
        assertTrue(catalog.list().isEmpty());
    }

    @Test public void incompleteStagesAndOrphanRevisionsNeverAppearInstalled() throws Exception {
        String orphan = UUID.randomUUID().toString().replace("-", "");
        Files.createDirectory(new File(root, "revisions/" + orphan).toPath());
        Files.createDirectory(new File(root, "staged/" + orphan).toPath());
        assertTrue(catalog.list().isEmpty());
        assertThrows(IOException.class, () -> catalog.commit(orphan));
        assertTrue(new ModuleCatalog(root).list().isEmpty());
    }

    @Test public void failedRevisionPublicationPreservesPriorInstalledRecord() throws Exception {
        var first = catalog.commit(stage(module("maple_demo", 1)).token);
        var pending = stage(module("maple_demo", 2));
        Files.write(new File(root, "revisions/" + pending.token).toPath(), new byte[] { 1 });
        assertThrows(IOException.class, () -> catalog.commit(pending.token));
        assertEquals(first.report.sha256, catalog.list().get(0).report.sha256);
        assertTrue(new File(root, "staged/" + pending.token + "/archive.zip").isFile());
    }

    @Test public void publishedRecordDoesNotInvokeFailingTemporaryCleanup() throws Exception {
        var first = catalog.commit(stage(module("maple_demo", 1)).token);
        Path record = new File(root, "installed").listFiles()[0].toPath();
        Properties values = new Properties();
        try (var input = Files.newInputStream(record)) { values.load(input); }
        values.setProperty("enabled", "false");
        AtomicInteger cleanupCalls = new AtomicInteger();
        ModuleCatalog.replaceRecord(record, values, path -> {
            cleanupCalls.incrementAndGet();
            throw new IOException("Injected temporary cleanup failure");
        });
        assertEquals(0, cleanupCalls.get());
        var reopened = new ModuleCatalog(root).get(ModuleType.KERNEL_SU, "maple_demo");
        assertFalse(reopened.enabled);
        assertEquals(first.report.sha256, reopened.report.sha256);
        assertTrue(reopened.archive.isFile());
    }

    @Test public void updateCleanupFailureStillLeavesNewVersionPublished() throws Exception {
        var first = catalog.commit(stage(module("maple_demo", 1)).token);
        Path extra = first.archive.toPath().getParent().resolve("extra-ordinary-file");
        Files.write(extra, new byte[] { 1 });
        var pending = stage(module("maple_demo", 2));
        assertThrows(DirectoryNotEmptyException.class, () -> catalog.commit(pending.token));
        var actual = new ModuleCatalog(root).get(ModuleType.KERNEL_SU, "maple_demo");
        assertEquals(2, actual.report.versionCode);
        assertEquals(pending.report.sha256, sha(actual.archive));
        assertEquals(1, catalog.list().size());
        assertFalse(first.archive.exists());
        assertTrue(Files.isRegularFile(extra));
        assertFalse(new File(root, "staged/" + pending.token).exists());
    }

    @Test public void uninstallCleanupFailureStillLeavesRecordRemoved() throws Exception {
        var first = catalog.commit(stage(module("maple_demo", 1)).token);
        Path extra = first.archive.toPath().getParent().resolve("extra-ordinary-file");
        Files.write(extra, new byte[] { 1 });
        assertThrows(DirectoryNotEmptyException.class, () -> catalog.uninstall(ModuleType.KERNEL_SU, "maple_demo"));
        assertNull(new ModuleCatalog(root).get(ModuleType.KERNEL_SU, "maple_demo"));
        assertTrue(catalog.list().isEmpty());
        assertFalse(first.archive.exists());
        assertTrue(Files.isRegularFile(extra));
    }

    @Test public void duplicateOrInvalidPersistentPropertiesFailClosed() throws Exception {
        catalog.commit(stage(module("maple_demo", 1)).token);
        Path record = new File(root, "installed").listFiles()[0].toPath();
        Files.writeString(record, "\nenabled=false\n", StandardOpenOption.APPEND);
        assertEquals("INVALID_MODULE_RECORD", assertThrows(ModuleCatalog.Failure.class, catalog::list).code);
    }

    @Test public void realFileLockPreventsAnotherCatalogInstanceFromMutatingState() throws Exception {
        ModuleCatalog second = new ModuleCatalog(root);
        try (FileChannel channel = FileChannel.open(new File(root, "catalog.lock").toPath(),
                StandardOpenOption.CREATE, StandardOpenOption.WRITE); FileLock ignored = channel.lock()) {
            assertEquals("MODULE_CATALOG_BUSY", assertThrows(ModuleCatalog.Failure.class, second::list).code);
        }
        assertTrue(second.list().isEmpty());
    }

    @Test public void rootAndChildStorageMustBeDirectories() throws Exception {
        assertThrows(ModuleCatalog.Failure.class, () -> new ModuleCatalog(temporary.newFile()));
        Files.delete(new File(root, "staged").toPath());
        Files.write(new File(root, "staged").toPath(), new byte[] { 1 });
        assertThrows(ModuleCatalog.Failure.class, catalog::list);
    }

    @Test public void maplesuAndKsuWithTheSameIdHaveSeparateRecords() throws Exception {
        String id = "abcdef0123456789abcdef0123456789";
        File nativeZip = temporary.newFile();
        try (ZipArchiveOutputStream output = new ZipArchiveOutputStream(nativeZip)) {
            output.putArchiveEntry(new ZipArchiveEntry("libmodule.so"));
            output.write(maplesuElf(id)); output.closeArchiveEntry();
        }
        var nativeEntry = catalog.commit(stage(nativeZip).token);
        assertEquals(ModuleType.MAPLESU, nativeEntry.report.type);
        assertEquals("libmodule.so", nativeEntry.report.nativeEntry);
        catalog.commit(stage(module(id, 2)).token);
        assertEquals(2, catalog.list().size());
        catalog.setEnabled(ModuleType.MAPLESU, id, false);
        assertFalse(catalog.get(ModuleType.MAPLESU, id).enabled);
        assertTrue(catalog.get(ModuleType.KERNEL_SU, id).enabled);
        catalog.uninstall(ModuleType.MAPLESU, id);
        assertEquals(1, catalog.list().size());
        assertNotNull(catalog.get(ModuleType.KERNEL_SU, id));
    }

    @Test public void scriptInventoryDoesNotReinspectUnconsumedNativeArchives() throws Exception {
        var script = catalog.commit(stage(module("script_fixture", 1)).token);
        catalog.setEnabled(ModuleType.KERNEL_SU, "script_fixture", false);
        File nativeZip = temporary.newFile();
        try (ZipArchiveOutputStream output = new ZipArchiveOutputStream(nativeZip)) {
            output.putArchiveEntry(new ZipArchiveEntry("libmodule.so"));
            output.write(maplesuElf("abcdef0123456789abcdef0123456789"));
            output.closeArchiveEntry();
        }
        var nativeEntry = catalog.commit(stage(nativeZip).token);
        assertEquals(2, catalog.list().size());
        var scripts = catalog.list(ModuleType.KERNEL_SU);
        assertEquals(1, scripts.size());
        assertEquals("script_fixture", scripts.get(0).report.id);
        assertFalse(scripts.get(0).enabled);
        assertEquals(ModuleType.MAPLESU, catalog.list(ModuleType.MAPLESU).get(0).report.type);
        // The native inventory comes from the live SDK, not this stored installation ZIP.
        // A script-only read must not decompress or open unrelated native archive bytes.
        Files.writeString(nativeEntry.archive.toPath(), "unconsumed native archive");
        assertEquals(1, catalog.list(ModuleType.KERNEL_SU).size());
        assertThrows(IOException.class, catalog::list);
        assertThrows(IOException.class, () -> catalog.list(ModuleType.MAPLESU));
        // Filtering never caches or weakens validation of the requested type.
        Files.writeString(script.archive.toPath(), "corrupt script archive");
        assertThrows(IOException.class, () -> catalog.list(ModuleType.KERNEL_SU));
    }

    @Test public void typedInventoryDoesNotHideMalformedCatalogMetadata() throws Exception {
        assertTrue(catalog.list(ModuleType.KERNEL_SU).isEmpty());
        catalog.commit(stage(module("script_fixture", 1)).token);
        Path record = new File(root, "installed").listFiles()[0].toPath();
        Files.writeString(record, "\nenabled=invalid\n", StandardOpenOption.APPEND);
        assertThrows(ModuleCatalog.Failure.class, () -> catalog.list(ModuleType.MAPLESU));
    }

    private static byte[] maplesuElf(String id) {
        String entry = dev.maplesu.manager.compat.NativeModuleAbi.ENTRY;
        String[] tags = {
            "de1f663bcae792d7c9ed1a21cdaeff00331fe11b074f0303e018f43998f8db3e" + "Catalog fixture" + "04429c3f7172e4cce7ac7a5d44b75631ce91777b5f2a5eec076a3a508a76fb17",
            "7dc74a2b86805f2cd0f45c6a82d384fd568e341c6f05af17c7229c9ba6d4318b" + "1.0" + "8dbc019a6e51fe8d4a3db9feaf05535d70879f35626050cd4131bfe323ecefc2",
            "05c62cd446c811e772c94d97fd546738328f7c6b9967ed135190ef37ff06d866" + "Static fixture" + "ed02c95e091c66100d6f2f4554f96392b2951b394ba042278eed8f236f43e1a3",
            "1f39b220291a2fb6e4fec95f179d0faf833ca534ef8ab2ffc4bd893768694451" + "MapleSU tests" + "d409c886fd6cedd694c1b126fd19eccd90e2463e04154c193effc7103ce63f1c",
            "b33dcddd88c07d079a8e0e9ec6ab976f15f2edba46cab91a61234cfbb982111c" + id + "3020d9a6c07a30e2649dd29a72d7e57121f0c0ca457b6d21dca5a69acbe6c2c4"
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
        bytes.putInt(256, 0xd65f03c0); // RET is fixture data, never executed.
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
