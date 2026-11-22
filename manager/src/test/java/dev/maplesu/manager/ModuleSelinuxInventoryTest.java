package dev.maplesu.manager;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import static org.junit.Assert.*;

/** The installation warning must include policy resources carried by native modules. */
public class ModuleSelinuxInventoryTest {
    @Rule public TemporaryFolder temporary = new TemporaryFolder();

    private File archive(String path) throws Exception {
        File file = temporary.newFile("module.zip");
        try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(file.toPath()))) {
            zip.putNextEntry(new ZipEntry("module.prop"));
            zip.write("id=policy_fixture\nname=Policy fixture\nversionCode=1\n".getBytes(StandardCharsets.UTF_8));
            zip.closeEntry();
            zip.putNextEntry(new ZipEntry(path));
            if (!path.endsWith("/")) zip.write("allow init init process getattr\n".getBytes(StandardCharsets.UTF_8));
            zip.closeEntry();
        }
        return file;
    }

    private void detected(String path) throws Exception {
        File file = archive(path);
        byte[] original = Files.readAllBytes(file.toPath());
        ModuleArchiveInspector.Report report = ModuleArchiveInspector.inspect(file);
        assertTrue(path, report.features.contains(ModuleArchiveInspector.Feature.SELINUX_POLICY));
        assertEquals(ModuleArchiveInspector.ModuleType.KERNEL_SU, report.type);
        assertEquals("policy_fixture", report.id);
        assertEquals(1, report.versionCode);
        assertArrayEquals(original, Files.readAllBytes(file.toPath()));
        ModuleArchiveInspector.verifyUnchanged(file, report);
    }

    @Test public void rootPolicyIsRecognized() throws Exception { detected("sepolicy.rule"); }
    @Test public void nativeResourcesAreRecognized() throws Exception { detected("resources/TEESimulatorRS_Core/sepolicy.rule"); }
    @Test public void embeddedCompanionIsRecognized() throws Exception { detected("payload/modules/companion/sepolicy.rule"); }
    @Test public void aPolicyDirectoryIsNotAFile() throws Exception {
        assertFalse(ModuleArchiveInspector.inspect(archive("resources/sepolicy.rule/")).features
            .contains(ModuleArchiveInspector.Feature.SELINUX_POLICY));
    }
    @Test public void documentationDoesNotDeclarePolicy() throws Exception {
        assertFalse(ModuleArchiveInspector.inspect(archive("docs/sepolicy.rule.txt")).features
            .contains(ModuleArchiveInspector.Feature.SELINUX_POLICY));
    }
}
