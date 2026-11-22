import dev.maplesu.image.AvbFooter;
import dev.maplesu.image.BootImageRebuilder;
import dev.maplesu.image.LenovoAvbSigner;
import dev.maplesu.installer.BlockDeviceTransaction;
import java.io.File;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.zip.ZipFile;
import kotlin.jvm.functions.Function1;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.rules.TemporaryFolder;

/** Isolated red probe; reuses the frozen real builder/resolver fixture without production edits. */
class OwnedSignedRecoveryRedMain {
    static Object call(Object target, String name, Object... arguments) throws Exception {
        for (Method method : target.getClass().getDeclaredMethods()) {
            if (method.getName().equals(name) && method.getParameterCount() == arguments.length) {
                method.setAccessible(true);
                try { return method.invoke(target, arguments); }
                catch (InvocationTargetException error) {
                    if (error.getCause() instanceof Exception cause) throw cause;
                    throw error;
                }
            }
        }
        throw new NoSuchMethodException(name);
    }

    static String sha(File file) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(file.toPath())));
    }

    static Object resolver(byte[] key) throws Exception {
        Map<String, byte[]> assets = key == null ? Map.of() : Map.of("maplesu/avb/testkey_rsa2048.pem", key);
        Object source = Class.forName("dev.maplesu.manager.ultrakernel.UltraKernelMemoryAssets").getConstructor(Map.class).newInstance(assets);
        for (var constructor : Class.forName("dev.maplesu.manager.installer.StockOriginalResolver").getDeclaredConstructors()) {
            if (constructor.getParameterCount() == 4) {
                constructor.setAccessible(true);
                return constructor.newInstance(source, null, java.util.List.of(), (Function1<File, Object>) ignored -> null);
            }
        }
        throw new NoSuchMethodException("StockOriginalResolver constructor");
    }

    static class MemoryDevice implements BlockDeviceTransaction.Device {
        final byte[] bytes;
        int writes;
        final boolean failFirst;
        MemoryDevice(File image, boolean failFirst) throws Exception { bytes = Files.readAllBytes(image.toPath()); this.failFirst = failFirst; }
        public long size() { return bytes.length; }
        public void revalidate() {}
        public int read(long offset, byte[] buffer, int length) { System.arraycopy(bytes, (int) offset, buffer, 0, length); return length; }
        public int write(long offset, byte[] buffer, int start, int length) throws IOException {
            writes++;
            if (failFirst && writes == 1) { bytes[(int) offset] = buffer[start]; throw new IOException("INSTALLER_DEVICE_WRITE_FAILED"); }
            System.arraycopy(buffer, start, bytes, (int) offset, length); return length;
        }
        public void sync() {}
        public void close() {}
    }

    static JSONArray simulateWrites(Map<String, File> live, File recovered) throws Exception {
        JSONArray results = new JSONArray();
        Class<?> image = Class.forName("dev.maplesu.manager.installer.NativeInstallSequence$Image");
        var constructor = image.getConstructor(String.class, File.class, String.class);
        Class<?> journal = Class.forName("dev.maplesu.manager.installer.NativeInstallSequence$Journal");
        Object observer = java.lang.reflect.Proxy.newProxyInstance(journal.getClassLoader(), new Class[]{journal}, (p, m, a) -> null);
        Object sequence = Class.forName("dev.maplesu.manager.installer.NativeInstallSequence").getField("INSTANCE").get(null);
        for (boolean failFirst : new boolean[]{false, true}) {
            Map<String, MemoryDevice> devices = new LinkedHashMap<>();
            Map<String, Object> pre = new LinkedHashMap<>();
            for (var entry : live.entrySet()) {
                devices.put(entry.getKey(), new MemoryDevice(entry.getValue(), failFirst && entry.getKey().equals("boot")));
                pre.put(entry.getKey(), constructor.newInstance(entry.getKey(), entry.getValue(), sha(entry.getValue())));
            }
            Object outcome = call(sequence, "commit", devices, pre,
                java.util.List.of(constructor.newInstance("boot", recovered, sha(recovered))), observer);
            boolean companionsUnchanged = true;
            for (var entry : live.entrySet()) if (!entry.getKey().equals("boot"))
                companionsUnchanged &= devices.get(entry.getKey()).writes == 0 && Arrays.equals(devices.get(entry.getKey()).bytes, Files.readAllBytes(entry.getValue().toPath()));
            boolean bootMatches = Arrays.equals(devices.get("boot").bytes, Files.readAllBytes((failFirst ? live.get("boot") : recovered).toPath()));
            String state = (String) call(outcome, "getState");
            results.put(new JSONObject().put("injectedWriteFailure", failFirst).put("state", state)
                .put("bootMatchesExpected", bootMatches).put("companionsUnchangedAndNotWritten", companionsUnchanged));
            if (!bootMatches || !companionsUnchanged || !state.equals(failFirst ? "RESTORED" : "REBOOT_REQUIRED"))
                throw new AssertionError("owned signed writer simulation failed");
        }
        return results;
    }

    public static void main(String[] arguments) throws Exception {
        Path output = Path.of(arguments[0]).toAbsolutePath();
        Files.createDirectories(output);
        Object test = Class.forName("dev.maplesu.manager.installer.OwnedEnvironmentRemovalTest").getConstructor().newInstance();
        TemporaryFolder temporary = (TemporaryFolder) call(test, "getTemporary");
        temporary.create();
        try {
            Object fixture = call(test, "fixture", false);
            File candidate = (File) call(fixture, "getBoot");
            File original = (File) call(fixture, "getOriginal");
            String candidateBefore = sha(candidate), originalBefore = sha(original);
            try (ZipFile archive = new ZipFile(arguments[1])) {
                for (String name : Set.of("boot.img", "vbmeta.img", "vbmeta-nonchained.img", "testkey_rsa2048.pem")) {
                    try (var input = archive.getInputStream(archive.getEntry(name))) {
                        Files.copy(input, output.resolve(name));
                    }
                }
            }
            var key = LenovoAvbSigner.decodeKey(Files.readAllBytes(output.resolve("testkey_rsa2048.pem")));
            Map<String, File> signed = LenovoAvbSigner.sign(LenovoAvbSigner.Mode.CHAINED, "boot", candidate,
                output.resolve("boot.img").toFile(), Map.of(), output.resolve("signed").toFile(), bits -> key, System.out::println);
            File signedBoot = signed.get("boot");
            LenovoAvbSigner.verifySigned(LenovoAvbSigner.Mode.CHAINED, "boot", signed);
            if (BootImageRebuilder.readRecoveryRecord(signedBoot) == null) throw new AssertionError("signer lost owned record");
            String signedBefore = sha(signedBoot);
            @SuppressWarnings("unchecked")
            Map<String, File> live = new LinkedHashMap<>((Map<String, File>) call(fixture, "getLive"));
            live.put("boot", signedBoot);
            live.put("vbmeta", output.resolve("vbmeta.img").toFile());
            LenovoAvbSigner.verifySigned(LenovoAvbSigner.Mode.CHAINED, "boot", live);
            Object snapshot = call(fixture, "snapshot", live);
            File recoveredDirectory = output.resolve("recovery").toFile();
            byte[] keyBytes = Files.readAllBytes(output.resolve("testkey_rsa2048.pem"));
            Object resolution = call(resolver(keyBytes), "resolveForRestore", snapshot, live,
                recoveredDirectory, Set.of("boot"), "", 0);
            @SuppressWarnings("unchecked")
            Map<String, File> restored = (Map<String, File>) call(resolution, "getOriginals");
            File recovered = restored.get("boot");
            Object companion = Class.forName("dev.maplesu.manager.ultrakernel.UltraKernelPlan").getField("Companion").get(null);
            boolean kernelRestored = Arrays.equals((byte[]) call(companion, "readKernel", original),
                (byte[]) call(companion, "readKernel", recovered));
            String signatureError = "";
            try {
                Map<String, File> finalImages = new LinkedHashMap<>(restored);
                finalImages.put("vbmeta", live.get("vbmeta"));
                LenovoAvbSigner.verifySigned(LenovoAvbSigner.Mode.CHAINED, "boot", finalImages);
            }
            catch (Exception error) { signatureError = error.getClass().getName() + ": " + error.getMessage(); }
            JSONObject result = new JSONObject().put("beforeAVBVerified", true).put("returnedResolution", true)
                .put("kind", call(resolution, "getKind").toString()).put("ownershipSource", call(resolution, "getOwnershipSource"))
                .put("kernelRestored", kernelRestored).put("recordRemoved", BootImageRebuilder.readRecoveryRecord(recovered) == null)
                .put("footerPresent", AvbFooter.parse(recovered).present).put("signedBytes", signedBoot.length())
                .put("recoveredBytes", recovered.length()).put("afterAVBVerified", signatureError.isEmpty())
                .put("signatureError", signatureError).put("signedSourceUnchanged", signedBefore.equals(sha(signedBoot)))
                .put("candidateUnchanged", candidateBefore.equals(sha(candidate))).put("originalUnchanged", originalBefore.equals(sha(original)))
                .put("signedSha256", signedBefore).put("recoveredSha256", sha(recovered))
                .put("deviceOperations", false).put("partitionWrites", false);
            JSONArray controls = new JSONArray();
            for (String control : Set.of("missing-key", "wrong-key", "wrong-main", "missing-main", "nonchained-main")) {
                Map<String, File> negativeLive = new LinkedHashMap<>(live);
                if (control.equals("missing-main")) negativeLive.remove("vbmeta");
                if (control.equals("nonchained-main")) negativeLive.put("vbmeta", output.resolve("vbmeta-nonchained.img").toFile());
                if (control.equals("wrong-main")) {
                    byte[] bytes = Files.readAllBytes(live.get("vbmeta").toPath()); bytes[128] ^= 1;
                    Path wrong = output.resolve("wrong-main.img"); Files.write(wrong, bytes); negativeLive.put("vbmeta", wrong.toFile());
                }
                File negativeOutput = output.resolve(control).toFile();
                String error = "";
                byte[] selectedKey = control.equals("missing-key") ? null : keyBytes;
                if (control.equals("wrong-key")) {
                    var generator = java.security.KeyPairGenerator.getInstance("RSA"); generator.initialize(2048);
                    selectedKey = ("-----BEGIN PRIVATE KEY-----\n" + java.util.Base64.getEncoder().encodeToString(generator.generateKeyPair().getPrivate().getEncoded())
                        + "\n-----END PRIVATE KEY-----\n").getBytes(java.nio.charset.StandardCharsets.US_ASCII);
                }
                try { call(resolver(selectedKey), "resolveForRestore",
                    call(fixture, "snapshot", negativeLive), negativeLive, negativeOutput, Set.of("boot"), "", 0); }
                catch (Exception failure) { error = failure.getClass().getName() + ": " + failure.getMessage(); }
                controls.put(new JSONObject().put("case", control).put("error", error)
                    .put("rejected", !error.isEmpty()).put("publishedCandidate", new File(negativeOutput, "boot.img").exists())
                    .put("unverifiedRecoveryRetained", new File(negativeOutput, "owned-recovery/original.img").exists()));
            }
            result.put("controls", controls);
            if (signatureError.isEmpty()) result.put("writeSimulation", simulateWrites(live, recovered));
            Files.writeString(output.resolve("result.json"), result.toString(2));
            System.out.println(result.toString(2));
            if (!kernelRestored || !signatureError.isEmpty()) throw new AssertionError("returned owned-removal candidate must remain AVB-verifiable");
            for (Object entry : controls) {
                JSONObject control = (JSONObject) entry;
                if (!control.getBoolean("rejected") || control.getBoolean("publishedCandidate") || control.getBoolean("unverifiedRecoveryRetained"))
                    throw new AssertionError("signed removal negative control failed: " + control);
            }
        } finally { temporary.delete(); }
    }
}
