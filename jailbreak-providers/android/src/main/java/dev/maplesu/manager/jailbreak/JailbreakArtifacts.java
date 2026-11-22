package dev.maplesu.manager.jailbreak;

import android.content.Context;
import android.content.res.AssetManager;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

/**
 * Packaged provider identity. The APK carries the digest manifest produced by the
 * same build that produced the native entries, so App-side admission can refuse
 * an artifact that does not match the admitted target before it starts a process.
 * This is artifact binding, not a capability or readiness claim.
 */
public final class JailbreakArtifacts {
    public static final String ASSET = "maplesu-jailbreak-artifacts.json";
    private static final Map<String, Entry> CACHE = new HashMap<>();

    /** One packaged entry with its build-time identity and the digest observed now. */
    public record Entry(String name, String sha256, long bytes, String targetKmi, String koVariant,
                        String koSha256, Map<String, String> koImages) {
        public String koSha256(String kmi) {
            // An unparsed release is selected by the native worker. Do not attach
            // another family's digest to that observation.
            return koImages.getOrDefault(kmi, targetKmi.equals(kmi) ? koSha256 : "");
        }
    }

    private JailbreakArtifacts() {}

    private static String readAsset(Context context) throws IOException {
        AssetManager assets = context.getAssets();
        try (InputStream input = assets.open(ASSET)) {
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            byte[] chunk = new byte[8192];
            for (int read; (read = input.read(chunk)) > 0;) buffer.write(chunk, 0, read);
            return buffer.toString(StandardCharsets.UTF_8.name());
        }
    }

    private static String sha256(File file) throws IOException {
        MessageDigest digest;
        try { digest = MessageDigest.getInstance("SHA-256"); }
        catch (Exception error) { throw new IOException("JAILBREAK_DIGEST_UNAVAILABLE", error); }
        try (InputStream input = new FileInputStream(file)) {
            byte[] chunk = new byte[65536];
            for (int read; (read = input.read(chunk)) > 0;) digest.update(chunk, 0, read);
        }
        StringBuilder hex = new StringBuilder(64);
        for (byte value : digest.digest())
            hex.append(Character.forDigit((value >>> 4) & 15, 16)).append(Character.forDigit(value & 15, 16));
        return hex.toString();
    }

    /**
     * Resolves one packaged entry and verifies it against the build manifest.
     * Throws when the manifest is absent, the entry is unlisted or the bytes on
     * disk differ from the built bytes.
     */
    public static Entry require(Context context, String name) throws IOException {
        synchronized (CACHE) {
            Entry cached = CACHE.get(name);
            if (cached != null) return cached;
        }
        final JSONObject document;
        try {
            document = new JSONObject(readAsset(context));
        } catch (JSONException error) {
            throw new IOException("JAILBREAK_MANIFEST_INVALID", error);
        }
        String nativeDir = context.getApplicationInfo().nativeLibraryDir;
        if (nativeDir == null) throw new IOException("JAILBREAK_NATIVE_DIRECTORY_MISSING");
        File file = new File(nativeDir, name);
        if (!file.isFile()) throw new IOException("JAILBREAK_ENTRY_MISSING:" + name);
        JSONArray entries = document.optJSONArray("artifacts");
        if (entries == null) throw new IOException("JAILBREAK_MANIFEST_EMPTY");
        for (int index = 0; index < entries.length(); index++) {
            JSONObject entry = entries.optJSONObject(index);
            if (entry == null || !name.equals(entry.optString("name"))) continue;
            String expected = entry.optString("sha256");
            long expectedBytes = entry.optLong("bytes", -1);
            long actualBytes = file.length();
            if (expectedBytes != actualBytes)
                throw new IOException("JAILBREAK_ENTRY_SIZE_MISMATCH:" + name);
            String actual = sha256(file);
            if (!actual.equals(expected)) throw new IOException("JAILBREAK_ENTRY_DIGEST_MISMATCH:" + name);
            Map<String, String> koImages = new HashMap<>();
            JSONObject images = entry.optJSONObject("koImages");
            if (images != null) {
                for (Iterator<String> keys = images.keys(); keys.hasNext();) {
                    String kmi = keys.next();
                    JSONObject image = images.optJSONObject(kmi);
                    String digest = image == null ? "" : image.optString("sha256");
                    if (!digest.matches("[0-9a-f]{64}"))
                        throw new IOException("JAILBREAK_MANIFEST_INVALID:koImages:" + kmi);
                    koImages.put(kmi, digest);
                }
            }
            Entry result = new Entry(name, actual, actualBytes, entry.optString("targetKmi"),
                    entry.optString("koVariant"), entry.optString("koSha256"), Map.copyOf(koImages));
            synchronized (CACHE) { CACHE.put(name, result); }
            return result;
        }
        throw new IOException("JAILBREAK_ENTRY_UNLISTED:" + name);
    }
}
