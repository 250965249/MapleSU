package dev.maplesu.manager.jailbreak;

import android.content.Context;
import android.content.res.AssetManager;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Resolves one packaged Ghostlock kernel profile for the running release.
 *
 * <p>Ghostlock's pinned profiles are release-exact documents with {@code include}
 * directives; the native decoder independently checks every resolved section and
 * the exact running release before it runs a stage. {@link #resolve} only decides
 * whether the APK carries a profile for this release at all - it never relaxes a
 * match, never fabricates offsets and never reports a nearby release as this one.
 *
 * <p>{@link #resolveForAttempt} adds the one relaxation the product asks for: when
 * the exact release is not packaged, the KMI template {@code <major>.<minor>-
 * template.conf} may be used <em>as a template</em>. That result is never
 * reported as an exact hit: it carries {@code assumed=true} and the template's
 * own declared release in {@code assumedFrom}, its document is retargeted to the
 * running release at the one {@code release} declaration (the packaged bytes stay
 * untouched) because the native decoder and the wire require the running release,
 * and the caller is expected to log/return {@link Profile#assumptionMarker()}.
 *
 * <p>The lookup is deliberately not Android-only: {@link #fromIndex} takes a
 * loader so host tests can exercise resolution, digest verification, include
 * expansion, template fallback and the negative cases without a device.
 */
public final class GhostlockProfiles {
    /**
     * One resolved document, ready for the native profile decoder.
     *
     * <p>{@code release} is always the running release the document was resolved
     * for. {@code assumed} is false only for a release-exact profile; when true,
     * {@code assumedFrom} names the template's own declared release (for example
     * {@code 6.6-template}) and the document was retargeted from it.
     */
    public record Profile(String release, String file, byte[] document,
                          boolean assumed, String assumedFrom) {
        /** An exact profile: the only shape {@link #resolve} ever returns. */
        public Profile(String release, String file, byte[] document) {
            this(release, file, document, false, null);
        }

        /**
         * The one prefix the App, logs and error codes must use for an inferred
         * profile, or null when the profile is an exact hit. It is deliberately
         * outside the document: the wire carries the running release (the native
         * decoder requires it), so provenance travels with this marker instead of
         * being smuggled into a field that means "target".
         */
        public String assumptionMarker() {
            return assumed ? "GHOSTLOCK_PROFILE_ASSUMED:" + release + " from " + assumedFrom : null;
        }
    }

    /** Reads one packaged document by its path relative to the profile root. */
    public interface Loader { byte[] load(String path) throws IOException; }

    private static final String MANIFEST = "maplesu-jailbreak-artifacts.json";
    private static final int MAX_INCLUDE_DEPTH = 4;
    private static final int MAX_DOCUMENT_BYTES = 512 * 1024;

    private final Map<String, String> index;
    private final Map<String, String> digests;
    private final Loader loader;
    private final String root;

    private GhostlockProfiles(Map<String, String> index, Map<String, String> digests,
                              Loader loader, String root) {
        this.index = index;
        this.digests = digests;
        this.loader = loader;
        this.root = root;
    }

    /**
     * Raw text of a packaged document relative to the profile root, or null when it
     * is absent. Parsing lives on the Kotlin side so the HOCON helpers stay in one
     * place; this only reads bytes through the same loader the profiles use.
     */
    public String packagedDocument(String name) {
        try {
            byte[] bytes = loader.load(root + "/" + name);
            return bytes == null ? null : new String(bytes, StandardCharsets.UTF_8);
        } catch (IOException error) {
            return null;
        }
    }

    /** Releases this build can resolve, in packaged order. */
    public List<String> releases() { return List.copyOf(index.keySet()); }

    public static GhostlockProfiles from(Context context) throws IOException {
        AssetManager assets = context.getAssets();
        byte[] document;
        try (InputStream input = assets.open(MANIFEST)) {
            document = readFully(input);
        }
        return fromManifest(document, path -> {
            try (InputStream input = assets.open(path)) { return readFully(input); }
        });
    }

    /**
     * Builds the resolver from already-parsed identity records. The manifest JSON
     * is an Android asset, but resolution itself has no Android dependency, so
     * host tests exercise the real code instead of a stub.
     */
    public static GhostlockProfiles fromIndex(Map<String, String> index,
                                              Map<String, String> digests, Loader loader,
                                              String root) throws IOException {
        if (index == null || digests == null || loader == null || root == null)
            throw new IOException("GHOSTLOCK_INDEX_INVALID");
        if (index.isEmpty()) throw new IOException("GHOSTLOCK_INDEX_EMPTY");
        return new GhostlockProfiles(new LinkedHashMap<>(index), new HashMap<>(digests), loader, root);
    }

    /** Builds the resolver from the packaged manifest and a document loader. */
    public static GhostlockProfiles fromManifest(byte[] manifest, Loader loader) throws IOException {
        final JSONObject document;
        try {
            document = new JSONObject(new String(manifest, StandardCharsets.UTF_8));
        } catch (JSONException error) {
            throw new IOException("GHOSTLOCK_MANIFEST_INVALID", error);
        }
        Map<String, String> index = new LinkedHashMap<>();
        JSONArray profiles = document.optJSONArray("profiles");
        if (profiles != null) {
            for (int i = 0; i < profiles.length(); i++) {
                JSONObject entry = profiles.optJSONObject(i);
                if (entry == null) continue;
                String release = entry.optString("release");
                String file = entry.optString("file");
                if (release.isEmpty() || file.isEmpty())
                    throw new IOException("GHOSTLOCK_MANIFEST_ENTRY_INVALID");
                if (index.put(release, file) != null)
                    throw new IOException("GHOSTLOCK_MANIFEST_DUPLICATE_RELEASE:" + release);
            }
        }
        Map<String, String> digests = new HashMap<>();
        JSONArray files = document.optJSONArray("profileFiles");
        if (files != null) {
            for (int i = 0; i < files.length(); i++) {
                JSONObject entry = files.optJSONObject(i);
                if (entry == null) continue;
                String file = entry.optString("file");
                String digest = entry.optString("sha256");
                if (file.isEmpty() || digest.length() != 64)
                    throw new IOException("GHOSTLOCK_PROFILE_ENTRY_INVALID");
                digests.put(file, digest);
            }
        }
        String root = document.optString("profileRoot", "ghostlock");
        return new GhostlockProfiles(index, digests, loader, root);
    }

    /**
     * The exact profile for this release, or an explicit refusal naming it. A
     * release that is absent stays absent: silence would let the product claim a
     * target it cannot serve.
     */
    public Profile resolve(String release) throws IOException {
        if (release == null || release.isEmpty())
            throw new IOException("GHOSTLOCK_RELEASE_UNKNOWN");
        String file = index.get(release);
        if (file == null) {
            if (isTemplate(release)) throw new IOException("GHOSTLOCK_TEMPLATE_SELECTED:" + release);
            throw new IOException("GHOSTLOCK_EXACT_PROFILE_MISSING:" + release);
        }
        String text = expand(file, 0, new ArrayList<>());
        int declarations = countReleaseDeclarations(text, release);
        if (declarations != 1)
            throw new IOException("GHOSTLOCK_PROFILE_RELEASE_MISMATCH:" + declarations);
        if (!text.contains("schema_version = 1"))
            throw new IOException("GHOSTLOCK_PROFILE_SCHEMA_UNSUPPORTED");
        return new Profile(release, file, text.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * The profile an attempt may run with: the exact one when packaged, otherwise
     * the same-KMI template, explicitly marked as assumed.
     *
     * <p>The fallback never invents geometry and never claims a match: it reuses
     * the packaged {@code <major>.<minor>-template.conf} document, records the
     * template's own {@code release} declaration in {@code assumedFrom}, and
     * retargets only the {@code release} declaration to the running release so the
     * downstream encoder and the native decoder see the release they require. The
     * packaged bytes are not modified. A missing template, an unknown KMI, an
     * empty release or an ambiguous document keep the historical refusal, so the
     * caller can distinguish "no profile at all" from "template used".
     */
    public Profile resolveForAttempt(String release) throws IOException {
        if (release == null || release.isEmpty())
            throw new IOException("GHOSTLOCK_RELEASE_UNKNOWN");
        // A template name is never a device release. resolve() would hand back a
        // registered template document by name; an attempt must not call that an
        // exact hit, so the attempt entry refuses the name outright.
        if (isTemplate(release)) throw new IOException("GHOSTLOCK_TEMPLATE_SELECTED:" + release);
        if (index.containsKey(release)) return resolve(release);
        /*
         * Prefer a real profile built for the same kernel sublevel (6.6.89-*)
         * over the empty KMI skeleton: its offsets were measured on that exact
         * sublevel, so an attempt on an unlisted build of the same sublevel has a
         * far better chance and is still reported as an assumption.
         */
        String sublevel = sublevelOf(release);
        if (sublevel != null) {
            String sibling = closestSublevelProfile(sublevel);
            if (sibling != null) {
                Profile base = resolve(sibling);
                String declared = declaredRelease(new String(base.document(),
                        StandardCharsets.UTF_8));
                String effective = retarget(new String(base.document(), StandardCharsets.UTF_8),
                        declared, release, sublevel);
                if (countReleaseDeclarations(effective, release) == 1 &&
                        countReleaseDeclarations(effective, declared) == 0) {
                    return new Profile(release, base.file(),
                            effective.getBytes(StandardCharsets.UTF_8), true, declared);
                }
            }
        }
        String kmi = kmiOf(release);
        if (kmi == null) throw new IOException("GHOSTLOCK_EXACT_PROFILE_MISSING:" + release);
        String templateFile = templateFile(kmi);
        if (templateFile == null)
            throw new IOException("GHOSTLOCK_EXACT_PROFILE_MISSING:" + release);
        String text = expand(templateFile, 0, new ArrayList<>());
        if (!text.contains("schema_version = 1"))
            throw new IOException("GHOSTLOCK_PROFILE_SCHEMA_UNSUPPORTED");
        String declared = declaredRelease(text);
        if (declared == null || declared.isEmpty() || declared.equals(release) ||
                !isWireRelease(release))
            throw new IOException("GHOSTLOCK_EXACT_PROFILE_MISSING:" + release);
        String effective = retarget(text, declared, release, kmi);
        if (countReleaseDeclarations(effective, release) != 1 ||
                countReleaseDeclarations(effective, declared) != 0)
            throw new IOException("GHOSTLOCK_PROFILE_RELEASE_MISMATCH:1");
        return new Profile(release, templateFile, effective.getBytes(StandardCharsets.UTF_8),
                true, declared);
    }


    /** {@code <major>.<minor>.<patch>} when the release starts with one, else null. */
    private static String sublevelOf(String release) {
        String kmi = kmiOf(release);
        if (kmi == null || kmi.length() >= release.length() || release.charAt(kmi.length()) != '.')
            return null;
        int at = kmi.length() + 1;
        int end = at;
        while (end < release.length() && release.charAt(end) >= '0' && release.charAt(end) <= '9') end++;
        if (end == at) return null;
        return release.substring(0, end);
    }

    /** A registered profile whose release shares the sublevel prefix, or null. */
    private String closestSublevelProfile(String sublevel) {
        String prefix = sublevel + "-";
        String best = null;
        for (String release : new java.util.TreeSet<>(index.keySet())) {
            if (release.endsWith("-template")) continue;
            if (!release.startsWith(prefix)) continue;
            String file = index.get(release);
            if (file == null || !digests.containsKey(file)) continue;
            best = release;
            break;
        }
        return best;
    }

    private static boolean isTemplate(String release) { return release.endsWith("-template"); }

    /** {@code <major>.<minor>} when the release starts with one, else null. */
    private static String kmiOf(String release) {
        int at = 0;
        while (at < release.length() && release.charAt(at) >= '0' && release.charAt(at) <= '9') at++;
        if (at == 0 || at >= release.length() || release.charAt(at) != '.') return null;
        int minorStart = at + 1;
        int minorEnd = minorStart;
        while (minorEnd < release.length() &&
                release.charAt(minorEnd) >= '0' && release.charAt(minorEnd) <= '9') minorEnd++;
        if (minorEnd == minorStart) return null;
        if (minorEnd < release.length() && ".-+_".indexOf(release.charAt(minorEnd)) < 0) return null;
        return release.substring(0, minorEnd);
    }

    /** The packaged KMI template for {@code kmi}, preferring the index registration. */
    private String templateFile(String kmi) {
        String registered = index.get(kmi + "-template");
        if (registered != null && digests.containsKey(registered)) return registered;
        String conventional = kmi + "-template.conf";
        return digests.containsKey(conventional) ? conventional : null;
    }

    /**
     * The release the packaged document itself declares, or null when the
     * document carries no declaration or more than one (an ambiguous document is
     * never guessed).
     */
    private static String declaredRelease(String text) {
        String found = null;
        for (String line : text.split("\n", -1)) {
            String value = releaseDeclaration(line);
            if (value == null) continue;
            if (found != null) return null;
            found = value;
        }
        return found;
    }

    /** The value of a non-comment {@code release = "..."} line, or null. */
    private static String releaseDeclaration(String line) {
        String trimmed = line.trim();
        if (trimmed.isEmpty() || trimmed.startsWith("#") || trimmed.startsWith("//")) return null;
        if (!trimmed.startsWith("release")) return null;
        int at = "release".length();
        while (at < trimmed.length() && Character.isWhitespace(trimmed.charAt(at))) at++;
        if (at >= trimmed.length() || trimmed.charAt(at) != '=') return null;
        at++;
        while (at < trimmed.length() && Character.isWhitespace(trimmed.charAt(at))) at++;
        if (at >= trimmed.length() || trimmed.charAt(at) != '"') return null;
        int end = trimmed.indexOf('"', at + 1);
        return end < 0 ? null : trimmed.substring(at + 1, end);
    }

    /**
     * Rewrites the single {@code release = "<declared>"} declaration to the
     * running release and states why in comments. This is the only edit the
     * fallback makes, it happens in memory only, and the caller sees the template
     * it came from through {@link Profile#assumedFrom()}.
     */
    private static String retarget(String text, String declared, String release, String kmi) {
        StringBuilder out = new StringBuilder(text.length() + 256);
        String[] lines = text.split("\n", -1);
        for (int index = 0; index < lines.length; index++) {
            if (index > 0) out.append('\n');
            String value = releaseDeclaration(lines[index]);
            if (value == null || !value.equals(declared)) { out.append(lines[index]); continue; }
            out.append("# maplesu: KMI ").append(kmi)
                    .append(" template fallback; the packaged file declares release \"")
                    .append(declared).append("\"\n");
            out.append("# maplesu: encoded for \"").append(release)
                    .append("\"; this is not an exact profile\n");
            out.append("release = \"").append(release).append('"');
        }
        return out.toString();
    }

    /** The wire carries the running release verbatim, so it must be encodable there. */
    private static boolean isWireRelease(String release) {
        return release.length() <= 255 && release.matches("[A-Za-z0-9._+\\-]+");
    }

    private static int countReleaseDeclarations(String text, String release) {
        int count = 0;
        String needle = "release = \"" + release + "\"";
        for (int at = text.indexOf(needle); at >= 0; at = text.indexOf(needle, at + 1)) count++;
        return count;
    }

    /** Expands {@code include "x.conf"} with cycle and depth limits. */
    private String expand(String file, int depth, List<String> chain) throws IOException {
        if (depth > MAX_INCLUDE_DEPTH) throw new IOException("GHOSTLOCK_INCLUDE_TOO_DEEP:" + file);
        if (chain.contains(file)) throw new IOException("GHOSTLOCK_INCLUDE_CYCLE:" + file);
        byte[] bytes = verified(file);
        if (bytes.length > MAX_DOCUMENT_BYTES) throw new IOException("GHOSTLOCK_PROFILE_TOO_LARGE:" + file);
        chain.add(file);
        StringBuilder out = new StringBuilder(bytes.length);
        for (String line : new String(bytes, StandardCharsets.UTF_8).split("\n", -1)) {
            String trimmed = line.trim();
            String included = includeTarget(trimmed);
            if (included == null) { out.append(line).append('\n'); continue; }
            out.append("# merged from ").append(included).append('\n');
            out.append(expand(included, depth + 1, chain));
        }
        chain.remove(chain.size() - 1);
        return out.toString();
    }

    private static String includeTarget(String line) {
        if (!line.startsWith("include")) return null;
        int start = line.indexOf('"');
        int end = line.lastIndexOf('"');
        if (start < 0 || end <= start) return null;
        String value = line.substring(start + 1, end);
        if (value.isEmpty() || value.contains("..") || value.startsWith("/")) return null;
        return value;
    }

    private byte[] verified(String file) throws IOException {
        String expected = digests.get(file);
        if (expected == null) throw new IOException("GHOSTLOCK_PROFILE_UNLISTED:" + file);
        byte[] bytes = loader.load(root + "/" + file);
        if (bytes == null) throw new IOException("GHOSTLOCK_PROFILE_UNREADABLE:" + file);
        String actual = sha256(bytes);
        if (!actual.equals(expected))
            throw new IOException("GHOSTLOCK_PROFILE_DIGEST_MISMATCH:" + file);
        return bytes;
    }

    private static String sha256(byte[] bytes) throws IOException {
        final MessageDigest digest;
        try { digest = MessageDigest.getInstance("SHA-256"); }
        catch (Exception error) { throw new IOException("GHOSTLOCK_DIGEST_UNAVAILABLE", error); }
        StringBuilder hex = new StringBuilder(64);
        for (byte value : digest.digest(bytes))
            hex.append(Character.forDigit((value >>> 4) & 15, 16)).append(Character.forDigit(value & 15, 16));
        return hex.toString();
    }

    private static byte[] readFully(InputStream input) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        byte[] chunk = new byte[8192];
        for (int read; (read = input.read(chunk)) > 0;) buffer.write(chunk, 0, read);
        return buffer.toByteArray();
    }
}
