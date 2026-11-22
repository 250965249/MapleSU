package dev.maplesu.manager.jailbreak;

import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * {@link GhostlockProfiles#resolveForAttempt} is the only place where the product
 * may use a KMI template instead of a release-exact profile. These tests pin the
 * boundary: an exact hit keeps the historical path, a missing release may use
 * {@code <major>.<minor>-template.conf} but is marked as assumed, a missing
 * template keeps the historical refusal, and the packaged bytes are never edited.
 *
 * <p>They are host tests: no device, no Android runtime and no provider process.
 */
public final class GhostlockProfileAssumptionTest {
    private static final String EXACT = "6.6.89-android15-8-fixture";
    private static final String TARGET = "6.6.89-android15-8-g7e1f3c083cc6-abogki467167594-4k";
    private static final String EXACT_FILE = EXACT + ".conf";
    private static final String TEMPLATE_FILE = "6.6-template.conf";

    private static final String EXACT_DOCUMENT = String.join("\n",
            "# fixture exact profile",
            "release = \"" + EXACT + "\"",
            "schema_version = 1",
            "kernel_major = 6",
            "");

    private static final String TEMPLATE_DOCUMENT = String.join("\n",
            "# fixture KMI template: copy and fill, never a device profile",
            "release = \"6.6-template\"",
            "schema_version = 1",
            "kernel_major = 6",
            "");

    private static String digest(String text) {
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            StringBuilder hex = new StringBuilder(64);
            for (byte value : sha.digest(text.getBytes(StandardCharsets.UTF_8)))
                hex.append(String.format("%02x", value));
            return hex.toString();
        } catch (Exception error) {
            throw new AssertionError(error);
        }
    }

    /** In-memory profile set: release -> file, digests, and the documents themselves. */
    private static final class Fixture {
        final Map<String, String> index = new LinkedHashMap<>();
        final Map<String, String> documents = new LinkedHashMap<>();
        final Map<String, String> digests = new LinkedHashMap<>();

        Fixture add(String release, String file, String document) {
            index.put(release, file);
            documents.put(file, document);
            digests.put(file, digest(document));
            return this;
        }

        GhostlockProfiles resolver() throws IOException {
            return GhostlockProfiles.fromIndex(index, digests, path -> {
                String file = path.startsWith("ghostlock/") ? path.substring("ghostlock/".length()) : path;
                String document = documents.get(file);
                return document == null ? null : document.getBytes(StandardCharsets.UTF_8);
            }, "ghostlock");
        }
    }

    private static Fixture fixture() {
        return new Fixture()
                .add(EXACT, EXACT_FILE, EXACT_DOCUMENT)
                .add("6.6-template", TEMPLATE_FILE, TEMPLATE_DOCUMENT);
    }

    private static String failure(GhostlockProfiles profiles, String release) {
        try {
            profiles.resolveForAttempt(release);
        } catch (IOException error) {
            return error.getMessage();
        }
        throw new AssertionError("expected a refusal for " + release);
    }

    /** (1) A packaged release keeps the release-exact path, unchanged. */
    @Test
    public void exactProfileKeepsTheExactPath() throws IOException {
        Fixture fixture = fixture();
        GhostlockProfiles profiles = fixture.resolver();
        GhostlockProfiles.Profile exact = profiles.resolveForAttempt(EXACT);
        GhostlockProfiles.Profile historical = profiles.resolve(EXACT);

        assertFalse("an exact hit is never assumed", exact.assumed());
        assertNull("an exact hit has no template origin", exact.assumedFrom());
        assertNull("an exact hit has no assumption marker", exact.assumptionMarker());
        assertEquals(EXACT, exact.release());
        assertEquals(EXACT_FILE, exact.file());
        assertEquals("exact resolution keeps its document", historical.file(), exact.file());
        assertArrayEquals(historical.document(), exact.document());
        assertTrue(new String(exact.document(), StandardCharsets.UTF_8)
                .contains("release = \"" + EXACT + "\""));
    }

    /**
     * (2) A missing release prefers a profile measured on the same kernel sublevel
     * (its offsets were measured on that exact sublevel) and only then the KMI
     * template; either way the result is marked as an assumption.
     */
    @Test
    public void missingReleaseUsesTheSameSublevelProfileAndIsMarked() throws IOException {
        Fixture fixture = fixture();
        GhostlockProfiles profiles = fixture.resolver();

        GhostlockProfiles.Profile assumed = profiles.resolveForAttempt(TARGET);
        String document = new String(assumed.document(), StandardCharsets.UTF_8);
        String sibling = EXACT;

        assertTrue("a same-sublevel fallback is assumed", assumed.assumed());
        assertEquals("the borrowed profile's own declaration is recorded", sibling,
                assumed.assumedFrom());
        assertEquals("the running release is preserved", TARGET, assumed.release());
        assertEquals(EXACT_FILE, assumed.file());
        assertEquals("GHOSTLOCK_PROFILE_ASSUMED:" + TARGET + " from " + sibling,
                assumed.assumptionMarker());
        assertEquals("exactly one declaration for the running release", 1,
                count(document, "release = \"" + TARGET + "\""));
        assertEquals("the borrowed profile's declaration is retargeted, not kept", 0,
                count(document, "release = \"" + sibling + "\""));
        assertTrue("the retarget is explicit in the document",
                document.contains("template fallback"));
        assertTrue("the document says it is not exact",
                document.contains("this is not an exact profile"));
        assertTrue("the document still declares the schema",
                document.contains("schema_version = 1"));
        assertEquals("the packaged template is never edited",
                TEMPLATE_DOCUMENT, fixture.documents.get(TEMPLATE_FILE));
    }

    /** (3) With neither a same-sublevel profile nor a template the refusal is unchanged. */
    @Test
    public void missingSiblingAndTemplateKeepTheExactProfileMissingRefusal() throws IOException {
        // 5.10.236 has no packaged sibling and no 5.10 template in this fixture.
        String lonely = "5.10.236-android12-9-gdeadbeef";
        GhostlockProfiles withoutTemplate = new Fixture()
                .add(EXACT, EXACT_FILE, EXACT_DOCUMENT)
                .resolver();
        assertEquals("GHOSTLOCK_EXACT_PROFILE_MISSING:" + lonely,
                failure(withoutTemplate, lonely));

        // A different KMI family has its own template only; 6.6 must not borrow it.
        GhostlockProfiles otherFamily = new Fixture()
                .add(EXACT, EXACT_FILE, EXACT_DOCUMENT)
                .add("6.1-template", "6.1-template.conf",
                        "release = \"6.1-template\"\nschema_version = 1\n")
                .resolver();
        assertEquals("GHOSTLOCK_EXACT_PROFILE_MISSING:" + lonely,
                failure(otherFamily, lonely));

        // A template whose bytes no longer match the packaged digest is refused
        // by the same digest gate every other profile passes. The target here has
        // no same-sublevel sibling, so the template really is its only fallback.
        Fixture tampered = new Fixture()
                .add(EXACT, EXACT_FILE, EXACT_DOCUMENT)
                .add("5.10-template", TEMPLATE_FILE, TEMPLATE_DOCUMENT);
        tampered.documents.put(TEMPLATE_FILE, TEMPLATE_DOCUMENT + "# drift\n");
        try {
            tampered.resolver().resolveForAttempt(lonely);
            fail("a drifted template must not be used");
        } catch (IOException error) {
            assertEquals("GHOSTLOCK_PROFILE_DIGEST_MISMATCH:" + TEMPLATE_FILE, error.getMessage());
        }
    }

    /** (4) Empty / unknown releases behave exactly as before. */
    @Test
    public void emptyAndUnknownReleasesAreUnchanged() throws IOException {
        GhostlockProfiles profiles = fixture().resolver();
        for (String release : new String[]{null, ""}) {
            assertEquals("GHOSTLOCK_RELEASE_UNKNOWN", failure(profiles, release));
            try {
                profiles.resolve(release);
                fail("resolve must refuse " + release);
            } catch (IOException error) {
                assertEquals("GHOSTLOCK_RELEASE_UNKNOWN", error.getMessage());
            }
        }
        for (String release : new String[]{"garbage", "unknown", "6", "6.x.1", "5.10.236-unknown"}) {
            assertEquals("GHOSTLOCK_EXACT_PROFILE_MISSING:" + release, failure(profiles, release));
            try {
                profiles.resolve(release);
                fail("resolve must refuse " + release);
            } catch (IOException error) {
                assertEquals("GHOSTLOCK_EXACT_PROFILE_MISSING:" + release, error.getMessage());
            }
        }
        // A template name may resolve as a document by name, but it is never an
        // attempt target: the attempt entry refuses to call it exact.
        assertEquals(TEMPLATE_FILE, profiles.resolve("6.6-template").file());
        assertEquals("GHOSTLOCK_TEMPLATE_SELECTED:6.6-template",
                failure(profiles, "6.6-template"));
    }

    /**
     * (5) The packaged 6.6 asset set: an exact pinned profile still encodes the
     * wire for its own release, and the shipped template fallback either encodes
     * the running release or fails with its own named code - it is never silently
     * promoted to an exact profile.
     */
    @Test
    public void packagedAssetsKeepWireAndAssumptionSemantics() throws IOException {
        File directory = new File("../jailbreak-providers/ghostlock/upstream"
                + "/app/src/main/assets/kernel_profiles");
        assertTrue("packaged profile assets are missing: " + directory.getAbsolutePath(),
                directory.isDirectory());
        Map<String, String> index = new LinkedHashMap<>();
        Map<String, String> digests = new LinkedHashMap<>();
        Map<String, String> documents = new LinkedHashMap<>();
        File[] files = directory.listFiles((ignored, name) -> name.endsWith(".conf"));
        assertTrue("packaged profile assets are empty", files != null && files.length > 0);
        for (File file : files) {
            String text = new String(Files.readAllBytes(file.toPath()), StandardCharsets.UTF_8);
            index.put(file.getName().substring(0, file.getName().length() - ".conf".length()),
                    file.getName());
            digests.put(file.getName(), digest(text));
            documents.put(file.getName(), text);
        }
        GhostlockProfiles profiles = GhostlockProfiles.fromIndex(index, digests,
                path -> documents.get(path.substring("ghostlock/".length()))
                        .getBytes(StandardCharsets.UTF_8), "ghostlock");

        String pinned = "6.6.89-android15-8-gf4dc45704e54-abogki446052083-4k";
        GhostlockProfiles.Profile exact = profiles.resolveForAttempt(pinned);
        assertFalse("a pinned release stays exact", exact.assumed());
        byte[] exactWire = GhostlockProfileCodec.INSTANCE.toWire(exact, exact.release());
        assertEquals("the exact wire carries its own release", pinned, wireRelease(exactWire));

        GhostlockProfiles.Profile assumed = profiles.resolveForAttempt(TARGET);
        assertTrue("an unmeasured 6.6.89 release is an assumption", assumed.assumed());
        assertTrue("the assumption borrows a real same-sublevel profile, was: "
                        + assumed.assumedFrom(),
                assumed.assumedFrom().startsWith("6.6.89-"));
        try {
            // Kotlin does not declare checked exceptions, so the codec's
            // IOException is only visible as Exception here.
            byte[] wire = GhostlockProfileCodec.INSTANCE.toWire(assumed, assumed.release());
            assertEquals("a wire built from the borrowed profile carries the running release",
                    TARGET, wireRelease(wire));
        } catch (Exception error) {
            assertTrue("an assumed profile must fail with its own named code, was: "
                            + error.getMessage(),
                    error instanceof IOException && error.getMessage() != null
                            && error.getMessage().startsWith("GHOSTLOCK_PROFILE_"));
        }
    }

    private static String wireRelease(byte[] wire) {
        ByteBuffer header = ByteBuffer.wrap(wire).order(ByteOrder.LITTLE_ENDIAN);
        assertEquals("magic", 0x0d000721, header.getInt());
        assertEquals("version", 2, header.getShort());
        header.getShort(); // frontend
        header.getShort(); // backend
        int route = header.getShort();
        int length = header.getShort();
        header.getShort(); // reserved, never part of the release
        assertTrue("route must be 1..3, was " + route, route >= 1 && route <= 3);
        byte[] release = new byte[length];
        header.get(release);
        return new String(release, StandardCharsets.US_ASCII);
    }

    private static int count(String text, String needle) {
        int count = 0;
        for (int at = text.indexOf(needle); at >= 0; at = text.indexOf(needle, at + 1)) count++;
        return count;
    }
}
