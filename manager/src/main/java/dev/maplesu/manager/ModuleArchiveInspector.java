package dev.maplesu.manager;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.LinkOption;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.zip.CRC32;
import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.compress.archivers.zip.ZipFile;
import org.apache.commons.compress.archivers.zip.ExtraFieldUtils;
import org.apache.commons.compress.archivers.zip.UnicodePathExtraField;
import org.apache.commons.compress.archivers.zip.Zip64ExtendedInformationExtraField;

/** Read-only preflight. An inventory never proves script behavior or backend compatibility. */
public final class ModuleArchiveInspector {
    public enum ModuleType { KERNEL_SU, MAPLESU }
    public enum Feature { SCRIPT, WEB_UI, SYSTEM_OVERLAY, SELINUX_POLICY, SYSTEM_PROPERTIES,
        INIT_RC, PREINIT, NATIVE_PAYLOAD, METAMODULE }
    public static final long MAX_ARCHIVE_BYTES = 256L * 1024 * 1024;
    private static final long MAX_EXPANDED = 512L * 1024 * 1024;
    private static final long MAX_ENTRY = 128L * 1024 * 1024;
    private static final long MAX_NATIVE_METADATA_BYTES = 32L * 1024 * 1024;
    private static final int MAX_ENTRIES = 20_000, MAX_PROPERTIES = 64 * 1024;
    private static final Set<String> SCRIPTS = Set.of("customize.sh", "install.sh", "uninstall.sh",
            "post-fs-data.sh", "post-mount.sh", "service.sh", "boot-completed.sh", "action.sh", "metainstall.sh");

    public static final class Failure extends IOException {
        public final String code;
        Failure(String code) { super(code); this.code = code; }
        private Failure(String code, Throwable cause) { super(code, cause); this.code = code; }
    }

    public static final class Report {
        public final String id, sha256;
        public final ModuleType type;
        public final String nativeEntry;
        /**
         * 顶层原生载荷（{@link #nativeEntry} 指向的那个 .so 成员）解压后字节的小写十六进制 SHA-256；
         * 归档不是 MAPLESU（即没有识别出原生入口）时为 null。
         *
         * <p>兼容判定绑定的是 ELF 身份，不是整包身份：重新打包 ZIP、改 module.prop 都会改变
         * {@link #sha256}，但成员字节没变时该值不变。所以只有它能对上已核对的原生载荷。
         */
        public final String nativePayloadSha256;
        public final int versionCode, entryCount;
        public final long expandedBytes;
        public final boolean skipMount;
        public final Map<String, String> properties, nativeAbis;
        public final Set<Feature> features;
        private Report(Properties properties, String hash, int entries, long expanded, boolean skipMount,
                       EnumSet<Feature> features, Map<String, String> nativeAbis, String nativeEntry,
                       String nativePayloadSha256, boolean kernelSu) throws Failure {
            type = nativeEntry == null ? ModuleType.KERNEL_SU : ModuleType.MAPLESU;
            this.nativeEntry = nativeEntry;
            // 非 MAPLESU 归档没有需要核对的原生载荷，字段必须是 null 而不是空串。
            this.nativePayloadSha256 = type == ModuleType.MAPLESU ? nativePayloadSha256 : null;
            String moduleId = properties.getProperty("id", "");
            id = type == ModuleType.MAPLESU ? moduleId : moduleId.trim();
            // Same ID pattern as pinned KernelSU/7kimisu userspace module.rs.
            if (type == ModuleType.KERNEL_SU && !id.matches("[a-zA-Z][a-zA-Z0-9._-]+")) throw new Failure("INVALID_MODULE_ID");
            int parsedVersionCode = 0;
            try { parsedVersionCode = Integer.parseInt(properties.getProperty("versionCode", "0").trim()); }
            catch (NumberFormatException exception) {
                if (!kernelSu) throw new Failure("INVALID_MODULE_METADATA", exception);
            }
            versionCode = parsedVersionCode;
            Map<String, String> values = new HashMap<>();
            for (String name : properties.stringPropertyNames()) values.put(name, properties.getProperty(name));
            this.properties = Collections.unmodifiableMap(values);
            this.nativeAbis = Collections.unmodifiableMap(new HashMap<>(nativeAbis));
            this.features = Collections.unmodifiableSet(EnumSet.copyOf(features));
            sha256 = hash; entryCount = entries; expandedBytes = expanded; this.skipMount = skipMount;
        }
    }

    public static Report inspect(File source) throws IOException {
        return inspect(source, false);
    }

    /** Normal delegates script archives to ksud; bundled native files are payloads. */
    public static Report inspectKernelSu(File source) throws IOException {
        return inspect(source, true);
    }

    private static Report inspect(File source, boolean kernelSu) throws IOException {
        cancelled();
        try (FileChannel channel = FileChannel.open(source.toPath(), StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) {
            if (channel.size() <= 0 || channel.size() > MAX_ARCHIVE_BYTES) throw new Failure("ARCHIVE_LIMIT_EXCEEDED");
            String before = digest(channel);
            try (ZipFile archive = ZipFile.builder().setSeekableByteChannel(channel)
                    .setUseUnicodeExtraFields(false).get()) {
                Set<String> names = new HashSet<>(), directories = new HashSet<>(), files = new HashSet<>();
                EnumSet<Feature> features = EnumSet.noneOf(Feature.class);
                Map<String, String> nativeAbis = new HashMap<>();
                Properties metadata = null;
                Properties nativeMetadata = null;
                String nativeEntry = null;
                String nativePayloadSha256 = null;
                boolean skipMount = false;
                long expanded = 0;
                int count = 0;
                var entries = archive.getEntries();
                byte[] buffer = new byte[64 * 1024];
                while (entries.hasMoreElements()) {
                    cancelled();
                    ZipArchiveEntry entry = entries.nextElement();
                    String name = checkedName(entry);
                    if (++count > MAX_ENTRIES || entry.getSize() < 0 || entry.getSize() > MAX_ENTRY
                            || entry.getSize() > MAX_EXPANDED - expanded
                            || (name.equals("module.prop") && entry.getSize() > MAX_PROPERTIES)) {
                        throw new Failure("ARCHIVE_LIMIT_EXCEEDED");
                    }
                    if (!names.add(name)) throw new Failure("DUPLICATE_ARCHIVE_PATH");
                    if ((!entry.isDirectory() && directories.contains(name)) || files.contains(name)) {
                        throw new Failure("ARCHIVE_PATH_CONFLICT");
                    }
                    for (int slash = name.indexOf('/'); slash >= 0; slash = name.indexOf('/', slash + 1)) {
                        String parent = name.substring(0, slash);
                        if (files.contains(parent)) throw new Failure("ARCHIVE_PATH_CONFLICT");
                        directories.add(parent);
                    }
                    if (entry.isDirectory()) directories.add(name); else files.add(name);
                    int type = entry.getUnixMode() & 0170000;
                    if (entry.isUnixSymlink() || (type != 0 && type != (entry.isDirectory() ? 0040000 : 0100000))
                            || !archive.canReadEntryData(entry)
                            || (entry.getMethod() != 0 && entry.getMethod() != 8 && entry.getMethod() != 95)) {
                        throw new Failure("UNSUPPORTED_ARCHIVE_ENTRY");
                    }
                    checkLocalHeader(channel, entry);
                    CRC32 crc = new CRC32();
                    long size = 0;
                    byte[] header = new byte[20];
                    ByteArrayOutputStream prop = name.equals("module.prop") && !entry.isDirectory()
                            ? new ByteArrayOutputStream() : null;
                    boolean nativeCandidate = !kernelSu && !entry.isDirectory() && name.endsWith(".so") && name.indexOf('/') < 0;
                    if (nativeCandidate && entry.getSize() > MAX_NATIVE_METADATA_BYTES) throw new Failure("ARCHIVE_LIMIT_EXCEEDED");
                    ByteArrayOutputStream nativeBytes = nativeCandidate ? new ByteArrayOutputStream() : null;
                    // 同一个候选成员的字节流里顺手更新摘要，不为哈希再读一遍条目。
                    MessageDigest nativeDigest = nativeCandidate ? sha256() : null;
                    try (InputStream input = archive.getInputStream(entry)) {
                        for (int read; (read = input.read(buffer)) != -1;) {
                            cancelled();
                            if (read > entry.getSize() - size) throw new Failure("ARCHIVE_CONTENT_MISMATCH");
                            if (size < header.length) System.arraycopy(buffer, 0, header, (int) size,
                                    (int) Math.min(read, header.length - size));
                            size += read;
                            crc.update(buffer, 0, read);
                            if (nativeDigest != null) nativeDigest.update(buffer, 0, read);
                            if (prop != null) prop.write(buffer, 0, read);
                            if (nativeBytes != null) nativeBytes.write(buffer, 0, read);
                        }
                    }
                    if (size != entry.getSize() || crc.getValue() != entry.getCrc()
                            || (entry.isDirectory() && size != 0)) throw new Failure("ARCHIVE_CONTENT_MISMATCH");
                    expanded += size;
                    if (prop != null) metadata = properties(prop.toByteArray(), kernelSu);
                    if (nativeBytes != null) {
                        Properties descriptor = MapleSuModuleMetadata.inspect(nativeBytes.toByteArray());
                        if (descriptor != null) {
                            if (nativeEntry != null) throw new Failure("AMBIGUOUS_MODULE_TYPE");
                            nativeEntry = name;
                            nativeMetadata = descriptor;
                            nativePayloadSha256 = hex(nativeDigest.digest());
                        }
                    }
                    if (!entry.isDirectory()) {
                        inventory(name, header, size, features, nativeAbis);
                        if (name.equals("skip_mount")) skipMount = true;
                    }
                }
                // Legacy native modules may bundle module.prop for their companion scripts.
                // A validated exported entry and descriptor define the host identity.
                if (nativeMetadata != null) metadata = nativeMetadata;
                if (metadata == null) throw new Failure("MISSING_MODULE_METADATA");
                String metamodule = metadata.getProperty("metamodule", "").trim();
                if (metamodule.equals("1") || metamodule.equalsIgnoreCase("true")) features.add(Feature.METAMODULE);
                if (!before.equals(digest(channel))) throw new Failure("MODULE_ARCHIVE_CHANGED");
                return new Report(metadata, before, count, expanded, skipMount, features, nativeAbis, nativeEntry,
                        nativePayloadSha256, kernelSu);
            }
        } catch (Failure failure) { throw failure; }
        catch (IOException | IllegalArgumentException exception) { throw new Failure("INVALID_MODULE_ARCHIVE", exception); }
    }

    /** Recheck the app-private staged bytes after the user has confirmed their type. */
    public static void verifyUnchanged(File source, Report report) throws IOException {
        try (FileChannel channel = FileChannel.open(source.toPath(), StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) {
            if (!report.sha256.equals(digest(channel))) throw new Failure("MODULE_ARCHIVE_CHANGED");
        }
    }

    /** Inventory of an already installed KSU tree. This is not an installable archive. */
    public static Report installedKsu(String directoryId, String metadata, String treeIdentity, Set<String> files,
                                      Set<String> directories, boolean zygisk) throws IOException {
        if (!directoryId.matches("[a-zA-Z][a-zA-Z0-9._-]+")) throw new Failure("INVALID_MODULE_ID");
        if (metadata.getBytes(StandardCharsets.UTF_8).length > MAX_PROPERTIES) throw new Failure("INVALID_MODULE_METADATA");
        Properties values = new Properties();
        values.load(new StringReader(metadata));
        // Runtime paths and operations use the directory name, as ksud does.
        values.setProperty("id", directoryId);
        // Existing modules remain operable even when an author supplied a nonnumeric version.
        try { Integer.parseInt(values.getProperty("versionCode", "0").trim()); }
        catch (NumberFormatException ignored) { values.setProperty("versionCode", "0"); }
        EnumSet<Feature> features = EnumSet.noneOf(Feature.class);
        for (String name : files) inventory(name, new byte[20], 0, features, new HashMap<>());
        for (String name : directories) inventory(name + "/", new byte[20], 0, features, new HashMap<>());
        if (zygisk) features.add(Feature.NATIVE_PAYLOAD);
        String meta = values.getProperty("metamodule", "").trim();
        if (meta.equals("1") || meta.equalsIgnoreCase("true")) features.add(Feature.METAMODULE);
        // Identity only: never used to verify archive bytes or replay customize.sh.
        String identity = directoryId + "\n" + treeIdentity;
        return new Report(values, hex(sha256().digest(identity.getBytes(StandardCharsets.UTF_8))),
                files.size() + directories.size(), 0, files.contains("skip_mount"), features,
                Collections.emptyMap(), null, null, false);
    }

    /** The inspector and extractor must use the same verified ZIP path. */
    public static String checkedName(ZipArchiveEntry entry) throws Failure {
        byte[] rawName = entry.getRawName(), encodedName = rawName;
        boolean unicodePath = false;
        if ((entry.getRawFlag() & 0x800) == 0
                && entry.getExtraField(UnicodePathExtraField.UPATH_ID) instanceof UnicodePathExtraField field) {
            CRC32 crc = new CRC32();
            crc.update(rawName);
            if (crc.getValue() == field.getNameCRC32()) {
                encodedName = field.getUnicodeName();
                unicodePath = true;
            }
        }
        String name;
        try { name = utf8(encodedName); }
        catch (CharacterCodingException exception) { throw new Failure("INVALID_ARCHIVE_PATH", exception); }
        if ((!unicodePath && !name.equals(entry.getName())) || name.length() > 4096 || name.indexOf('\\') >= 0
                || name.indexOf(':') >= 0 || name.chars().anyMatch(c -> c < 32 || c == 127)) {
            throw new Failure("INVALID_ARCHIVE_PATH");
        }
        if (entry.isDirectory()) {
            if (!name.endsWith("/")) throw new Failure("INVALID_ARCHIVE_PATH");
            name = name.substring(0, name.length() - 1);
        }
        for (String part : name.split("/", -1)) {
            if (part.isEmpty() || part.equals(".") || part.equals("..")) throw new Failure("INVALID_ARCHIVE_PATH");
        }
        return name;
    }

    private static void checkLocalHeader(FileChannel channel, ZipArchiveEntry entry) throws IOException {
        ByteBuffer header = ByteBuffer.allocate(30).order(ByteOrder.LITTLE_ENDIAN);
        read(channel, header, entry.getLocalHeaderOffset());
        if (header.getInt(0) != 0x04034b50 || Short.toUnsignedInt(header.getShort(6)) != entry.getRawFlag()
                || Short.toUnsignedInt(header.getShort(8)) != entry.getMethod()
                || Short.toUnsignedInt(header.getShort(26)) != entry.getRawName().length) {
            throw new Failure("ARCHIVE_HEADER_MISMATCH");
        }
        ByteBuffer name = ByteBuffer.allocate(entry.getRawName().length);
        read(channel, name, entry.getLocalHeaderOffset() + 30);
        if (!Arrays.equals(name.array(), entry.getRawName())) throw new Failure("ARCHIVE_HEADER_MISMATCH");
        if ((entry.getRawFlag() & 8) == 0) {
            long compressed = Integer.toUnsignedLong(header.getInt(18)), size = Integer.toUnsignedLong(header.getInt(22));
            if (compressed == 0xffffffffL || size == 0xffffffffL) {
                ByteBuffer extra = ByteBuffer.allocate(Short.toUnsignedInt(header.getShort(28)));
                read(channel, extra, entry.getLocalHeaderOffset() + 30 + name.capacity());
                Zip64ExtendedInformationExtraField zip64 = null;
                for (var field : ExtraFieldUtils.parse(extra.array(), true)) {
                    if (field instanceof Zip64ExtendedInformationExtraField) {
                        if (zip64 != null) throw new Failure("ARCHIVE_HEADER_MISMATCH");
                        zip64 = (Zip64ExtendedInformationExtraField) field;
                    }
                }
                if (zip64 == null || zip64.getSize() == null || zip64.getCompressedSize() == null) {
                    throw new Failure("ARCHIVE_HEADER_MISMATCH");
                }
                if (size == 0xffffffffL) size = zip64.getSize().getLongValue();
                if (compressed == 0xffffffffL) compressed = zip64.getCompressedSize().getLongValue();
            }
            if (Integer.toUnsignedLong(header.getInt(14)) != entry.getCrc()
                    || compressed != entry.getCompressedSize() || size != entry.getSize()) {
                throw new Failure("ARCHIVE_HEADER_MISMATCH");
            }
        }
    }

    private static void read(FileChannel channel, ByteBuffer bytes, long offset) throws IOException {
        while (bytes.hasRemaining()) {
            cancelled();
            int count = channel.read(bytes, offset + bytes.position());
            if (count < 0) throw new Failure("ARCHIVE_HEADER_MISMATCH");
        }
    }

    private static Properties properties(byte[] bytes, boolean kernelSu) throws Failure {
        // ksud's PropertiesIter inserts into a HashMap: the final value wins.
        Properties result = kernelSu ? new Properties() : new Properties() {
            @Override public synchronized Object put(Object key, Object value) {
                if (containsKey(key)) throw new IllegalArgumentException("Duplicate module property");
                return super.put(key, value);
            }
        };
        try {
            String text = utf8(bytes);
            if (kernelSu && text.startsWith("\uFEFF")) text = text.substring(1);
            result.load(new StringReader(text));
        }
        catch (IOException | IllegalArgumentException exception) { throw new Failure("INVALID_MODULE_METADATA", exception); }
        return result;
    }

    private static String utf8(byte[] bytes) throws CharacterCodingException {
        return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString();
    }

    private static void inventory(String name, byte[] header, long size, EnumSet<Feature> features,
                                  Map<String, String> nativeAbis) {
        if (SCRIPTS.contains(name)) features.add(Feature.SCRIPT);
        if (name.startsWith("webroot/") || name.startsWith("wwwroot/")) features.add(Feature.WEB_UI);
        if (name.startsWith("system/") || name.startsWith("vendor/") || name.startsWith("product/")
                || name.startsWith("system_ext/") || name.startsWith("odm/")) features.add(Feature.SYSTEM_OVERLAY);
        // Native modules may unpack companion policy resources during installation.
        if (name.equals("sepolicy.rule") || name.endsWith("/sepolicy.rule")) features.add(Feature.SELINUX_POLICY);
        if (name.equals("system.prop")) features.add(Feature.SYSTEM_PROPERTIES);
        if (name.startsWith("initrc/")) features.add(Feature.INIT_RC);
        if (name.startsWith("preinit/")) features.add(Feature.PREINIT);
        boolean elf = size >= 20 && header[0] == 0x7f && header[1] == 'E' && header[2] == 'L' && header[3] == 'F';
        if (elf || name.endsWith(".so") || name.endsWith(".ko")) {
            features.add(Feature.NATIVE_PAYLOAD);
            String abi = "unknown";
            if (elf && header[5] == 1 && header[6] == 1) {
                int machine = Byte.toUnsignedInt(header[18]) | (Byte.toUnsignedInt(header[19]) << 8);
                if (header[4] == 2 && machine == 183) abi = "arm64-v8a";
                if (header[4] == 1 && machine == 40) abi = "armeabi-v7a";
                if (header[4] == 2 && machine == 62) abi = "x86_64";
                if (header[4] == 1 && machine == 3) abi = "x86";
            }
            nativeAbis.put(name, abi);
        }
    }

    private static String digest(FileChannel channel) throws IOException {
        MessageDigest digest = sha256();
        ByteBuffer bytes = ByteBuffer.allocate(64 * 1024);
        channel.position(0);
        while (channel.read(bytes) != -1) {
            cancelled();
            bytes.flip(); digest.update(bytes); bytes.clear();
        }
        return hex(digest.digest());
    }

    private static MessageDigest sha256() {
        try { return MessageDigest.getInstance("SHA-256"); }
        catch (NoSuchAlgorithmException exception) { throw new IllegalStateException(exception); }
    }

    private static String hex(byte[] value) {
        StringBuilder result = new StringBuilder(value.length * 2);
        for (byte current : value) {
            result.append(Character.forDigit((current >>> 4) & 15, 16))
                    .append(Character.forDigit(current & 15, 16));
        }
        return result.toString();
    }

    private static void cancelled() throws Failure {
        if (Thread.currentThread().isInterrupted()) throw new Failure("CANCELLED");
    }
}
