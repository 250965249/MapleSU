// SPDX-License-Identifier: GPL-3.0-or-later
// AVB rebuild flow adapted from VioletToolBox NativeAvbRebuilder.cs, commit 153a0d13.
package dev.maplesu.image;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.function.Consumer;

/** Offline, streaming AVB signer. Sources are immutable; only private output copies are changed. */
public final class LenovoAvbSigner {
    public enum Mode { CHAINED, NON_CHAINED, AOSP }
    public interface Keys { PrivateKey get(int bits) throws Exception; }
    public static final List<String> AOSP_PARTITIONS = List.of("boot", "recovery", "vbmeta_system");
    private static final int BLOCK = 4096, HEADER = 256, MAX_METADATA = 1024 * 1024;
    private LenovoAvbSigner() {}

    /** Original AVB parameters come from source, never from a stale footer left by a patch tool. */
    public static Map<String, File> sign(Mode mode, String partition, File patched, File source,
            Map<String, File> companions, File directory, Keys keys, Consumer<String> log) throws Exception {
        return sign(mode, partition, patched, source, companions, Map.of(), directory, keys, log);
    }

    /** Restored non-target partitions must also match the final main vbmeta hash descriptors. */
    public static Map<String, File> sign(Mode mode, String partition, File patched, File source,
            Map<String, File> companions, Map<String, File> restored, File directory, Keys keys, Consumer<String> log) throws Exception {
        require(partition.equals("boot") || partition.equals("init_boot"), "PARTITION_INVALID");
        require(mode != Mode.AOSP || partition.equals("boot"), "AOSP_REQUIRES_BOOT");
        require(!directory.exists() && directory.mkdirs(), "OUTPUT_DIRECTORY_EXISTS");
        Map<String, File> outputs = new LinkedHashMap<>();
        try {
            Info original;
            if (mode == Mode.NON_CHAINED && !hasMetadata(source)) {
                original = new Info();
                byte[] descriptor = find(read(required(companions, "vbmeta")), 2, partition);
                require(descriptor != null, "VBMETA_HASH_MISSING_" + partition);
                original.contentSize = u64(descriptor, 16);
                require(original.contentSize > 0 && original.contentSize <= source.length(), "HASH_IMAGE_SIZE");
                original.raw.add(descriptor);
            } else original = read(source);
            File image = copy(patched, directory, partition);
            outputs.put(partition, image);
            if (mode == Mode.AOSP) {
                Info main = read(required(companions, "vbmeta"));
                // Check the complete chain before producing or publishing any signed files.
                for (String name : AOSP_PARTITIONS) require(find(main, 4, name) != null, "CHAIN_MISSING_" + name);
                rebuildPartition(image, original, source.length(), partition, true, keys, log);
                File recovery = copy(required(companions, "recovery"), directory, "recovery");
                rebuildPartition(recovery, read(recovery), recovery.length(), "recovery", true, keys, log);
                outputs.put("recovery", recovery);
                File system = copy(required(companions, "vbmeta_system"), directory, "vbmeta_system");
                Info systemInfo = read(system);
                writeStandalone(system, generate(2, systemInfo.raw, systemInfo, systemInfo.location, keys), system.length());
                outputs.put("vbmeta_system", system);
                List<byte[]> descriptors = new ArrayList<>();
                for (byte[] raw : main.raw) {
                    if (u64(raw, 0) != 4 || !AOSP_PARTITIONS.contains(name(raw))) descriptors.add(raw);
                }
                descriptors = restoreDescriptors(descriptors, restored);
                byte[] publicKey = publicKey(keys.get(4096));
                for (String name : AOSP_PARTITIONS) {
                    byte[] old = find(main, 4, name);
                    descriptors.add(chain(name, u32(old, 16), u32(old, 28), publicKey));
                }
                File vbmeta = copy(required(companions, "vbmeta"), directory, "vbmeta");
                writeStandalone(vbmeta, generate(2, descriptors, main, main.location, keys), vbmeta.length());
                outputs.put("vbmeta", vbmeta);
            } else {
                require(mode != Mode.CHAINED || original.algorithm != 0, "CHAINED_SIGNATURE_MISSING");
                rebuildPartition(image, original, source.length(), partition, false, keys, log);
                if (mode == Mode.NON_CHAINED && original.algorithm == 0) {
                    File vbmeta = copy(required(companions, "vbmeta"), directory, "vbmeta");
                    Info main = read(vbmeta), rebuilt = read(image);
                    require(find(main, 2, partition) != null, "VBMETA_HASH_MISSING_" + partition);
                    List<byte[]> merged = restoreDescriptors(merge(main.raw, rebuilt.raw), restored);
                    main.minor = Math.max(main.minor, rebuilt.minor);
                    require(main.algorithm != 0, "VBMETA_UNSIGNED");
                    writeStandalone(vbmeta, generate(main.algorithm, merged, main, 0, keys), BLOCK);
                    outputs.put("vbmeta", vbmeta);
                } else if (companions.containsKey("vbmeta")) {
                    File vbmeta = copy(required(companions, "vbmeta"), directory, "vbmeta");
                    Info main = read(vbmeta);
                    Map<String, File> finalImages = new LinkedHashMap<>(restored);
                    finalImages.put(partition, image);
                    List<byte[]> descriptors = restoreDescriptors(main.raw, finalImages);
                    if (!sameDescriptors(main.raw, descriptors)) {
                        require(main.algorithm != 0, "VBMETA_UNSIGNED");
                        writeStandalone(vbmeta, generate(main.algorithm, descriptors, main, main.location, keys), vbmeta.length());
                    }
                    outputs.put("vbmeta", vbmeta);
                }
            }
            Map<String, File> verifyImages = new LinkedHashMap<>(restored);
            verifyImages.putAll(outputs);
            verifySigned(mode, partition, verifyImages);
            for (Map.Entry<String, File> item : outputs.entrySet()) log.accept("AVB verified: " + item.getKey() + " -> " + item.getValue());
            return outputs;
        } catch (Exception error) {
            // No partially signed copy can be mistaken for a complete signing result.
            for (File file : directory.listFiles() == null ? new File[0] : directory.listFiles()) Files.deleteIfExists(file.toPath());
            Files.deleteIfExists(directory.toPath());
            throw error;
        }
    }

    public static PrivateKey decodeKey(byte[] pem) throws Exception {
        String text = new String(pem, StandardCharsets.US_ASCII);
        boolean pkcs1 = text.contains("-----BEGIN RSA PRIVATE KEY-----");
        byte[] data = Base64.getDecoder().decode(text.replaceAll("-----[A-Z ]+-----", "").replaceAll("\\s", ""));
        if (pkcs1) data = der(0x30, concat(new byte[]{2, 1, 0},
                new byte[]{0x30, 13, 6, 9, 0x2a, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xf7, 13, 1, 1, 1, 5, 0}, der(4, data)));
        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(data));
    }

    private static byte[] der(int tag, byte[] data) {
        int n = data.length, count = n < 128 ? 0 : (32 - Integer.numberOfLeadingZeros(n) + 7) / 8;
        byte[] header = new byte[2 + count]; header[0] = (byte) tag;
        header[1] = (byte) (count == 0 ? n : 0x80 | count);
        for (int i = 0; i < count; i++) header[2 + i] = (byte) (n >>> ((count - i - 1) * 8));
        return concat(header, data);
    }

    private static boolean hasMetadata(File image) throws Exception {
        if (AvbFooter.parse(image).present) return true;
        try (RandomAccessFile input = new RandomAccessFile(image, "r")) { return input.length() >= 4 && input.readInt() == 0x41564230; }
    }

    private static void rebuildPartition(File image, Info original, long partitionSize, String partition,
            boolean aosp, Keys keys, Consumer<String> log) throws Exception {
        AvbFooter footer = AvbFooter.parse(image);
        require(!footer.present || validFooter(footer, image.length()), "FOOTER_INVALID");
        long content = footer.present && footer.valid(image.length()) ? footer.originalImageSize : image.length();
        // A patcher may drop the footer but keep full partition padding. Derive the new payload
        // boundary from the patched header, not the old ramdisk size, and retain nonzero tail data.
        if (!footer.present && image.length() == partitionSize && original.contentSize < partitionSize) {
            BootImageInspector.Report report = BootImageInspector.inspect(image);
            long end = report.pageSize;
            long[][] sections = {{report.kernelOffset, report.kernelSize}, {report.ramdiskOffset, report.ramdiskSize},
                    {report.secondOffset, report.secondSize}, {report.recoveryDtboOffset, report.recoveryDtboSize},
                    {report.dtbOffset, report.dtbSize}, {report.signatureOffset, report.signatureSize}};
            for (long[] section : sections) if (section[1] > 0) end = Math.max(end, align(section[0] + section[1], report.pageSize));
            require(end < partitionSize, "PARTITION_SPACE");
            content = end;
            try (RandomAccessFile input = new RandomAccessFile(image, "r")) {
                content = BootImageRebuilder.recoveryRecordEnd(input.getChannel(), end);
                input.seek(end);
                byte[] buffer = new byte[65536];
                long position = end;
                while (position < image.length()) {
                    int count = input.read(buffer, 0, (int) Math.min(buffer.length, image.length() - position));
                    require(count > 0, "TRUNCATED_IMAGE");
                    for (int i = 0; i < count; i++) if (buffer[i] != 0) content = Math.max(content, position + i + 1);
                    position += count;
                }
            }
        }
        require(content > 0 && content <= partitionSize, "IMAGE_SIZE");
        byte[] previous = find(original, 2, partition);
        String hashName = aosp || previous == null ? "sha256" : ascii(previous, 24, 32);
        byte[] salt = aosp || previous == null ? randomSalt() : salt(previous);
        if (salt.length == 0) salt = randomSalt();
        byte[] digest = hashFile(image, content, hashName, salt);
        List<byte[]> descriptors = new ArrayList<>();
        descriptors.add(hash(partition, content, hashName, salt, digest, previous == null ? 0 : u32(previous, 68)));
        if (aosp) {
            String prefix = "com.android.build." + partition + ".";
            Map<String, String> properties = properties(original);
            descriptors.add(property(prefix + "os_version", value(properties, prefix + "os_version", "15")));
            descriptors.add(property(prefix + "fingerprint", value(properties, prefix + "fingerprint", "")));
            descriptors.add(property(prefix + "security_patch", value(properties, prefix + "security_patch", "2025-02-05")));
        } else {
            for (byte[] raw : original.raw) if (u64(raw, 0) == 0) descriptors.add(raw);
        }
        int algorithm = aosp ? 2 : original.algorithm;
        Info parameters = algorithm == 0 ? new Info() : original;
        parameters.minor = original.minor;
        byte[] blob = generate(algorithm, descriptors, parameters, aosp ? original.location : 0, keys);
        long offset = align(content, BLOCK), footerBlock = partitionSize - BLOCK;
        require(offset + align(blob.length, BLOCK) <= footerBlock, "PARTITION_SPACE");
        try (RandomAccessFile output = new RandomAccessFile(image, "rw")) {
            output.setLength(content);
            output.setLength(partitionSize);
            output.seek(offset); output.write(blob);
            byte[] tail = new byte[64];
            magic(tail, "AVBf"); put32(tail, 4, 1);
            // The footer must describe the NEW payload (Violet's preserved old size is stale
            // when Normal grows the ramdisk); hash size and footer size must agree.
            put64(tail, 12, content); put64(tail, 20, offset); put64(tail, 28, blob.length);
            output.seek(partitionSize - 64); output.write(tail); output.getFD().sync();
        }
        log.accept("AVB rebuilt: " + partition + ", algorithm=" + algorithm + ", payload=" + content);
    }

    /** Parse only bounded metadata; a 512 MiB boot is never loaded in one allocation. */
    static Info read(File file) throws Exception {
        require(file.isFile(), "IMAGE_MISSING");
        AvbFooter footer = AvbFooter.parse(file);
        require(!footer.present || validFooter(footer, file.length()), "FOOTER_INVALID");
        long offset = footer.present ? footer.vbmetaOffset : 0;
        try (RandomAccessFile input = new RandomAccessFile(file, "r")) {
            require(offset <= file.length() - HEADER, "HEADER_TRUNCATED");
            input.seek(offset);
            byte[] header = new byte[HEADER]; input.readFully(header);
            require(ascii(header, 0, 4).equals("AVB0") && u32(header, 4) == 1, "HEADER_INVALID");
            long auth = u64(header, 12), aux = u64(header, 20);
            require(auth % 64 == 0 && aux % 64 == 0 && auth <= MAX_METADATA && aux <= MAX_METADATA &&
                    HEADER + auth + aux <= file.length() - offset && (!footer.present || HEADER + auth + aux <= footer.vbmetaSize), "METADATA_RANGE");
            Info info = new Info();
            info.blob = new byte[(int) (HEADER + auth + aux)];
            input.seek(offset); input.readFully(info.blob);
            info.algorithm = (int) u32(header, 28); algorithm(info.algorithm);
            info.minor = u32(header, 8); info.rollback = u64(header, 112);
            info.flags = u32(header, 120); info.location = u32(header, 124);
            info.contentSize = footer.present ? footer.originalImageSize : file.length();
            info.key = within(info.blob, HEADER + auth, aux, u64(header, 64), u64(header, 72));
            long start = u64(header, 96), size = u64(header, 104);
            require(start <= aux && size <= aux - start, "DESCRIPTOR_RANGE");
            int cursor = (int) (HEADER + auth + start), end = cursor + (int) size;
            while (cursor < end) {
                require(end - cursor >= 16, "DESCRIPTOR_TRUNCATED");
                long following = u64(info.blob, cursor + 8);
                require(following % 8 == 0 && following <= end - cursor - 16, "DESCRIPTOR_SIZE");
                byte[] raw = slice(info.blob, cursor, 16 + following);
                long tag = u64(raw, 0);
                if (tag == 1 || tag == 2 || tag == 4) name(raw);
                if (tag == 2) { salt(raw); hashDigest(raw); }
                if (tag == 0) parseProperty(raw);
                info.raw.add(raw); cursor += raw.length;
            }
            return info;
        }
    }

    /** Independent cryptographic read-back, including signed digests, hashes and chain keys. */
    public static void verifySigned(Mode mode, String partition, Map<String, File> images) throws Exception {
        require(partition.equals("boot") || partition.equals("init_boot"), "PARTITION_INVALID");
        require(mode != Mode.AOSP || partition.equals("boot"), "AOSP_REQUIRES_BOOT");
        Info target = read(required(images, partition));
        require(mode != Mode.CHAINED || target.algorithm != 0, "CHAINED_SIGNATURE_MISSING");
        require(find(target, 2, partition) != null, "HASH_MISSING_" + partition);
        Info main = images.containsKey("vbmeta") ? read(required(images, "vbmeta")) : null;
        if (mode == Mode.AOSP) {
            for (String name : List.of("boot", "recovery", "vbmeta_system", "vbmeta"))
                require(read(required(images, name)).algorithm == 2, "AOSP_ALGORITHM_" + name);
            for (String name : AOSP_PARTITIONS) require(find(main, 4, name) != null, "CHAIN_MISSING_" + name);
        } else if (mode == Mode.CHAINED && main != null) {
            require(main.algorithm != 0, "VBMETA_UNSIGNED");
            require(find(main, 4, partition) != null, "CHAIN_MISSING_" + partition);
        } else if (mode == Mode.NON_CHAINED) {
            require(main != null && main.algorithm != 0, "VBMETA_UNSIGNED");
            require(find(main, 2, partition) != null || find(main, 4, partition) != null, "VBMETA_REFERENCE_MISSING_" + partition);
        }
        verify(images);
    }

    public static void verify(Map<String, File> images) throws Exception {
        Map<String, Info> parsed = new LinkedHashMap<>();
        for (Map.Entry<String, File> entry : images.entrySet()) {
            // A restored stock partition may have its hash in main vbmeta only.
            if (!hasMetadata(entry.getValue())) continue;
            Info info = read(entry.getValue()); parsed.put(entry.getKey(), info);
            verifySignature(info);
            byte[] descriptor = find(info, 2, entry.getKey());
            if (descriptor != null) verifyHash(entry.getValue(), descriptor);
        }
        Info main = parsed.get("vbmeta");
        if (main != null) for (byte[] raw : main.raw) {
            long tag = u64(raw, 0);
            if (tag != 2 && tag != 4) continue;
            String name = name(raw);
            if (!images.containsKey(name)) continue;
            if (tag == 2) verifyHash(images.get(name), raw);
            else require(parsed.containsKey(name) && Arrays.equals(slice(raw, 92 + u32(raw, 20), u32(raw, 24)), parsed.get(name).key), "CHAIN_KEY_MISMATCH_" + name);
        }
    }

    /** Read-only proof that every supplied boot image is covered by the current signed vbmeta. */
    public static void verifyOriginals(Map<String, File> images) throws Exception {
        Info main = read(required(images, "vbmeta"));
        require(main.algorithm != 0, "VBMETA_UNSIGNED");
        verifySignature(main);
        for (String partition : List.of("boot", "init_boot")) {
            if (!images.containsKey(partition)) continue;
            byte[] hash = find(main, 2, partition), chain = find(main, 4, partition);
            require((hash != null) != (chain != null), "ORIGINAL_REFERENCE_AMBIGUOUS_" + partition);
            if (hash != null) {
                verifyHash(images.get(partition), hash);
            } else {
                Info original = read(required(images, partition));
                require(original.algorithm != 0, "ORIGINAL_UNSIGNED_" + partition);
                verifySignature(original);
                require(Arrays.equals(slice(chain, 92 + u32(chain, 20), u32(chain, 24)), original.key),
                        "CHAIN_KEY_MISMATCH_" + partition);
                byte[] selfHash = find(original, 2, partition);
                require(selfHash != null, "HASH_MISSING_" + partition);
                verifyHash(images.get(partition), selfHash);
            }
        }
    }

    private static boolean validFooter(AvbFooter footer, long length) {
        return footer.versionMajor == 1 && footer.originalImageSize > 0 && footer.vbmetaOffset >= 0 &&
                footer.vbmetaSize > 0 && footer.reservedZero && footer.valid(length);
    }

    private static List<byte[]> restoreDescriptors(List<byte[]> descriptors, Map<String, File> restored) throws Exception {
        List<byte[]> result = new ArrayList<>();
        for (byte[] raw : descriptors) {
            long tag = u64(raw, 0);
            File image = tag == 2 || tag == 4 ? restored.get(name(raw)) : null;
            if (image != null && tag == 2) {
                AvbFooter footer = AvbFooter.parse(image);
                require(!footer.present || validFooter(footer, image.length()), "FOOTER_INVALID");
                long content = footer.present ? footer.originalImageSize : u64(raw, 16);
                require(content > 0 && content <= image.length(), "HASH_IMAGE_SIZE");
                String algorithm = ascii(raw, 24, 32);
                result.add(hash(name(raw), content, algorithm, salt(raw), hashFile(image, content, algorithm, salt(raw)), u32(raw, 68)));
            } else if (image != null) {
                Info stock = read(image);
                require(stock.algorithm != 0, "RESTORED_CHAIN_UNSIGNED_" + name(raw));
                verifySignature(stock);
                byte[] key = slice(raw, 92 + u32(raw, 20), u32(raw, 24));
                result.add(Arrays.equals(key, stock.key) ? raw : chain(name(raw), u32(raw, 16), u32(raw, 28), stock.key));
            } else result.add(raw);
        }
        return result;
    }

    private static boolean sameDescriptors(List<byte[]> a, List<byte[]> b) {
        if (a.size() != b.size()) return false;
        for (int i = 0; i < a.size(); i++) if (!Arrays.equals(a.get(i), b.get(i))) return false;
        return true;
    }

    private static void verifyHash(File image, byte[] raw) throws Exception {
        long size = u64(raw, 16);
        require(size > 0 && size <= image.length(), "HASH_IMAGE_SIZE");
        require(MessageDigest.isEqual(hashDigest(raw), hashFile(image, size, ascii(raw, 24, 32), salt(raw))), "HASH_MISMATCH");
    }

    private static void verifySignature(Info info) throws Exception {
        int[] spec = algorithm(info.algorithm);
        if (info.algorithm == 0) { require(info.key.length == 0, "UNSIGNED_KEY"); return; }
        byte[] header = slice(info.blob, 0, HEADER);
        long auth = u64(header, 12), aux = u64(header, 20);
        require(u64(header, 40) == spec[0] && u64(header, 56) == spec[1] && info.key.length == 8 + 2 * spec[1] && u32(info.key, 0) == spec[1] * 8L, "SIGNATURE_LAYOUT");
        byte[] auxiliary = slice(info.blob, HEADER + auth, aux), signed = concat(header, auxiliary);
        byte[] hash = within(info.blob, HEADER, auth, u64(header, 32), spec[0]);
        require(MessageDigest.isEqual(hash, MessageDigest.getInstance(digestName(spec[0])).digest(signed)), "VBMETA_DIGEST_MISMATCH");
        BigInteger modulus = new BigInteger(1, slice(info.key, 8, spec[1]));
        java.security.PublicKey key = KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(modulus, BigInteger.valueOf(65537)));
        Signature verifier = Signature.getInstance(signatureName(spec[0])); verifier.initVerify(key); verifier.update(signed);
        require(verifier.verify(within(info.blob, HEADER, auth, u64(header, 48), spec[1])), "RSA_VERIFY_FAILED");
    }

    private static byte[] generate(int algorithm, List<byte[]> descriptors, Info info, long location, Keys keys) throws Exception {
        int[] spec = algorithm(algorithm);
        PrivateKey key = algorithm == 0 ? null : keys.get(spec[1] * 8);
        byte[] encoded = key == null ? new byte[0] : publicKey(key), data = concat(descriptors.toArray(new byte[0][]));
        int auth = (int) align(spec[0] + spec[1], 64), aux = (int) align(data.length + encoded.length, 64);
        byte[] header = new byte[HEADER]; magic(header, "AVB0");
        put32(header, 4, 1); put32(header, 8, info.minor); put64(header, 12, auth); put64(header, 20, aux);
        put32(header, 28, algorithm); put64(header, 40, spec[0]); put64(header, 48, spec[0]); put64(header, 56, spec[1]);
        put64(header, 64, data.length); put64(header, 72, encoded.length); put64(header, 80, data.length + encoded.length);
        put64(header, 104, data.length); put64(header, 112, info.rollback); put32(header, 120, info.flags); put32(header, 124, location);
        byte[] release = "avbtool 1.3.0".getBytes(StandardCharsets.US_ASCII); System.arraycopy(release, 0, header, 128, release.length);
        byte[] auxiliary = Arrays.copyOf(concat(data, encoded), aux), authentication = new byte[auth];
        if (key != null) {
            require(((RSAPrivateCrtKey) key).getModulus().bitLength() == spec[1] * 8, "KEY_SIZE");
            byte[] signed = concat(header, auxiliary), hash = MessageDigest.getInstance(digestName(spec[0])).digest(signed);
            Signature signer = Signature.getInstance(signatureName(spec[0])); signer.initSign(key); signer.update(signed);
            byte[] signature = signer.sign(); require(signature.length == spec[1], "SIGNATURE_SIZE");
            System.arraycopy(hash, 0, authentication, 0, hash.length); System.arraycopy(signature, 0, authentication, hash.length, signature.length);
        }
        return concat(header, authentication, auxiliary);
    }

    public static byte[] publicKey(PrivateKey key) throws IOException {
        require(key instanceof RSAPrivateCrtKey, "KEY_FORMAT");
        RSAPrivateCrtKey rsa = (RSAPrivateCrtKey) key;
        require(rsa.getPublicExponent().equals(BigInteger.valueOf(65537)), "KEY_EXPONENT");
        BigInteger n = rsa.getModulus(), r = BigInteger.ONE.shiftLeft(32);
        int bits = n.bitLength(), bytes = bits / 8;
        require(bits == 2048 || bits == 4096, "KEY_SIZE");
        byte[] result = new byte[8 + bytes * 2]; put32(result, 0, bits);
        put32(result, 4, r.subtract(n.mod(r).modInverse(r)).longValue());
        System.arraycopy(integer(n, bytes), 0, result, 8, bytes);
        System.arraycopy(integer(BigInteger.ONE.shiftLeft(bits * 2).mod(n), bytes), 0, result, 8 + bytes, bytes);
        return result;
    }

    private static byte[] hash(String name, long size, String algorithm, byte[] salt, byte[] digest, long flags) throws IOException {
        byte[] partition = utf8(name), raw = new byte[(int) align(132 + partition.length + salt.length + digest.length, 8)];
        put64(raw, 0, 2); put64(raw, 8, raw.length - 16); put64(raw, 16, size);
        byte[] alg = utf8(algorithm); require(alg.length < 32, "HASH_ALGORITHM"); System.arraycopy(alg, 0, raw, 24, alg.length);
        put32(raw, 56, partition.length); put32(raw, 60, salt.length); put32(raw, 64, digest.length); put32(raw, 68, flags);
        byte[] payload = concat(partition, salt, digest); System.arraycopy(payload, 0, raw, 132, payload.length); return raw;
    }

    private static byte[] chain(String name, long location, long flags, byte[] key) throws IOException {
        byte[] partition = utf8(name), raw = new byte[(int) align(92 + partition.length + key.length, 8)];
        put64(raw, 0, 4); put64(raw, 8, raw.length - 16); put32(raw, 16, location); put32(raw, 20, partition.length);
        put32(raw, 24, key.length); put32(raw, 28, flags);
        byte[] payload = concat(partition, key); System.arraycopy(payload, 0, raw, 92, payload.length); return raw;
    }

    private static byte[] property(String key, String value) throws IOException {
        byte[] k = utf8(key), v = utf8(value), raw = new byte[(int) align(32 + k.length + v.length + 2, 8)];
        put64(raw, 8, raw.length - 16); put64(raw, 16, k.length); put64(raw, 24, v.length);
        System.arraycopy(k, 0, raw, 32, k.length); System.arraycopy(v, 0, raw, 33 + k.length, v.length); return raw;
    }

    private static Map<String, String> properties(Info info) throws IOException {
        Map<String, String> result = new LinkedHashMap<>();
        for (byte[] raw : info.raw) if (u64(raw, 0) == 0) { String[] prop = parseProperty(raw); result.put(prop[0], prop[1]); }
        return result;
    }
    private static String[] parseProperty(byte[] raw) throws IOException {
        long k = u64(raw, 16), v = u64(raw, 24);
        require(k <= raw.length - 34 && v <= raw.length - 34 - k && raw[32 + (int) k] == 0 && raw[33 + (int) (k + v)] == 0, "PROPERTY_RANGE");
        return new String[]{new String(slice(raw, 32, k), StandardCharsets.UTF_8), new String(slice(raw, 33 + k, v), StandardCharsets.UTF_8)};
    }
    private static String value(Map<String, String> props, String key, String fallback) { String v = props.get(key); return v == null || v.isBlank() ? fallback : v; }
    private static String name(byte[] raw) throws IOException {
        long tag = u64(raw, 0);
        int fixed = tag == 1 ? 180 : tag == 2 ? 132 : 92, at = tag == 1 ? 104 : tag == 2 ? 56 : 20;
        require(raw.length >= fixed, "DESCRIPTOR_TRUNCATED");
        return new String(slice(raw, fixed, u32(raw, at)), StandardCharsets.UTF_8);
    }
    private static byte[] salt(byte[] raw) throws IOException { return slice(raw, 132 + u32(raw, 56), u32(raw, 60)); }
    private static byte[] hashDigest(byte[] raw) throws IOException { return slice(raw, 132 + u32(raw, 56) + u32(raw, 60), u32(raw, 64)); }
    private static byte[] find(Info info, long tag, String partition) throws IOException {
        byte[] found = null;
        for (byte[] raw : info.raw) if (u64(raw, 0) == tag && name(raw).equals(partition)) { require(found == null, "DUPLICATE_DESCRIPTOR"); found = raw; }
        return found;
    }
    private static List<byte[]> merge(List<byte[]> original, List<byte[]> rebuilt) throws IOException {
        List<byte[]> result = new ArrayList<>(); TreeMap<String, byte[]> named = new TreeMap<>();
        Set<ByteBuffer> properties = new HashSet<>();
        for (List<byte[]> list : List.of(original, rebuilt)) for (byte[] raw : list) {
            long tag = u64(raw, 0);
            String type = tag == 1 ? "AvbHashtreeDescriptor" : tag == 2 ? "AvbHashDescriptor" : tag == 4 ? "AvbChainPartitionDescriptor" : null;
            if (type == null) {
                if (tag != 0 || properties.add(ByteBuffer.wrap(raw))) result.add(raw);
            } else named.put(type + "_" + name(raw), raw);
        }
        result.addAll(named.values()); return result;
    }
    private static byte[] hashFile(File file, long count, String algorithm, byte[] salt) throws Exception {
        require(algorithm.equals("sha256") || algorithm.equals("sha512"), "HASH_ALGORITHM");
        MessageDigest digest = MessageDigest.getInstance(algorithm.equals("sha256") ? "SHA-256" : "SHA-512"); digest.update(salt);
        try (RandomAccessFile input = new RandomAccessFile(file, "r")) {
            byte[] buffer = new byte[65536]; long remaining = count;
            while (remaining > 0) {
                require(!Thread.currentThread().isInterrupted(), "CANCELLED");
                int size = input.read(buffer, 0, (int) Math.min(buffer.length, remaining)); require(size > 0, "TRUNCATED_IMAGE");
                digest.update(buffer, 0, size); remaining -= size;
            }
        }
        return digest.digest();
    }
    private static void writeStandalone(File file, byte[] data, long padding) throws Exception {
        long size = align(data.length, padding); require(size <= file.length(), "VBMETA_PARTITION_SPACE");
        try (RandomAccessFile output = new RandomAccessFile(file, "rw")) { output.setLength(0); output.write(data); output.setLength(size); output.getFD().sync(); }
    }
    private static File copy(File source, File directory, String name) throws Exception {
        File output = new File(directory, name + ".img"); Files.copy(source.toPath(), output.toPath(), StandardCopyOption.REPLACE_EXISTING); return output;
    }
    private static File required(Map<String, File> files, String name) throws IOException { File f = files.get(name); require(f != null && f.isFile(), "IMAGE_MISSING_" + name); return f; }
    private static int[] algorithm(int type) throws IOException {
        switch (type) { case 0: return new int[]{0, 0}; case 1: return new int[]{32, 256}; case 2: return new int[]{32, 512};
            case 4: return new int[]{64, 256}; case 5: return new int[]{64, 512}; default: throw new IOException("LENOVO_AVB_ALGORITHM_UNSUPPORTED_" + type); }
    }
    private static String digestName(int size) { return size == 64 ? "SHA-512" : "SHA-256"; }
    private static String signatureName(int size) { return size == 64 ? "SHA512withRSA" : "SHA256withRSA"; }
    private static byte[] integer(BigInteger value, int size) { byte[] bytes = value.toByteArray(), result = new byte[size]; int length = Math.min(size, bytes.length); System.arraycopy(bytes, bytes.length - length, result, size - length, length); return result; }
    private static byte[] randomSalt() { byte[] salt = new byte[32]; new SecureRandom().nextBytes(salt); return salt; }
    private static long align(long value, long alignment) throws IOException { require(value >= 0 && alignment > 0 && value <= Long.MAX_VALUE - alignment, "SIZE_OVERFLOW"); return (value + alignment - 1) / alignment * alignment; }
    private static byte[] within(byte[] data, long base, long length, long offset, long size) throws IOException { require(offset <= length && size <= length - offset, "AUTH_RANGE"); return slice(data, base + offset, size); }
    private static byte[] slice(byte[] data, long offset, long size) throws IOException { require(offset >= 0 && size >= 0 && offset <= data.length && size <= data.length - offset, "METADATA_RANGE"); return Arrays.copyOfRange(data, (int) offset, (int) (offset + size)); }
    private static long u64(byte[] data, int at) throws IOException { require(at >= 0 && at <= data.length - 8, "METADATA_RANGE"); long n = ByteBuffer.wrap(data, at, 8).order(ByteOrder.BIG_ENDIAN).getLong(); require(n >= 0, "UINT64_RANGE"); return n; }
    private static long u32(byte[] data, int at) throws IOException { require(at >= 0 && at <= data.length - 4, "METADATA_RANGE"); return Integer.toUnsignedLong(ByteBuffer.wrap(data, at, 4).order(ByteOrder.BIG_ENDIAN).getInt()); }
    private static void put64(byte[] data, int at, long n) { ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN).putLong(at, n); }
    private static void put32(byte[] data, int at, long n) { ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN).putInt(at, (int) n); }
    private static byte[] utf8(String text) { return text.getBytes(StandardCharsets.UTF_8); }
    private static String ascii(byte[] bytes, int at, int size) throws IOException { byte[] text = slice(bytes, at, size); int end = 0; while (end < text.length && text[end] != 0) end++; return new String(text, 0, end, StandardCharsets.US_ASCII); }
    private static void magic(byte[] bytes, String text) { System.arraycopy(utf8(text), 0, bytes, 0, 4); }
    private static byte[] concat(byte[]... arrays) { int size = 0; for (byte[] array : arrays) size = Math.addExact(size, array.length); byte[] result = new byte[size]; int at = 0; for (byte[] array : arrays) { System.arraycopy(array, 0, result, at, array.length); at += array.length; } return result; }
    private static void require(boolean condition, String code) throws IOException { if (!condition) throw new IOException("LENOVO_AVB_" + code); }
    static final class Info {
        int algorithm; long minor, rollback, flags, location, contentSize;
        byte[] blob, key; final List<byte[]> raw = new ArrayList<>();
    }
}
