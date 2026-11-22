package dev.maplesu.image;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import static dev.maplesu.image.UltraInitRamdisk.append;
import static dev.maplesu.image.UltraInitRamdisk.entry;
import static dev.maplesu.image.UltraInitRamdisk.inspect;
import static dev.maplesu.image.UltraInitRamdisk.rename;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/** File-only migration: the Producer records the full foreign input before these edits. */
final class UltraInitForeignRamdisk {
    private UltraInitForeignRamdisk() {}

    static byte[] normalize(byte[] cpio, String ksuInitSha256) throws IOException {
        RamdiskInspector.Report report = inspect(cpio);
        RamdiskInspector.Entry init = unique(report, "init");
        RamdiskInspector.Entry ko = unique(report, "kernelsu.ko");
        RamdiskInspector.Entry derivative = unique(report, "sevenk.ko");
        if (ko != null && derivative != null) throw error("MIXED_MODULES");
        String moduleName = ko == null && derivative != null ? "sevenk.ko" : "kernelsu.ko";
        if (ko == null) ko = derivative;
        RamdiskInspector.Entry real = unique(report, "init.real");
        boolean backups = report.entries.stream().anyMatch(entry ->
                path(entry.path).equals(".backup") || path(entry.path).startsWith(".backup/"));
        if (backups) {
            if (ko != null || real != null || unique(report, "sevenk.ko") != null)
                throw error("MIXED_LAYOUT");
            return restoreBackups(cpio, report, init);
        }
        if (report.hasMagiskMarker || report.has("init.magisk.rc") || report.has("overlay/init.magisk.rc"))
            throw error("BACKUP_REQUIRED");
        if (ko == null || real != null) return cpio;
        executable(init);
        if (!ko.isRegularFile() || ko.uid != 0 || ko.links != 1 || ko.size == 0)
            throw error("KSU_MODULE_METADATA");
        byte[] shim = Arrays.copyOfRange(cpio, (int) init.offset, (int) (init.offset + init.size));
        if (ksuInitSha256 != null) {
            if (!init.sha256.equals(ksuInitSha256)) throw error("KSU_INIT_PROVENANCE_MISMATCH");
        } else if (!elf(shim) || !contains(shim, "init.real") || !contains(shim, "/system/bin/init") ||
                !contains(shim, moduleName) || !contains(shim, "ksu_config")) {
            throw error("KSU_FALLBACK_PROOF_REQUIRED");
        }
        // Fixed KernelSU ksuinit chooses this path when the original ramdisk had no init.
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        append(out, cpio, 0, report.trailerOffset);
        byte[] fallback = entry("init.real", 0120777, "/system/bin/init".getBytes(StandardCharsets.US_ASCII), report.trailerCrc);
        append(out, fallback, 0, fallback.length);
        append(out, cpio, report.trailerOffset, cpio.length - report.trailerOffset);
        byte[] result = out.toByteArray();
        inspect(result);
        return result;
    }

    private static byte[] restoreBackups(byte[] cpio, RamdiskInspector.Report report,
                                         RamdiskInspector.Entry init) throws IOException {
        executable(init);
        RamdiskInspector.Entry config = unique(report, ".backup/.magisk");
        if (config == null || !config.isRegularFile() || config.uid != 0 || config.links != 1 || config.size == 0)
            throw error("BACKUP_METADATA");
        Set<String> removed = new LinkedHashSet<>();
        RamdiskInspector.Entry list = unique(report, ".backup/.rmlist");
        if (list != null) {
            if (!list.isRegularFile() || list.uid != 0 || list.links != 1 || list.size > 65536)
                throw error("REMOVAL_LIST_METADATA");
            int start = (int) list.offset, end = (int) (list.offset + list.size);
            if (end > start && cpio[end - 1] != 0) throw error("REMOVAL_LIST_FORMAT");
            for (int at = start; at < end; at++) if (cpio[at] == 0) {
                if (at == start) throw error("REMOVAL_LIST_FORMAT");
                String name = safe(new String(cpio, start, at - start, StandardCharsets.UTF_8));
                if (!removed.add(name)) throw error("REMOVAL_LIST_DUPLICATE");
                start = at + 1;
            }
        }
        Map<String, RamdiskInspector.Entry> restored = new LinkedHashMap<>();
        for (RamdiskInspector.Entry backup : report.entries) {
            String name = path(backup.path);
            if (!name.startsWith(".backup/") || name.equals(".backup/.magisk") || name.equals(".backup/.rmlist")) continue;
            String target = safe(name.substring(8));
            if (!backup.path.equals(name) || restored.put(target, backup) != null)
                throw error("BACKUP_DUPLICATE:" + target);
            if (removed.stream().anyMatch(value -> target.equals(value) || target.startsWith(value + "/")))
                throw error("BACKUP_REMOVAL_CONFLICT:" + target);
            unique(report, target);
        }
        RamdiskInspector.Entry original = restored.get("init");
        boolean emptyOrigin = original == null && removed.contains("init");
        if (original == null && !emptyOrigin) throw error("ORIGINAL_INIT_REQUIRED");
        if (original != null && original.sha256.equals(init.sha256)) throw error("ORIGINAL_INIT_CONFLICT");
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Map<String, RamdiskInspector.Entry> pending = new LinkedHashMap<>(restored);
        for (RamdiskInspector.Entry current : report.entries) {
            String name = path(current.path);
            if (name.equals(".backup") || name.startsWith(".backup/") ||
                    removed.stream().anyMatch(value -> name.equals(value) || name.startsWith(value + "/"))) continue;
            RamdiskInspector.Entry old = pending.remove(name);
            byte[] bytes = old == null ? Arrays.copyOfRange(cpio, current.headerOffset, current.endOffset) : rename(cpio, old, name);
            append(out, bytes, 0, bytes.length);
        }
        for (Map.Entry<String, RamdiskInspector.Entry> old : pending.entrySet()) {
            byte[] bytes = rename(cpio, old.getValue(), old.getKey());
            append(out, bytes, 0, bytes.length);
        }
        if (emptyOrigin) {
            if (!elf(Arrays.copyOfRange(cpio, (int) init.offset, (int) (init.offset + init.size))))
                throw error("EMPTY_ORIGIN_INIT_PROOF");
            byte[] fallback = entry("init", 0120777, "/system/bin/init".getBytes(StandardCharsets.US_ASCII), report.trailerCrc);
            append(out, fallback, 0, fallback.length);
        }
        append(out, cpio, report.trailerOffset, cpio.length - report.trailerOffset);
        byte[] result = out.toByteArray();
        inspect(result);
        return result;
    }

    private static String safe(String value) throws IOException {
        if (value.isEmpty() || value.length() > 255 || !value.equals(path(value)) || value.startsWith("/") ||
                value.equals("TRAILER!!!") || value.equals(".backup") || value.startsWith(".backup/") ||
                value.equals(UltraInitRamdisk.ORIGINAL) || value.startsWith(UltraInitRamdisk.ORIGINAL + "/") ||
                value.equals(UltraInitRamdisk.DIRECTORY) || value.startsWith(UltraInitRamdisk.DIRECTORY + "/"))
            throw error("BACKUP_PATH");
        for (String part : value.split("/", -1)) if (part.equals("..")) throw error("BACKUP_PATH");
        for (int index = 0; index < value.length(); index++) if (value.charAt(index) < 0x21 ||
                value.charAt(index) > 0x7e || value.charAt(index) == '\\') throw error("BACKUP_PATH");
        return value;
    }

    private static void executable(RamdiskInspector.Entry value) throws IOException {
        if (value == null || !value.isRegularFile() || value.uid != 0 || value.links != 1 ||
                value.size == 0 || (value.mode & 0111) == 0) throw error("INIT_METADATA");
    }

    private static boolean elf(byte[] bytes) {
        if (bytes.length < 64 || bytes[0] != 127 || bytes[1] != 'E' || bytes[2] != 'L' || bytes[3] != 'F' ||
                bytes[4] != 2 || bytes[5] != 1 || bytes[6] != 1) return false;
        ByteBuffer h = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);
        int type = Short.toUnsignedInt(h.getShort(16));
        if ((type != 2 && type != 3) || h.getShort(18) != 183 || h.getInt(20) != 1) return false;
        long table = h.getLong(32);
        int width = Short.toUnsignedInt(h.getShort(54)), count = Short.toUnsignedInt(h.getShort(56));
        if (width != 56 || count == 0 || count > 128 || table < 64 || table > bytes.length - (long) count * width) return false;
        boolean executable = false;
        for (int index = 0; index < count; index++) {
            int at = (int) table + index * width;
            if (h.getInt(at) != 1) continue;
            long start = h.getLong(at + 8), size = h.getLong(at + 32);
            if (start < 0 || size <= 0 || start > bytes.length || size > bytes.length - start) return false;
            executable |= (h.getInt(at + 4) & 1) != 0;
        }
        return executable;
    }

    private static boolean contains(byte[] bytes, String value) {
        byte[] token = value.getBytes(StandardCharsets.US_ASCII);
        outer: for (int at = 0; at <= bytes.length - token.length; at++) {
            for (int index = 0; index < token.length; index++) if (bytes[at + index] != token[index]) continue outer;
            return true;
        }
        return false;
    }

    private static RamdiskInspector.Entry unique(RamdiskInspector.Report report, String name) throws IOException {
        RamdiskInspector.Entry found = null;
        for (RamdiskInspector.Entry entry : report.entries) if (path(entry.path).equals(name)) {
            if (found != null) throw error("DUPLICATE:" + name);
            found = entry;
        }
        return found;
    }

    private static String path(String value) {
        return String.join("/", Arrays.stream(value.split("/", -1)).filter(part -> !part.isEmpty() && !part.equals(".")).toArray(String[]::new));
    }

    private static IOException error(String value) { return new IOException("ULTRA_INIT_FOREIGN_" + value); }
}
