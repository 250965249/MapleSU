package dev.maplesu.installer;

import java.io.Closeable;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.LongSupplier;

/**
 * Append-only JSONL switch journal (02-switch-contract §3.3 / F3): one fixed-key JSON object per
 * line, {@code fd.sync()} after every line, {@code prev} chaining the sha256 of the previous line.
 *
 * <p>This file is a write-ahead log, not a partition writer: partition bytes stay with
 * {@link BlockDeviceTransaction}. The static write-path guard therefore allowlists this class
 * explicitly, and this class writes only the journal file.</p>
 */
public final class FileSwitchJournal implements SwitchJournalSink, Closeable {
    /** Exact line key set; extra or missing keys make the journal unreadable on purpose. */
    private static final List<String> KEYS = List.of("schema", "seq", "switchId", "planSha256",
            "atUptimeMs", "bootId", "stage", "step", "partition", "op", "expectedSha256",
            "observedSha256", "code", "prev");
    private static final String ZERO_HASH = "0".repeat(64);

    private final Path path;
    private final String bootId;
    private final LongSupplier uptimeMs;
    private final boolean durable;
    private FileChannel channel;
    private long seq;
    private String prev;

    private FileSwitchJournal(Path path, String bootId, LongSupplier uptimeMs, boolean durable) {
        this.path = path;
        this.bootId = bootId == null ? "" : bootId;
        this.uptimeMs = uptimeMs;
        this.durable = durable;
    }

    /**
     * Opens (or creates) the journal and resumes its sequence. A corrupt chain or a
     * switchId/planSha256 conflict is refused rather than appended to.
     */
    public static FileSwitchJournal open(Path journal, String bootId, LongSupplier uptimeMs)
            throws IOException {
        return open(journal, bootId, uptimeMs, true);
    }

    /** Same as {@link #open(Path, String, LongSupplier)}; {@code durable=false} only for test seams. */
    public static FileSwitchJournal open(Path journal, String bootId, LongSupplier uptimeMs,
                                         boolean durable) throws IOException {
        if (journal == null) throw new IOException("SWITCH_JOURNAL_WRITE_FAILED: missing path");
        Path parent = journal.toAbsolutePath().getParent();
        if (parent != null) Files.createDirectories(parent);
        FileSwitchJournal result = new FileSwitchJournal(journal, bootId, uptimeMs, durable);
        Replay replay = read(journal);
        if (replay.corrupt) {
            throw new SwitchFailure("SWITCH_RECOVERY_JOURNAL_CORRUPT", replay.detail);
        }
        result.seq = replay.lastSeq;
        result.prev = replay.lastHash;
        result.channel = FileChannel.open(journal, StandardOpenOption.CREATE,
                StandardOpenOption.WRITE, StandardOpenOption.APPEND);
        return result;
    }

    public Path path() { return path; }

    public long lastSeq() { return seq; }

    @Override
    public void append(SwitchEvent event) throws IOException {
        if (event == null) throw new IOException("SWITCH_JOURNAL_WRITE_FAILED: missing event");
        if (channel == null || !channel.isOpen()) throw new IOException("SWITCH_JOURNAL_WRITE_FAILED: closed");
        long nextSeq = seq + 1;
        SwitchEvent sequenced = event.withSeq(nextSeq);
        if (sequenced.bootId.isEmpty() && !bootId.isEmpty()) {
            sequenced = sequenced.withBoot(bootId, sequenced.atUptimeMs);
        }
        if (sequenced.atUptimeMs == 0 && uptimeMs != null) {
            sequenced = sequenced.withBoot(sequenced.bootId, uptimeMs.getAsLong());
        }
        String line = serialize(sequenced, prev);
        writeFully((line + "\n").getBytes(StandardCharsets.UTF_8));
        if (durable) channel.force(true);
        seq = nextSeq;
        prev = SwitchHashes.sha256Hex(line);
    }

    private void writeFully(byte[] bytes) throws IOException {
        ByteBuffer buffer = ByteBuffer.wrap(bytes);
        while (buffer.hasRemaining()) {
            if (channel.write(buffer) <= 0) {
                throw new IOException("SWITCH_JOURNAL_WRITE_FAILED: short journal write");
            }
        }
    }

    @Override
    public void close() throws IOException {
        FileChannel open = channel;
        channel = null;
        if (open == null) return;
        try {
            open.force(true);
        } finally {
            open.close();
        }
    }

    static String serialize(SwitchEvent event, String previousHash) {
        Map<String, String> fields = new LinkedHashMap<>();
        fields.put("schema", Integer.toString(event.schema));
        fields.put("seq", Long.toString(event.seq));
        fields.put("switchId", event.switchId);
        fields.put("planSha256", event.planSha256);
        fields.put("atUptimeMs", Long.toString(event.atUptimeMs));
        fields.put("bootId", event.bootId);
        fields.put("stage", event.stage);
        fields.put("step", event.step);
        fields.put("partition", event.partition);
        fields.put("op", event.op.name());
        fields.put("expectedSha256", event.expectedSha256);
        fields.put("observedSha256", event.observedSha256);
        fields.put("code", event.code);
        fields.put("prev", previousHash == null ? ZERO_HASH : previousHash);
        StringBuilder line = new StringBuilder(256);
        line.append('{');
        boolean first = true;
        for (String key : KEYS) {
            if (!first) line.append(',');
            first = false;
            appendString(line, key);
            line.append(':');
            String value = fields.get(key);
            if (key.equals("schema") || key.equals("seq") || key.equals("atUptimeMs")) {
                line.append(value);
            } else {
                appendString(line, value);
            }
        }
        return line.append('}').toString();
    }

    private static void appendString(StringBuilder target, String value) {
        target.append('"');
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            switch (character) {
                case '"': target.append("\\\""); break;
                case '\\': target.append("\\\\"); break;
                case '\n': target.append("\\n"); break;
                case '\r': target.append("\\r"); break;
                case '\t': target.append("\\t"); break;
                default:
                    if (character < 0x20) target.append(String.format("\\u%04x", (int) character));
                    else target.append(character);
            }
        }
        target.append('"');
    }

    /** Reads and validates the chain; never throws for corrupt content, reports it instead. */
    public static Replay read(Path journal) throws IOException {
        if (journal == null || !Files.exists(journal)) return Replay.missing();
        List<String> lines = Files.readAllLines(journal, StandardCharsets.UTF_8);
        List<SwitchEvent> events = new ArrayList<>();
        boolean corrupt = false;
        String detail = "";
        long expectedSeq = 1;
        String expectedPrev = ZERO_HASH;
        String switchId = null;
        String planSha256 = null;
        for (String raw : lines) {
            String line = raw.strip();
            if (line.isEmpty()) continue;
            if (corrupt) break;
            try {
                Map<String, String> fields = parseObject(line);
                if (!fields.keySet().equals(new LinkedHashSet<>(KEYS))) {
                    throw new IllegalArgumentException("journal key set");
                }
                if (!"1".equals(fields.get("schema"))) throw new IllegalArgumentException("journal schema");
                long seq = Long.parseLong(fields.get("seq"));
                long uptime = Long.parseLong(fields.get("atUptimeMs"));
                SwitchOp op = SwitchOp.valueOf(fields.get("op"));
                String prev = fields.get("prev");
                if (seq != expectedSeq) throw new IllegalArgumentException("journal seq " + seq);
                if (!prev.equals(expectedPrev)) throw new IllegalArgumentException("journal chain " + seq);
                if (switchId == null) {
                    switchId = fields.get("switchId");
                    planSha256 = fields.get("planSha256");
                } else if (!switchId.equals(fields.get("switchId"))
                        || !planSha256.equals(fields.get("planSha256"))) {
                    throw new IllegalArgumentException("journal plan conflict");
                }
                events.add(new SwitchEvent(Integer.parseInt(fields.get("schema")), seq,
                        fields.get("switchId"), fields.get("planSha256"), fields.get("bootId"), uptime,
                        fields.get("stage"), fields.get("step"), fields.get("partition"), op,
                        fields.get("expectedSha256"), fields.get("observedSha256"), fields.get("code")));
                expectedSeq = seq + 1;
                expectedPrev = SwitchHashes.sha256Hex(line);
            } catch (RuntimeException invalid) {
                corrupt = true;
                detail = invalid.getMessage() == null ? invalid.getClass().getSimpleName() : invalid.getMessage();
            }
        }
        return new Replay(true, corrupt, detail, events, expectedSeq - 1, expectedPrev,
                corrupt ? "" : switchId, corrupt ? "" : planSha256);
    }

    private static Map<String, String> parseObject(String line) {
        Map<String, String> fields = new LinkedHashMap<>();
        int index = 0;
        if (index >= line.length() || line.charAt(index) != '{') throw new IllegalArgumentException("json object");
        index++;
        while (true) {
            while (index < line.length() && Character.isWhitespace(line.charAt(index))) index++;
            if (index >= line.length()) throw new IllegalArgumentException("json eof");
            if (line.charAt(index) == '}') { index++; break; }
            if (line.charAt(index) == ',') { index++; continue; }
            Parsed key = parseString(line, index);
            index = key.next;
            while (index < line.length() && Character.isWhitespace(line.charAt(index))) index++;
            if (index >= line.length() || line.charAt(index) != ':') throw new IllegalArgumentException("json colon");
            index++;
            while (index < line.length() && Character.isWhitespace(line.charAt(index))) index++;
            String value;
            if (index < line.length() && line.charAt(index) == '"') {
                Parsed parsed = parseString(line, index);
                value = parsed.value;
                index = parsed.next;
            } else {
                int start = index;
                while (index < line.length() && "-+0123456789".indexOf(line.charAt(index)) >= 0) index++;
                if (start == index) throw new IllegalArgumentException("json value");
                value = line.substring(start, index);
            }
            if (fields.put(key.value, value) != null) throw new IllegalArgumentException("json duplicate key");
        }
        if (index != line.length()) throw new IllegalArgumentException("json trailing bytes");
        return fields;
    }

    private static final class Parsed {
        final String value;
        final int next;
        Parsed(String value, int next) { this.value = value; this.next = next; }
    }

    private static Parsed parseString(String line, int start) {
        if (line.charAt(start) != '"') throw new IllegalArgumentException("json string");
        StringBuilder value = new StringBuilder();
        int index = start + 1;
        while (index < line.length()) {
            char character = line.charAt(index++);
            if (character == '"') return new Parsed(value.toString(), index);
            if (character != '\\') { value.append(character); continue; }
            if (index >= line.length()) throw new IllegalArgumentException("json escape");
            char escape = line.charAt(index++);
            switch (escape) {
                case '"': value.append('"'); break;
                case '\\': value.append('\\'); break;
                case '/': value.append('/'); break;
                case 'n': value.append('\n'); break;
                case 'r': value.append('\r'); break;
                case 't': value.append('\t'); break;
                case 'b': value.append('\b'); break;
                case 'f': value.append('\f'); break;
                case 'u':
                    if (index + 4 > line.length()) throw new IllegalArgumentException("json unicode");
                    value.append((char) Integer.parseInt(line.substring(index, index + 4), 16));
                    index += 4;
                    break;
                default: throw new IllegalArgumentException("json escape " + escape);
            }
        }
        throw new IllegalArgumentException("json string eof");
    }

    /** Read-only projection used by recovery and by the power-loss replay tests. */
    public static final class Replay {
        public final boolean exists;
        public final boolean corrupt;
        public final String detail;
        public final List<SwitchEvent> events;
        public final long lastSeq;
        public final String lastHash;
        public final String switchId;
        public final String planSha256;

        private Replay(boolean exists, boolean corrupt, String detail, List<SwitchEvent> events,
                       long lastSeq, String lastHash, String switchId, String planSha256) {
            this.exists = exists;
            this.corrupt = corrupt;
            this.detail = detail == null ? "" : detail;
            this.events = Collections.unmodifiableList(events);
            this.lastSeq = lastSeq;
            this.lastHash = lastHash;
            this.switchId = switchId;
            this.planSha256 = planSha256;
        }

        static Replay missing() {
            return new Replay(false, false, "", List.of(), 0, ZERO_HASH, "", "");
        }

        /** True when every plan step's last stateful op is DONE. */
        public boolean isComplete(SwitchPlan plan) {
            if (corrupt || plan == null) return false;
            Set<String> done = donePartitions();
            for (SwitchStep step : plan.steps) if (!done.contains(step.partition)) return false;
            return true;
        }

        public Set<String> donePartitions() {
            Set<String> done = new LinkedHashSet<>();
            for (SwitchStepLike view : lastStateful()) {
                if (view.last == SwitchOp.DONE) done.add(view.partition);
            }
            return done;
        }

        /** Partitions with an intent that never reached DONE: exactly the "may be written" set. */
        public Set<String> openIntents() {
            Set<String> open = new LinkedHashSet<>();
            for (SwitchStepLike view : lastStateful()) {
                if (view.last == SwitchOp.INTENT || view.last == SwitchOp.COMMIT_INTENT) open.add(view.partition);
            }
            return open;
        }

        /** Every partition that was ever targeted by an intent/rollback, in first-seen order. */
        public Set<String> touchedPartitions() {
            Set<String> touched = new LinkedHashSet<>();
            for (SwitchEvent event : events) {
                if (event.partition.isEmpty()) continue;
                if (event.op == SwitchOp.INTENT || event.op == SwitchOp.COMMIT_INTENT
                        || event.op == SwitchOp.ROLLBACK_INTENT || event.op == SwitchOp.ROLLBACK_DONE
                        || event.op == SwitchOp.DONE) {
                    touched.add(event.partition);
                }
            }
            return touched;
        }

        private List<SwitchStepLike> lastStateful() {
            Map<String, SwitchOp> last = new LinkedHashMap<>();
            for (SwitchEvent event : events) {
                if (event.partition.isEmpty()) continue;
                switch (event.op) {
                    case INTENT: case COMMIT_INTENT: case DONE: case FAIL: case SKIP:
                    case ROLLBACK_INTENT: case ROLLBACK_DONE: case RECOVERY_REQUIRED:
                        last.put(event.partition, event.op);
                        break;
                    default:
                        break;
                }
            }
            List<SwitchStepLike> result = new ArrayList<>();
            for (Map.Entry<String, SwitchOp> entry : last.entrySet()) {
                result.add(new SwitchStepLike(entry.getKey(), entry.getValue()));
            }
            return result;
        }
    }

    private static final class SwitchStepLike {
        final String partition;
        final SwitchOp last;
        SwitchStepLike(String partition, SwitchOp last) { this.partition = partition; this.last = last; }
    }
}
