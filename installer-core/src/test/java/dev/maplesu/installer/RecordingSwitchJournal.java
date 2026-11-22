package dev.maplesu.installer;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/** In-memory journal sink with deterministic ordering and failure/crash injection. */
final class RecordingSwitchJournal implements SwitchJournalSink {
    final List<SwitchEvent> events = new ArrayList<>();
    long seq;

    /** Throws before recording, simulating a journal write failure (nothing was persisted). */
    SwitchOp failOnOp;
    /** Throws before recording when the next seq equals this value (0 disables). */
    long failAtSeq;
    /** Throws an {@link AssertionError} after recording, simulating a process death. */
    SwitchOp crashAfterOp;
    /** Only crash when the event's partition matches this value (null matches any). */
    String crashPartition;

    @Override
    public void append(SwitchEvent event) throws IOException {
        if (failOnOp != null && event.op == failOnOp) {
            throw new IOException("INSTALLER_JOURNAL_WRITE_FAILED");
        }
        long next = seq + 1;
        if (failAtSeq > 0 && next == failAtSeq) {
            throw new IOException("INSTALLER_JOURNAL_WRITE_FAILED");
        }
        events.add(event.withSeq(next));
        seq = next;
        if (crashAfterOp != null && event.op == crashAfterOp
                && (crashPartition == null || crashPartition.equals(event.partition))) {
            throw new AssertionError("simulated power loss after " + event.op + " " + event.partition);
        }
    }

    int firstIndex(SwitchOp op, String partition) {
        for (int index = 0; index < events.size(); index++) {
            SwitchEvent event = events.get(index);
            if (event.op == op && event.partition.equals(partition)) return index;
        }
        return -1;
    }

    int count(SwitchOp op, String partition) {
        int result = 0;
        for (SwitchEvent event : events) {
            if (event.op == op && event.partition.equals(partition)) result++;
        }
        return result;
    }

    SwitchEvent last() {
        return events.isEmpty() ? null : events.get(events.size() - 1);
    }

    SwitchEvent lastFor(String partition) {
        for (int index = events.size() - 1; index >= 0; index--) {
            if (events.get(index).partition.equals(partition)) return events.get(index);
        }
        return null;
    }
}
