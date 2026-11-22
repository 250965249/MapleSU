package dev.maplesu.installer;

import java.io.IOException;

/** One journal event. {@link #append} returning means the event is durable (file fsync). */
public interface SwitchJournalSink {
    void append(SwitchEvent event) throws IOException;
}
