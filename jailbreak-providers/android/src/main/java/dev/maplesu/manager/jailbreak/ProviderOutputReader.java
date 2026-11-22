package dev.maplesu.manager.jailbreak;

import java.io.IOException;
import java.io.Reader;
import java.util.function.Consumer;

/** Preserve every output chunk immediately; parse complete, bounded lines separately. */
final class ProviderOutputReader {
    private ProviderOutputReader() { }

    @FunctionalInterface
    interface LineSink { void accept(String line) throws IOException; }

    static void read(Reader reader, Consumer<String> persist, LineSink onLine) throws IOException {
        char[] chunk = new char[2048];
        StringBuilder line = new StringBuilder();
        for (int count; (count = reader.read(chunk)) >= 0;) {
            if (count == 0) continue;
            persist.accept(new String(chunk, 0, count));
            for (int i = 0; i < count; i++) {
                if (chunk[i] == '\n') {
                    onLine.accept(line.toString());
                    line.setLength(0);
                } else if (line.length() < 8192) {
                    line.append(chunk[i]);
                }
            }
        }
        if (line.length() > 0) onLine.accept(line.toString());
    }
}
