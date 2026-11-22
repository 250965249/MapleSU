package dev.maplesu.manager.jailbreak

import com.maplesu.core.ui.util.BugreportArchive
import org.json.JSONObject
import java.io.File

/** Freeze exactly the displayed log when Export or Share is pressed. */
class JailbreakScreenLog internal constructor(
    snapshot: JailbreakLogReader.Snapshot,
    method: String,
    backend: String,
) {
    private val text = BugreportArchive.redact(snapshot.text())
    private val metadata = JSONObject().apply {
        put("schema", "maplesu.jailbreak.screen.v1")
        put("attemptId", snapshot.attemptId ?: JSONObject.NULL)
        put("method", method)
        put("rootBackend", backend)
        put("stage", snapshot.stage ?: JSONObject.NULL)
        put("capturedAtMillis", System.currentTimeMillis())
        put("lines", snapshot.lines.size)
        put("omitted", snapshot.omitted)
    }.toString()

    internal fun writeTo(destination: File) {
        val directory = File(destination, "jailbreak-screen").apply { mkdirs() }
        File(directory, "screen.log").writeText(text)
        File(directory, "metadata.json").writeText(metadata)
    }
}
