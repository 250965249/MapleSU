package dev.maplesu.manager

import java.io.File

/** Selected images only publish a candidate; no installation transaction is involved. */
internal fun <Candidate> exportSelectedImage(
    source: File,
    copySource: (File) -> Unit,
    build: (File) -> Candidate,
    publish: (Candidate) -> String,
): String = try {
    copySource(source)
    publish(build(source))
} finally {
    source.delete()
}
