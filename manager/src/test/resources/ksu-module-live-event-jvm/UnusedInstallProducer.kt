package dev.maplesu.manager.ksu

/** The tests inject a shell runner; candidate-image production is outside their boundary. */
object KsuInstallProducer {
    fun shellJoin(tokens: List<String>): String = error("Candidate-image producer is outside this fixture")
}
