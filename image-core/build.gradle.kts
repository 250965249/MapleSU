plugins { `java-library`; application }
java { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
application { mainClass.set("dev.maplesu.image.ImageTool") }
tasks.register<JavaExec>("checkFixtures") {
    dependsOn(tasks.testClasses)
    classpath = sourceSets.test.get().runtimeClasspath
    mainClass.set("dev.maplesu.image.ImagePipelineTest")
}
tasks.register<JavaExec>("checkInspectorFixtures") {
    dependsOn(tasks.testClasses)
    classpath = sourceSets.test.get().runtimeClasspath
    mainClass.set("dev.maplesu.image.BootImageInspectorTest")
}

tasks.register<JavaExec>("checkRebuildFixtures") {
    dependsOn(tasks.testClasses)
    classpath = sourceSets.test.get().runtimeClasspath
    mainClass.set("dev.maplesu.image.BootImageRebuilderTest")
}

tasks.register<JavaExec>("checkRecoveryRegionFixtures") {
    dependsOn(tasks.testClasses)
    classpath = sourceSets.test.get().runtimeClasspath
    mainClass.set("dev.maplesu.image.RecoveryRegionRebuilderTest")
}

tasks.register<JavaExec>("checkRamdiskRebuildFixtures") {
    dependsOn(tasks.testClasses)
    classpath = sourceSets.test.get().runtimeClasspath
    mainClass.set("dev.maplesu.image.RamdiskRebuilderTest")
}

tasks.register<JavaExec>("checkRamdiskEntryFixtures") {
    dependsOn(tasks.testClasses)
    classpath = sourceSets.test.get().runtimeClasspath
    mainClass.set("dev.maplesu.image.RamdiskEntryEditorTest")
}

tasks.register<JavaExec>("checkRamdiskComponentFixtures") {
    dependsOn(tasks.testClasses)
    classpath = sourceSets.test.get().runtimeClasspath
    mainClass.set("dev.maplesu.image.RamdiskComponentWriterTest")
}

// W2: write-journal / declared-diff equivalence fixtures. Synthetic always; the device-proven
// 6.6.89 stock + k21 kernel are used when the reference artefacts are present.
tasks.register<JavaExec>("checkEquivalenceFixtures") {
    dependsOn(tasks.testClasses)
    classpath = sourceSets.test.get().runtimeClasspath
    mainClass.set("dev.maplesu.image.BootImageEquivalenceTest")
    // Reference boot images live in the repository root, not in this module.
    systemProperty("maplesu.root", rootProject.projectDir.absolutePath)
}

// W12 prerequisite: synthetic CPIO/gzip/LZ4 ramdisk fixtures. No private device image.
tasks.register<JavaExec>("checkRamdiskFixtures") {
    dependsOn(tasks.testClasses)
    classpath = sourceSets.test.get().runtimeClasspath
    mainClass.set("dev.maplesu.image.RamdiskInspectorTest")
}

// These dependency-free suites have main entry points, not JUnit annotations.
tasks.register<JavaExec>("checkLenovoAvbFixtures") {
    dependsOn(tasks.testClasses)
    classpath = sourceSets.test.get().runtimeClasspath
    mainClass.set("dev.maplesu.image.LenovoAvbSignerTest")
    providers.gradleProperty("lenovoAvbOutputs").orNull?.let { systemProperty("maplesu.avb.outputs", it) }
}

tasks.test { enabled = false }
tasks.check {
    dependsOn("checkFixtures", "checkInspectorFixtures", "checkRebuildFixtures", "checkRecoveryRegionFixtures", "checkRamdiskRebuildFixtures", "checkRamdiskFixtures",
            "checkRamdiskEntryFixtures", "checkRamdiskComponentFixtures",
            "checkEquivalenceFixtures", "checkLenovoAvbFixtures")
}
tasks.jar { manifest { attributes["Main-Class"] = application.mainClass.get() } }

tasks.register<JavaExec>("checkVendorBootFixtures") {
    dependsOn(tasks.testClasses)
    classpath = sourceSets.test.get().runtimeClasspath
    mainClass.set("dev.maplesu.image.VendorBootInspectorTest")
}
tasks.check { dependsOn("checkVendorBootFixtures") }

tasks.register<JavaExec>("checkKernelComponentFixtures") {
    dependsOn(tasks.testClasses)
    classpath = sourceSets.test.get().runtimeClasspath
    mainClass.set("dev.maplesu.image.KernelComponentTailTest")
}
tasks.check { dependsOn("checkKernelComponentFixtures") }

tasks.register<JavaExec>("checkKernelStreamFixtures") {
    dependsOn(tasks.testClasses)
    classpath = sourceSets.test.get().runtimeClasspath
    mainClass.set("dev.maplesu.image.KernelStreamCompatibilityTest")
}
tasks.check { dependsOn("checkKernelStreamFixtures") }

tasks.register<JavaExec>("checkZstdCompressedFixtures") {
    dependsOn(tasks.testClasses)
    classpath = sourceSets.test.get().runtimeClasspath
    mainClass.set("dev.maplesu.image.ZstdCompressedTest")
}
tasks.check { dependsOn("checkZstdCompressedFixtures") }

tasks.register<JavaExec>("checkLz4EncoderFixtures") {
    dependsOn(tasks.testClasses)
    classpath = sourceSets.test.get().runtimeClasspath
    mainClass.set("dev.maplesu.image.Lz4BlockEncoderTest")
}

tasks.check { dependsOn("checkLz4EncoderFixtures") }

tasks.register<JavaExec>("checkBootRecoveryFixtures") {
    dependsOn(tasks.testClasses)
    classpath = sourceSets.test.get().runtimeClasspath
    mainClass.set("dev.maplesu.image.BootImageRecoveryTest")
}
tasks.check { dependsOn("checkBootRecoveryFixtures") }

tasks.register<JavaExec>("checkStreamingRecoveryFixtures") {
    dependsOn(tasks.testClasses)
    classpath = sourceSets.test.get().runtimeClasspath
    mainClass.set("dev.maplesu.image.StreamingRecoveryRebuilderTest")
}

tasks.check { dependsOn("checkStreamingRecoveryFixtures") }

tasks.register<JavaExec>("checkRamdiskRecoveryFileFixtures") {
    dependsOn(tasks.testClasses)
    classpath = sourceSets.test.get().runtimeClasspath
    mainClass.set("dev.maplesu.image.RamdiskRecoveryFileTest")
}

tasks.check { dependsOn("checkRamdiskRecoveryFileFixtures") }

tasks.register<JavaExec>("checkUltraInitBootProducerFixtures") {
    dependsOn(tasks.testClasses)
    classpath = sourceSets.test.get().runtimeClasspath
    mainClass.set("dev.maplesu.image.UltraInitBootProducerTest")
}
tasks.check { dependsOn("checkUltraInitBootProducerFixtures") }
