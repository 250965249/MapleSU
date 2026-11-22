// Independent-UID consumer for the cooperative (no-Key) Binder entry.
// Deliberately: no credential, no native SDK, no permissions, no Compose.
plugins {
    alias(libs.plugins.agp.app)
}

android {
    namespace = "dev.maplesu.consumer"
    compileSdk { version = release(37) { minorApiLevel = 0 } }
    buildToolsVersion = "37.0.0"
    defaultConfig {
        // Must stay different from dev.maplesu.manager: the test only means
        // something when this app runs under its own Linux UID.
        applicationId = "dev.maplesu.consumer"
        minSdk = 31
        targetSdk = 37
        versionCode = 1
        versionName = "0.1.0"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }
    buildFeatures { buildConfig = true }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }
}

// AGP 9 compiles Kotlin itself; JVM target still has to match compileOptions.
kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_21)
    }
}

dependencies {
    implementation(project(":maplesu-client"))
    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.androidx.test.junit)
}

// This module is tiny, so its dependency graph resolves the low end of every
// transitive range. Those older artifacts are not in the local cache while the
// versions the Manager module already resolves are. Pinning them keeps an offline
// build possible without changing what the test actually exercises.
configurations.configureEach {
    resolutionStrategy {
        force("androidx.annotation:annotation:1.9.1")
        force("androidx.lifecycle:lifecycle-common:2.11.0")
        force("androidx.lifecycle:lifecycle-runtime:2.11.0")
        force("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.11.0")
        force("org.jetbrains.kotlinx:kotlinx-coroutines-core-jvm:1.11.0")
    }
}
