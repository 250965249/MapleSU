// Cooperative (no-credential) client library for MapleSU's Binder Root entry.
//
// Deliberately contains: AIDL, a bindService client, and request/session adapters.
// Deliberately contains no credential, no native library, no permission, no
// component, and no hidden API.
plugins {
    // The root project already puts AGP on the build classpath, and that jar
    // registers com.android.library too. Asking for a versioned alias here fails
    // with "already on the classpath with an unknown version", so request the id
    // without a version, exactly like a subproject of a classic AGP build.
    id("com.android.library")
}

android {
    // The AIDL package has to stay dev.maplesu.manager.runtime: a Binder interface
    // descriptor is derived from the AIDL package and name, so the client and the
    // Root side must agree on it exactly. Only the Kotlin namespace is ours.
    namespace = "dev.maplesu.client"
    compileSdk { version = release(37) { minorApiLevel = 0 } }
    buildToolsVersion = "37.0.0"
    defaultConfig { minSdk = 31 }
    buildFeatures { aidl = true; buildConfig = false }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }
}

// AGP 9 compiles Kotlin itself; the JVM target still has to match compileOptions.
kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_21)
    }
}
