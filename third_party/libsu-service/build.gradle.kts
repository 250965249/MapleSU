import java.security.MessageDigest

plugins { id("com.android.library") }

android {
    namespace = "com.topjohnwu.superuser.ipc"
    compileSdk = 37
    buildToolsVersion = "37.0.0"
    defaultConfig { minSdk = 31 }
    buildFeatures { aidl = true; buildConfig = false }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }
}

dependencies {
    api("com.github.topjohnwu.libsu:core:6.0.0")
    compileOnly("androidx.annotation:annotation:1.9.1")
}

val verifyOfficialTrampoline by tasks.registering {
    val asset = layout.projectDirectory.file("src/main/assets/main.jar")
    inputs.file(asset)
    doLast {
        val actual = MessageDigest.getInstance("SHA-256")
            .digest(asset.asFile.readBytes()).joinToString("") { "%02x".format(it) }
        check(actual == "ae7fdb8b70bd2c1cc2c27043e985f8dc5cfff2cb9142a1576dcdbc889763ef7b") {
            "Official libsu 6.0.0 trampoline asset changed"
        }
    }
}
tasks.named("preBuild").configure { dependsOn(verifyOfficialTrampoline) }
