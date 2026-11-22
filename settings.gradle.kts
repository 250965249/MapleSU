pluginManagement {
    repositories { google(); mavenCentral(); gradlePluginPortal() }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories { google(); mavenCentral(); maven("https://jitpack.io") }
}
rootProject.name = "MapleSU"
include(":image-core", ":installer-core", ":manager")
include(":libsu-service")
project(":libsu-service").projectDir = file("third_party/libsu-service")
// Cooperative Binder SDK and its independent-UID example application.
include(":maplesu-client", ":maplesu-consumer")
project(":maplesu-client").projectDir = file("client")
project(":maplesu-consumer").projectDir = file("consumer")
