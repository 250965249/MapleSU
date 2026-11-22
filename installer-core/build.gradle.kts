plugins { `java-library` }
java { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
tasks.register<JavaExec>("checkTransactions") {
    dependsOn(tasks.testClasses)
    classpath = sourceSets.test.get().runtimeClasspath
    mainClass.set("dev.maplesu.installer.FileInstallTransactionTest")
}
tasks.test { enabled = false }
tasks.check { dependsOn("checkTransactions") }
tasks.register<JavaExec>("checkBlockTransactions") {
    dependsOn(tasks.testClasses)
    classpath = sourceSets.test.get().runtimeClasspath
    mainClass.set("dev.maplesu.installer.BlockDeviceTransactionTest")
}
tasks.check { dependsOn("checkBlockTransactions") }
tasks.register<JavaExec>("checkMultiPartitionTransactions") {
    dependsOn(tasks.testClasses)
    classpath = sourceSets.test.get().runtimeClasspath
    mainClass.set("dev.maplesu.installer.MultiPartitionTransactionTest")
}
tasks.check { dependsOn("checkMultiPartitionTransactions") }
tasks.register<JavaExec>("checkSwitchPlanValidation") {
    dependsOn(tasks.testClasses)
    classpath = sourceSets.test.get().runtimeClasspath
    mainClass.set("dev.maplesu.installer.SwitchPlanValidationTest")
}
tasks.check { dependsOn("checkSwitchPlanValidation") }
tasks.register<JavaExec>("checkSwitchVerify") {
    dependsOn(tasks.testClasses)
    classpath = sourceSets.test.get().runtimeClasspath
    mainClass.set("dev.maplesu.installer.SwitchVerifyTest")
}
tasks.check { dependsOn("checkSwitchVerify") }
tasks.register<JavaExec>("checkWritePathGuard") {
    dependsOn(tasks.testClasses)
    classpath = sourceSets.test.get().runtimeClasspath
    mainClass.set("dev.maplesu.installer.WritePathGuardTest")
}
tasks.check { dependsOn("checkWritePathGuard") }
