# The test runner resolves this shared dependency before its first test runs.
-keep class androidx.tracing.Trace { *; }

# Instrumentation reuses the target APK runtime, including its base classes.
-keep class kotlin.** { *; }
-keep class kotlinx.coroutines.** { *; }

# These production types form the ABI of the three SDK acceptance tests.
# Test mapping preserves names, not target-side optimizations such as object
# staticization or removed getters; retain their callable shape in this variant.
-keep class dev.maplesu.manager.modules.UltraRootKeyStore { *; }
-keep class dev.maplesu.manager.ultrakernel.UltraKernelCredential { *; }
-keep class dev.maplesu.manager.ultrakernel.UltraKernelCredential$Companion { *; }
-keep class dev.maplesu.manager.runtime.ultra.IdentityVerification { *; }
-keep class dev.maplesu.manager.runtime.ultra.InstalledIdentity { *; }
-keep class dev.maplesu.manager.runtime.ultra.NativeReceipt { *; }
-keep class dev.maplesu.manager.runtime.ultra.UltraEnvironmentInstaller { *; }
-keep class dev.maplesu.manager.runtime.ultra.UltraEnvironmentProbe { *; }
-keep class dev.maplesu.manager.runtime.ultra.UltraEnvironmentProbe$State { *; }
-keep class dev.maplesu.manager.runtime.ultra.UltraIdentityRecovery { *; }
-keep class dev.maplesu.manager.runtime.ultra.UltraInstalledIdentityProbe { *; }
-keep class dev.maplesu.manager.runtime.ultra.UltraInstalledIdentityProbe$Readback { *; }
-keep class dev.maplesu.manager.runtime.ultra.UltraKeyPairedStore { *; }
-keep class dev.maplesu.manager.runtime.ultra.UltraRecoveryKeyStore { *; }
-keep class dev.maplesu.manager.runtime.ultra.UltraRecoveryKeyStore$BackupOutcome { *; }
-keep class dev.maplesu.manager.runtime.ultra.UltraRuntimeClient { *; }
-keep class dev.maplesu.manager.runtime.ultra.Source { *; }
-keep class dev.maplesu.manager.workmode.ModeRuntime { *; }
-keep class dev.maplesu.manager.workmode.WorkMode { *; }
