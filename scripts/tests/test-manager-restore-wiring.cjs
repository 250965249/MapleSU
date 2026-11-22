// Source-contract checks only: no Kotlin/Android compilation or device mutation.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const baseline = process.argv[2];
const read = file => fs.readFileSync(baseline && fs.existsSync(path.join(baseline, file))
  ? path.join(baseline, file) : file, 'utf8').replace(/\r\n/g, '\n');
const confirmation = read('manager/src/main/java/dev/maplesu/manager/recovery/ManagerRestoreConfirmation.kt');
const activity = read('manager/src/main/java/com/maplesu/core/ui/MainActivity.kt');
const home = read('manager/src/main/java/com/maplesu/core/ui/viewmodel/HomeViewModel.kt');
const daemon = read('manager/src/main/java/dev/maplesu/manager/liteweb/daemon/LiteWebDaemonMain.kt');
const unhide = read('manager/src/main/java/dev/maplesu/manager/liteweb/daemon/DaemonParasiteUnhide.kt');
const revoke = read('manager/src/main/java/dev/maplesu/manager/liteweb/daemon/ProSdkSuAuthRevoke.kt');
const theme = read('manager/src/main/java/com/maplesu/core/ui/screen/host/HiddenFlowComponents.kt');
const tests = read('manager/src/test/java/dev/maplesu/manager/liteweb/daemon/DaemonUnhideTest.kt');
const checks = [
 ['confirmation uses shared MIUIX/Material dialog', () => {
   assert.match(confirmation, /HiddenFlowDialog\(/);
   assert.doesNotMatch(confirmation, /android\.app\.AlertDialog|AlertDialog\.Builder/);
   assert.match(theme, /UiMode\.Miuix -> WindowDialog\(/);
   assert.match(theme, /UiMode\.Material -> AlertDialog\(/);
 }],
 ['dialog is hosted in application theme with live home refresh', () => {
   const themeBody = activity.slice(activity.indexOf('KernelSUTheme(appSettings ='));
   assert.match(themeBody, /managerRestoreConfirmation\.Content\(onRestoreObserved = \{/);
   assert.match(themeBody, /homeViewModel\.refreshAfterManagerRestore\(\)/);
   assert.equal((activity.match(/val homeViewModel = viewModel<HomeViewModel>\(\)/g) || []).length, 1);
 }],
 ['confirmation stays open on failure and blocks duplicate/dismiss while busy', () => {
   assert.match(confirmation, /confirmEnabled = !confirming/);
   assert.match(confirmation, /dismissEnabled = !confirming/);
   assert.match(confirmation, /if \(confirming \|\| pending != restored/);
   assert.match(confirmation, /failureCode = result\.code/);
   assert.match(confirmation, /manager_restore_confirm_retry_code/);
 }],
 ['root ticket observation is not gated on a stale environment cache', () => {
   assert.doesNotMatch(confirmation, /ProEnvironmentProbe/);
   assert.match(confirmation, /root\(\)\.run\(/);
   assert.ok(confirmation.includes('id -u'));
   assert.match(confirmation, /synchronized\(LiteHiddenController\)/);
 }],
 ['late key recovery is retried inside the foreground check', () => {
   const check = confirmation.slice(confirmation.indexOf('    fun check('), confirmation.indexOf('    private suspend fun observeRestore()'));
   const load = confirmation.slice(confirmation.indexOf('    private fun load()'), confirmation.indexOf('    private fun confirm('));
   assert.doesNotMatch(check, /ProRootKeyStore\.read/);
   assert.match(load, /check\(ProRootKeyStore\.read\(activity\) != null\)/);
   assert.match(check, /activity\.repeatOnLifecycle\(Lifecycle\.State\.RESUMED\)/);
   assert.match(activity, /getBooleanExtra\("maplesu_restore", false\)\) managerRestoreConfirmation\.check\(restart = true\)/);
   assert.match(check, /observationJob\?\.cancel\(\)/);
 }],
 ['submit retries ticket reads and uses latest endpoint for the same nonce', () => {
   assert.ok((confirmation.match(/readRestoreOnceReady\((?:attempts = \d+, )?load = \{ load\(\) \}\)/g) || []).length >= 2);
   assert.match(confirmation, /current\.nonce != restored\.nonce/);
   assert.match(confirmation, /postConfirmation\(current\)/);
   assert.match(confirmation, /result\.nextPending\?\.let \{ pending = it \}/);
 }],
 ['lost replies require a root-only matching confirmed ticket', () => {
   assert.match(confirmation, /!response\.ok && confirmed\(restored\)/);
   const readback = confirmation.slice(confirmation.indexOf('private fun confirmed('));
   assert.ok(readback.includes('id -u'));
   assert.ok(readback.includes('RecoveryPaths.HIDDEN_STATE'));
   assert.ok(readback.includes('confirmed:${restored.nonce}'));
 }],
 ['home re-probe queues behind older publication without reusing it', () => {
   const refresh = home.slice(home.indexOf('fun refreshAfterManagerRestore()'), home.indexOf('    fun refresh()'));
   assert.match(refresh, /ProEnvironmentProbe\.refresh\(ksuApp, force = true\)/);
   assert.match(refresh, /checkEnvironmentPresence\(\)/);
   assert.match(refresh, /probeAndPublish\(/);
   assert.doesNotMatch(refresh, /publishMutex\.isLocked|refreshFlight|reuseCompletedDetection = true/);
   assert.match(home, /HomeUiState = publishMutex\.withLock/);
 }],
 ['all complete host backups are restored to their own verified directories', () => {
   assert.doesNotMatch(unhide, /BackupInventory\.Ambiguous/);
   assert.match(unhide, /val restored = hosts\.map \{ host ->/);
   assert.match(unhide, /restoreHost\(host, found\)/);
   assert.match(unhide, /removeLoader\(host, restored\[index\]\.libraryDir\)/);
   assert.match(unhide, /manifest\.packageName != hostPackage \|\| manifest\.libraryDir != libDir/);
   assert.match(unhide, /verifyOriginalFiles\(manifest, backup = true\)/);
   assert.match(unhide, /verifyOriginalFiles\(manifest, backup = false\)/);
 }],
 ['every host is revoked before the single daemon stop', () => {
   assert.match(unhide, /val revoked = hosts\.map \{ host ->/);
   assert.ok(unhide.indexOf('val revoked =') < unhide.indexOf('steps += stopDaemon()'));
   assert.equal((unhide.match(/steps \+= stopDaemon\(\)/g) || []).length, 1);
   assert.match(revoke, /val absent = SuAuthReadbackPolicy\.verify/);
   assert.ok(revoke.indexOf('if (absent.ok)') < revoke.indexOf('client.removeSuAuth(hostPackage)'));
 }],
 ['server retains durable pending status and reports failed cleanup steps', () => {
   assert.match(daemon, /RecoveryCleanupResult\(false, failed\.error, steps\)/);
   assert.match(daemon, /awaitingConfirmation = handover\.pending\(\)/);
   assert.match(daemon, /if \(result\.ok\) DaemonSelfStop\.schedule\(COMPLETION_GRACE_MILLIS\)/);
 }],
 ['multi-host success, corrupt-backup and retry regressions are present', () => {
   assert.match(tests, /fun multipleCompleteBackupsRestoreAndRevokeEveryHostBeforeStopping\(/);
   assert.match(tests, /fun corruptSecondHostPreservesBothBackupsAndNeverStopsRecovery\(/);
   assert.match(tests, /fun secondHostRevokeFailureCanRetryWithoutLosingRecovery\(/);
 }],
];
let failures = 0;
for (const [name, check] of checks) {
  try { check(); console.log('PASS: '+name); }
  catch (error) { failures++; console.error('FAIL: '+name); }
}
console.log(`${checks.length-failures}/${checks.length} source contracts passed (not a compiled/runtime test).`);
process.exitCode = failures ? 1 : 0;
