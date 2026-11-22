param(
    [Parameter(Mandatory = $true)][string]$Serial,
    [string]$SdkDirectory = $(if ($env:ANDROID_HOME) { $env:ANDROID_HOME } else { $env:ANDROID_SDK_ROOT }),
    [switch]$WithReferenceSamples,
    [switch]$WithExistingRootInstaller,
    [switch]$InstallerBackendOnly,
    [switch]$RuntimeBackendOnly,
    [switch]$StorageBackendOnly
)
if (-not $SdkDirectory) { throw 'Set ANDROID_HOME (or ANDROID_SDK_ROOT), or pass -SdkDirectory.' }
$ErrorActionPreference = 'Stop'
$workspace = Split-Path $PSScriptRoot -Parent
$adb = Join-Path $SdkDirectory 'platform-tools\adb.exe'
$apk = Join-Path $workspace 'manager\build\outputs\apk\debug\manager-debug.apk'
$testApk = Join-Path $workspace 'manager\build\outputs\apk\androidTest\debug\manager-debug-androidTest.apk'
$logDirectory = Join-Path $workspace $(if ($InstallerBackendOnly) { '.analysis\installer-service-validation' }
    elseif ($RuntimeBackendOnly) { '.analysis\runtime-apk-validation' }
    elseif ($StorageBackendOnly) { '.analysis\storage-apk-validation' } else { '.analysis\manager-validation' })
if ($InstallerBackendOnly -and -not $WithExistingRootInstaller) {
    throw 'InstallerBackendOnly requires WithExistingRootInstaller'
}
if ($RuntimeBackendOnly -and ($InstallerBackendOnly -or $StorageBackendOnly -or $WithReferenceSamples -or $WithExistingRootInstaller)) {
    throw 'RuntimeBackendOnly runs ordinary-UID executor checks and requires no other scope switch'
}
if ($StorageBackendOnly -and ($InstallerBackendOnly -or $RuntimeBackendOnly -or $WithReferenceSamples -or $WithExistingRootInstaller)) {
    throw 'StorageBackendOnly runs ordinary-UID backend checks and requires no other scope switch'
}
New-Item -ItemType Directory -Path $logDirectory -Force | Out-Null
$runId = [Guid]::NewGuid().ToString('N')
$summary = [ordered]@{ schemaVersion = 1; serial = $Serial; referenceSamples = [bool]$WithReferenceSamples;
    existingRootInstaller = [bool]$WithExistingRootInstaller;
    testScope = $(if ($InstallerBackendOnly) { 'installer-backend' }
        elseif ($RuntimeBackendOnly) { 'runtime-executor' }
        elseif ($StorageBackendOnly) { 'storage-backend' } else { 'manager-complete' }); passed = $false }

function Invoke-AdbChecked {
    param([string[]]$Arguments)
    $preference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $lines = & $adb -s $Serial @Arguments 2>&1
        $code = $LASTEXITCODE
    } finally { $ErrorActionPreference = $preference }
    $text = ($lines | ForEach-Object { "$_" }) -join "`n"
    Add-Content -LiteralPath (Join-Path $logDirectory "$runId.log") -Value $text -Encoding UTF8
    Write-Host $text
    if ($code -ne 0) { throw "adb operation failed (exit $code)" }
    return $text
}

function Confirm-InstalledApk {
    param([string]$Package, [string]$ExpectedSha256)
    $packagePath = Invoke-AdbChecked -Arguments @('shell', 'pm', 'path', $Package)
    if ($packagePath -notmatch '(?m)^package:([/A-Za-z0-9_~+=.\-]+/base\.apk)\s*$') {
        throw "Installed APK path was not returned: $Package"
    }
    $installedHash = Invoke-AdbChecked -Arguments @('shell', 'sha256sum', $Matches[1])
    if ($installedHash -notmatch "^$ExpectedSha256\s") { throw "Installed APK differs from build output: $Package" }
}

function Read-CurrentPartitionHashes {
    $slot = (Invoke-AdbChecked -Arguments @('shell', 'getprop', 'ro.boot.slot_suffix')).Trim()
    if ($slot -notin @('', '_a', '_b')) { throw 'Unexpected boot slot' }
    $paths = @('boot', 'init_boot', 'vbmeta') | ForEach-Object { "/dev/block/by-name/$_$slot" }
    $output = Invoke-AdbChecked -Arguments @('shell', "su -c 'sha256sum $($paths -join ' ')'")
    $hashes = [ordered]@{}
    foreach ($path in $paths) {
        if ($output -notmatch "(?m)^([0-9a-f]{64})\s+$([regex]::Escape($path))\s*$") {
            throw "Partition hash was not returned: $path"
        }
        $hashes[$path] = $Matches[1]
    }
    return $hashes
}

try {
    $sourceInputJson = & py -3.12 (Join-Path $workspace 'tools\research\export_installer_service_validation.py') --capture-inputs
    if ($LASTEXITCODE -ne 0) { throw 'Could not capture Manager test-run sources' }
    $summary.sourceInputs = $sourceInputJson | ConvertFrom-Json
    $buildIdentityJson = & py -3.12 (Join-Path $workspace 'tools\research\export_installer_service_validation.py') --check-build
    if ($LASTEXITCODE -ne 0) { throw 'Run tools/research/build_manager_validation.py to build and bind current Manager sources first' }
    $summary.buildIdentity = $buildIdentityJson | ConvertFrom-Json
    if ($InstallerBackendOnly) { $summary.partitionHashesBefore = Read-CurrentPartitionHashes }
    $summary.apkSha256 = (Get-FileHash -LiteralPath $apk -Algorithm SHA256).Hash.ToLowerInvariant()
    $summary.testApkSha256 = (Get-FileHash -LiteralPath $testApk -Algorithm SHA256).Hash.ToLowerInvariant()
    Invoke-AdbChecked -Arguments @('install', '-r', '-t', $apk) | Out-Null
    Invoke-AdbChecked -Arguments @('install', '-r', '-t', $testApk) | Out-Null
    Confirm-InstalledApk -Package 'dev.maplesu.manager' -ExpectedSha256 $summary.apkSha256
    Confirm-InstalledApk -Package 'dev.maplesu.manager.test' -ExpectedSha256 $summary.testApkSha256
    $summary.installedApkVerified = $true
    $summary.installedTestApkVerified = $true
    if ($WithReferenceSamples) {
        Invoke-AdbChecked -Arguments @('push', (Join-Path $workspace 'SKRoot_Reference\Boot\Oringial_boot.img'), '/data/local/tmp/maplesu-validation-original.img') | Out-Null
        Invoke-AdbChecked -Arguments @('push', (Join-Path $workspace '.analysis\skroot-reference\patched\boot.img'), '/data/local/tmp/maplesu-validation-patched.img') | Out-Null
    }
    $useReferences = if ($WithReferenceSamples) { 'true' } else { 'false' }
    $useExistingRoot = if ($WithExistingRootInstaller) { 'true' } else { 'false' }
    Invoke-AdbChecked -Arguments @('shell', 'input', 'keyevent', 'KEYCODE_WAKEUP') | Out-Null
    $instrumentArguments = @('shell', 'am', 'instrument', '-w', '-r', '-e', 'referenceSamples', $useReferences,
        '-e', 'existingRootInstaller', $useExistingRoot)
    if ($InstallerBackendOnly) {
        $instrumentArguments += @('-e', 'class', 'dev.maplesu.manager.installer.InstallerRootSessionAndroidTest,dev.maplesu.manager.installer.InstallerServiceAndroidTest,dev.maplesu.manager.ImageRepositoryTest#installedBootImportChecksSizeAndDigestBeforePublication,dev.maplesu.manager.ImageRepositoryTest#installedBootImportAndVerificationHoldOneRepositoryOperation,dev.maplesu.manager.ImageRepositoryTest#installedBootDecodeFailureRetainsPreviouslyVerifiedImage,dev.maplesu.manager.ImageRepositoryTest#installedBootKernelReleaseIsVerifiedBeforePublication,dev.maplesu.manager.installer.InstallerUiAndroidTest#authorizedDirectSourceIsTheCurrentBootImage')
    }
    if ($RuntimeBackendOnly) {
        $instrumentArguments += @('-e', 'class', 'dev.maplesu.manager.runtime.MapleSuExecutorAndroidTest')
    }
    if ($StorageBackendOnly) {
        $instrumentArguments += @('-e', 'class', 'dev.maplesu.manager.BootRebuildAndroidTest,dev.maplesu.installer.FileInstallTransactionAndroidTest,dev.maplesu.manager.runtime.authorization.AuthorizationPolicyAndroidTest,dev.maplesu.manager.modules.ModuleCatalogAndroidTest')
    }
    if (-not $WithExistingRootInstaller) {
        $instrumentArguments += @('-e', 'notClass', 'dev.maplesu.manager.installer.InstallerRootSessionAndroidTest,dev.maplesu.manager.installer.InstallerUiAndroidTest,dev.maplesu.manager.installer.InstallerServiceAndroidTest')
    }
    $instrumentArguments += 'dev.maplesu.manager.test/androidx.test.runner.AndroidJUnitRunner'
    $testOutput = Invoke-AdbChecked -Arguments $instrumentArguments
    # AndroidJUnitRunner can return shell exit 0 and INSTRUMENTATION_CODE=-1 on a failed test run.
    if ($testOutput -notmatch 'OK \(([0-9]+) tests?\)' -or
        $testOutput -match 'FAILURES!!!|INSTRUMENTATION_FAILED|Process crashed|shortMsg=') {
        throw 'Instrumentation did not report a successful test result'
    }
    $testOutput -match 'OK \(([0-9]+) tests?\)' | Out-Null
    $summary.tests = [int]$Matches[1]
    $summary.completedTests = [regex]::Matches($testOutput, '(?m)^INSTRUMENTATION_STATUS_CODE: 0\s*$').Count
    $summary.skippedTests = [regex]::Matches($testOutput, '(?m)^INSTRUMENTATION_STATUS_CODE: -(3|4)\s*$').Count
    if ($summary.tests -eq 0 -or $summary.tests -ne $summary.completedTests + $summary.skippedTests) {
        throw 'Instrumentation summary differs from completed test events'
    }
    if ($WithReferenceSamples -and $summary.skippedTests -ne 0) {
        throw 'Selected device validation contains skipped tests'
    }
    $summary.passed = $true
} finally {
    if ($summary.Contains('sourceInputs')) {
        try {
            $currentSourceJson = & py -3.12 (Join-Path $workspace 'tools\research\export_installer_service_validation.py') --capture-inputs
            if ($LASTEXITCODE -ne 0) { throw 'Could not recheck installation test-run sources' }
            $summary.sourceInputsUnchanged = ($summary.sourceInputs | ConvertTo-Json -Compress) -eq
                (($currentSourceJson | ConvertFrom-Json) | ConvertTo-Json -Compress)
        } catch {
            $summary.sourceInputsUnchanged = $false
            $summary.sourceInputCheckError = "$_"
        }
        if (-not $summary.sourceInputsUnchanged) { $summary.passed = $false }
    }
    if ($InstallerBackendOnly -and $summary.Contains('partitionHashesBefore')) {
        try {
            $summary.partitionHashesAfter = Read-CurrentPartitionHashes
            $summary.partitionHashesUnchanged = ($summary.partitionHashesBefore | ConvertTo-Json -Compress) -eq
                ($summary.partitionHashesAfter | ConvertTo-Json -Compress)
        } catch {
            $summary.partitionHashesUnchanged = $false
            $summary.partitionCheckError = "$_"
        }
        if (-not $summary.partitionHashesUnchanged) { $summary.passed = $false }
    }
    $summary | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $logDirectory "$runId-summary.json") -Encoding UTF8
    if ($summary.Contains('sourceInputsUnchanged') -and $summary.sourceInputsUnchanged -ne $true) {
        throw 'Installation test-run sources changed or could not be verified'
    }
    if ($summary.Contains('partitionHashesUnchanged') -and $summary.partitionHashesUnchanged -ne $true) {
        throw 'Partition hashes changed or could not be verified after validation'
    }
}
