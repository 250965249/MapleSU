param(
    [Parameter(Mandatory = $true)][string]$Serial,
    [string]$SdkDirectory = $(if ($env:ANDROID_HOME) { $env:ANDROID_HOME } else { $env:ANDROID_SDK_ROOT }),
    [string]$KernelPath,
    [switch]$WithPlan
)
if (-not $SdkDirectory) { throw 'Set ANDROID_HOME (or ANDROID_SDK_ROOT), or pass -SdkDirectory.' }
$ErrorActionPreference = 'Stop'
if ($WithPlan -and -not $KernelPath) { throw '-WithPlan requires -KernelPath' }
$workspace = Split-Path $PSScriptRoot -Parent
$adb = Join-Path $SdkDirectory 'platform-tools\adb.exe'
$build = Join-Path $workspace 'patch-engine\build\android-arm64'
$logDirectory = Join-Path $workspace '.analysis\native-validation'
New-Item -ItemType Directory -Path $logDirectory -Force | Out-Null
$runId = [Guid]::NewGuid().ToString('N')
$remote = "/data/local/tmp/maplesu-native-audit-$runId"
$results = [ordered]@{ schemaVersion = 1; serial = $Serial; checks = @(); passed = $false }

function Invoke-AdbChecked {
    param([string[]]$Arguments)
    $preference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue' # Windows PowerShell treats native stderr as ErrorRecord.
        $output = & $adb -s $Serial @Arguments 2>&1
        $code = $LASTEXITCODE
    } finally { $ErrorActionPreference = $preference }
    $output | ForEach-Object { Write-Host "$_" }
    if ($code -ne 0) { throw "adb operation failed (exit $code)" }
}

function Invoke-Check {
    param([string]$Name, [string[]]$Command, [string]$RequiredOutput)
    $preference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = & $adb -s $Serial shell @Command 2>&1
        $code = $LASTEXITCODE
    } finally { $ErrorActionPreference = $preference }
    $text = ($output | ForEach-Object { "$_" }) -join "`n"
    $text | Set-Content -LiteralPath (Join-Path $logDirectory "$runId-$Name.log") -Encoding UTF8
    $output | ForEach-Object { Write-Host "$_" }
    $passed = $code -eq 0 -and $text -match $RequiredOutput
    $results.checks += [ordered]@{ name = $Name; exitCode = $code; passed = $passed }
    if (-not $passed) { throw "$Name failed (exit $code); see native-validation logs" }
}

try {
    Invoke-AdbChecked -Arguments @('shell', 'mkdir', '-p', $remote)
    foreach ($name in @('maplesu-native-tests', 'maplesu-kernel-analyze')) {
        $binary = Join-Path $build $name
        Invoke-AdbChecked -Arguments @('push', $binary, "$remote/$name")
        Invoke-AdbChecked -Arguments @('shell', 'chmod', '700', "$remote/$name")
    }
    $results.testsSha256 = (Get-FileHash -LiteralPath (Join-Path $build 'maplesu-native-tests') -Algorithm SHA256).Hash.ToLowerInvariant()
    $results.analyzerSha256 = (Get-FileHash -LiteralPath (Join-Path $build 'maplesu-kernel-analyze') -Algorithm SHA256).Hash.ToLowerInvariant()
    Invoke-Check -Name 'core' -Command @("$remote/maplesu-native-tests") -RequiredOutput 'PASS [0-9]+ native core checks'
    if ($KernelPath) {
        $source = (Resolve-Path -LiteralPath $KernelPath).Path
        $before = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant()
        $results.sourceSha256 = $before
        Invoke-AdbChecked -Arguments @('push', $source, "$remote/input.bin")
        Invoke-Check -Name 'symbols' -Command @("$remote/maplesu-kernel-analyze", '--symbols', "$remote/input.bin") -RequiredOutput 'SYMBOL_TABLE_OK count=[1-9][0-9]*'
        if ($WithPlan) {
            Invoke-Check -Name 'plan' -Command @("$remote/maplesu-kernel-analyze", '--plan', "$remote/input.bin") -RequiredOutput 'PLAN_REPLAY_OK changedBytes=[1-9][0-9]*'
            $results.experimentalPlanReplayed = $true
        }
        Invoke-Check -Name 'device-source-hash' -Command @('sha256sum', "$remote/input.bin") -RequiredOutput "^$before\s"
        if ($before -ne (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant()) {
            throw 'Host source changed during validation'
        }
        $results.sourceUnchanged = $true
    }
    $results.passed = $true
} finally {
    $results | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $logDirectory "$runId-summary.json") -Encoding UTF8
}
Write-Host 'Native checks and requested read-only analysis passed. No candidate or partition was written.'
