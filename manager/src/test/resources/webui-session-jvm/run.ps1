param(
    [Parameter(Mandatory)][string]$Java,
    [Parameter(Mandatory)][string]$CompilerClassPath,
    [Parameter(Mandatory)][string]$DependencyClassPath,
    [Parameter(Mandatory)][string]$ProductionClassPath,
    [Parameter(Mandatory)][string]$OutputDirectory,
    [string]$ProductionSourceRoot = (Join-Path $PSScriptRoot '../../../main/java')
)
$ErrorActionPreference = 'Stop'
$source = (Resolve-Path -LiteralPath $ProductionSourceRoot).Path
$tests = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '../../java')).Path
$output = [System.IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $output) { throw "Use a fresh output directory: $output" }
New-Item -ItemType Directory -Path $output | Out-Null
$results = [System.Collections.Generic.List[object]]::new()

function Invoke-JavaArgs([string]$Name, [string[]]$Arguments) {
    $argsPath = Join-Path $output "$Name.args"
    $Arguments | ForEach-Object { '"' + $_.Replace('\', '\\').Replace('"', '\"') + '"' } |
        Set-Content -LiteralPath $argsPath -Encoding utf8NoBOM
    & $Java "@$argsPath" *> (Join-Path $output "$Name.log")
    $code = $LASTEXITCODE
    $results.Add([ordered]@{ name = $Name; exitCode = $code; args = $argsPath })
    if ($code -ne 0) {
        Get-Content -LiteralPath (Join-Path $output "$Name.log")
        throw "$Name exited $code"
    }
}

$pageSources = @(
    'com/maplesu/core/ui/webui/WebUIState.kt',
    'com/maplesu/core/ui/webui/WebViewInterface.kt',
    'com/maplesu/core/ui/webui/WebUIResourceCleanup.kt',
    'com/maplesu/core/ui/webui/NormalWebUiCompatibility.kt',
    'dev/maplesu/manager/modules/webui/ModuleWebUiSessions.kt'
) | ForEach-Object { Join-Path $source $_ }
$pageSources += Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'fixtures') -File -Filter '*.kt' |
    Sort-Object Name | Select-Object -ExpandProperty FullName
$pageSources += Join-Path $PSScriptRoot 'WebUiSessionLifecycleJvmTest.kt'
$transactionSources = @(
    'dev/maplesu/manager/runtime/ultra/UltraReceipt.kt',
    'dev/maplesu/manager/runtime/ultra/UltraAuthorizationResult.kt',
    'dev/maplesu/manager/compat/StoredInputs.kt',
    'dev/maplesu/manager/modules/compat/UltraModuleCompatibility.kt',
    'dev/maplesu/manager/modules/compat/UltraModuleCompatibilityRegistry.kt',
    'dev/maplesu/manager/modules/compat/UltraModuleCompatibilityGate.kt',
    'dev/maplesu/manager/modules/compat/UltraModuleDeviceFacts.kt',
    'dev/maplesu/manager/modules/compat/UltraModuleEvidence.kt',
    'dev/maplesu/manager/modules/compat/UltraModuleInstallTransaction.kt',
    'dev/maplesu/manager/modules/compat/UltraModuleUninstallTransaction.kt',
    'dev/maplesu/manager/modules/compat/UltraModuleHost.kt',
    'dev/maplesu/manager/modules/webui/ModuleWebUiSessions.kt'
) | ForEach-Object { Join-Path $source $_ }
$transactionSources += Join-Path $tests 'dev/maplesu/manager/modules/compat/UltraModuleSessionNotificationTest.kt'
$inputs = @($pageSources + $transactionSources | Sort-Object -Unique | ForEach-Object {
    $file = Get-Item -LiteralPath $_
    [ordered]@{ path = $file.FullName; bytes = $file.Length; sha256 = (Get-FileHash -LiteralPath $_ -Algorithm SHA256).Hash.ToLowerInvariant() }
})
$inputs | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $output 'INPUTS.json') -Encoding utf8NoBOM
$friendPaths = @($ProductionClassPath -split ';' | Where-Object { Test-Path -LiteralPath $_ -PathType Container }) -join ','
$common = @('-Xmx640m', '-cp', $CompilerClassPath, 'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler',
    '-no-stdlib', '-no-reflect', '-nowarn', '-jvm-target', '21')
try {
    $pages = Join-Path $output 'pages'
    $transactions = Join-Path $output 'transactions'
    Invoke-JavaArgs 'compile-pages' ($common + @('-classpath', $DependencyClassPath, '-d', $pages) + $pageSources)
    Invoke-JavaArgs 'compile-transactions' ($common + @(
        "-Xfriend-paths=$friendPaths", '-classpath', "$DependencyClassPath;$ProductionClassPath",
        '-d', $transactions) + $transactionSources)
    Invoke-JavaArgs 'run-pages' @('-cp', "$pages;$DependencyClassPath", 'org.junit.runner.JUnitCore',
        'com.maplesu.core.ui.webui.WebUiSessionLifecycleJvmTest')
    Invoke-JavaArgs 'run-transactions' @('-cp', "$transactions;$DependencyClassPath;$ProductionClassPath",
        'org.junit.runner.JUnitCore', 'dev.maplesu.manager.modules.compat.UltraModuleSessionNotificationTest')
} finally {
    [ordered]@{ recordedUtc = [DateTime]::UtcNow.ToString('o'); inputs = (Join-Path $output 'INPUTS.json');
        attempts = $results; scope = 'JVM only; platform/libsu/IO substitutes for page composition; injected transaction receipts/catalog; no native host, root, kernel, APK or device actions.' } |
        ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $output 'RESULT.json') -Encoding utf8NoBOM
}
