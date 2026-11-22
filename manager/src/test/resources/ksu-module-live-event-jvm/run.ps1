param(
    [Parameter(Mandatory)][string]$Java,
    [Parameter(Mandatory)][string]$CompilerClassPath,
    [Parameter(Mandatory)][string]$DependencyClassPath,
    [Parameter(Mandatory)][string]$OutputDirectory,
    [string]$ManagerRoot = (Join-Path $PSScriptRoot '../../../..')
)
$ErrorActionPreference = 'Stop'
$manager = (Resolve-Path -LiteralPath $ManagerRoot).Path
$output = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $output) { throw "Use a fresh output directory: $output" }
New-Item -ItemType Directory -Path $output | Out-Null
$results = [Collections.Generic.List[object]]::new()
$sourcePaths = @(
    'src/ksu/java/dev/maplesu/manager/ksu/KsuModuleOps.kt',
    'src/ksu/java/dev/maplesu/manager/ksu/KsuCommandBackend.kt',
    'src/ksu/java/dev/maplesu/manager/ksu/KsuModuleActionResult.kt',
    'src/ksu/java/dev/maplesu/manager/ksu/KsuSupport.kt',
    'src/ksu/java/dev/maplesu/manager/ksu/KsuSettingsFeature.kt',
    'src/ksu/java/dev/maplesu/manager/ksu/KsuRootShell.kt',
    'src/main/java/dev/maplesu/manager/modules/webui/ModuleWebUiSessions.kt',
    'src/test/java/dev/maplesu/manager/ksu/KsuModuleLiveEventTest.kt',
    'src/test/java/dev/maplesu/manager/ksu/KsuModuleInstallTest.kt'
) | ForEach-Object { Join-Path $manager $_ }
$sourcePaths += Join-Path $PSScriptRoot 'UnusedInstallProducer.kt'
$inputPaths = @($sourcePaths) + @($PSCommandPath)
$inputs = @($inputPaths | ForEach-Object {
    [ordered]@{ path = $_; sha256 = (Get-FileHash -LiteralPath $_ -Algorithm SHA256).Hash.ToLowerInvariant() }
})
function Invoke-JavaArgs([string]$Name, [string[]]$Arguments) {
    $argsPath = Join-Path $output "$Name.args"
    $Arguments | ForEach-Object { '"' + $_.Replace('\', '\\').Replace('"', '\"') + '"' } |
        Set-Content -LiteralPath $argsPath -Encoding utf8NoBOM
    & $Java "@$argsPath" *> (Join-Path $output "$Name.log")
    $code = $LASTEXITCODE
    $results.Add([ordered]@{ name = $Name; exitCode = $code; args = $argsPath })
    if ($code -ne 0) { Get-Content -LiteralPath (Join-Path $output "$Name.log"); throw "$Name exited $code" }
}
$classes = Join-Path $output 'classes'
try {
    Invoke-JavaArgs 'compile' (@('-Xmx512m', '-cp', $CompilerClassPath, 'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler',
        '-no-stdlib', '-no-reflect', '-nowarn', '-jvm-target', '21', '-classpath', $DependencyClassPath, '-d', $classes) + $sourcePaths)
    Invoke-JavaArgs 'test' @('-cp', "$classes;$DependencyClassPath", 'org.junit.runner.JUnitCore',
        'dev.maplesu.manager.ksu.KsuModuleLiveEventTest', 'dev.maplesu.manager.ksu.KsuModuleInstallTest')
} finally {
    $stable = @($inputs | Where-Object { (Get-FileHash -LiteralPath $_.path -Algorithm SHA256).Hash.ToLowerInvariant() -ne $_.sha256 }).Count -eq 0
    [ordered]@{ recordedUtc = [DateTime]::UtcNow.ToString('o'); inputs = $inputs; inputsStable = $stable;
        attempts = $results; scope = 'Current complete KsuModuleOps, command backend, root-shell adapter, support and ModuleWebUiSessions; injected shell transport and path probe, fail-fast unused image producer. JVM only; no real ksud process, root shell, native swap, APK or device.' } |
        ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $output 'RESULT.json') -Encoding utf8NoBOM
    if (-not $stable) { throw 'Source inputs changed while validating' }
}
