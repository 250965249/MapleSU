param(
    [Parameter(Mandatory)][string]$Java,
    [Parameter(Mandatory)][string]$CompilerClassPath,
    [Parameter(Mandatory)][string]$DependencyClassPath,
    [Parameter(Mandatory)][string]$ProductionClassPath,
    [Parameter(Mandatory)][string]$OutputDirectory
)
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '../../../../..')).Path
$source = Join-Path $repo 'manager/src/main/java/dev/maplesu/manager'
$output = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $output) { throw "Use a fresh output directory: $output" }
New-Item -ItemType Directory -Path $output | Out-Null
$sources = @(
    'runtime/ultra/UltraReceipt.kt', 'runtime/ultra/UltraAuthorizationResult.kt', 'compat/StoredInputs.kt',
    'modules/compat/UltraModuleCompatibility.kt', 'modules/compat/UltraModuleCompatibilityRegistry.kt',
    'modules/compat/UltraModuleCompatibilityGate.kt', 'modules/compat/UltraModuleDeviceFacts.kt',
    'modules/compat/UltraModuleEvidence.kt', 'modules/compat/UltraModuleHost.kt',
    'modules/compat/UltraModuleInstallTransaction.kt', 'modules/compat/UltraModuleToggleTransaction.kt'
) | ForEach-Object { Join-Path $source $_ }
$sources += Join-Path $repo 'manager/src/test/java/dev/maplesu/manager/modules/compat/UltraModuleJournalAdmissionTest.kt'
$inputs = @($sources + $PSCommandPath | ForEach-Object {
    [ordered]@{ path = $_; sha256 = (Get-FileHash -LiteralPath $_ -Algorithm SHA256).Hash.ToLowerInvariant() }
})
$inputs | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $output 'INPUTS.json') -Encoding utf8NoBOM
$commands = [Collections.Generic.List[object]]::new()
function Run([string]$Name, [string[]]$Arguments) {
    $argfile = Join-Path $output "$Name.args"
    $Arguments | ForEach-Object { '"' + $_.Replace('\', '\\').Replace('"', '\"') + '"' } |
        Set-Content -LiteralPath $argfile -Encoding utf8NoBOM
    & $Java "@$argfile" *> (Join-Path $output "$Name.log")
    $commands.Add([ordered]@{ name = $Name; exitCode = $LASTEXITCODE; args = $argfile })
    if ($LASTEXITCODE -ne 0) { Get-Content (Join-Path $output "$Name.log"); throw "$Name failed" }
}
try {
    $friends = @($ProductionClassPath -split ';' | Where-Object { Test-Path -LiteralPath $_ -PathType Container }) -join ','
    Run 'compile' (@('-Xmx640m', '-cp', $CompilerClassPath, 'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler',
        '-no-stdlib', '-no-reflect', '-nowarn', '-jvm-target', '21', "-Xfriend-paths=$friends",
        '-classpath', "$DependencyClassPath;$ProductionClassPath", '-d', (Join-Path $output 'classes')) + $sources)
    Run 'tests' @('-cp', "$(Join-Path $output 'classes');$DependencyClassPath;$ProductionClassPath",
        'org.junit.runner.JUnitCore', 'dev.maplesu.manager.modules.compat.UltraModuleJournalAdmissionTest')
} finally {
    $stable = @($inputs | Where-Object {
        (Get-FileHash -LiteralPath $_.path -Algorithm SHA256).Hash.ToLowerInvariant() -ne $_.sha256
    }).Count -eq 0
    [ordered]@{ passed = $commands.Count -eq 2 -and @($commands | Where-Object exitCode -ne 0).Count -eq 0 -and $stable;
        sourceInputsStable = $stable; commands = $commands;
        scope = 'Complete production transaction/receipt/compatibility sources with injected journal/catalog/host. No actual installation, Android, Root, APK or device.' } |
        ConvertTo-Json -Depth 6 | Set-Content (Join-Path $output 'RESULT.json') -Encoding utf8NoBOM
}
