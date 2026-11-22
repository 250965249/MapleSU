param(
    [Parameter(Mandatory)][string]$Java,
    [Parameter(Mandatory)][string]$CompilerClassPath,
    [Parameter(Mandatory)][string]$DependencyClassPath,
    [Parameter(Mandatory)][string]$ProductionClassPath,
    [Parameter(Mandatory)][string]$OutputDirectory
)
$ErrorActionPreference = 'Stop'
$source = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '../../../main/java')).Path
$output = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $output) { throw "Use a fresh output directory: $output" }
New-Item -ItemType Directory -Path $output | Out-Null
$classes = Join-Path $output 'classes'
$attempts = [Collections.Generic.List[object]]::new()

function Invoke-Args([string]$Name, [string]$Executable, [string[]]$Arguments) {
    $argsFile = Join-Path $output "$Name.args"
    $Arguments | ForEach-Object { '"' + $_.Replace('\', '\\').Replace('"', '\"') + '"' } |
        Set-Content -LiteralPath $argsFile -Encoding utf8NoBOM
    & $Executable "@$argsFile" *> (Join-Path $output "$Name.log")
    $code = $LASTEXITCODE
    $attempts.Add([ordered]@{ name = $Name; executable = $Executable; exitCode = $code; args = $argsFile })
    if ($code -ne 0) {
        Get-Content -LiteralPath (Join-Path $output "$Name.log")
        throw "$Name exited $code"
    }
}

$production = @(
    'com/maplesu/core/ui/webui/WebUIState.kt',
    'com/maplesu/core/ui/webui/WebViewInterface.kt',
    'com/maplesu/core/ui/webui/WebUIDownloadInterface.kt',
    'com/maplesu/core/ui/webui/WebUIBridge.kt',
    'com/maplesu/core/ui/webui/ModuleWebOrigin.kt',
    'com/maplesu/core/ui/webui/SuFilePathHandler.java',
    'com/maplesu/core/ui/webui/NormalWebUiCompatibility.kt',
    'com/maplesu/core/ui/webui/BlobDownloadHandler.kt',
    'com/maplesu/core/ui/webui/Download.kt',
    'com/maplesu/core/ui/webui/WebUIResourceCleanup.kt',
    'dev/maplesu/manager/modules/webui/ModuleWebUiSessions.kt'
) | ForEach-Object { Join-Path $source $_ }
$fixtures = Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'fixtures') -File -Filter '*.kt' |
    Sort-Object Name | Select-Object -ExpandProperty FullName
$sources = @($production) + @($fixtures) + @(Join-Path $PSScriptRoot 'WebUiRetirementJvmTest.kt') +
    @(Join-Path $PSScriptRoot 'SelectedRetirementTests.kt')
$inputs = @($sources | ForEach-Object {
    [ordered]@{ path = $_; sha256 = (Get-FileHash -LiteralPath $_ -Algorithm SHA256).Hash.ToLowerInvariant() }
})
$inputs | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $output 'INPUTS.json') -Encoding utf8NoBOM
$cp = "$DependencyClassPath;$ProductionClassPath"
$friendPaths = @($ProductionClassPath -split ';' | Where-Object { Test-Path -LiteralPath $_ -PathType Container }) -join ','
try {
    Invoke-Args 'compile' $Java (@('-Xmx640m', '-cp', $CompilerClassPath,
        'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler', '-no-stdlib', '-no-reflect', '-nowarn',
        '-jvm-target', '21', "-Xfriend-paths=$friendPaths", '-classpath', $cp, '-d', $classes) + $sources)
    $javac = Join-Path (Split-Path -Parent $Java) 'javac.exe'
    Invoke-Args 'javac' $javac @('-proc:none', '-cp', "$classes;$cp", '-d', $classes,
        (Join-Path $source 'com/maplesu/core/ui/webui/SuFilePathHandler.java'))
    Invoke-Args 'run' $Java @('-cp', "$classes;$cp", 'org.junit.runner.JUnitCore',
        'com.maplesu.core.ui.webui.WebUiRetirementJvmTest')
} finally {
    $stable = @($inputs | Where-Object { (Get-FileHash -LiteralPath $_.path -Algorithm SHA256).Hash.ToLowerInvariant() -ne $_.sha256 }).Count -eq 0
    [ordered]@{ recordedUtc = [DateTime]::UtcNow.ToString('o'); attempts = $attempts;
        inputsStable = $stable; cases = 7;
        scope = 'Current production page/Chrome/download/asset code; Android, libsu shell/file and KsuIO boundaries are JVM substitutes. No MediaStore publish, authentication scope, native host, APK, device or prior green matrix execution.' } |
        ConvertTo-Json -Depth 7 | Set-Content -LiteralPath (Join-Path $output 'RESULT.json') -Encoding utf8NoBOM
}

