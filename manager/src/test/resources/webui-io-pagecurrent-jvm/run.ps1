param(
    [Parameter(Mandatory)][string]$Java,
    [Parameter(Mandatory)][string]$CompilerClassPath,
    [Parameter(Mandatory)][string]$DependencyClassPath,
    [Parameter(Mandatory)][string]$LibsuClassPath,
    [Parameter(Mandatory)][string]$OutputDirectory
)
$ErrorActionPreference = 'Stop'
$source = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '../../../main/java')).Path
$tests = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '../../java')).Path
$output = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $output) { throw "Use a fresh output directory: $output" }
New-Item -ItemType Directory -Path $output | Out-Null
$classes = Join-Path $output 'classes'
$sources = @(Get-ChildItem -LiteralPath (Join-Path $source 'com/maplesu/core/ui/webui/file') -File -Filter '*.kt' |
    Sort-Object Name | Select-Object -ExpandProperty FullName)
$sources += Join-Path $source 'com/maplesu/core/ui/webui/WebUIResourceCleanup.kt'
$sources += Join-Path $tests 'com/maplesu/core/ui/webui/WebUiIoLifecycleTest.kt'
$sources += Get-ChildItem -LiteralPath $PSScriptRoot -File -Filter '*.kt' |
    Sort-Object Name | Select-Object -ExpandProperty FullName
$inputs = @($sources | ForEach-Object {
    [ordered]@{ path = $_; sha256 = (Get-FileHash -LiteralPath $_ -Algorithm SHA256).Hash.ToLowerInvariant() }
})
$inputs | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $output 'INPUTS.json') -Encoding utf8NoBOM
$attempts = [Collections.Generic.List[object]]::new()
function Invoke-JavaArgs([string]$Name, [string[]]$Arguments) {
    $argsPath = Join-Path $output "$Name.args"
    $Arguments | ForEach-Object { '"' + $_.Replace('\', '\\').Replace('"', '\"') + '"' } |
        Set-Content -LiteralPath $argsPath -Encoding utf8NoBOM
    & $Java "@$argsPath" *> (Join-Path $output "$Name.log")
    $code = $LASTEXITCODE
    $attempts.Add([ordered]@{ name = $Name; command = @($Java, "@$argsPath"); exitCode = $code })
    if ($code -ne 0) {
        Get-Content -LiteralPath (Join-Path $output "$Name.log")
        throw "$Name exited $code"
    }
}
try {
    Invoke-JavaArgs 'compile' (@('-Xmx512m', '-cp', $CompilerClassPath,
        'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler', '-no-stdlib', '-no-reflect', '-nowarn',
        '-jvm-target', '21', '-classpath', "$DependencyClassPath;$LibsuClassPath", '-d', $classes) + $sources)
    Invoke-JavaArgs 'selected-junit' @('-cp', "$classes;$DependencyClassPath;$LibsuClassPath",
        'com.maplesu.core.ui.webui.SelectedIoTestsKt')
} finally {
    $stable = @($inputs | ForEach-Object {
        $after = (Get-FileHash -LiteralPath $_.path -Algorithm SHA256).Hash.ToLowerInvariant()
        [ordered]@{ path = $_.path; beforeSha256 = $_.sha256; afterSha256 = $after; unchanged = $_.sha256 -eq $after }
    })
    [ordered]@{ recordedUtc = [DateTime]::UtcNow.ToString('o'); attempts = $attempts; inputs = $stable;
        inputsStable = @($stable | Where-Object { !$_.unchanged }).Count -eq 0;
        scope = 'Current real KsuIO and all six IO sources with original libsu jars; explicit Android Base64/Log/annotation and fail-fast root-shell fixture. Only five new pageCurrent cases run; no existing IO tests, page session tests, native, APK or device actions.' } |
        ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $output 'RESULT.json') -Encoding utf8NoBOM
}
