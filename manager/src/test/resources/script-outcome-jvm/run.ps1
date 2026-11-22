param(
    [Parameter(Mandatory)][string]$Java,
    [Parameter(Mandatory)][string]$CompilerClassPath,
    [Parameter(Mandatory)][string]$DependencyClassPath,
    [Parameter(Mandatory)][string]$OutputDirectory,
    [string]$ProductionSourceRoot = (Join-Path $PSScriptRoot '../../../main/java')
)
$ErrorActionPreference = 'Stop'
$source = (Resolve-Path -LiteralPath $ProductionSourceRoot).Path
$output = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $output) { throw "Use a fresh output directory: $output" }
New-Item -ItemType Directory -Path $output | Out-Null
$results = [Collections.Generic.List[object]]::new()
$generated = [Collections.Generic.List[string]]::new()
$inputPaths = @(
    (Join-Path $source 'com/maplesu/core/ui/util/KsuCli.kt'),
    (Join-Path $source 'dev/maplesu/manager/modules/LiteScriptModuleBackend.kt'),
    (Join-Path $source 'dev/maplesu/manager/runtime/ultra/UltraReceipt.kt'),
    (Join-Path $PSScriptRoot 'ScriptOutcomeJvmTest.kt'),
    $PSCommandPath
)
$inputs = @($inputPaths | ForEach-Object {
    [ordered]@{ path = $_; sha256 = (Get-FileHash -LiteralPath $_ -Algorithm SHA256).Hash.ToLowerInvariant() }
})

function Region([string]$Text, [string]$Start, [string]$End) {
    $from = $Text.IndexOf($Start, [StringComparison]::Ordinal)
    if ($from -lt 0 -or $Text.IndexOf($Start, $from + 1, [StringComparison]::Ordinal) -ge 0) { throw "Expected one source marker: $Start" }
    $to = $Text.IndexOf($End, $from, [StringComparison]::Ordinal)
    if ($to -lt 0) { throw "Missing end marker: $End" }
    return $Text.Substring($from, $to - $from)
}

function Emit([string]$Name, [string]$Text) {
    $path = Join-Path $output $Name
    [IO.File]::WriteAllText($path, $Text, [Text.UTF8Encoding]::new($false))
    $generated.Add($path)
}

function Invoke-JavaArgs([string]$Name, [string[]]$Arguments) {
    $argsPath = Join-Path $output "$Name.args"
    $Arguments | ForEach-Object { '"' + $_.Replace('\', '\\').Replace('"', '\"') + '"' } |
        Set-Content -LiteralPath $argsPath -Encoding utf8NoBOM
    & $Java "@$argsPath" *> (Join-Path $output "$Name.log")
    $code = $LASTEXITCODE
    $results.Add([ordered]@{ name = $Name; exitCode = $code; args = $argsPath })
    if ($code -ne 0) { Get-Content -LiteralPath (Join-Path $output "$Name.log"); throw "$Name exited $code" }
}

$cli = Get-Content -LiteralPath $inputPaths[0] -Raw
$backend = Get-Content -LiteralPath $inputPaths[1] -Raw
$receipt = Get-Content -LiteralPath $inputPaths[2] -Raw
$flash = Region $cli 'enum class FlashOutcome {' "/**`r`n * ⚠️"
$install = Region $backend '    data class InstallResult(' '    internal data class BootTask('
$outcome = Region $receipt 'enum class UltraOutcome {' '/** Lifecycle phase'
$branch = Region $cli '                val result = dev.maplesu.manager.modules.LiteScriptModuleBackend.get(ksuApp)' '        } catch (exception: Exception) {'
# The branch ends at the enclosing else brace, directly before the catch. Preserve its body verbatim.
$lastBrace = $branch.LastIndexOf('}')
if ($lastBrace -lt 0 -or $branch.Substring($lastBrace + 1).Trim().Length -ne 0) { throw 'Unexpected script branch boundary' }
$branch = $branch.Substring(0, $lastBrace)
Emit 'ActualProjection.kt' @"
package com.maplesu.core.ui.util
import com.topjohnwu.superuser.Shell
import dev.maplesu.manager.installer.InstallCandidateImage
import dev.maplesu.manager.workmode.service.SwitchOutcome
$flash
fun projectScriptInstall(onStdout: (String) -> Unit, onStderr: (String) -> Unit): FlashResult {
    val ksuApp = Any()
    val file = Any()
    val report = Any()
    return run {
$branch
    }
}
"@
Emit 'ActualOutcome.kt' "package dev.maplesu.manager.runtime.ultra`n$outcome"
Emit 'BackendFixture.kt' @"
package dev.maplesu.manager.modules
object LiteScriptModuleBackend {
$install
    var calls = 0
    lateinit var next: InstallResult
    fun get(context: Any) = this
    fun install(file: Any, report: Any, onStdout: (String) -> Unit, onStderr: (String) -> Unit): InstallResult {
        calls++
        onStdout("raw out\nsecond line"); onStdout("")
        onStderr("FIRST_ERROR:75\nraw diagnostic"); onStderr("")
        return next
    }
}
"@
Emit 'ShellFixture.kt' "package com.topjohnwu.superuser`nclass Shell { class Result(val code: Int, val err: List<String>, val isSuccess: Boolean) }"
Emit 'InstallerFixture.kt' "package dev.maplesu.manager.installer`nclass InstallCandidateImage"
Emit 'SwitchFixture.kt' "package dev.maplesu.manager.workmode.service`nclass SwitchOutcome { class ImagesRequired }"
$classes = Join-Path $output 'classes'
try {
    Invoke-JavaArgs 'compile' (@('-Xmx384m', '-cp', $CompilerClassPath, 'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler',
        '-no-stdlib', '-no-reflect', '-nowarn', '-jvm-target', '21', '-classpath', $DependencyClassPath, '-d', $classes) +
        $generated.ToArray() + @($inputPaths[3]))
    Invoke-JavaArgs 'test' @('-cp', "$classes;$DependencyClassPath", 'org.junit.runner.JUnitCore',
        'scriptoutcomefixture.ScriptOutcomeJvmTest')
} finally {
    $stable = @($inputs | Where-Object { (Get-FileHash -LiteralPath $_.path -Algorithm SHA256).Hash.ToLowerInvariant() -ne $_.sha256 }).Count -eq 0
    [ordered]@{ recordedUtc = [DateTime]::UtcNow.ToString('o'); inputs = $inputs; inputsStable = $stable;
        attempts = $results; generated = @($generated | ForEach-Object {
            [ordered]@{ path = $_; sha256 = (Get-FileHash -LiteralPath $_ -Algorithm SHA256).Hash.ToLowerInvariant() }
        }); scope = 'Current script branch and result/enum declarations extracted verbatim; JVM backend callbacks and type fixtures only. No archive installer, batch UI, native host, root, APK or device execution.' } |
        ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $output 'RESULT.json') -Encoding utf8NoBOM
    if (-not $stable) { throw 'Source inputs changed while validating' }
}
