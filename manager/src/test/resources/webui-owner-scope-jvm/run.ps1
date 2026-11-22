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
$generated = New-Item -ItemType Directory -Path (Join-Path $output 'generated')
$results = [Collections.Generic.List[object]]::new()

function Read-Source([string]$Relative) {
    return [IO.File]::ReadAllText((Join-Path $source $Relative)).Replace("`r`n", "`n")
}
function Slice([string]$Text, [string]$From, [string]$Until) {
    $start = $Text.IndexOf($From, [StringComparison]::Ordinal)
    if ($start -lt 0) { throw "Missing production start: $From" }
    $end = $Text.IndexOf($Until, $start + $From.Length, [StringComparison]::Ordinal)
    if ($end -lt 0) { throw "Missing production end: $Until" }
    return $Text.Substring($start, $end - $start)
}
function Write-Generated([string]$Name, [string]$Text) {
    $Text | Set-Content -LiteralPath (Join-Path $generated.FullName $Name) -Encoding utf8NoBOM
}
function Invoke-JavaArgs([string]$Name, [string[]]$Arguments) {
    $argsPath = Join-Path $output "$Name.args"
    $Arguments | ForEach-Object { '"' + $_.Replace('\', '\\').Replace('"', '\"') + '"' } |
        Set-Content -LiteralPath $argsPath -Encoding utf8NoBOM
    & $Java "@$argsPath" *> (Join-Path $output "$Name.log")
    $code = $LASTEXITCODE
    $results.Add([ordered]@{name=$Name;exitCode=$code;args=$argsPath})
    if ($code -ne 0) { Get-Content -LiteralPath (Join-Path $output "$Name.log"); throw "$Name exited $code" }
}

$probePath = 'dev/maplesu/manager/runtime/ultra/UltraEnvironmentProbe.kt'
$launcherPath = 'dev/maplesu/manager/modules/ModuleWebUiLauncher.kt'
$activityPath = 'com/maplesu/core/ui/webui/ModuleWebUIActivity.kt'
$probe = Read-Source $probePath
$snapshot = Slice $probe '    /** The five states' '    private const val TAG'
$publish = Slice $probe '    internal fun publishSnapshot(' '    private fun publish('
$capture = Slice $probe '    internal fun webUiOwnerScope(' '    /** A proof belongs'
Write-Generated 'Probe.kt' @"
package dev.maplesu.manager.runtime.ultra
import android.content.Context
import dev.maplesu.manager.workmode.*
import dev.maplesu.manager.modules.webui.ModuleWebUiSessions
import kotlinx.coroutines.flow.MutableStateFlow
object UltraRuntimeClient {
    data class ManagerOwnerIdentity(val fullUid: Int, val epoch: Long, val hostInstance: String)
}
object UltraEnvironmentProbe {
$snapshot
    private val lock = Any()
    private val snapshots = MutableStateFlow(Snapshot())
    // Credential/boot scoping is a boundary fixture; the live capture/producer are above it.
    internal fun currentSnapshot(context: Context): Snapshot = snapshots.value.let {
        if (it.modeActivation === ModeRuntime.activation) it else Snapshot()
    }
$capture
$publish
}
"@

$launcher = Read-Source $launcherPath
$launch = Slice $launcher '    private suspend fun launch(' '    // ------------------------------------------------------- P0'
$helpers = Slice $launcher '    internal fun safeUrl(' "`n}"
Write-Generated 'Launcher.kt' @"
package dev.maplesu.manager.modules
import android.content.Context
import android.content.Intent
import android.util.Log
import com.maplesu.core.ui.webui.ModuleWebUIActivity
import dev.maplesu.manager.modules.webui.*
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
internal object ModuleWebUiLauncher {
    const val TAG = "MapleSUWebUi"
    private const val MODULE_INFO_SEED_MAX_CHARS = 8 * 1024
    suspend fun launchCaptured(app: Context, id: String, revision: Long,
                              owner: ModuleWebUiSessions.OwnerScope?) =
        launch(app, "http://127.0.0.1:19001/", id, id, WebUiRoute.ULTRA_SDK,
            sessionRevision = revision, ownerScope = owner)
$launch
$helpers
}
"@
$activity = Read-Source $activityPath
$constants = ([regex]::Matches($activity, '(?m)^\s*(?:internal )?const val EXTRA_[^\n]+') |
    ForEach-Object { $_.Value.Trim() }) -join "`n"
$binding = Slice $activity '        val revision = if (intent.hasExtra(EXTRA_SESSION_REVISION))' '        val origin = requireNotNull'
Write-Generated 'Activity.kt' @"
package com.maplesu.core.ui.webui
import android.app.Activity
import android.content.Intent
class ModuleWebUIActivity : Activity() {
    var intent = Intent()
    val pageState = WebUIState()
    companion object {
$constants
    }
    fun bindRequest(moduleId: String) {
$binding
    }
}
"@

$production = @('com/maplesu/core/ui/webui/WebUIState.kt', 'com/maplesu/core/ui/webui/WebViewInterface.kt',
    'com/maplesu/core/ui/webui/WebUIResourceCleanup.kt', 'com/maplesu/core/ui/webui/NormalWebUiCompatibility.kt',
    'dev/maplesu/manager/modules/webui/ModuleWebUiSessions.kt', 'dev/maplesu/manager/modules/webui/ModuleWebUiPlan.kt') |
    ForEach-Object { Join-Path $source $_ }
$sharedFixtures = Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot '../webui-session-jvm/fixtures') -File -Filter '*.kt' |
    Where-Object { $_.Name -notin @('mode.kt','intent.kt','activity.kt','android_util.kt') } |
    Select-Object -ExpandProperty FullName
$local = Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'fixtures') -File -Filter '*.kt' | Select-Object -ExpandProperty FullName
$sources = @($production) + @($sharedFixtures) + @($local) +
    @(Get-ChildItem -LiteralPath $generated.FullName -File -Filter '*.kt' | Select-Object -ExpandProperty FullName) +
    @((Join-Path $PSScriptRoot 'WebUiOwnerScopeJvmTest.kt'))
$inputs = @($sources + @($probePath,$launcherPath,$activityPath | ForEach-Object { Join-Path $source $_ }) + @($PSCommandPath) |
    Sort-Object -Unique | ForEach-Object {
        $file = Get-Item -LiteralPath $_
        [ordered]@{path=$file.FullName;bytes=$file.Length;sha256=(Get-FileHash -LiteralPath $_ -Algorithm SHA256).Hash.ToLowerInvariant()}
    })
$inputs | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $output 'INPUTS.json') -Encoding utf8NoBOM
try {
    $classes = Join-Path $output 'classes'
    Invoke-JavaArgs 'compile' (@('-Xmx640m','-cp',$CompilerClassPath,'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler',
        '-no-stdlib','-no-reflect','-nowarn','-jvm-target','21','-classpath',$DependencyClassPath,'-d',$classes) + $sources)
    Invoke-JavaArgs 'run' @('-cp',"$classes;$DependencyClassPath",'org.junit.runner.JUnitCore',
        'com.maplesu.core.ui.webui.WebUiOwnerScopeJvmTest')
} finally {
    [ordered]@{recordedUtc=[DateTime]::UtcNow.ToString('o');inputs=(Join-Path $output 'INPUTS.json');attempts=$results;
        scope='JVM; actual registry/page/bridge plus live-sliced producer/capture/Intent methods. Android, credential/boot scope, libsu and IO stand-ins. Only already observed owner tuples; no IPC push, native probe, root, kernel, Gradle, APK or device acceptance.'} |
        ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $output 'RESULT.json') -Encoding utf8NoBOM
}
