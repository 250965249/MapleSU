#Requires -Version 5.1
<#
.SYNOPSIS
    MapleSU Ultra 模块故障证据：主机侧只读采集（P0 §4.3）。

.DESCRIPTION
    只读 / READ-ONLY：本脚本不修改设备状态、不重启模块、不制造故障。
    It does not modify device state, does not restart any module, and does not
    reproduce the fault.

    它只做四件事：
      1. 通过 adb 读取设备上已经存在的东西（`adb devices -l`、`getprop` 白名单、
         `uname -r`、`getenforce`、`dumpsys activity exit-info`、`logcat -d`、
         `ls -la /sys/fs/pstore`、`ls` 模块目录、模块阶段日志的尾部）；
      2. 把管理器自己写的 §4.3 证据文件整份拉下来
         （`adb exec-out run-as dev.maplesu.manager cat files/ultra-module-evidence.jsonl`），
         落盘后算 SHA-256 并写进 manifest 的 `moduleEvidence` 段；
      3. 把每条命令的原文、开始/结束 UTC、退出码、输出文件名、输出 SHA-256、boot ID
         写进 OutDir\manifest.json；
      4. 在**落盘之前**做脱敏（序列号、`/data/...` 私有路径、32 位以上十六进制、
         48 字符以上凭据），所以原始设备输出不会以未脱敏形式留在磁盘上。唯一的例外是
         第 2 步那个 JSONL：它在设备侧已经过 UltraModuleEvidenceSanitizer，主机侧不再二次脱敏
         （二次脱敏会把 buildDigest 与 detail 里的机器码抹掉，见 Save-ModuleEvidenceJsonl）。

    全部命令都是读操作：不含 `adb root`、`pm`、`am`、`reboot`、`push`、`install`、
    `uninstall`、`su`、`setprop` 或任何写文件的动作。给本脚本加命令时也必须保持只读。

.PARAMETER OutDir
    采集输出目录。不存在则创建；已存在则覆盖同名文件（用 manifest.startedUtc 区分批次）。

.PARAMETER Serial
    设备序列号。省略时：只有一台 `device` 状态的设备才自动选；0 台或多台都优雅失败
    （不猜设备），并在 manifest.json 里写清原因。

.EXAMPLE
    pwsh -NoProfile -File tools/collect-ultra-module-evidence.ps1 -OutDir .\evidence\20261031

.EXAMPLE
    pwsh -NoProfile -File tools/collect-ultra-module-evidence.ps1 -OutDir ./ev -Serial <serial>

.NOTES
    退出码：0 = 采集完成；2 = 没有可用设备 / adb 不存在 / 设备不唯一（manifest 已写）；
    1 = 脚本自身失败（manifest 已写，reason 里有原因）。

    与 Kotlin 侧的关系：本脚本只保全原始文本，不做退出原因分类。
    FORCE STOP 与原生异常的分别统计由 `UltraModuleExitClassifier` 完成——冻结证据
    `app-exit-info.txt` 里的 `reason=10 (USER REQUESTED) subreason=21 (FORCE STOP)
    description=stop dev.maplesu.manager due to set debug app state` 属于外部终止，
    不是崩溃；这里不能把整段 exit-info 当成"崩溃记录"。
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string] $OutDir,

    [Parameter(Mandatory = $false)]
    [string] $Serial
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:ToolName = 'collect-ultra-module-evidence.ps1'
$script:SchemaVersion = 1
$script:ManagerPackage = 'dev.maplesu.manager'
$script:ReadOnlyStatement = 'READ-ONLY: this script does not modify device state, does not restart any module, and does not reproduce the fault. 只读：不修改设备状态、不重启模块、不制造故障。'
$script:Utf8 = New-Object System.Text.UTF8Encoding($false)

$script:Commands = New-Object System.Collections.ArrayList
$script:Notes = New-Object System.Collections.ArrayList
$script:ModuleLogs = New-Object System.Collections.ArrayList
$script:PublicIdentifiers = New-Object System.Collections.ArrayList
$script:StepCounter = 0
$script:StartedUtc = ''
$script:OutputPath = ''
$script:AdbExecutable = ''
$script:Serial = ''
$script:SerialMasked = '<serial>'
$script:DeviceResolved = $false
$script:BootId = ''
$script:ModuleEvidence = [ordered]@{
    remotePath = 'files/ultra-module-evidence.jsonl'
    collected = $false
    status = 'not-attempted'
    reason = 'device-not-ready'
    outputFile = $null
    outputSha256 = $null
    outputBytes = $null
    lines = $null
    invalidLines = $null
    bootId = ''
    collectedAtUtc = ''
    hostRedactionApplied = $false
    note = '未采集：脚本在设备就绪之前就结束了（见 status）。这不等于证据文件为空。 ' +
        'not collected; this is not evidence that the file is empty.'
}
$script:Pstore = [ordered]@{
    collected = $false
    entries = $null
    empty = $null
    note = '未采集：设备未就绪，pstore 状态 unknown。不得据此认为 pstore 为空。 pstore was not collected; that is not evidence that it is empty.'
}
$script:DeviceSummary = [ordered]@{
    fingerprint = ''
    kernelRelease = ''
    sdk = ''
    verifiedBootState = ''
    selinux = ''
    selinuxBootProperty = ''
}

# ---------------------------------------------------------------------------- helpers

function Get-UtcIso {
    param([datetime] $Stamp = [datetime]::UtcNow)
    return $Stamp.ToUniversalTime().ToString(
        'yyyy-MM-ddTHH:mm:ss.fffZ',
        [System.Globalization.CultureInfo]::InvariantCulture
    )
}

function Format-SafeFileName {
    param([string] $Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return 'item' }
    $clean = [regex]::Replace($Value, '[^A-Za-z0-9._-]', '_')
    if ($clean.Length -eq 0) { return 'item' }
    if ($clean.Length -gt 40) { return $clean.Substring(0, 40) }
    return $clean
}

function Get-MaskedSerial {
    param([string] $Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return '<serial>' }
    $trimmed = $Value.Trim()
    if ($trimmed.Length -le 8) { return '<serial>' }
    return $trimmed.Substring(0, 4) + '...' + $trimmed.Substring($trimmed.Length - 4)
}

<#
    结构保持的私有路径脱敏。规则与 Kotlin 侧
    `UltraModuleEvidenceSanitizer.redactPath` 对齐（PS 侧只用于 manifest 的 command 记录）：
      - 保留 `/data`、已知公共环境段、`modules`、模块 id（32 位十六进制）或 <=47 位安全名字；
      - 替换：未知环境段 -> `<env>`，包名 -> `<package>`，用户号 -> `<user>`，
        其余实例段 -> `<data-item>`/`<seg>`。
    非 /data 路径原样返回。
#>
function Get-RedactedPath {
    param([string] $Path)

    if ([string]::IsNullOrEmpty($Path)) { return '' }
    $trimmed = $Path.Trim()
    if ($trimmed.Length -eq 0) { return '' }
    $absolute = $trimmed
    if (-not $absolute.StartsWith('/')) { $absolute = '/' + $absolute }

    $segments = @($absolute.Split('/') | Where-Object { $_.Length -gt 0 })
    if ($segments.Count -eq 0) { return $Path }
    if ($segments[0] -ne 'data') { return $Path }
    if ($segments.Count -eq 1) { return '/data' }

    $publicEnvironment = @('adb', 'data', 'user', 'media', 'local', 'misc', 'system', 'vendor', 'app', 'dalvik-cache')
    $environment = $segments[1]
    $environmentIsPublic = $publicEnvironment -contains $environment

    $parts = New-Object System.Collections.Generic.List[string]
    [void]$parts.Add('data')
    if ($environmentIsPublic) { [void]$parts.Add($environment) } else { [void]$parts.Add('<env>') }

    $modulesIndex = -1
    foreach ($index in @(2, 3)) {
        if ($index -lt $segments.Count -and $segments[$index] -eq 'modules') {
            $modulesIndex = $index
            break
        }
    }

    if ($modulesIndex -ge 0) {
        for ($index = 2; $index -lt $modulesIndex; $index++) { [void]$parts.Add('<seg>') }
        [void]$parts.Add('modules')
        $moduleIndex = $modulesIndex + 1
        if ($moduleIndex -lt $segments.Count) {
            $moduleSegment = $segments[$moduleIndex]
            $isModuleId = $moduleSegment -match '^[0-9a-fA-F]{32}$'
            $isPublicName = ($moduleSegment -match '^[A-Za-z0-9._-]{1,47}$') -and
                ($moduleSegment -notmatch '[0-9a-fA-F]{32,}')
            if ($isModuleId -or $isPublicName) {
                [void]$parts.Add($moduleSegment)
            } else {
                [void]$parts.Add('<module>')
            }
            for ($index = $moduleIndex + 1; $index -lt $segments.Count; $index++) { [void]$parts.Add('<seg>') }
        }
        return '/' + ($parts -join '/')
    }

    switch ($environment) {
        'data' {
            if ($segments.Count -gt 2) { [void]$parts.Add('<package>') }
            for ($index = 3; $index -lt $segments.Count; $index++) { [void]$parts.Add('<seg>') }
        }
        'user' {
            if ($segments.Count -gt 2) { [void]$parts.Add('<user>') }
            if ($segments.Count -gt 3) { [void]$parts.Add('<package>') }
            for ($index = 4; $index -lt $segments.Count; $index++) { [void]$parts.Add('<seg>') }
        }
        'media' {
            if ($segments.Count -gt 2) { [void]$parts.Add('<user>') }
            for ($index = 3; $index -lt $segments.Count; $index++) { [void]$parts.Add('<seg>') }
        }
        default {
            if (-not $environmentIsPublic) {
                for ($index = 2; $index -lt $segments.Count; $index++) { [void]$parts.Add('<seg>') }
            } else {
                if ($segments.Count -gt 2) { [void]$parts.Add('<data-item>') }
                for ($index = 3; $index -lt $segments.Count; $index++) { [void]$parts.Add('<seg>') }
            }
        }
    }
    return '/' + ($parts -join '/')
}

<#
    落盘前的文本脱敏。顺序有讲究：
      1. 序列号；
      2. 先给"设备模块目录里发现的模块名"打哨兵（它们是公开身份，冻结证据里也原样保留）；
      3. `/data/...` 私有路径在正文里统一折叠成 `/data/<redacted-path>`
         （结构信息保留在 manifest 的 command 记录里，正文只需要不泄露）；
      4. 32 位以上十六进制 -> `<hex>`；48 字符以上凭据 -> `<token>`；
      5. 还原模块名。
#>
function Get-RedactedText {
    param([string] $Text)

    if ([string]::IsNullOrEmpty($Text)) { return '' }
    $result = $Text
    if ($script:Serial.Length -ge 4) {
        $result = $result.Replace($script:Serial, $script:SerialMasked)
    }

    $restore = @{}
    $sentinel = 0
    foreach ($identifier in $script:PublicIdentifiers) {
        if ([string]::IsNullOrEmpty($identifier) -or $identifier.Length -lt 8) { continue }
        if (-not $result.Contains($identifier)) { continue }
        $placeholder = '__PUBLIC_ID_' + $sentinel + '__'
        $restore[$placeholder] = $identifier
        $result = $result.Replace($identifier, $placeholder)
        $sentinel++
    }

    $result = [regex]::Replace($result, '/data/[A-Za-z0-9._/<>-]+', '/data/<redacted-path>')
    $result = [regex]::Replace($result, '(?<![0-9A-Za-z])[0-9a-fA-F]{32,}(?![0-9A-Za-z])', '<hex>')
    $result = [regex]::Replace($result, '(?<![0-9A-Za-z])[A-Za-z0-9+/_-]{48,}={0,2}(?![0-9A-Za-z+/=_-])', '<token>')

    foreach ($placeholder in $restore.Keys) {
        $result = $result.Replace($placeholder, $restore[$placeholder])
    }
    return $result
}

function Invoke-Process {
    param(
        [string] $Executable,
        [string[]] $Arguments = @()
    )
    $text = ''
    $exitCode = 127
    try {
        $lines = & $Executable @Arguments 2>&1
        $text = (@($lines | ForEach-Object { [string]$_ })) -join "`n"
        if ($null -ne $LASTEXITCODE) { $exitCode = [int]$LASTEXITCODE } else { $exitCode = 0 }
    } catch {
        $text = 'exec failed: ' + $_.Exception.Message
        $exitCode = 127
    }
    return [pscustomobject]@{ Text = $text; ExitCode = $exitCode }
}

function Format-RecordedCommand {
    param([string] $ShellCommand)
    if ($script:SerialMasked -eq '<serial>' -or [string]::IsNullOrEmpty($script:SerialMasked)) {
        return 'adb shell ' + $ShellCommand
    }
    return 'adb -s ' + $script:SerialMasked + ' shell ' + $ShellCommand
}

<#
    写一个采集件 + 一条 manifest 记录。**先脱敏再落盘**：磁盘上不存在未脱敏原文，
    所以 outputSha256 是对脱敏后文件的摘要（交付件可复算）。
#>
function Save-Capture {
    param(
        [string] $Step,
        [string] $RecordedCommand,
        [string] $FileStem,
        [string] $RawText,
        [int] $ExitCode,
        [string] $StartedUtc,
        [long] $DurationMs
    )

    $script:StepCounter++
    $fileName = ('{0:D2}-{1}.txt' -f $script:StepCounter, (Format-SafeFileName -Value $FileStem))
    $path = Join-Path $script:OutputPath $fileName
    $header = '# read-only capture (no device writes) | step=' + $Step +
        ' | command=' + $RecordedCommand + ' | exit=' + $ExitCode + "`n"
    $redacted = Get-RedactedText -Text $RawText
    [System.IO.File]::WriteAllText($path, $header + $redacted, $script:Utf8)

    $sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    $bytes = (Get-Item -LiteralPath $path).Length
    $record = [ordered]@{
        step = $Step
        command = $RecordedCommand
        startedUtc = $StartedUtc
        finishedUtc = (Get-UtcIso)
        durationMs = [int]$DurationMs
        exitCode = $ExitCode
        ok = ($ExitCode -eq 0)
        bootId = $script:BootId
        serialMasked = $script:SerialMasked
        outputFile = $fileName
        outputSha256 = $sha256
        outputBytes = $bytes
    }
    [void]$script:Commands.Add($record)
    return $record
}

<#
    §4.3：把管理器自己写的证据文件（`filesDir/ultra-module-evidence.jsonl`）整份拉下来。

    与其它采集件有**两点刻意的不同**，不写清就会被读成"漏了脱敏"或"抓漏了"：

      1. **字节原样落盘**：用 .NET 的 StandardOutput.BaseStream 直接复制，不走 PowerShell 的
         行管道（Windows PowerShell 5.1 的 `>` 重定向会写成 UTF-16，`$(...)` 会把换行改成 CRLF），
         所以落盘字节与设备上的文件逐字节相同，manifest 里的 SHA-256 才有意义。
      2. **主机侧不再二次脱敏**：这些行在设备上已经过 `UltraModuleEvidenceSanitizer`（只有机器码：
         operationId / bootId / 阶段 / 返回码 / 构建摘要 / `gate=... state=...` 之类）。再套一层
         主机脱敏会把 `buildDigest`（64 位十六进制 -> `<hex>`）和 detail 里的原因码抹掉，
         等于把 §4.3 要交付的字段删掉。文件里没有自由文本、没有私有路径、没有 root key。

    失败语义（优雅失败，不打断整轮采集）：
      * `run-as` 不可用 / 包不可调试 / adb 报错  -> `status=failed` + 原因码 + 脱敏后的 stderr 摘要，
        不写空文件冒充"采集到空证据"；部分产物会被删除；
      * 文件存在但 0 字节                      -> `status=empty`（这是事实：还没有写过任何事件）；
      * 有内容                                 -> `status=collected` + SHA-256 + 字节数 + 行数 +
        无法解析为 JSON 的行数（`invalidLines`，用于发现格式漂移）。
#>
function Save-ModuleEvidenceJsonl {
    $script:StepCounter++
    $fileName = ('{0:D2}-{1}.jsonl' -f $script:StepCounter, 'ultra-module-evidence')
    $path = Join-Path $script:OutputPath $fileName
    $remote = $script:ModuleEvidence.remotePath
    $recordedCommand = 'adb -s ' + $script:SerialMasked + ' exec-out run-as ' +
        $script:ManagerPackage + ' cat ' + $remote
    $startedUtc = Get-UtcIso
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

    $exitCode = 127
    $stderrText = ''
    try {
        $startInfo = New-Object System.Diagnostics.ProcessStartInfo
        $startInfo.FileName = $script:AdbExecutable
        $startInfo.Arguments = '-s "' + $script:Serial + '" exec-out run-as ' +
            $script:ManagerPackage + ' cat ' + $remote
        $startInfo.UseShellExecute = $false
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true
        $startInfo.CreateNoWindow = $true
        $process = [System.Diagnostics.Process]::Start($startInfo)
        $fileStream = [System.IO.File]::Create($path)
        try {
            # 原始字节复制：不经过任何文本行处理。
            $process.StandardOutput.BaseStream.CopyTo($fileStream)
        } finally {
            $fileStream.Dispose()
        }
        # stderr 只有一行级别的诊断（run-as 拒绝、文件不存在），读取顺序不会造成管道阻塞。
        $stderrText = $process.StandardError.ReadToEnd()
        $process.WaitForExit()
        $exitCode = $process.ExitCode
        $process.Dispose()
    } catch {
        $stderrText = 'exec failed: ' + $_.Exception.Message
        $exitCode = 127
    }
    $stopwatch.Stop()

    $exists = [System.IO.File]::Exists($path)
    $bytes = 0
    if ($exists) { $bytes = (New-Object System.IO.FileInfo($path)).Length }

    # ---- 失败：删掉可能写了一半的文件，按具名原因记录
    if ($exitCode -ne 0) {
        if ($exists) {
            try { [System.IO.File]::Delete($path) } catch { }
        }
        $reason = 'run-as-failed'
        if ($stderrText -match 'not debuggable') { $reason = 'package-not-debuggable' }
        elseif ($stderrText -match 'No such file|not found') { $reason = 'file-missing' }
        elseif ($exitCode -eq 127) { $reason = 'adb-exec-failed' }
        $script:ModuleEvidence.collected = $false
        $script:ModuleEvidence.status = 'failed'
        $script:ModuleEvidence.reason = $reason
        $script:ModuleEvidence.outputFile = $null
        $script:ModuleEvidence.outputSha256 = $null
        $script:ModuleEvidence.outputBytes = $null
        $script:ModuleEvidence.lines = $null
        $script:ModuleEvidence.invalidLines = $null
        $script:ModuleEvidence.bootId = $script:BootId
        $script:ModuleEvidence.collectedAtUtc = (Get-UtcIso)
        $script:ModuleEvidence.note = '没拿到 §4.3 证据文件（原因：' + $reason +
            '，exit=' + $exitCode + '）：这不等于没有事件，也不等于文件为空。 ' +
            'not collected; this is not evidence that the file is empty.'
        [void]$script:Notes.Add('§4.3 证据文件未采集：' + $reason + '（exit=' + $exitCode + '）；' +
            '脱敏后的 stderr 摘要：' + (Get-RedactedText -Text $stderrText.Trim()))
        [void]$script:Commands.Add([ordered]@{
            step = ('module-evidence-jsonl')
            command = $recordedCommand
            startedUtc = $startedUtc
            finishedUtc = (Get-UtcIso)
            durationMs = [int]$stopwatch.ElapsedMilliseconds
            exitCode = $exitCode
            ok = $false
            bootId = $script:BootId
            serialMasked = $script:SerialMasked
            outputFile = $null
            outputSha256 = $null
            outputBytes = $null
            note = 'failed: ' + $reason
        })
        return
    }

    # ---- 成功：算摘要 + 行数 + 非法行数
    $sha256 = $null
    $lines = 0
    $invalidLines = 0
    if ($bytes -gt 0) {
        $sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($bytes -le 8388608) {
            $content = [System.IO.File]::ReadAllText($path, (New-Object System.Text.UTF8Encoding($false)))
            foreach ($line in ($content -split "`n")) {
                $trimmed = $line.Trim()
                if ($trimmed.Length -eq 0) { continue }
                $lines++
                try { $null = $trimmed | ConvertFrom-Json } catch { $invalidLines++ }
            }
        } else {
            [void]$script:Notes.Add('§4.3 证据文件超过 8 MiB，只算摘要，不逐行校验。')
        }
    }

    $script:ModuleEvidence.collected = $true
    $script:ModuleEvidence.status = 'collected'
    if ($bytes -eq 0) { $script:ModuleEvidence.status = 'empty' }
    $script:ModuleEvidence.reason = ''
    $script:ModuleEvidence.outputFile = $fileName
    $script:ModuleEvidence.outputSha256 = $sha256
    $script:ModuleEvidence.outputBytes = $bytes
    $script:ModuleEvidence.lines = $lines
    $script:ModuleEvidence.invalidLines = $invalidLines
    $script:ModuleEvidence.bootId = $script:BootId
    $script:ModuleEvidence.collectedAtUtc = (Get-UtcIso)
    if ($bytes -eq 0) {
        $script:ModuleEvidence.note = '设备上的证据文件存在但为 0 字节：这一点是事实（还没有写过任何事件），' +
            '不等于没有发生过模块操作。 the file exists and is empty.'
    } else {
        $script:ModuleEvidence.note = '字节原样落盘（未做主机侧二次脱敏，见函数注释）；' +
            '输出摘要可复算。 invalidLines>0 说明格式漂移，必须查。'
    }

    [void]$script:Commands.Add([ordered]@{
        step = ('module-evidence-jsonl')
        command = $recordedCommand
        startedUtc = $startedUtc
        finishedUtc = (Get-UtcIso)
        durationMs = [int]$stopwatch.ElapsedMilliseconds
        exitCode = $exitCode
        ok = $true
        bootId = $script:BootId
        serialMasked = $script:SerialMasked
        outputFile = $fileName
        outputSha256 = $sha256
        outputBytes = $bytes
        note = $script:ModuleEvidence.status
    })
}

<# 执行一条 adb 命令并记录：device / shell 共用。 #>
function Invoke-Recorded {
    param(
        [string] $Step,
        [string] $RecordedCommand,
        [string[]] $Arguments,
        [string] $FileStem
    )
    $started = Get-UtcIso
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $result = Invoke-Process -Executable $script:AdbExecutable -Arguments $Arguments
    $stopwatch.Stop()
    return Save-Capture -Step $Step -RecordedCommand $RecordedCommand -FileStem $FileStem `
        -RawText $result.Text -ExitCode $result.ExitCode -StartedUtc $started `
        -DurationMs $stopwatch.ElapsedMilliseconds
}

<#
    一条 `adb shell` 命令：记录到 manifest（命令原文按路径规则脱敏），同时把**未脱敏的原始
    文本**返回给调用方用于解析（例如 getprop 的值、pstore 条数）。解析结果要进 manifest 的值
    都是设备身份字段，不含私有路径；日志正文只走写盘路径。
#>
function Invoke-ShellCapture {
    param(
        [string] $Step,
        [string] $ShellCommand,
        [string] $FileStem
    )
    $started = Get-UtcIso
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $result = Invoke-Process -Executable $script:AdbExecutable `
        -Arguments @('-s', $script:Serial, 'shell', $ShellCommand)
    $stopwatch.Stop()
    $record = Save-Capture -Step $Step `
        -RecordedCommand (Format-RecordedCommand -ShellCommand $ShellCommand) `
        -FileStem $FileStem -RawText $result.Text -ExitCode $result.ExitCode `
        -StartedUtc $started -DurationMs $stopwatch.ElapsedMilliseconds
    return [pscustomobject]@{ Record = $record; Text = $result.Text; ExitCode = $result.ExitCode }
}

function Get-PropValue {
    param([string] $Name)
    $nameValue = Invoke-ShellCapture -Step ('getprop-' + $Name) -ShellCommand ('getprop ' + $Name) `
        -FileStem ('getprop-' + $Name)
    if ($nameValue.ExitCode -ne 0) { return '' }
    return $nameValue.Text.Trim()
}

function Get-PstoreSummary {
    param([string] $Text, [int] $ExitCode)

    if ($ExitCode -ne 0) {
        return [ordered]@{
            collected = $false
            entries = $null
            empty = $null
            note = '读取 /sys/fs/pstore 失败（exit=' + $ExitCode +
                '）：pstore 状态 unknown，不能写成空。 pstore could not be read; the state is unknown, not empty.'
        }
    }

    $entries = 0
    if (-not [string]::IsNullOrEmpty($Text)) {
        foreach ($line in ($Text -split "`n")) {
            $trimmed = $line.Trim()
            if ($trimmed -match '^[-dlcbps][rwxStTs-]{9}') {
                $fields = @($trimmed -split '\s+')
                $name = $fields[$fields.Length - 1]
                if ($name -ne '.' -and $name -ne '..') { $entries++ }
            }
        }
    }
    $empty = ($entries -eq 0)
    $note = if ($empty) {
        '已确认 /sys/fs/pstore 为空（0 条记录）。空 pstore 不能证明没有崩溃：SDK 默认会清理 tombstone，' +
        '旧日志缺失不算无故障（开发方案 §4.3）。' +
        ' pstore is empty; an empty pstore does not prove there was no crash.'
    } else {
        'pstore 中存在 ' + $entries + ' 条记录；请先原样保存再分析，本脚本不会改动设备。' +
        ' pstore is NOT empty; preserve these dumps before any analysis.'
    }
    return [ordered]@{ collected = $true; entries = $entries; empty = $empty; note = $note }
}

function Write-Manifest {
    param(
        [string] $Status,
        [string] $Reason
    )

    $manifestPath = Join-Path $script:OutputPath 'manifest.json'
    $requestedMasked = ''
    if (-not [string]::IsNullOrWhiteSpace($Serial)) { $requestedMasked = Get-MaskedSerial -Value $Serial }
    $adbResolved = (-not [string]::IsNullOrEmpty($script:AdbExecutable))

    $manifest = [ordered]@{
        tool = $script:ToolName
        schemaVersion = $script:SchemaVersion
        readOnly = $true
        readOnlyStatement = $script:ReadOnlyStatement
        startedUtc = $script:StartedUtc
        finishedUtc = (Get-UtcIso)
        status = $Status
        reason = $Reason
        host = [ordered]@{
            powershellVersion = $PSVersionTable.PSVersion.ToString()
            os = [System.Environment]::OSVersion.VersionString
        }
        device = [ordered]@{
            serialMasked = $script:SerialMasked
            requestedSerialMasked = $requestedMasked
            resolved = $script:DeviceResolved
            bootId = $script:BootId
            adbResolved = $adbResolved
        }
        deviceSummary = $script:DeviceSummary
        pstore = $script:Pstore
        moduleEvidence = $script:ModuleEvidence
        exitInfo = [ordered]@{
            package = $script:ManagerPackage
            classification = 'not_classified_by_this_script'
            note = '本脚本只原样保全 dumpsys activity exit-info 文本；管理器 FORCE STOP 与原生异常的分别统计' +
                '由 UltraModuleExitClassifier 完成（reason=10 + subreason=21 + "set debug app state" 属外部终止，不是崩溃）。' +
                ' FORCE STOP and native crashes must be counted separately by UltraModuleExitClassifier.'
        }
        moduleLogs = [ordered]@{
            discovered = @($script:ModuleLogs)
            note = '只读：仅当模块阶段日志在设备上存在时才读取尾部；路径已脱敏（结构见命令记录）。' +
                ' 模块目录可能是 Ultra 宿主自定义路径（冻结证据显示 /data/<env>/modules/...），' +
                '本脚本按 §4.3 只列 /data/adb/modules，其它路径为 unknown。'
        }
        redaction = [ordered]@{
            serial = '前 4 位 + "..." + 后 4 位；长度 <= 8 时为 <serial>'
            privatePathsInCapturedText = '/data/... => /data/<redacted-path>'
            privatePathsInCommandRecords = '结构保持：/data/<env>/modules/<module>/<seg>、<package>、<user>、<data-item>、<seg>'
            hexRuns32Plus = '<hex>'
            tokenRuns48Plus = '<token>'
            preservedPublicModuleIdentifiers = @($script:PublicIdentifiers)
            rawOutputStored = $false
            moduleEvidenceNotReRedacted = $true
            note = '脱敏发生在写盘之前；磁盘上没有未脱敏原文，manifest 的 outputSha256 是对脱敏后文件的摘要。' +
                ' 公开身份（模块目录 id/名字）在正文中保留；自由文本里的 32 位以上十六进制一律替换为 <hex>。' +
                ' 唯一例外是 §4.3 证据文件（files/ultra-module-evidence.jsonl）：它在设备侧已由 ' +
                'UltraModuleEvidenceSanitizer 脱敏，主机侧按原字节落盘（再脱敏会把 buildDigest 与机器码抹掉），' +
                ' 摘要因此是对设备侧已脱敏文件的可复算摘要。'
        }
        commands = @($script:Commands)
        notes = @($script:Notes)
    }
    $json = $manifest | ConvertTo-Json -Depth 8
    [System.IO.File]::WriteAllText($manifestPath, $json, $script:Utf8)
    return $manifestPath
}

# ---------------------------------------------------------------------------- main

try {
    $script:StartedUtc = Get-UtcIso

    $outDirectory = $OutDir
    if (-not [System.IO.Path]::IsPathRooted($outDirectory)) {
        $outDirectory = Join-Path (Get-Location).ProviderPath $outDirectory
    }
    if (-not [System.IO.Directory]::Exists($outDirectory)) {
        [void][System.IO.Directory]::CreateDirectory($outDirectory)
    }
    $script:OutputPath = [System.IO.Path]::GetFullPath($outDirectory)
    [void]$script:Notes.Add('输出目录：' + $script:OutputPath)

    # ---- adb
    $adbCommand = Get-Command -Name 'adb' -CommandType Application -ErrorAction SilentlyContinue
    if ($null -eq $adbCommand) {
        [void]$script:Notes.Add('adb 不在 PATH 上：未连接设备，采集未开始。adb was not found on PATH.')
        [void](Write-Manifest -Status 'no-adb' -Reason 'adb executable not found on PATH; nothing was collected from any device')
        Write-Warning ('adb not found on PATH. Manifest written: ' + (Join-Path $script:OutputPath 'manifest.json'))
        exit 2
    }
    $script:AdbExecutable = $adbCommand.Source

    # ---- devices（先拿原始输出，解析出序列号后才能脱敏）
    $devicesStarted = Get-UtcIso
    $devicesWatch = [System.Diagnostics.Stopwatch]::StartNew()
    $devicesResult = Invoke-Process -Executable $script:AdbExecutable -Arguments @('devices', '-l')
    $devicesWatch.Stop()

    $readySerials = New-Object System.Collections.ArrayList
    $otherStates = New-Object System.Collections.ArrayList
    foreach ($line in ($devicesResult.Text -split "`n")) {
        $trimmed = $line.Trim()
        if ($trimmed -match '^(\S+)\s+(device|offline|unauthorized|recovery|sideload|bootloader)\b') {
            $deviceSerial = $matches[1]
            $deviceState = $matches[2]
            if ($deviceState -eq 'device') {
                [void]$readySerials.Add($deviceSerial)
            } else {
                [void]$otherStates.Add($deviceSerial + ':' + $deviceState)
            }
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($Serial)) {
        $script:Serial = $Serial.Trim()
    } elseif ($readySerials.Count -eq 1) {
        $script:Serial = [string]$readySerials[0]
    }
    $script:SerialMasked = Get-MaskedSerial -Value $script:Serial

    [void](Save-Capture -Step 'adb-devices' -RecordedCommand 'adb devices -l' -FileStem 'adb-devices' `
        -RawText $devicesResult.Text -ExitCode $devicesResult.ExitCode -StartedUtc $devicesStarted `
        -DurationMs $devicesWatch.ElapsedMilliseconds)

    if ([string]::IsNullOrEmpty($script:Serial)) {
        $reason = if ($readySerials.Count -eq 0) {
            if ($otherStates.Count -gt 0) {
                'no device in "device" state (seen: ' + ($otherStates -join ', ') + ')'
            } else {
                'no device attached'
            }
        } else {
            'multiple devices reported "device" state; pass -Serial to choose one (no device was touched)'
        }
        $status = 'no-device'
        if ($readySerials.Count -gt 1) { $status = 'ambiguous-device' }
        [void]$script:Notes.Add('未选择设备：' + $reason)
        [void](Write-Manifest -Status $status -Reason $reason)
        Write-Warning ('No usable device: ' + $reason)
        exit 2
    }

    # ---- 指定了 -Serial 但设备不在 device 状态：不继续猜
    if (-not ($readySerials -contains $script:Serial)) {
        $reason = 'requested serial is not attached in "device" state; nothing was collected'
        if ($readySerials.Count -gt 0) {
            $reason = 'requested serial is not in "device" state; other device(s) are attached but were not touched'
        }
        [void]$script:Notes.Add($reason)
        [void](Write-Manifest -Status 'no-device' -Reason $reason)
        Write-Warning ('No usable device: ' + $reason)
        exit 2
    }

    $script:DeviceResolved = $true
    [void]$script:Notes.Add('已选择设备（序列号已脱敏）：' + $script:SerialMasked)

    # ---- boot id（后续每条记录都带它；读不到就写空，不伪造）
    $bootCapture = Invoke-ShellCapture -Step 'boot-id' `
        -ShellCommand 'cat /proc/sys/kernel/random/boot_id' -FileStem 'boot-id'
    if ($bootCapture.ExitCode -eq 0) {
        $bootText = $bootCapture.Text.Trim()
        if ($bootText -match '^[0-9A-Za-z][0-9A-Za-z._-]{0,63}$') {
            $script:BootId = $bootText
        } else {
            [void]$script:Notes.Add('boot_id 读取结果不可用，按空值记录（不伪造）。boot id was unreadable.')
        }
    } else {
        [void]$script:Notes.Add('boot_id 读取失败（exit=' + $bootCapture.ExitCode + '），按空值记录。boot id read failed.')
    }

    # ---- getprop 白名单（§4.3：fingerprint / SDK / verified boot state / SELinux）
    $script:DeviceSummary.fingerprint = Get-PropValue -Name 'ro.build.fingerprint'
    $script:DeviceSummary.sdk = Get-PropValue -Name 'ro.build.version.sdk'
    $script:DeviceSummary.verifiedBootState = Get-PropValue -Name 'ro.boot.verifiedbootstate'
    $script:DeviceSummary.selinuxBootProperty = Get-PropValue -Name 'ro.boot.selinux'

    # ---- 内核 release（内核没有标准 getprop，用 uname -r；白名单要求的一项）
    $kernelCapture = Invoke-ShellCapture -Step 'uname-r' -ShellCommand 'uname -r' -FileStem 'uname-r'
    if ($kernelCapture.ExitCode -eq 0) {
        $script:DeviceSummary.kernelRelease = $kernelCapture.Text.Trim()
    } else {
        [void]$script:Notes.Add('uname -r 失败（exit=' + $kernelCapture.ExitCode + '）；内核 release 为 unknown。')
    }

    # ---- SELinux 运行态
    $selinuxCapture = Invoke-ShellCapture -Step 'getenforce' -ShellCommand 'getenforce' -FileStem 'getenforce'
    if ($selinuxCapture.ExitCode -eq 0) {
        $script:DeviceSummary.selinux = $selinuxCapture.Text.Trim()
    } else {
        [void]$script:Notes.Add('getenforce 失败（exit=' + $selinuxCapture.ExitCode + '）；SELinux 运行态为 unknown。')
    }

    # ---- 管理器退出原因（原样保全；分类在 Kotlin 侧）
    [void](Invoke-ShellCapture -Step 'exit-info' `
        -ShellCommand ('dumpsys activity exit-info ' + $script:ManagerPackage) -FileStem 'exit-info')

    # ---- logcat（main + crash，最近 5000 行；-v threadtime 保留设备时间用于对账）
    [void](Invoke-Recorded -Step 'logcat' `
        -RecordedCommand ('adb -s ' + $script:SerialMasked + ' logcat -d -b main,crash -t 5000 -v threadtime') `
        -Arguments @('-s', $script:Serial, 'logcat', '-d', '-b', 'main,crash', '-t', '5000', '-v', 'threadtime') `
        -FileStem 'logcat-main-crash')

    # ---- pstore（空要明确写空）
    $pstoreCapture = Invoke-ShellCapture -Step 'pstore-list' -ShellCommand 'ls -la /sys/fs/pstore' `
        -FileStem 'pstore-list'
    $script:Pstore = Get-PstoreSummary -Text $pstoreCapture.Text -ExitCode $pstoreCapture.ExitCode

    # ---- §4.3 证据文件：管理器自己写的 JSONL（整份拉取 + 摘要 + 行校验）
    Save-ModuleEvidenceJsonl

    # ---- 模块目录（可读则列；不可读不是失败）
    $modulesStarted = Get-UtcIso
    $modulesWatch = [System.Diagnostics.Stopwatch]::StartNew()
    $modulesResult = Invoke-Process -Executable $script:AdbExecutable `
        -Arguments @('-s', $script:Serial, 'shell', 'ls -1 /data/adb/modules')
    $modulesWatch.Stop()

    $moduleDirectories = New-Object System.Collections.ArrayList
    if ($modulesResult.ExitCode -eq 0) {
        foreach ($line in ($modulesResult.Text -split "`n")) {
            $name = $line.Trim()
            if ($name -match '^[A-Za-z0-9._-]{1,64}$' -and $name -ne '.' -and $name -ne '..') {
                [void]$moduleDirectories.Add($name)
                [void]$script:PublicIdentifiers.Add($name)
            }
        }
    }
    [void](Save-Capture -Step 'modules-dir' `
        -RecordedCommand ('adb -s ' + $script:SerialMasked + ' shell ls -1 /data/adb/modules') `
        -FileStem 'modules-dir' -RawText $modulesResult.Text -ExitCode $modulesResult.ExitCode `
        -StartedUtc $modulesStarted -DurationMs $modulesWatch.ElapsedMilliseconds)
    if ($modulesResult.ExitCode -ne 0) {
        [void]$script:Notes.Add('无法列出 /data/adb/modules（exit=' + $modulesResult.ExitCode +
            '）：可能没有 root 或路径不同；模块阶段日志未采集。')
    }

    # ---- 模块阶段日志：存在才取（按模块目录逐个列，失败即跳过）
    $maxModules = 8
    $maxLogsPerModule = 3
    $maxTailBytes = 131072
    $moduleOrdinal = 0
    foreach ($directory in $moduleDirectories) {
        if ($moduleOrdinal -ge $maxModules) {
            [void]$script:Notes.Add('模块目录超过 ' + $maxModules + ' 个，其余未采集（避免无界读取）。')
            break
        }
        $moduleOrdinal++

        $candidates = New-Object System.Collections.ArrayList
        $base = '/data/adb/modules/' + $directory

        $topStarted = Get-UtcIso
        $topWatch = [System.Diagnostics.Stopwatch]::StartNew()
        $topResult = Invoke-Process -Executable $script:AdbExecutable `
            -Arguments @('-s', $script:Serial, 'shell', 'ls -1 ' + $base)
        $topWatch.Stop()
        [void](Save-Capture -Step ('module-list:' + $directory) `
            -RecordedCommand ('adb -s ' + $script:SerialMasked + ' shell ls -1 ' + (Get-RedactedPath -Path $base)) `
            -FileStem ('module-list-' + $directory) -RawText $topResult.Text -ExitCode $topResult.ExitCode `
            -StartedUtc $topStarted -DurationMs $topWatch.ElapsedMilliseconds)
        if ($topResult.ExitCode -eq 0) {
            foreach ($line in ($topResult.Text -split "`n")) {
                $name = $line.Trim()
                if ($name -match '^[A-Za-z0-9._-]{1,64}\.log$') {
                    [void]$candidates.Add($base + '/' + $name)
                }
            }
        }

        $logsDir = $base + '/logs'
        $logsStarted = Get-UtcIso
        $logsWatch = [System.Diagnostics.Stopwatch]::StartNew()
        $logsResult = Invoke-Process -Executable $script:AdbExecutable `
            -Arguments @('-s', $script:Serial, 'shell', 'ls -1 ' + $logsDir)
        $logsWatch.Stop()
        [void](Save-Capture -Step ('module-logs-dir:' + $directory) `
            -RecordedCommand ('adb -s ' + $script:SerialMasked + ' shell ls -1 ' + (Get-RedactedPath -Path $logsDir)) `
            -FileStem ('module-logs-dir-' + $directory) -RawText $logsResult.Text -ExitCode $logsResult.ExitCode `
            -StartedUtc $logsStarted -DurationMs $logsWatch.ElapsedMilliseconds)
        if ($logsResult.ExitCode -eq 0) {
            foreach ($line in ($logsResult.Text -split "`n")) {
                $name = $line.Trim()
                if ($name -match '^[A-Za-z0-9._-]{1,64}\.log$') {
                    [void]$candidates.Add($logsDir + '/' + $name)
                }
            }
        }

        if ($candidates.Count -eq 0) {
            [void]$script:Notes.Add('模块 ' + $directory + ' 没有可读的 .log（阶段日志不存在，未采集）。')
        }

        $taken = 0
        foreach ($candidate in $candidates) {
            if ($taken -ge $maxLogsPerModule) {
                [void]$script:Notes.Add('模块 ' + $directory + ' 的日志超过 ' + $maxLogsPerModule + ' 个，其余未采集。')
                break
            }
            $taken++
            $tailCommand = 'tail -c ' + $maxTailBytes + " '" + $candidate + "'"
            $tailStarted = Get-UtcIso
            $tailWatch = [System.Diagnostics.Stopwatch]::StartNew()
            $tailResult = Invoke-Process -Executable $script:AdbExecutable `
                -Arguments @('-s', $script:Serial, 'shell', $tailCommand)
            $tailWatch.Stop()
            $redactedTail = Get-RedactedPath -Path $candidate
            $record = Save-Capture -Step ('module-log:' + $redactedTail) `
                -RecordedCommand ('adb -s ' + $script:SerialMasked + ' shell tail -c ' + $maxTailBytes + ' ' + $redactedTail) `
                -FileStem ('module-log-' + $directory) -RawText $tailResult.Text -ExitCode $tailResult.ExitCode `
                -StartedUtc $tailStarted -DurationMs $tailWatch.ElapsedMilliseconds
            if ($record.ok) {
                [void]$script:ModuleLogs.Add([ordered]@{
                    path = $redactedTail
                    outputFile = $record.outputFile
                    outputSha256 = $record.outputSha256
                    outputBytes = $record.outputBytes
                    tailBytesLimit = $maxTailBytes
                    complete = ($record.outputBytes -lt $maxTailBytes)
                })
            } else {
                [void]$script:Notes.Add('读取模块日志失败（exit=' + $record.exitCode + '）：' + $redactedTail)
            }
        }
    }
    if ($moduleDirectories.Count -eq 0) {
        [void]$script:Notes.Add('未发现模块目录：模块阶段日志未采集（不是"没有故障"的证据）。')
    }

    $manifestPath = Write-Manifest -Status 'complete' -Reason ''
    Write-Host ('read-only evidence collected: ' + $script:OutputPath)
    Write-Host ('manifest: ' + $manifestPath)
    exit 0
} catch {
    $failure = $_.Exception.Message
    if ([string]::IsNullOrEmpty($script:OutputPath) -or -not [System.IO.Directory]::Exists($script:OutputPath)) {
        Write-Warning ('collection failed before the output directory existed: ' + $failure)
        exit 1
    }
    try {
        [void]$script:Notes.Add('脚本失败：' + $failure)
        [void](Write-Manifest -Status 'failed' -Reason $failure)
    } catch {
        Write-Warning ('manifest could not be written: ' + $_.Exception.Message)
    }
    Write-Warning ('collection failed: ' + $failure)
    exit 1
}
