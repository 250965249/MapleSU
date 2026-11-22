# SPDX-License-Identifier: GPL-3.0-or-later
<#
.SYNOPSIS
  MapleSU Normal (=KSU) 模块子系统设备判据（开发文档 §7.2 / T13）。

.DESCRIPTION
  把 scripts/check-normal-module-parity.sh 推到设备 /data/local/tmp 并以 root 执行，
  逐条输出 PASS/FAIL 与原始证据，任一 FAIL 时本脚本退出码非 0。

  为什么逻辑在 .sh 里而不在 ps1 里：`adb shell su -c "<复杂命令>"` 会经过 PowerShell →
  adb → 设备 sh 三层重新分词，多层引号必然被拆坏（首版就踩到：P1 路径拼接错、P5/P6/G7
  命令被 shell 拆开）。整脚本上设备执行只有一次参数传递，引号稳定。

.PARAMETER Serial
  adb 序列号；省略时用唯一在线设备。

.PARAMETER ExpectedKsudSha256
  期望的 ksud 摘要（= APK 内 lib/arm64-v8a/libksud_ksu.so）。给了才校验 G6。

.EXAMPLE
  pwsh -NoProfile -File scripts/check-normal-module-parity.ps1 -Serial 3B15CC00CMU00000
#>
[CmdletBinding()]
param(
    [string]$Serial = "",
    [string]$ExpectedKsudSha256 = "",
    [string]$EvidenceDir = "evidence/normal-ksu-parity-20261102"
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$localScript = Join-Path $PSScriptRoot "check-normal-module-parity.sh"
$remoteScript = "/data/local/tmp/maplesu-normal-parity.sh"

function Invoke-Adb {
    param([string[]]$Arguments)
    $prefix = @()
    if ($Serial) { $prefix += @("-s", $Serial) }
    return (& adb @prefix @Arguments 2>&1 | Out-String)
}

if (-not (Test-Path $localScript)) { throw "missing $localScript" }

$devices = (Invoke-Adb @("devices")) -split "`n" | Where-Object { $_ -match "\sdevice$" }
if (-not $Serial) {
    if ($devices.Count -ne 1) { throw "need -Serial (found $($devices.Count) devices)" }
    $Serial = ($devices[0] -split "\s+")[0]
}

Write-Host "== MapleSU Normal module parity ==" -ForegroundColor Cyan
Write-Host "serial: $Serial"

& adb -s $Serial push $localScript $remoteScript | Out-Null
& adb -s $Serial shell "chmod 755 $remoteScript" | Out-Null

$bootId = (Invoke-Adb @("shell", "cat /proc/sys/kernel/random/boot_id")).Trim()
$uptime = (Invoke-Adb @("shell", "cat /proc/uptime")).Trim()
Write-Host "boot_id: $bootId"
Write-Host "uptime : $uptime"

$suPrefix = if ($ExpectedKsudSha256) {
    "MAPLESU_EXPECTED_KSUD_SHA256=$ExpectedKsudSha256 sh $remoteScript"
} else {
    "sh $remoteScript"
}

# 单次传递：只有一层引号
$output = (& adb -s $Serial shell "su -c '$suPrefix'" 2>&1 | Out-String)
$code = $LASTEXITCODE

Write-Host $output

$failed = ([regex]::Matches($output, "(?m)^FAIL ")).Count
$passed = ([regex]::Matches($output, "(?m)^PASS ")).Count
$summary = if ($failed -eq 0 -and $code -eq 0) { "ALL PASS ($passed)" } else { "$failed FAILED / $passed PASS" }
$color = if ($failed -eq 0 -and $code -eq 0) { "Green" } else { "Red" }
Write-Host "== $summary ==" -ForegroundColor $color

if ($EvidenceDir) {
    New-Item -ItemType Directory -Force -Path (Join-Path $repoRoot $EvidenceDir) | Out-Null
    $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $path = Join-Path (Join-Path $repoRoot $EvidenceDir) "device-parity-$stamp.txt"
    @(
        "MapleSU Normal module parity - $stamp",
        "serial : $Serial",
        "boot_id: $bootId",
        "uptime : $uptime",
        "expectedKsudSha256: $ExpectedKsudSha256",
        "",
        $output,
        "== $summary ==",
        "exit: $code"
    ) | Set-Content -Path $path -Encoding UTF8
    Write-Host "evidence: $path"
}

exit $(if ($failed -eq 0 -and $code -eq 0) { 0 } else { 1 })
