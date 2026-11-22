param(
    [string]$CompilerDirectory,
    [string]$SdkDirectory = $(if ($env:ANDROID_HOME) { $env:ANDROID_HOME } else { $env:ANDROID_SDK_ROOT }),
    [string]$CmakeVersion = '3.22.1',
    [ValidateRange(1, 32)][int]$Jobs = 6
)
if (-not $SdkDirectory) { throw 'Set ANDROID_HOME (or ANDROID_SDK_ROOT), or pass -SdkDirectory.' }
$ErrorActionPreference = 'Stop'
$workspace = Split-Path $PSScriptRoot -Parent
if (-not $CompilerDirectory) {
    $CompilerDirectory = Join-Path $workspace '.research\toolchains\llvm-mingw-20261020-ucrt-x86_64'
}
$compiler = (Resolve-Path -LiteralPath $CompilerDirectory).Path.Replace('\', '/')
$sdk = (Resolve-Path -LiteralPath $SdkDirectory).Path.Replace('\', '/')
$cmake = "$sdk/cmake/$CmakeVersion/bin/cmake.exe"
$ninja = "$sdk/cmake/$CmakeVersion/bin/ninja.exe"
$cc = "$compiler/bin/x86_64-w64-mingw32-clang.exe"
$cxx = "$compiler/bin/x86_64-w64-mingw32-clang++.exe"
foreach ($required in @($cmake, $ninja, $cc, $cxx)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) { throw "Missing build dependency: $required" }
}
$source = Join-Path $workspace 'patch-engine'
$output = Join-Path $source 'build\windows-x64'
& $cmake -S $source -B $output -G Ninja "-DCMAKE_MAKE_PROGRAM=$ninja" `
    "-DCMAKE_C_COMPILER=$cc" "-DCMAKE_CXX_COMPILER=$cxx" `
    -DCMAKE_BUILD_TYPE=Release -DCMAKE_EXE_LINKER_FLAGS=-static
if ($LASTEXITCODE -ne 0) { throw 'Host configure failed' }
& $cmake --build $output -j $Jobs
if ($LASTEXITCODE -ne 0) { throw 'Host build failed' }
