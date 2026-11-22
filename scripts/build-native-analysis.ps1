param(
    [string]$SdkDirectory = $(if ($env:ANDROID_HOME) { $env:ANDROID_HOME } else { $env:ANDROID_SDK_ROOT }),
    [string]$NdkVersion = '26.1.10909125',
    [string]$CmakeVersion = '3.22.1',
    [ValidateRange(1, 32)][int]$Jobs = 6
)
if (-not $SdkDirectory) { throw 'Set ANDROID_HOME (or ANDROID_SDK_ROOT), or pass -SdkDirectory.' }
$ErrorActionPreference = 'Stop'
$workspace = Split-Path $PSScriptRoot -Parent
$sdk = (Resolve-Path -LiteralPath $SdkDirectory).Path.Replace('\', '/')
$cmake = "$sdk/cmake/$CmakeVersion/bin/cmake.exe"
$ninja = "$sdk/cmake/$CmakeVersion/bin/ninja.exe"
$toolchain = "$sdk/ndk/$NdkVersion/build/cmake/android.toolchain.cmake"
foreach ($required in @($cmake, $ninja, $toolchain)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) { throw "Missing build dependency: $required" }
}
$source = Join-Path $workspace 'patch-engine'
$output = Join-Path $source 'build\android-arm64'
& $cmake -S $source -B $output -G Ninja "-DCMAKE_MAKE_PROGRAM=$ninja" `
    "-DCMAKE_TOOLCHAIN_FILE=$toolchain" -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-31 `
    -DANDROID_STL=c++_static -DCMAKE_BUILD_TYPE=Release
if ($LASTEXITCODE -ne 0) { throw 'Native configure failed' }
& $cmake --build $output -j $Jobs
if ($LASTEXITCODE -ne 0) { throw 'Native build failed' }
