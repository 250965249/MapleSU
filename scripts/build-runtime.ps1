param(
    [string]$SdkDirectory = $(if ($env:ANDROID_HOME) { $env:ANDROID_HOME } else { $env:ANDROID_SDK_ROOT }),
    [string]$NdkVersion = '26.1.10909125',
    [string]$CmakeVersion = '3.22.1',
    [string]$OutputDirectory,
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
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $workspace 'runtime\build\android-arm64' }
& $cmake -S (Join-Path $workspace 'runtime') -B $OutputDirectory -G Ninja "-DCMAKE_MAKE_PROGRAM=$ninja" `
    "-DCMAKE_TOOLCHAIN_FILE=$toolchain" -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-31 `
    -DANDROID_STL=c++_static -DCMAKE_BUILD_TYPE=Release
if ($LASTEXITCODE -ne 0) { throw 'Runtime configure failed' }
& $cmake --build $OutputDirectory -j $Jobs
if ($LASTEXITCODE -ne 0) { throw 'Runtime build failed' }
