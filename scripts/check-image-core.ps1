param([string]$JdkDirectory, [switch]$WithReferenceSamples)
$ErrorActionPreference = 'Stop'
$workspace = Split-Path $PSScriptRoot -Parent
if(-not $JdkDirectory) {
    $compiler = (Get-Command javac -ErrorAction Stop).Source
    $JdkDirectory = Split-Path (Split-Path $compiler -Parent) -Parent
}
$java = Join-Path $JdkDirectory 'bin\java.exe'
$javac = Join-Path $JdkDirectory 'bin\javac.exe'
$classes = Join-Path $workspace '.analysis\image-core\classes'
New-Item -ItemType Directory -Path $classes -Force | Out-Null
$sources = @(Get-ChildItem -LiteralPath (Join-Path $workspace 'image-core\src') -Filter '*.java' -Recurse | Select-Object -ExpandProperty FullName)
& $javac --release 17 -encoding UTF-8 -d $classes @sources
if($LASTEXITCODE -ne 0) { throw 'Java compilation failed' }
if($WithReferenceSamples) {
    $original = Join-Path $workspace 'SKRoot_Reference\Boot\Oringial_boot.img'
    $patched = Join-Path $workspace '.analysis\skroot-reference\patched\boot.img'
    & $java -cp $classes dev.maplesu.image.BootImageInspectorTest $original $patched
} else {
    & $java -cp $classes dev.maplesu.image.BootImageInspectorTest
}
if($LASTEXITCODE -ne 0) { throw 'Image-core checks failed' }
if($WithReferenceSamples) {
    & $java -Xmx512m -cp $classes dev.maplesu.image.ImagePipelineTest $original $patched
} else {
    & $java -Xmx512m -cp $classes dev.maplesu.image.ImagePipelineTest
}
if($LASTEXITCODE -ne 0) { throw 'Image pipeline checks failed' }
if($WithReferenceSamples) {
    & $java -cp $classes dev.maplesu.image.BootImageInspector $original
    if($LASTEXITCODE -ne 0) { throw 'Original image inspection failed' }
    & $java -cp $classes dev.maplesu.image.BootImageInspector $patched
    if($LASTEXITCODE -ne 0) { throw 'Patched image inspection failed' }
}
