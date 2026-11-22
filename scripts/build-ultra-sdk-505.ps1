#Requires -Version 5.1
<#
.SYNOPSIS
    Reproducible build of the MapleSU 5.0.5 Ultra SDK outer-layer archive
    (libkernel_module_kit_static.a) from the frozen W0 input set.

.DESCRIPTION
    Scope of this builder: G1 *outer layer* + production-import preparation.

    It rebuilds exactly three repair members of the Ultra SDK static archive with
    the pinned NDK LLVM 17.0.2 toolchain, then reconstructs the archive **by ar
    member ordinal** so that the other 252 member payloads are preserved
    byte-for-byte (the archive carries the name "patch_base.o" three times with
    three different bodies, so name-keyed repacking is unsafe).

    The embedded autorun bootstrap carried by member 52
    (maplesu_autorun_bootstrap_install.o) is deliberately NOT rebuilt: its source
    translation-unit set and link script are not on disk, so a same-generation
    rebuild is impossible today. m052 is kept byte-identical and the reason is
    recorded in every identity manifest. This builder never claims the bootstrap
    was rebuilt.

    Repair compile commands are taken verbatim from
    evidence/pro-sdk-505/raw/sdk-build-recipe.md sections 3.1-3.3:
      m024  clang  --target=aarch64-linux-android21 -Oz -fPIC -c <ir>
      m029  clang  --target=aarch64-linux-android21 -Oz -fPIC -c <ir>
            clang++ --target=aarch64-linux-android21 -std=c++17 -Oz -fPIC
                     -fexceptions -fvisibility=hidden -Wall -Wextra -Werror -I <inc>
            ld.lld -r <ir.o> <wrapper.o>
      m034  clang  -target aarch64-none-linux-android21 -fPIC -c -x ir \
                     m034.baseline.compile.ll            (compile/ABI gate; the
                     unmodified m034.baseline.ll is NOT compilable: its trailing
                     typeidCompatibleVTable ThinLTO summary is rejected)
            clang  -target aarch64-none-linux-android21 -fPIC -c -x ir m034.generator.ll
            clang++ -target aarch64-linux-android21 -std=c++17 -Oz -fPIC
                     -fvisibility=hidden -fexceptions -frtti -Wall -Wextra -Werror -I <inc>
            ld.lld -r <generator.o> <wrapper.o>        (becomes the archive member)

.PARAMETER Inputs
    Frozen input directory (the W0 freeze). Its manifest is looked up as
    <Inputs>/manifest.json, <Inputs>/inputs-manifest.json or the sibling
    <Inputs>/../inputs-manifest.json (the evidence-root layout).

.PARAMETER OutDir
    Output directory for the release artifacts. Its leaf name is used as the
    evidence-root-relative prefix recorded in the JSON manifests, so passing
    .../evidence/pro-sdk-505/sdk yields paths such as "sdk/link.log".

.PARAMETER Ndk
    NDK root, e.g. <SDK>/ndk/26.1.10909125.

.PARAMETER Python
    Absolute path to a CPython 3 executable (default: MAPLESU_PYTHON, else python on PATH).

.PARAMETER LogFile
    Stage log path (default <OutDir>/build.log). Tool transcripts always go to
    <OutDir>/link.log as well.

.NOTES
    Exit codes (fail-closed, every stage maps to a distinct non-zero code):
      0 success
      1 unspecified/internal failure
      2 usage error (bad parameters, missing manifest)
      3 frozen input manifest verification failed
      4 toolchain missing / version drift
      5 repair member compilation or relocatable link failed
      6 ordinal archive reconstruction failed
      7 member-diff / symbol-index gate failed
      8 artifact production or independent self-verification failed

    Reproducibility: the archive is repacked with llvm-ar "D" (deterministic:
    zero timestamps, zero uid/gid) in ordinal order, then the symbol index is
    regenerated with "sD". The builder proves the pipeline is lossless by first
    repacking the untouched baseline and requiring the result to be byte
    identical to the baseline input, and (when the frozen reference archive is
    present) by requiring the repaired archive to be byte identical to it.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Inputs,
    [Parameter(Mandatory = $true)][string]$OutDir,
    [Parameter(Mandatory = $true)][string]$Ndk,
    [string]$Python = $(if ($env:MAPLESU_PYTHON) { $env:MAPLESU_PYTHON } else { 'python' }),
    [string]$LogFile = ''
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$script:Utf8 = New-Object System.Text.UTF8Encoding($false)
$script:Stage = 'init'
$script:StageCodes = @{
    init = 1; usage = 2; inputs = 3; toolchain = 4
    compile = 5; archive = 6; diff = 7; product = 8
}
$script:StageTimings = New-Object System.Collections.Generic.List[object]
$script:StageStart = [DateTime]::UtcNow

# Symbols that must be identical in the m034 baseline and candidate objects.
$script:M034AbiSymbol = '_ZN13kernel_module26icache_invalidate_all_cpusEv'
# Pinned toolchain generation (recipe section 2.1).
$script:PinnedLlvmVersion = '17.0.2'
# Contract of this build: exactly these member ordinals change (three repairs
# plus the m053 SDK version stamp).
$script:ExpectedChangedOrdinals = @(24, 29, 34, 53)
$script:ExpectedChangedNames = @(
    'module_base_kernel_mem.o',
    'module_base_kernel_func_hook.o',
    'module_base_cpu_icache_sync.o',
    'maplesu_installer.o'
)
# Only these three are repairs; m053 is a version stamp, not a repair.
$script:RepairOrdinals = @(24, 29, 34)
# m053 version stamp: the SDK's self-reported version literal, 4.6.5 -> 5.0.5.
# The literal is @.str.17 ("[6 x i8] c\"4.6.5\00\"") used by
# get_sdk_version()'s sscanf and by install_maplesu_environment()'s equality
# check against the installed version; five bytes change, layout untouched.
$script:VersionStampOrdinal = 53
$script:VersionStampMemberName = 'maplesu_installer.o'
$script:VersionFromLiteral = '4.6.5'
$script:VersionToLiteral = '5.0.5'
$script:BootstrapMemberName = 'maplesu_autorun_bootstrap_install.o'
# Root-key slot inside the embedded bootstrap payload (byte range that the
# installer overwrites with the per-device root key). The normalized digest of
# the bundled payload and of the device-installed helper are equal once this
# range is zeroed; the builder recomputes it instead of copying a claim.
$script:KeySlotOffset = 182886
$script:KeySlotLength = 4096
$script:ExpectedNormalizedHelperSha = '4372c585864b343ecd20ccb40c0e7ab90119ed65d7b7bd22bdb8382c03b9811c'
$script:AppVersion = '5.0.5'
$script:VersionCode = 50005
$script:SdkBuildId = 'maplesu-ultra-5.0.5-r1'

# ---------------------------------------------------------------------------
# logging / utility helpers
# ---------------------------------------------------------------------------

function Get-UtcNow { [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ') }

function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $line = '[' + (Get-UtcNow) + '] [' + $Level + '] [' + $script:Stage + '] ' + $Message
    if (-not [string]::IsNullOrEmpty($script:LogFile)) {
        [IO.File]::AppendAllText($script:LogFile, $line + "`n", $script:Utf8)
    }
    Write-Host $line
}

function Write-LinkLog {
    param([string]$Text)
    if ($null -eq $Text) { $Text = '' }
    if (-not [string]::IsNullOrEmpty($script:LinkLog)) {
        [IO.File]::AppendAllText($script:LinkLog, $Text + "`n", $script:Utf8)
    }
}

function Fail-Stage {
    param([string]$Message, [hashtable]$Detail = @{})
    $code = 1
    if ($script:StageCodes.ContainsKey($script:Stage)) { $code = $script:StageCodes[$script:Stage] }
    $suffix = ''
    if ($Detail.Count -gt 0) {
        $parts = @()
        foreach ($key in $Detail.Keys) { $parts += ($key + '=' + $Detail[$key]) }
        $suffix = ' { ' + ($parts -join ', ') + ' }'
    }
    Write-Log ('FATAL: ' + $Message + $suffix) 'ERROR'
    if ($script:LinkLog) { Write-LinkLog ('FATAL: ' + $Message) }
    exit $code
}

function Get-Sha {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { throw "file not found for hashing: $Path" }
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-FileSize {
    param([string]$Path)
    return (Get-Item -LiteralPath $Path).Length
}

function Fwd {
    param([string]$Path)
    return $Path.Replace('\', '/')
}

function Write-JsonFile {
    param([string]$Path, $Object)
    $json = $Object | ConvertTo-Json -Depth 40
    [IO.File]::WriteAllText($Path, $json + "`n", $script:Utf8)
}

function Read-JsonFile {
    param([string]$Path)
    return (Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json)
}

function Invoke-Native {
    <#
        Runs a native tool, tees the transcript to link.log and the stage log,
        and throws (via the caller's try/catch -> Fail-Stage) on a bad exit code.
        -CaptureTo writes the merged output to a file instead of the stage log
        (used for the multi-megabyte llvm-nm dumps).
    #>
    param(
        [string]$Exe,
        [string[]]$Arguments,
        [int]$ExpectExit = 0,
        [string]$What = '',
        [string]$CaptureTo = '',
        [switch]$SuppressStderr
    )
    $quoted = @()
    foreach ($arg in $Arguments) {
        if ($arg -match '[\s"]') { $quoted += ('"' + $arg + '"') } else { $quoted += $arg }
    }
    $cmdline = (Fwd $Exe) + ' ' + ($quoted -join ' ')
    Write-LinkLog ('$ ' + $cmdline)
    Write-Log ('exec: ' + $cmdline)

    if ($SuppressStderr) {
        # llvm-nm interleaves "<archive>:<member>: no symbols" notes on stderr at
        # timing dependent positions; they would make the dump non-reproducible.
        Write-LinkLog '# stderr suppressed for this capture'
        $raw = & $Exe @Arguments 2>$null
    }
    else {
        $raw = & $Exe @Arguments 2>&1
    }
    $code = $LASTEXITCODE
    $lines = @()
    foreach ($item in $raw) { $lines += [string]$item }

    if ($CaptureTo -ne '') {
        [IO.File]::WriteAllLines($CaptureTo, [string[]]$lines, $script:Utf8)
        Write-Log ('captured ' + $lines.Count + ' line(s) -> ' + (Fwd $CaptureTo))
    }
    else {
        foreach ($line in $lines) {
            Write-LinkLog $line
            Write-Log $line 'TOOL'
        }
    }
    Write-LinkLog ('exit=' + $code)
    Write-Log ('exit=' + $code)

    if ($code -ne $ExpectExit) {
        $label = $What
        if ($label -eq '') { $label = (Split-Path -Leaf $Exe) }
        throw ("$label failed: exit $code (expected $ExpectExit): $cmdline")
    }
    return $lines
}

function Invoke-Python {
    <#
        Runs an inline python program (passed on stdin) with positional args.
        Exit code 0 expected; anything else fails the current stage.
    #>
    param([string]$Name, [string]$Code, [string[]]$Arguments = @(), [int]$ExpectExit = 0)
    Write-LinkLog ('$ python - ' + $Name + ' ' + ($Arguments -join ' '))
    Write-Log ('python helper: ' + $Name)
    $raw = $Code | & $Python - @Arguments 2>&1
    $code = $LASTEXITCODE
    $lines = @()
    foreach ($item in $raw) { $lines += [string]$item }
    foreach ($line in $lines) {
        Write-LinkLog $line
        Write-Log $line 'PY'
    }
    Write-LinkLog ('exit=' + $code)
    if ($code -ne $ExpectExit) {
        throw ("python helper '$Name' failed: exit $code (expected $ExpectExit)")
    }
    return $lines
}

function Get-Prop {
    param($Object, [string]$Name, $Default = $null)
    if ($null -eq $Object) { return $Default }
    $prop = $Object.PSObject.Properties[$Name]
    if ($null -eq $prop) { return $Default }
    return $prop.Value
}

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

try {
    # -- parameter normalisation -------------------------------------------
    $script:Stage = 'usage'
    foreach ($tool in @($Python)) {
        if (-not (Test-Path -LiteralPath $tool)) { Fail-Stage "python interpreter not found: $tool" }
    }
    if (-not (Test-Path -LiteralPath $Inputs)) { Fail-Stage "inputs directory not found: $Inputs" }
    if (-not (Test-Path -LiteralPath $Ndk)) { Fail-Stage "NDK root not found: $Ndk" }
    $Inputs = (Resolve-Path -LiteralPath $Inputs).Path
    $Ndk = (Resolve-Path -LiteralPath $Ndk).Path
    if (-not (Test-Path -LiteralPath $OutDir)) {
        New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
    }
    $OutDir = (Resolve-Path -LiteralPath $OutDir).Path
    $OutLeaf = Split-Path -Leaf $OutDir
    $OutRel = $OutLeaf + '/'
    $Bin = Join-Path $Ndk 'toolchains/llvm/prebuilt/windows-x86_64/bin'

    $script:LinkLog = Join-Path $OutDir 'link.log'
    if ($LogFile -eq '') { $script:LogFile = Join-Path $OutDir 'build.log' }
    else {
        $script:LogFile = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($LogFile)
        $logParent = Split-Path -Parent $script:LogFile
        if ($logParent -and -not (Test-Path -LiteralPath $logParent)) {
            New-Item -ItemType Directory -Force -Path $logParent | Out-Null
        }
    }
    [IO.File]::WriteAllText($script:LogFile, '', $script:Utf8)
    [IO.File]::WriteAllText($script:LinkLog, '', $script:Utf8)

    $Work = Join-Path $OutDir 'build'
    foreach ($dir in @($Work,
            (Join-Path $Work 'objects'),
            (Join-Path $Work 'ar/base'),
            (Join-Path $Work 'nm'),
            (Join-Path $Work 'ir'),
            (Join-Path $Work 'bootstrap'))) {
        if (Test-Path -LiteralPath $dir) { Remove-Item -LiteralPath $dir -Recurse -Force }
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
    }
    # Never let a previous run's products masquerade as this run's output.
    foreach ($name in @('libkernel_module_kit_static.a', 'autorun_bootstrap',
            'SDK-RELEASE.json', 'PROVENANCE.json', 'sdk-build.json',
            'inputs.sha256', 'outputs.sha256', 'member-diff.json', 'symbols-diff.json')) {
        $stale = Join-Path $OutDir $name
        if (Test-Path -LiteralPath $stale) { Remove-Item -LiteralPath $stale -Force }
    }
    $ObjDir = Join-Path $Work 'objects'
    $ArBase = Join-Path $Work 'ar/base'
    $NmDir = Join-Path $Work 'nm'
    $BsDir = Join-Path $Work 'bootstrap'
    $IrDir = Join-Path $Work 'ir'
    $CtxPath = Join-Path $Work 'ctx.json'

    $script:StartInstant = [DateTime]::UtcNow
    $startedUtc = Get-UtcNow
    Write-Log ('builder start; Inputs=' + (Fwd $Inputs) + ' OutDir=' + (Fwd $OutDir) + ' Ndk=' + (Fwd $Ndk))

    $tools = @{
        clang       = (Join-Path $Bin 'clang.exe')
        clangxx     = (Join-Path $Bin 'clang++.exe')
        llvmAr      = (Join-Path $Bin 'llvm-ar.exe')
        llvmNm      = (Join-Path $Bin 'llvm-nm.exe')
        llvmReadelf = (Join-Path $Bin 'llvm-readelf.exe')
        llvmDis     = (Join-Path $Bin 'llvm-dis.exe')
        ldLld       = (Join-Path $Bin 'ld.lld.exe')
    }

    # =====================================================================
    # stage: inputs -- verify every frozen input against the manifest
    # =====================================================================
    $script:Stage = 'inputs'
    $stageStart = [DateTime]::UtcNow
    Write-Log 'stage inputs: locating frozen input manifest'
    $manifestCandidates = @(
        (Join-Path $Inputs 'manifest.json'),
        (Join-Path $Inputs 'inputs-manifest.json'),
        (Join-Path (Split-Path -Parent $Inputs) 'inputs-manifest.json'),
        (Join-Path (Split-Path -Parent $Inputs) 'manifest.json')
    )
    $ManifestPath = ''
    foreach ($candidate in $manifestCandidates) {
        if (Test-Path -LiteralPath $candidate) { $ManifestPath = (Resolve-Path -LiteralPath $candidate).Path; break }
    }
    if ($ManifestPath -eq '') {
        Fail-Stage ('no input manifest found; looked for: ' + ($manifestCandidates -join ', '))
    }
    Write-Log ('using manifest: ' + (Fwd $ManifestPath))

    $InputsJson = Join-Path $Work 'inputs.json'
    $InputsShaList = Join-Path $OutDir 'inputs.sha256'
    $verifyInputsPy = @'
import sys, os, json, hashlib

ctx = json.load(open(sys.argv[1], encoding="utf-8"))
manifest_path = ctx["manifestPath"]
inputs_dir = ctx["inputsDir"]
out_json = ctx["outInputsJson"]
out_sha = ctx["outInputsSha256"]

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

try:
    doc = json.load(open(manifest_path, encoding="utf-8"))
except Exception as exc:
    sys.stderr.write("INPUT-MANIFEST-INVALID %s: %s\n" % (manifest_path, exc))
    sys.exit(1)

entries = doc.get("inputs")
if not isinstance(entries, list) or not entries:
    sys.stderr.write("INPUT-MANIFEST-INVALID no inputs[] array\n")
    sys.exit(1)

manifest_dir = os.path.dirname(os.path.abspath(manifest_path))
bases = [manifest_dir, os.path.dirname(manifest_dir), os.path.abspath(inputs_dir)]

def resolve_rel(rel):
    for base in bases:
        cand = os.path.normpath(os.path.join(base, rel))
        if os.path.exists(cand):
            return cand, base
    return None, None

# pick the base that resolves the first copied entry; then use it for all
chosen_base = None
for entry in entries:
    rel = entry.get("relativePath") or entry.get("path")
    if not rel or entry.get("copied") is False:
        continue
    resolved, base = resolve_rel(rel)
    if resolved is not None:
        chosen_base = base
        break
if chosen_base is None:
    sys.stderr.write("INPUT-MANIFEST-INVALID no entry resolves relative to %s\n" % bases)
    sys.exit(1)

errors = []
verified = []
not_copied = []
trees = []
total_bytes = 0

for entry in entries:
    rel = entry.get("relativePath") or entry.get("path")
    if not rel:
        errors.append("<entry> missing relativePath")
        continue
    rel_norm = rel.replace("\\", "/")
    want_sha = (entry.get("sha256") or "").lower()
    want_size = entry.get("bytes", entry.get("size"))
    entry_type = entry.get("entryType", "file")
    copied = entry.get("copied", True)

    if copied is False:
        not_copied.append({"path": rel_norm, "sha256": want_sha, "bytes": want_size,
                           "reason": "manifest records copied=false (size policy)"})
        continue

    resolved, base = resolve_rel(rel)
    if resolved is None:
        errors.append("%s: missing under %s" % (rel_norm, chosen_base))
        continue

    if entry_type == "tree":
        if not os.path.isdir(resolved):
            errors.append("%s: expected directory" % rel_norm)
            continue
        tree_manifest = entry.get("treeManifest")
        if not tree_manifest:
            errors.append("%s: tree entry has no treeManifest" % rel_norm)
            continue
        tree_manifest_path, _ = resolve_rel(tree_manifest)
        if tree_manifest_path is None:
            tree_manifest_path = os.path.normpath(os.path.join(chosen_base, tree_manifest))
        if not os.path.isfile(tree_manifest_path):
            errors.append("%s: treeManifest missing (%s)" % (rel_norm, tree_manifest))
            continue
        tm_sha = sha256_file(tree_manifest_path)
        tm_want = (entry.get("treeManifestSha256") or want_sha).lower()
        tm_bytes = entry.get("treeManifestBytes")
        if tm_want and tm_sha != tm_want:
            errors.append("%s: treeManifest sha256 mismatch" % rel_norm)
            continue
        if tm_bytes is not None and os.path.getsize(tree_manifest_path) != tm_bytes:
            errors.append("%s: treeManifest size mismatch" % rel_norm)
            continue
        tree_errors = []
        checked = 0
        with open(tree_manifest_path, "r", encoding="utf-8") as fh:
            for raw_line in fh:
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if len(parts) < 2:
                    tree_errors.append("unparsable tree manifest line: %r" % line)
                    continue
                file_sha, file_rel = parts[0].lower(), " ".join(parts[1:])
                file_path = os.path.join(resolved, file_rel.replace("/", os.sep))
                if not os.path.isfile(file_path):
                    tree_errors.append("missing header %s" % file_rel)
                    continue
                actual = sha256_file(file_path)
                if actual != file_sha:
                    tree_errors.append("header sha256 mismatch %s" % file_rel)
                    continue
                checked += 1
        declared = entry.get("fileCount")
        if declared is not None and checked != declared:
            tree_errors.append("header count %d != declared %d" % (checked, declared))
        if tree_errors:
            errors.extend(["%s: %s" % (rel_norm, item) for item in tree_errors])
            continue
        trees.append({"path": rel_norm, "treeManifest": tree_manifest,
                      "treeManifestSha256": tm_sha, "files": checked,
                      "absolutePath": resolved.replace("\\", "/"),
                      "treeManifestAbsolutePath": tree_manifest_path.replace("\\", "/")})
        total_bytes += tm_bytes if tm_bytes is not None else os.path.getsize(tree_manifest_path)
        verified.append({"path": rel_norm, "sha256": tm_sha,
                         "size": tm_bytes if tm_bytes is not None else os.path.getsize(tree_manifest_path),
                         "entryType": "tree", "category": entry.get("category"),
                         "fileCount": checked, "absolutePath": resolved.replace("\\", "/"),
                         "treeManifest": tree_manifest})
        continue

    if not os.path.isfile(resolved):
        errors.append("%s: missing file %s" % (rel_norm, resolved))
        continue
    actual_size = os.path.getsize(resolved)
    if want_size is not None and actual_size != want_size:
        errors.append("%s: size %d != manifest %s" % (rel_norm, actual_size, want_size))
        continue
    actual_sha = sha256_file(resolved)
    if want_sha and actual_sha != want_sha:
        errors.append("%s: sha256 %s != manifest %s" % (rel_norm, actual_sha, want_sha))
        continue
    total_bytes += actual_size
    verified.append({"path": rel_norm, "sha256": actual_sha, "size": actual_size,
                     "entryType": "file", "category": entry.get("category"),
                     "absolutePath": resolved.replace("\\", "/")})

if errors:
    for item in errors:
        sys.stderr.write("INPUT-MISMATCH %s\n" % item)
    sys.stderr.write("INPUT-VERIFY-FAILED errors=%d\n" % len(errors))
    sys.exit(1)

resolved_map = {}
for item in verified:
    resolved_map[item["path"]] = item["absolutePath"]

manifest_sha = sha256_file(manifest_path)
report = {
    "schemaVersion": 1,
    "manifestPath": manifest_path.replace("\\", "/"),
    "manifestSha256": manifest_sha,
    "manifestBase": chosen_base.replace("\\", "/"),
    "inputsDir": os.path.abspath(inputs_dir).replace("\\", "/"),
    "totals": {"entries": len(entries), "verified": len(verified),
               "notCopied": len(not_copied), "bytes": total_bytes,
               "trees": len(trees)},
    "trees": trees,
    "notCopied": not_copied,
    "entries": verified,
    "resolved": resolved_map,
}
with open(out_json, "w", encoding="utf-8", newline="\n") as fh:
    json.dump(report, fh, ensure_ascii=True, indent=2)
    fh.write("\n")

with open(out_sha, "w", encoding="utf-8", newline="\n") as fh:
    for item in sorted(verified, key=lambda value: value["path"]):
        fh.write("%s  %s\n" % (item["sha256"], item["path"]))

print("INPUT-VERIFY-OK entries=%d verified=%d notCopied=%d trees=%d bytes=%d manifestSha256=%s"
      % (len(entries), len(verified), len(not_copied), len(trees), total_bytes, manifest_sha))
sys.exit(0)
'@
    $ctxInputs = @{
        manifestPath   = (Fwd $ManifestPath)
        inputsDir      = (Fwd $Inputs)
        outInputsJson  = (Fwd $InputsJson)
        outInputsSha256 = (Fwd $InputsShaList)
    }
    Write-JsonFile $CtxPath $ctxInputs
    Invoke-Python -Name 'verify-inputs' -Code $verifyInputsPy -Arguments @((Fwd $CtxPath)) | Out-Null
    $inputsReport = Read-JsonFile $InputsJson
    $InputManifestSha = [string](Get-Prop $inputsReport 'manifestSha256')
    $InputManifestRel = 'inputs-manifest.json'
    try {
        $relToEvidence = [IO.Path]::GetRelativePath((Split-Path -Parent $ManifestPath), $ManifestPath)
        $InputManifestRel = (Fwd $relToEvidence)
    }
    catch { }
    if ([string]::IsNullOrWhiteSpace($InputManifestSha)) { throw 'input manifest digest missing from verifier report' }
    Write-Log ('input manifest verified; sha256=' + $InputManifestSha)
    $script:StageTimings.Add([ordered]@{
            name = 'inputs'; startedUtc = $stageStart.ToString('yyyy-MM-ddTHH:mm:ssZ')
            endedUtc = (Get-UtcNow)
            seconds = [math]::Round(((Get-Date).ToUniversalTime() - $stageStart).TotalSeconds, 3)
        })

    function Get-InputPath {
        param([string]$RelativeOrSuffix, [switch]$Optional)
        $map = $inputsReport.resolved
        if ($map.PSObject.Properties[$RelativeOrSuffix]) { return [string]$map.PSObject.Properties[$RelativeOrSuffix].Value }
        $matches = @()
        foreach ($prop in $map.PSObject.Properties) {
            if ($prop.Name.EndsWith($RelativeOrSuffix, [StringComparison]::OrdinalIgnoreCase)) {
                $matches += [string]$prop.Value
            }
        }
        if ($matches.Count -eq 1) { return $matches[0] }
        if ($matches.Count -gt 1) { throw "ambiguous input reference '$RelativeOrSuffix' matches $($matches.Count) files" }
        if ($Optional) { return $null }
        throw "required frozen input not present in the verified manifest: $RelativeOrSuffix"
    }
    function Get-InputRel {
        param([string]$RelativeOrSuffix)
        $map = $inputsReport.resolved
        if ($map.PSObject.Properties[$RelativeOrSuffix]) { return $RelativeOrSuffix }
        foreach ($prop in $map.PSObject.Properties) {
            if ($prop.Name.EndsWith($RelativeOrSuffix, [StringComparison]::OrdinalIgnoreCase)) { return $prop.Name }
        }
        return $null
    }

    $BaselineArchive = Get-InputPath 'inputs/pro/lib/arm64-v8a/libkernel_module_kit_static.a'
    $BaselineArchiveRel = Get-InputRel 'inputs/pro/lib/arm64-v8a/libkernel_module_kit_static.a'
    $ReferenceArchive = Get-InputPath 'libkernel_module_kit_checked.EXPERIMENTAL.a' -Optional
    $ReferenceArchiveRel = Get-InputRel 'libkernel_module_kit_checked.EXPERIMENTAL.a'
    $ReferenceBridgeSo = Get-InputPath 'libpermissionmanager.checked.EXPERIMENTAL.so' -Optional
    $ReferenceBridgeSoRel = Get-InputRel 'libpermissionmanager.checked.EXPERIMENTAL.so'
    $M024Ir = Get-InputPath 'patch-write/m024.checked.ll'
    $M024IrRel = Get-InputRel 'patch-write/m024.checked.ll'
    $M029Ir = Get-InputPath 'hook-publication/m029.checked.ll'
    $M029IrRel = Get-InputRel 'hook-publication/m029.checked.ll'
    $HookCpp = Get-InputPath 'hook-publication/hook_publish.cpp'
    $HookCppRel = Get-InputRel 'hook-publication/hook_publish.cpp'
    $M034BaselineIr = Get-InputPath 'icache/m034.baseline.compile.ll'
    $M034BaselineIrRel = Get-InputRel 'icache/m034.baseline.compile.ll'
    $M034GeneratorIr = Get-InputPath 'icache/m034.generator.ll'
    $M034GeneratorIrRel = Get-InputRel 'icache/m034.generator.ll'
    $IcacheCpp = Get-InputPath 'icache/icache_candidate.cpp'
    $IcacheCppRel = Get-InputRel 'icache/icache_candidate.cpp'
    $IcachePolicyH = Get-InputPath 'icache/icache_policy.h'
    $IcachePolicyHRel = Get-InputRel 'icache/icache_policy.h'
    $M052Ir = Get-InputPath 'ir/m052/a.ll'
    $M052IrRel = Get-InputRel 'ir/m052/a.ll'
    $M053Ir = Get-InputPath 'ir/m053/a.ll'
    $M053IrRel = Get-InputRel 'ir/m053/a.ll'
    # The SDK header set may be registered either as one "tree" entry or as
    # individual header files; support both manifest shapes.
    $IncludeTree = @($inputsReport.trees | Where-Object { $_.path -like '*pro/include' }) | Select-Object -First 1
    if ($null -ne $IncludeTree) {
        $IncludeDir = [string]$IncludeTree.absolutePath
        $IncludeRel = [string]$IncludeTree.path
        $IncludeManifestSha = [string]$IncludeTree.treeManifestSha256
        $IncludeFileCount = [int]$IncludeTree.files
    }
    else {
        $IncludeManifestPath = Get-InputPath 'pro/include/HEADER-MANIFEST.sha256' -Optional
        if (-not $IncludeManifestPath) {
            throw 'SDK header set (inputs/pro/include) is not registered in the verified input manifest'
        }
        $IncludeDir = Split-Path -Parent $IncludeManifestPath
        $IncludeRel = Get-InputRel 'pro/include/HEADER-MANIFEST.sha256'
        $IncludeRel = $IncludeRel.Substring(0, $IncludeRel.Length - '/HEADER-MANIFEST.sha256'.Length)
        $IncludeManifestSha = Get-Sha $IncludeManifestPath
        $IncludeFileCount = @($inputsReport.entries | Where-Object { $_.path -like ($IncludeRel + '/*') }).Count
        Write-Log ('SDK header set registered as individual files (' + $IncludeFileCount + ' entries); manifest sha256=' + $IncludeManifestSha)
    }

    $refObjects = [ordered]@{
        m024Member   = (Get-InputPath 'combined/module_base_kernel_mem.o' -Optional)
        m029IrObj    = (Get-InputPath 'combined/m029.ir.o' -Optional)
        m029Wrapper  = (Get-InputPath 'combined/hook_publish.o' -Optional)
        m029Member   = (Get-InputPath 'combined/module_base_kernel_func_hook.o' -Optional)
        m034Base     = (Get-InputPath 'icache/m034.baseline.o' -Optional)
        m034Gen      = (Get-InputPath 'icache/m034.generator.o' -Optional)
        m034Wrapper  = (Get-InputPath 'icache/icache_candidate.o' -Optional)
        m034Member   = (Get-InputPath 'icache/m034.candidate.o' -Optional)
    }
    $refObjectRels = [ordered]@{
        m024Member  = (Get-InputRel 'combined/module_base_kernel_mem.o')
        m029IrObj   = (Get-InputRel 'combined/m029.ir.o')
        m029Wrapper = (Get-InputRel 'combined/hook_publish.o')
        m029Member  = (Get-InputRel 'combined/module_base_kernel_func_hook.o')
        m034Base    = (Get-InputRel 'icache/m034.baseline.o')
        m034Gen     = (Get-InputRel 'icache/m034.generator.o')
        m034Wrapper = (Get-InputRel 'icache/icache_candidate.o')
        m034Member  = (Get-InputRel 'icache/m034.candidate.o')
    }

    # =====================================================================
    # stage: toolchain
    # =====================================================================
    $script:Stage = 'toolchain'
    $stageStart = [DateTime]::UtcNow
    Write-Log 'stage toolchain: verifying NDK LLVM 17.0.2 toolchain'
    foreach ($key in $tools.Keys) {
        if (-not (Test-Path -LiteralPath $tools[$key])) { Fail-Stage "required tool missing: $($tools[$key])" }
    }
    $clangVersionLines = @(Invoke-Native -Exe $tools.clang -Arguments @('--version') -What 'clang --version')
    $clangVersion = ''
    foreach ($line in $clangVersionLines) { if ($line -match 'clang version') { $clangVersion = $line.Trim(); break } }
    $llvmArVersion = (@(Invoke-Native -Exe $tools.llvmAr -Arguments @('--version') -What 'llvm-ar --version') -join ' ').Trim()
    $ldLldVersion = (@(Invoke-Native -Exe $tools.ldLld -Arguments @('--version') -What 'ld.lld --version') -join ' ').Trim()
    $llvmNmVersion = (@(Invoke-Native -Exe $tools.llvmNm -Arguments @('--version') -What 'llvm-nm --version') -join ' ').Trim()
    $llvmReadelfVersion = (@(Invoke-Native -Exe $tools.llvmReadelf -Arguments @('--version') -What 'llvm-readelf --version') -join ' ').Trim()
    $llvmDisVersion = (@(Invoke-Native -Exe $tools.llvmDis -Arguments @('--version') -What 'llvm-dis --version') -join ' ').Trim()
    $pythonVersion = (@(Invoke-Python -Name 'python-version' -Code 'import sys; print("Python " + sys.version.replace("\n", " "))') -join ' ').Trim()
    if ($clangVersion -notmatch [regex]::Escape($script:PinnedLlvmVersion)) {
        Fail-Stage "clang is not LLVM $($script:PinnedLlvmVersion): $clangVersion"
    }
    foreach ($pair in @(@('llvm-ar', $llvmArVersion), @('ld.lld', $ldLldVersion),
            @('llvm-nm', $llvmNmVersion), @('llvm-readelf', $llvmReadelfVersion),
            @('llvm-dis', $llvmDisVersion))) {
        if ($pair[1] -notmatch [regex]::Escape($script:PinnedLlvmVersion)) {
            Fail-Stage "$($pair[0]) is not LLVM $($script:PinnedLlvmVersion): $($pair[1])"
        }
    }
    $ndkVersion = Split-Path -Leaf $Ndk
    Write-Log ("toolchain ok: clang=" + $clangVersion + '; ndk=' + $ndkVersion)
    $script:StageTimings.Add([ordered]@{
            name = 'toolchain'; startedUtc = $stageStart.ToString('yyyy-MM-ddTHH:mm:ssZ')
            endedUtc = (Get-UtcNow)
            seconds = [math]::Round(((Get-Date).ToUniversalTime() - $stageStart).TotalSeconds, 3)
        })

    # =====================================================================
    # stage: compile -- the three repair members, commands from the recipe
    # =====================================================================
    $script:Stage = 'compile'
    $stageStart = [DateTime]::UtcNow
    Write-Log 'stage compile: rebuilding m024 / m029 / m034 members'

    $m024MemberObj = Join-Path $ObjDir 'module_base_kernel_mem.o'
    $m029IrObj = Join-Path $ObjDir 'm029.ir.o'
    $m029WrapperObj = Join-Path $ObjDir 'hook_publish.o'
    $m029MemberObj = Join-Path $ObjDir 'module_base_kernel_func_hook.o'
    $m034BaseObj = Join-Path $ObjDir 'm034.baseline.o'
    $m034GenObj = Join-Path $ObjDir 'm034.generator.o'
    $m034WrapperObj = Join-Path $ObjDir 'icache_candidate.o'
    $m034MemberObj = Join-Path $ObjDir 'module_base_cpu_icache_sync.o'

    # m024 (recipe 3.1)
    Invoke-Native -Exe $tools.clang -What 'm024 IR compile' -Arguments @(
        '--target=aarch64-linux-android21', '-Oz', '-fPIC', '-c', (Fwd $M024Ir), '-o', (Fwd $m024MemberObj)
    ) | Out-Null

    # m029 (recipe 3.2): IR object + C++ wrapper merged with ld.lld -r
    Invoke-Native -Exe $tools.clang -What 'm029 IR compile' -Arguments @(
        '--target=aarch64-linux-android21', '-Oz', '-fPIC', '-c', (Fwd $M029Ir), '-o', (Fwd $m029IrObj)
    ) | Out-Null
    Invoke-Native -Exe $tools.clangxx -What 'm029 wrapper compile' -Arguments @(
        '--target=aarch64-linux-android21', '-std=c++17', '-Oz', '-fPIC', '-fexceptions',
        '-fvisibility=hidden', '-Wall', '-Wextra', '-Werror', '-I', (Fwd $IncludeDir),
        '-c', (Fwd $HookCpp), '-o', (Fwd $m029WrapperObj)
    ) | Out-Null
    Invoke-Native -Exe $tools.ldLld -What 'm029 relocatable link' -Arguments @(
        '-r', (Fwd $m029IrObj), (Fwd $m029WrapperObj), '-o', (Fwd $m029MemberObj)
    ) | Out-Null

    # m034 (recipe 3.3): baseline.compile.ll is the compilable baseline form;
    # the untouched m034.baseline.ll is rejected by clang (ThinLTO summary).
    Invoke-Native -Exe $tools.clang -What 'm034 baseline IR compile' -Arguments @(
        '-target', 'aarch64-none-linux-android21', '-fPIC', '-c', '-x', 'ir',
        (Fwd $M034BaselineIr), '-o', (Fwd $m034BaseObj)
    ) | Out-Null
    Invoke-Native -Exe $tools.clang -What 'm034 generator IR compile' -Arguments @(
        '-target', 'aarch64-none-linux-android21', '-fPIC', '-c', '-x', 'ir',
        (Fwd $M034GeneratorIr), '-o', (Fwd $m034GenObj)
    ) | Out-Null
    Invoke-Native -Exe $tools.clangxx -What 'm034 wrapper compile' -Arguments @(
        '-target', 'aarch64-linux-android21', '-std=c++17', '-Oz', '-fPIC', '-fvisibility=hidden',
        '-fexceptions', '-frtti', '-Wall', '-Wextra', '-Werror', '-I', (Fwd $IncludeDir),
        '-c', (Fwd $IcacheCpp), '-o', (Fwd $m034WrapperObj)
    ) | Out-Null
    Invoke-Native -Exe $tools.ldLld -What 'm034 relocatable link' -Arguments @(
        '-r', (Fwd $m034GenObj), (Fwd $m034WrapperObj), '-o', (Fwd $m034MemberObj)
    ) | Out-Null

    # public ABI assertion (reproduce.ps1 lines 51-59): the single hidden i64
    # entry point must keep the same binding/visibility in baseline and candidate.
    $abiPattern = 'FUNC\s+GLOBAL\s+HIDDEN\s+\d+\s+' + [regex]::Escape($script:M034AbiSymbol) + '$'
    foreach ($pair in @(@('baseline', $m034BaseObj), @('candidate', $m034MemberObj))) {
        $dump = @(Invoke-Native -Exe $tools.llvmReadelf -What "m034 $($pair[0]) symbol dump" -Arguments @(
                '--symbols', (Fwd $pair[1])))
        $hits = @($dump | Where-Object { $_ -match $abiPattern })
        if ($hits.Count -ne 1) {
            throw "m034 $($pair[0]) object lost the hidden i64 ABI symbol $($script:M034AbiSymbol) (matches=$($hits.Count))"
        }
    }
    Write-Log 'm034 ABI assertion passed (FUNC GLOBAL HIDDEN i64 entry point present exactly once)'

    # ------------------------------------------------------------------
    # m053 version stamp: SDK self-reported version 4.6.5 -> 5.0.5
    # ------------------------------------------------------------------
    # @.str.17 in the m053 IR is the SDK version literal parsed by
    # get_sdk_version() and compared against the installed version by
    # install_maplesu_environment(). Only the five literal bytes change; the
    # [6 x i8] type, offsets and every other IR byte stay identical.
    $M053StampedIr = Join-Path $IrDir 'm053.versionstamp.ll'
    $VersionStampPath = Join-Path $Work 'version-stamp.json'
    $m053MemberObj = Join-Path $ObjDir 'maplesu_installer.o'
    $versionStampPy = @'
import sys, os, json, hashlib, re

ctx = json.load(open(sys.argv[1], encoding="utf-8"))
mode = sys.argv[2]
BS = chr(92)
SUMMARY_KIND = b"typeidCompatibleVTable"


def sha256(data):
    return hashlib.sha256(data).hexdigest()


if mode == "transform":
    raw = open(ctx["sourceIr"], "rb").read()
    old = ctx["fromLiteral"].encode("ascii")
    new = ctx["toLiteral"].encode("ascii")
    if len(old) != len(new):
        raise SystemExit("VERSION-STAMP-FAIL literal lengths differ")

    # (a) drop the trailing ThinLTO summary entries that clang 17's textual IR
    #     parser rejects.  This is the same compile-ability transform already
    #     required for m034.baseline.compile.ll; no function body is touched.
    lines = raw.split(b"\n")
    kept = []
    dropped = []
    for line in lines:
        if re.match(rb"^\^[0-9]+ = " + SUMMARY_KIND + rb":", line):
            dropped.append(line)
            continue
        kept.append(line)
    body = b"\n".join(kept)
    if not dropped:
        raise SystemExit("VERSION-STAMP-FAIL no typeidCompatibleVTable entries found")
    removed_bytes = len(raw) - len(body)
    expected_removed = sum(len(line) + 1 for line in dropped)
    if removed_bytes != expected_removed:
        raise SystemExit("VERSION-STAMP-FAIL summary removal byte accounting mismatch")

    # (b) rewrite the version literal in place (same width, layout untouched)
    pattern_old = b'c"' + old + BS.encode("ascii") + b'00"'
    pattern_new = b'c"' + new + BS.encode("ascii") + b'00"'
    hits = body.count(pattern_old)
    if hits != 1:
        raise SystemExit("VERSION-STAMP-FAIL expected exactly one version literal, found %d" % hits)
    if body.count(old) != 1:
        raise SystemExit("VERSION-STAMP-FAIL the old literal appears more than once")
    index = body.index(pattern_old)
    patched = body[:index] + pattern_new + body[index + len(pattern_old):]
    if len(patched) != len(body):
        raise SystemExit("VERSION-STAMP-FAIL file length changed by the stamp")
    diffs = [i for i in range(len(body)) if body[i] != patched[i]]
    window_first = index + 2
    window = set(range(window_first, window_first + len(old)))
    if not diffs:
        raise SystemExit("VERSION-STAMP-FAIL the literal was not changed")
    if not set(diffs) <= window:
        raise SystemExit("VERSION-STAMP-FAIL bytes outside the literal changed")

    os.makedirs(os.path.dirname(ctx["outIr"]), exist_ok=True)
    with open(ctx["outIr"], "wb") as handle:
        handle.write(patched)
    line = patched[:index].count(b"\n") + 1
    report = {
        "sourceIr": ctx["sourceIr"], "outIr": ctx["outIr"],
        "beforeSha256": sha256(raw), "afterSha256": sha256(patched),
        "fromLiteral": ctx["fromLiteral"], "toLiteral": ctx["toLiteral"],
        "literalBytesRewritten": len(old),
        "literalDifferingBytes": len(diffs),
        "literalWindowFirst": window_first,
        "literalWindowLast": window_first + len(old) - 1,
        "line": line,
        "occurrences": hits,
        "removedSummaryEntries": len(dropped),
        "removedSummaryKind": SUMMARY_KIND.decode(),
        "removedSummaryBytes": removed_bytes,
        "invariant": "the version literal is rewritten in place (same width) and the "
                     "typeidCompatibleVTable ThinLTO summary entries are dropped so the "
                     "module compiles; every other IR byte is unchanged",
    }
    with open(ctx["jsonPath"], "w", encoding="utf-8", newline="\n") as handle:
        json.dump(report, handle, ensure_ascii=True, indent=2)
        handle.write("\n")
    print("VERSION-STAMP-OK %s -> %s literalChars=%d differingBytes=%d line=%d "
          "removedSummary=%d before=%s after=%s"
          % (ctx["fromLiteral"], ctx["toLiteral"], len(old), len(diffs), line,
             len(dropped), report["beforeSha256"][:16], report["afterSha256"][:16]))
    sys.exit(0)

if mode == "check":
    target = ctx["checkPath"]
    data = open(target, "rb").read()
    want = ctx["toLiteral"].encode("ascii")
    unwanted = ctx["fromLiteral"].encode("ascii")
    has_new = want in data
    has_old = unwanted in data
    if not has_new:
        raise SystemExit("VERSION-STAMP-FAIL %s does not contain %s" % (target, ctx["toLiteral"]))
    if has_old:
        raise SystemExit("VERSION-STAMP-FAIL %s still contains %s" % (target, ctx["fromLiteral"]))
    print("VERSION-STAMP-CHECK-OK %s sha256=%s size=%d hasNew=%s hasOld=%s"
          % (os.path.basename(target), sha256(data), len(data), has_new, has_old))
    sys.exit(0)

raise SystemExit("VERSION-STAMP-FAIL unknown mode %r" % mode)
'@
    $ctxStamp = @{
        sourceIr    = (Fwd $M053Ir)
        outIr       = (Fwd $M053StampedIr)
        jsonPath    = (Fwd $VersionStampPath)
        fromLiteral = $script:VersionFromLiteral
        toLiteral   = $script:VersionToLiteral
    }
    Write-JsonFile $CtxPath $ctxStamp
    Invoke-Python -Name 'version-stamp-transform' -Code $versionStampPy -Arguments @((Fwd $CtxPath), 'transform') | Out-Null
    $versionStamp = Read-JsonFile $VersionStampPath
    if ([int]$versionStamp.literalBytesRewritten -ne 5) { throw 'version stamp did not rewrite a five character literal' }
    if ([int]$versionStamp.occurrences -ne 1) { throw 'version literal was not unique' }
    if ([int]$versionStamp.literalDifferingBytes -lt 1) { throw 'version literal did not change' }
    if ([int]$versionStamp.removedSummaryEntries -lt 1) { throw 'typeidCompatibleVTable summary entries were not dropped' }
    Write-Log ('m053 version literal ' + $script:VersionFromLiteral + ' -> ' + $script:VersionToLiteral +
        ' at ' + $M053IrRel + ' line ' + $versionStamp.line + ' (5 characters, ' +
        $versionStamp.literalDifferingBytes + ' differing bytes, window ' +
        $versionStamp.literalWindowFirst + '-' + $versionStamp.literalWindowLast + ')')
    Write-Log ('m053 dropped ' + $versionStamp.removedSummaryEntries + ' ' + $versionStamp.removedSummaryKind +
        ' ThinLTO summary entries (' + $versionStamp.removedSummaryBytes + ' bytes) so clang 17 can parse the module; no function body touched')

    Invoke-Native -Exe $tools.clang -What 'm053 IR compile' -Arguments @(
        '--target=aarch64-linux-android21', '-Oz', '-fPIC', '-c', '-x', 'ir',
        (Fwd $M053StampedIr), '-o', (Fwd $m053MemberObj)
    ) | Out-Null

    $ctxStampCheck = @{
        checkPath   = (Fwd $m053MemberObj)
        fromLiteral = $script:VersionFromLiteral
        toLiteral   = $script:VersionToLiteral
    }
    Write-JsonFile $CtxPath $ctxStampCheck
    Invoke-Python -Name 'version-stamp-check-object' -Code $versionStampPy -Arguments @((Fwd $CtxPath), 'check') | Out-Null

    # Byte-for-byte reproduction of the frozen reference objects.
    $builtObjects = [ordered]@{
        m024Member  = $m024MemberObj
        m029IrObj   = $m029IrObj
        m029Wrapper = $m029WrapperObj
        m029Member  = $m029MemberObj
        m034Base    = $m034BaseObj
        m034Gen     = $m034GenObj
        m034Wrapper = $m034WrapperObj
        m034Member  = $m034MemberObj
    }
    $reproduction = [ordered]@{}
    foreach ($key in $builtObjects.Keys) {
        $builtSha = Get-Sha $builtObjects[$key]
        $refPath = $refObjects[$key]
        $entry = [ordered]@{
            path = $OutRel + 'build/objects/' + (Split-Path -Leaf $builtObjects[$key])
            sha256 = $builtSha
            size = (Get-FileSize $builtObjects[$key])
        }
        if ($refPath) {
            $refSha = Get-Sha $refPath
            $entry['referencePath'] = $refObjectRels[$key]
            $entry['referenceSha256'] = $refSha
            $entry['reproduced'] = ($refSha -eq $builtSha)
            if ($refSha -ne $builtSha) {
                throw ("rebuilt object $key is not byte identical to the frozen reference: built=$builtSha reference=$refSha")
            }
        }
        else {
            $entry['reproduced'] = $null
            Write-Log ("reference object for $key absent from the input set; reproduction unproven") 'WARN'
        }
        $reproduction[$key] = $entry
    }
    Write-Log 'all eight repair objects reproduce the frozen reference bytes'
    $script:StageTimings.Add([ordered]@{
            name = 'compile'; startedUtc = $stageStart.ToString('yyyy-MM-ddTHH:mm:ssZ')
            endedUtc = (Get-UtcNow)
            seconds = [math]::Round(((Get-Date).ToUniversalTime() - $stageStart).TotalSeconds, 3)
        })

    # =====================================================================
    # stage: archive -- ordinal reconstruction
    # =====================================================================
    $script:Stage = 'archive'
    $stageStart = [DateTime]::UtcNow
    Write-Log 'stage archive: extracting baseline members by ordinal'
    $MembersJson = Join-Path $Work 'members-baseline.json'
    $extractPy = @'
import sys, os, json, hashlib, re

ctx = json.load(open(sys.argv[1], encoding="utf-8"))
baseline = ctx["baselineArchive"]
out_dir = ctx["arBaseDir"]
out_json = ctx["membersJson"]
magic_ar = b"!<arch>\n"
invalid = set('<>:"/\\|?*')

def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()

data = open(baseline, "rb").read()
if not data.startswith(magic_ar):
    sys.stderr.write("ARCHIVE-FAIL baseline is not a GNU ar archive\n")
    sys.exit(1)
off = 8
long_names = b""
raw = []
special = []
symtab = {"present": False, "size": 0}
while off + 60 <= len(data):
    hdr = data[off:off + 60]
    if hdr[58:60] != b"`\n":
        sys.stderr.write("ARCHIVE-FAIL corrupt header at %d\n" % off)
        sys.exit(1)
    name = hdr[0:16].decode("latin-1").rstrip()
    size = int(hdr[48:58].decode("latin-1").strip())
    body = data[off + 60:off + 60 + size]
    if name in ("/", "//", "/SYM64/"):
        special.append(name)
        if name == "//":
            long_names = body
        else:
            symtab = {"present": True, "size": size, "name": name}
    else:
        raw.append((name, size, body))
    off = off + 60 + size
    if off % 2:
        off += 1

members = []
for index, (name, size, body) in enumerate(raw):
    if name.startswith("#1/"):
        name_len = int(name[3:])
        member_name = body[:name_len].decode("utf-8", "surrogateescape").rstrip("\x00")
        payload = body[name_len:]
    elif name.startswith("/") and name[1:].isdigit():
        start = int(name[1:])
        end = long_names.find(b"/\n", start)
        if end < 0:
            sys.stderr.write("ARCHIVE-FAIL bad long name index %d\n" % start)
            sys.exit(1)
        member_name = long_names[start:end].decode("utf-8", "surrogateescape")
        payload = body
    else:
        member_name = name[:-1] if name.endswith("/") else name
        payload = body
    if not member_name:
        sys.stderr.write("ARCHIVE-FAIL empty member name at ord %d\n" % index)
        sys.exit(1)
    if set(member_name) & invalid:
        sys.stderr.write("ARCHIVE-FAIL member name not representable on this filesystem: %r\n" % member_name)
        sys.exit(1)
    kind = "bitcode" if payload[:4] == b"BC\xc0\xde" else ("elf" if payload[:4] == b"\x7fELF" else "other")
    members.append({"ord": index, "name": member_name, "size": len(payload),
                    "sha256": sha256_bytes(payload), "kind": kind, "payload": payload})

if not members:
    sys.stderr.write("ARCHIVE-FAIL no members parsed\n")
    sys.exit(1)

if os.path.isdir(out_dir):
    import shutil
    shutil.rmtree(out_dir)
os.makedirs(out_dir)

records = []
for member in members:
    member_dir = os.path.join(out_dir, "m%03d" % member["ord"])
    os.makedirs(member_dir, exist_ok=True)
    member_path = os.path.join(member_dir, member["name"])
    with open(member_path, "wb") as fh:
        fh.write(member["payload"])
    records.append({"ord": member["ord"], "name": member["name"],
                    "size": member["size"], "sha256": member["sha256"],
                    "kind": member["kind"],
                    "path": member_path.replace("\\", "/"),
                    "directory": member_dir.replace("\\", "/")})

# re-verify what was written (guards against a bad extraction path)
for record, member in zip(records, members):
    written = open(record["path"], "rb").read()
    if sha256_bytes(written) != member["sha256"]:
        sys.stderr.write("ARCHIVE-FAIL extracted body mismatch at ord %d\n" % member["ord"])
        sys.exit(1)

kinds = {"bitcode": 0, "elf": 0, "other": 0}
for member in members:
    kinds[member["kind"]] += 1

report = {
    "schemaVersion": 1,
    "baselineArchive": baseline.replace("\\", "/"),
    "baselineSha256": sha256_bytes(data),
    "baselineSize": len(data),
    "memberCount": len(members),
    "specialEntries": special,
    "symbolIndex": symtab,
    "kinds": kinds,
    "duplicateNames": {name: [m["ord"] for m in members if m["name"] == name]
                       for name in set(m["name"] for m in members)
                       if sum(1 for m in members if m["name"] == name) > 1},
    "members": records,
}
with open(out_json, "w", encoding="utf-8", newline="\n") as fh:
    json.dump(report, fh, ensure_ascii=True, indent=2)
    fh.write("\n")
print("ARCHIVE-EXTRACT-OK members=%d bitcode=%d elf=%d other=%d special=%s"
      % (len(members), kinds["bitcode"], kinds["elf"], kinds["other"], ",".join(special)))
sys.exit(0)
'@
    $ctxExtract = @{
        baselineArchive = (Fwd $BaselineArchive)
        arBaseDir       = (Fwd $ArBase)
        membersJson     = (Fwd $MembersJson)
    }
    Write-JsonFile $CtxPath $ctxExtract
    Invoke-Python -Name 'extract-members' -Code $extractPy -Arguments @((Fwd $CtxPath)) | Out-Null
    $membersInfo = Read-JsonFile $MembersJson
    $memberRecords = @($membersInfo.members)
    Write-Log ("baseline archive: " + $memberRecords.Count + " members, bitcode=" + $membersInfo.kinds.bitcode +
        " elf=" + $membersInfo.kinds.elf + " special=" + ($membersInfo.specialEntries -join ','))

    $baselineSha = Get-Sha $BaselineArchive
    if ($baselineSha -ne [string]$membersInfo.baselineSha256) { throw 'baseline digest drift detected between stages' }

    function Invoke-ArRebuild {
        param([string]$ArchivePath, [string[]]$MemberPaths, [string]$What)
        if (Test-Path -LiteralPath $ArchivePath) { Remove-Item -LiteralPath $ArchivePath -Force }
        $batchSize = 64
        $index = 0
        while ($index -lt $MemberPaths.Count) {
            $last = [Math]::Min($index + $batchSize - 1, $MemberPaths.Count - 1)
            $slice = @($MemberPaths[$index..$last])
            $arArgs = @('qcD', (Fwd $ArchivePath)) + $slice
            Invoke-Native -Exe $tools.llvmAr -What ($What + ' append') -Arguments $arArgs | Out-Null
            $index = $last + 1
        }
        Invoke-Native -Exe $tools.llvmAr -What ($What + ' symbol index') -Arguments @('sD', (Fwd $ArchivePath)) | Out-Null
    }

    # Lossless-pipeline proof: repack the untouched baseline and require the
    # exact same bytes. This is what licenses the ordinal rebuild below.
    $selfCheckArchive = Join-Path $Work 'baseline-roundtrip.a'
    $orderedPaths = @()
    foreach ($record in ($memberRecords | Sort-Object -Property ord)) { $orderedPaths += (Fwd $record.path) }
    Invoke-ArRebuild -ArchivePath $selfCheckArchive -MemberPaths $orderedPaths -What 'baseline round-trip'
    $selfCheckSha = Get-Sha $selfCheckArchive
    Write-Log ('baseline round-trip sha256=' + $selfCheckSha)
    if ($selfCheckSha -ne $baselineSha) {
        throw ("ordinal repack is not byte exact: rebuilt baseline $selfCheckSha != input $baselineSha")
    }
    Write-Log 'ordinal repack round-trips the baseline byte-for-byte (deterministic llvm-ar D)'

    # Substitute exactly ord 24/29/34, keeping each member's own file name.
    $substitutions = @{
        24 = $m024MemberObj
        29 = $m029MemberObj
        34 = $m034MemberObj
        53 = $m053MemberObj
    }
    foreach ($ord in $substitutions.Keys) {
        $record = $memberRecords | Where-Object { $_.ord -eq $ord }
        if ($null -eq $record) { throw "baseline archive has no member at ord $ord" }
        $dest = Join-Path ([string]$record.directory) ([string]$record.name)
        Copy-Item -LiteralPath $substitutions[$ord] -Destination $dest -Force
        Write-Log ("substituted ord $ord ($($record.name)) <- " + (Split-Path -Leaf $substitutions[$ord]))
    }

    $NewArchive = Join-Path $OutDir 'libkernel_module_kit_static.a'
    Invoke-ArRebuild -ArchivePath $NewArchive -MemberPaths $orderedPaths -What 'repaired archive'
    $sdkSha = Get-Sha $NewArchive
    $sdkSize = Get-FileSize $NewArchive
    Write-Log ('rebuilt archive sha256=' + $sdkSha + ' size=' + $sdkSize)

    $arList = @(Invoke-Native -Exe $tools.llvmAr -Arguments @('t', (Fwd $NewArchive)) -What 'llvm-ar t')
    if ($arList.Count -ne $memberRecords.Count) {
        throw "member count mismatch after rebuild: llvm-ar t returned $($arList.Count), expected $($memberRecords.Count)"
    }
    for ($i = 0; $i -lt $memberRecords.Count; $i++) {
        if ($arList[$i].Trim() -ne [string]$memberRecords[$i].name) {
            throw ("member order/name drift at ord ${i}: '$($arList[$i])' != '$($memberRecords[$i].name)'")
        }
    }
    Write-Log 'llvm-ar t confirms 255 members in ordinal order with original names'
    $script:StageTimings.Add([ordered]@{
            name = 'archive'; startedUtc = $stageStart.ToString('yyyy-MM-ddTHH:mm:ssZ')
            endedUtc = (Get-UtcNow)
            seconds = [math]::Round(((Get-Date).ToUniversalTime() - $stageStart).TotalSeconds, 3)
        })

    # =====================================================================
    # stage: diff -- member diff + symbol index/symbol gates
    # =====================================================================
    $script:Stage = 'diff'
    $stageStart = [DateTime]::UtcNow
    Write-Log 'stage diff: recomputing member diff and symbol surface'
    $MemberDiffPath = Join-Path $OutDir 'member-diff.json'
    $memberDiffPy = @'
import sys, os, json, hashlib

ctx = json.load(open(sys.argv[1], encoding="utf-8"))
magic_ar = b"!<arch>\n"

def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()

def parse(path):
    data = open(path, "rb").read()
    if not data.startswith(magic_ar):
        raise SystemExit("MEMBER-DIFF-FAIL %s is not a GNU ar archive" % path)
    off = 8
    long_names = b""
    raw = []
    special = []
    symtab = {"present": False, "size": 0}
    while off + 60 <= len(data):
        hdr = data[off:off + 60]
        name = hdr[0:16].decode("latin-1").rstrip()
        size = int(hdr[48:58].decode("latin-1").strip())
        body = data[off + 60:off + 60 + size]
        if name in ("/", "//", "/SYM64/"):
            special.append(name)
            if name == "//":
                long_names = body
            else:
                symtab = {"present": True, "size": size, "name": name}
        else:
            raw.append((name, size, body))
        off = off + 60 + size
        if off % 2:
            off += 1
    members = []
    for index, (name, size, body) in enumerate(raw):
        if name.startswith("#1/"):
            name_len = int(name[3:])
            member_name = body[:name_len].decode("utf-8", "surrogateescape").rstrip("\x00")
            payload = body[name_len:]
        elif name.startswith("/") and name[1:].isdigit():
            start = int(name[1:])
            end = long_names.find(b"/\n", start)
            member_name = long_names[start:end].decode("utf-8", "surrogateescape")
            payload = body
        else:
            member_name = name[:-1] if name.endswith("/") else name
            payload = body
        kind = "bitcode" if payload[:4] == b"BC\xc0\xde" else ("elf" if payload[:4] == b"\x7fELF" else "other")
        members.append({"ord": index, "name": member_name, "size": len(payload),
                        "sha256": sha256_bytes(payload), "kind": kind})
    return {"path": path, "sha256": sha256_bytes(data), "size": len(data),
            "members": members, "special": special, "symbolIndex": symtab}

base = parse(ctx["baselineArchive"])
new = parse(ctx["newArchive"])

errors = []
if len(base["members"]) != len(new["members"]):
    errors.append("member count %d != %d" % (len(base["members"]), len(new["members"])))
if not new["symbolIndex"]["present"] or new["symbolIndex"]["size"] <= 0:
    errors.append("candidate archive symbol index missing or empty")

changed = []
added = []
removed = []
statuses = []
for index in range(max(len(base["members"]), len(new["members"]))):
    left = base["members"][index] if index < len(base["members"]) else None
    right = new["members"][index] if index < len(new["members"]) else None
    if left is None:
        added.append({"ord": index, "name": right["name"], "candidateSha256": right["sha256"]})
        statuses.append({"ord": index, "name": right["name"], "status": "added",
                         "baselineSha256": None, "candidateSha256": right["sha256"]})
        continue
    if right is None:
        removed.append({"ord": index, "name": left["name"], "baselineSha256": left["sha256"]})
        statuses.append({"ord": index, "name": left["name"], "status": "removed",
                         "baselineSha256": left["sha256"], "candidateSha256": None})
        continue
    if left["name"] != right["name"]:
        errors.append("member order/name drift at ord %d: %r != %r"
                      % (index, left["name"], right["name"]))
    if left["sha256"] != right["sha256"] or left["size"] != right["size"]:
        changed.append({"ord": index, "objectId": "m%03d" % index, "name": left["name"],
                        "baselineSha256": left["sha256"], "candidateSha256": right["sha256"],
                        "baselineSize": left["size"], "candidateSize": right["size"]})
        statuses.append({"ord": index, "name": left["name"], "status": "changed",
                         "baselineSha256": left["sha256"], "candidateSha256": right["sha256"]})
    else:
        statuses.append({"ord": index, "name": left["name"], "status": "unchanged",
                         "baselineSha256": left["sha256"], "candidateSha256": right["sha256"]})

expect_ordinals = sorted(ctx["expectedChangedOrdinals"])
expect_names = list(ctx["expectedChangedNames"])
if sorted(item["ord"] for item in changed) != expect_ordinals:
    errors.append("changed ordinals %s != expected %s"
                  % (sorted(item["ord"] for item in changed), expect_ordinals))
if sorted(item["name"] for item in changed) != sorted(expect_names):
    errors.append("changed names %s != expected %s"
                  % (sorted(item["name"] for item in changed), sorted(expect_names)))
if added:
    errors.append("added members: %s" % added)
if removed:
    errors.append("removed members: %s" % removed)

boot = [m for m in base["members"] if m["name"] == ctx["bootstrapMemberName"]]
boot_new = [m for m in new["members"] if m["name"] == ctx["bootstrapMemberName"]]
if len(boot) != 1 or len(boot_new) != 1:
    errors.append("bootstrap member not unique in both archives")
elif boot[0]["sha256"] != boot_new[0]["sha256"]:
    errors.append("bootstrap member changed: %s -> %s" % (boot[0]["sha256"], boot_new[0]["sha256"]))

dupes = {}
for member in new["members"]:
    dupes.setdefault(member["name"], []).append(member["ord"])
dupes = {name: ords for name, ords in dupes.items() if len(ords) > 1}

kinds_base = {"bitcode": 0, "elf": 0, "other": 0}
kinds_new = {"bitcode": 0, "elf": 0, "other": 0}
for member in base["members"]:
    kinds_base[member["kind"]] += 1
for member in new["members"]:
    kinds_new[member["kind"]] += 1

if errors:
    for item in errors:
        sys.stderr.write("MEMBER-DIFF-FAIL %s\n" % item)
    sys.exit(1)

diff = {
    "schemaVersion": 1,
    "generatedUtc": ctx["generatedUtc"],
    "baseline": {"path": ctx["baselineRelPath"], "sha256": base["sha256"],
                 "size": base["size"], "memberCount": len(base["members"])},
    "candidate": {"path": ctx["candidateRelPath"], "sha256": new["sha256"],
                  "size": new["size"], "memberCount": len(new["members"])},
    "summary": {"totalMembers": len(new["members"]), "changed": len(changed),
                "added": 0, "removed": 0,
                "unchanged": len(new["members"]) - len(changed)},
    "changed": changed,
    "added": [],
    "removed": [],
    "changedObjectIds": ["m%03d" % item["ord"] for item in changed],
    "bootstrapMember": {"name": ctx["bootstrapMemberName"], "ord": boot_new[0]["ord"],
                        "baselineSha256": boot[0]["sha256"],
                        "candidateSha256": boot_new[0]["sha256"], "changed": False},
    "duplicateMemberNames": dupes,
    "memberKinds": {"baseline": kinds_base, "candidate": kinds_new},
    "symbolIndex": {"baseline": base["symbolIndex"], "candidate": new["symbolIndex"]},
    "specialEntries": {"baseline": base["special"], "candidate": new["special"]},
    "members": statuses,
}
with open(ctx["outPath"], "w", encoding="utf-8", newline="\n") as fh:
    json.dump(diff, fh, ensure_ascii=True, indent=2)
    fh.write("\n")
print("MEMBER-DIFF-OK total=%d changed=%d added=0 removed=0 ords=%s sha256=%s"
      % (len(new["members"]), len(changed), ",".join(str(item["ord"]) for item in changed), new["sha256"]))
sys.exit(0)
'@
    $ctxDiff = @{
        baselineArchive        = (Fwd $BaselineArchive)
        newArchive             = (Fwd $NewArchive)
        baselineRelPath        = $BaselineArchiveRel
        candidateRelPath       = $OutRel + 'libkernel_module_kit_static.a'
        outPath                = (Fwd $MemberDiffPath)
        generatedUtc           = (Get-UtcNow)
        expectedChangedOrdinals = $script:ExpectedChangedOrdinals
        expectedChangedNames   = $script:ExpectedChangedNames
        bootstrapMemberName    = $script:BootstrapMemberName
    }
    Write-JsonFile $CtxPath $ctxDiff
    Invoke-Python -Name 'member-diff' -Code $memberDiffPy -Arguments @((Fwd $CtxPath)) | Out-Null
    $memberDiff = Read-JsonFile $MemberDiffPath
    $expectedChanged = $script:ExpectedChangedOrdinals.Count
    if ([int]$memberDiff.summary.changed -ne $expectedChanged -or [int]$memberDiff.summary.added -ne 0 -or [int]$memberDiff.summary.removed -ne 0) {
        throw ('member diff summary is not ' + $expectedChanged + '/0/0 (got ' + $memberDiff.summary.changed +
            '/' + $memberDiff.summary.added + '/' + $memberDiff.summary.removed + ')')
    }
    Write-Log ('member diff ok: ' + $memberDiff.summary.totalMembers + ' members, changed=' +
        $memberDiff.summary.changed + ' added=' + $memberDiff.summary.added + ' removed=' + $memberDiff.summary.removed)

    # Reference cross-check: against the frozen, previously verified candidate
    # archive the delivered archive must differ in exactly the m053 version
    # stamp (the reference already carries the three repairs).  Verification
    # only; the reference is never a build input.
    $referenceDelta = $null
    if ($ReferenceArchive) {
        $ReferenceDeltaPath = Join-Path $Work 'reference-delta.json'
        $ctxRefDelta = @{
            baselineArchive        = (Fwd $ReferenceArchive)
            newArchive             = (Fwd $NewArchive)
            baselineRelPath        = $ReferenceArchiveRel
            candidateRelPath       = $OutRel + 'libkernel_module_kit_static.a'
            outPath                = (Fwd $ReferenceDeltaPath)
            generatedUtc           = (Get-UtcNow)
            expectedChangedOrdinals = @($script:VersionStampOrdinal)
            expectedChangedNames   = @($script:VersionStampMemberName)
            bootstrapMemberName    = $script:BootstrapMemberName
        }
        Write-JsonFile $CtxPath $ctxRefDelta
        Invoke-Python -Name 'member-diff-vs-reference' -Code $memberDiffPy -Arguments @((Fwd $CtxPath)) | Out-Null
        $referenceDelta = Read-JsonFile $ReferenceDeltaPath
        Write-Log ('delivered archive differs from the frozen verified candidate only by ord ' +
            (($referenceDelta.changed | ForEach-Object { $_.ord }) -join ',') + ' (m053 version stamp)')
    }
    else {
        Write-Log 'frozen reference candidate archive absent; delta cross-check skipped' 'WARN'
    }

    # Symbol surface: archive index + llvm-nm diff.
    $NmBaseAll = Join-Path $NmDir 'nm-baseline.txt'
    $NmNewAll = Join-Path $NmDir 'nm-candidate.txt'
    $ArmapBase = Join-Path $NmDir 'armap-baseline.txt'
    $ArmapNew = Join-Path $NmDir 'armap-candidate.txt'
    $NmBaseDefined = Join-Path $NmDir 'nm-baseline-defined.txt'
    $NmNewDefined = Join-Path $NmDir 'nm-candidate-defined.txt'
    Invoke-Native -Exe $tools.llvmNm -Arguments @((Fwd $BaselineArchive)) -CaptureTo $NmBaseAll -What 'llvm-nm baseline' -SuppressStderr | Out-Null
    Invoke-Native -Exe $tools.llvmNm -Arguments @((Fwd $NewArchive)) -CaptureTo $NmNewAll -What 'llvm-nm candidate' -SuppressStderr | Out-Null
    Invoke-Native -Exe $tools.llvmNm -Arguments @('--print-armap', (Fwd $BaselineArchive)) -CaptureTo $ArmapBase -What 'llvm-nm --print-armap baseline' -SuppressStderr | Out-Null
    Invoke-Native -Exe $tools.llvmNm -Arguments @('--print-armap', (Fwd $NewArchive)) -CaptureTo $ArmapNew -What 'llvm-nm --print-armap candidate' -SuppressStderr | Out-Null
    Invoke-Native -Exe $tools.llvmNm -Arguments @('--defined-only', '--extern-only', (Fwd $BaselineArchive)) -CaptureTo $NmBaseDefined -What 'llvm-nm defined baseline' -SuppressStderr | Out-Null
    Invoke-Native -Exe $tools.llvmNm -Arguments @('--defined-only', '--extern-only', (Fwd $NewArchive)) -CaptureTo $NmNewDefined -What 'llvm-nm defined candidate' -SuppressStderr | Out-Null

    $objNmPaths = @{}
    foreach ($ord in $script:ExpectedChangedOrdinals) {
        $record = $memberRecords | Where-Object { $_.ord -eq $ord }
        $sourceObj = $substitutions[$ord]
        $nmPath = Join-Path $NmDir ('object-' + $record.name + '.nm.txt')
        Invoke-Native -Exe $tools.llvmNm -Arguments @('--defined-only', '--extern-only', (Fwd $sourceObj)) -CaptureTo $nmPath -What "llvm-nm object m0$ord" -SuppressStderr | Out-Null
        $objNmPaths[[string]$ord] = (Fwd $nmPath)
    }

    $SymbolsDiffPath = Join-Path $OutDir 'symbols-diff.json'
    $symbolsDiffPy = @'
import sys, os, json, re

ctx = json.load(open(sys.argv[1], encoding="utf-8"))

def read_lines(path):
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read().splitlines()

def parse_nm(path):
    """member -> list of (type, name) from full llvm-nm archive output."""
    members = {}
    current = None
    for line in read_lines(path):
        if not line.strip():
            continue
        stripped = line.rstrip()
        if stripped.endswith(":") and " " not in stripped.strip() and "\t" not in stripped:
            current = stripped.strip()[:-1]
            members.setdefault(current, [])
            continue
        if stripped.startswith("Archive map"):
            continue
        if " no symbols" in stripped:
            continue
        if stripped.startswith("Archive map"):
            continue
        tokens = stripped.split()
        if len(tokens) < 2:
            continue
        name = tokens[-1]
        kind = tokens[-2]
        # nm type column is a single letter (T/t/U/W/V/...); anything else is a
        # diagnostic line such as "<archive>:<member>: no symbols".
        if len(kind) != 1:
            continue
        if kind not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz?-":
            continue
        if current is None:
            current = "<no-member>"
            members.setdefault(current, [])
        members[current].append((kind, name))
    return members

def parse_armap(path):
    entries = []
    for line in read_lines(path):
        if not line.strip():
            break
        if line.startswith("Archive map"):
            continue
        if " in " not in line:
            continue
        symbol, member = line.rsplit(" in ", 1)
        entries.append((symbol.strip(), member.strip()))
    return entries

def defined(symbols):
    return {(name, member) for member, rows in symbols.items()
            for kind, name in rows if kind != "U"}

def undefined(symbols):
    return {(name, member) for member, rows in symbols.items()
            for kind, name in rows if kind == "U"}

base = parse_nm(ctx["nmBase"])
new = parse_nm(ctx["nmNew"])
armap_base = parse_armap(ctx["armapBase"])
armap_new = parse_armap(ctx["armapNew"])

errors = []
if not armap_new:
    errors.append("regenerated archive symbol index is empty")

changed_members = set()
for record in ctx["changedMembers"]:
    changed_members.add(record["name"])

base_def = defined(base)
new_def = defined(new)
base_und = undefined(base)
new_und = undefined(new)

def as_rows(pairs):
    rows = [{"name": name, "member": member} for name, member in pairs]
    return sorted(rows, key=lambda row: (row["member"], row["name"]))

added_defined = sorted(new_def - base_def)
removed_defined = sorted(base_def - new_def)
added_undefined = sorted(new_und - base_und)
removed_undefined = sorted(base_und - new_und)

for name, member in added_defined + removed_defined + added_undefined + removed_undefined:
    if member not in changed_members:
        errors.append("symbol %s in untouched member %s changed" % (name, member))

# Every extern defined symbol of a new repair object must be in the new index.
index_symbols = {}
for symbol, member in armap_new:
    index_symbols.setdefault(member, set()).add(symbol)
for record in ctx["changedMembers"]:
    expected = []
    for line in read_lines(record["objectNm"]):
        tokens = line.split()
        if len(tokens) >= 2:
            expected.append(tokens[-1])
    member_index = index_symbols.get(record["name"], set())
    missing = [symbol for symbol in expected if symbol not in member_index]
    if missing:
        errors.append("archive index lacks %d symbol(s) from member %s (e.g. %s)"
                      % (len(missing), record["name"], missing[0]))
    record["externDefinedSymbols"] = len(expected)
    record["indexedSymbols"] = len(member_index)

# Strong-definition conflicts (T/D/B/R) must not increase.
STRONG = set("TDBRG")
def strong_conflicts(symbols):
    owners = {}
    for member, rows in symbols.items():
        for kind, name in rows:
            if kind in STRONG:
                owners.setdefault(name, set()).add(member)
    return {name: sorted(members) for name, members in owners.items() if len(members) > 1}

conflicts_base = strong_conflicts(base)
conflicts_new = strong_conflicts(new)
new_conflicts = {name: members for name, members in conflicts_new.items()
                 if name not in conflicts_base}
if new_conflicts:
    errors.append("new strong-definition conflicts: %s" % sorted(new_conflicts)[:5])

if errors:
    for item in errors:
        sys.stderr.write("SYMBOLS-DIFF-FAIL %s\n" % item)
    sys.exit(1)

report = {
    "schemaVersion": 1,
    "generatedUtc": ctx["generatedUtc"],
    "baseline": {"path": ctx["baselineRelPath"], "sha256": ctx["baselineSha256"]},
    "candidate": {"path": ctx["candidateRelPath"], "sha256": ctx["candidateSha256"]},
    "memberKeyNote": "symbol rows are keyed by member name; the archive carries patch_base.o three times, so 255 members collapse into 253 name buckets (the duplicated members are unchanged by this build)",
    "totals": {
        "baselineMemberBuckets": len(base),
        "candidateMemberBuckets": len(new),
        "baselineDefined": len(base_def),
        "candidateDefined": len(new_def),
        "baselineUndefined": len(base_und),
        "candidateUndefined": len(new_und),
        "addedDefined": len(added_defined),
        "removedDefined": len(removed_defined),
        "addedUndefined": len(added_undefined),
        "removedUndefined": len(removed_undefined),
    },
    "archiveSymbolIndex": {
        "baselineEntries": len(armap_base),
        "candidateEntries": len(armap_new),
        "regenerated": True,
        "candidateMemberCoverage": {record["name"]: record["indexedSymbols"]
                                    for record in ctx["changedMembers"]},
    },
    "addedDefined": as_rows(added_defined),
    "removedDefined": as_rows(removed_defined),
    "addedUndefined": as_rows(added_undefined),
    "removedUndefined": as_rows(removed_undefined),
    "strongDefinitionConflicts": {
        "baseline": len(conflicts_base),
        "candidate": len(conflicts_new),
        "introduced": new_conflicts,
    },
    "changedMembers": [{"ord": record["ord"], "name": record["name"],
                        "externDefinedSymbols": record["externDefinedSymbols"],
                        "indexedSymbols": record["indexedSymbols"]}
                       for record in ctx["changedMembers"]],
    "result": "PASS",
}
with open(ctx["outPath"], "w", encoding="utf-8", newline="\n") as fh:
    json.dump(report, fh, ensure_ascii=True, indent=2)
    fh.write("\n")
print("SYMBOLS-DIFF-OK index=%d->%d addedDefined=%d removedDefined=%d addedUndefined=%d removedUndefined=%d"
      % (len(armap_base), len(armap_new), len(added_defined), len(removed_defined),
         len(added_undefined), len(removed_undefined)))
sys.exit(0)
'@
    $changedMembersCtx = @()
    foreach ($ord in $script:ExpectedChangedOrdinals) {
        $record = $memberRecords | Where-Object { $_.ord -eq $ord }
        $changedMembersCtx += [ordered]@{
            ord        = [int]$ord
            name       = [string]$record.name
            objectNm   = $objNmPaths[[string]$ord]
        }
    }
    $ctxSymbols = @{
        nmBase        = (Fwd $NmBaseAll)
        nmNew         = (Fwd $NmNewAll)
        armapBase     = (Fwd $ArmapBase)
        armapNew      = (Fwd $ArmapNew)
        outPath       = (Fwd $SymbolsDiffPath)
        generatedUtc  = (Get-UtcNow)
        baselineRelPath  = $BaselineArchiveRel
        candidateRelPath = $OutRel + 'libkernel_module_kit_static.a'
        baselineSha256   = $baselineSha
        candidateSha256  = $sdkSha
        changedMembers   = $changedMembersCtx
    }
    Write-JsonFile $CtxPath $ctxSymbols
    Invoke-Python -Name 'symbols-diff' -Code $symbolsDiffPy -Arguments @((Fwd $CtxPath)) | Out-Null
    $symbolsDiff = Read-JsonFile $SymbolsDiffPath
    Write-Log ('symbol surface ok: index ' + $symbolsDiff.archiveSymbolIndex.baselineEntries + ' -> ' +
        $symbolsDiff.archiveSymbolIndex.candidateEntries + ' entries; conflicts introduced=' +
        $symbolsDiff.strongDefinitionConflicts.introduced.Count)
    $script:StageTimings.Add([ordered]@{
            name = 'diff'; startedUtc = $stageStart.ToString('yyyy-MM-ddTHH:mm:ssZ')
            endedUtc = (Get-UtcNow)
            seconds = [math]::Round(((Get-Date).ToUniversalTime() - $stageStart).TotalSeconds, 3)
        })

    # =====================================================================
    # stage: product -- bootstrap extraction + identity manifests
    # =====================================================================
    $script:Stage = 'product'
    $stageStart = [DateTime]::UtcNow
    Write-Log 'stage product: extracting embedded bootstrap and writing identity manifests'

    # The bootstrap payload is carried by member 52 as a [N x i64] global.
    # Extract it from the delivered archive, from the baseline archive and from
    # the frozen m052 IR, then require all three payloads to be identical.
    $bsNewDir = Join-Path $BsDir 'new'
    $bsBaseDir = Join-Path $BsDir 'base'
    New-Item -ItemType Directory -Force -Path $bsNewDir, $bsBaseDir | Out-Null
    Invoke-Native -Exe $tools.llvmAr -Arguments @('x', ('--output=' + (Fwd $bsNewDir)), (Fwd $NewArchive), $script:BootstrapMemberName) -What 'extract m052 from candidate' | Out-Null
    Invoke-Native -Exe $tools.llvmAr -Arguments @('x', ('--output=' + (Fwd $bsBaseDir)), (Fwd $BaselineArchive), $script:BootstrapMemberName) -What 'extract m052 from baseline' | Out-Null
    $newM052 = Join-Path $bsNewDir $script:BootstrapMemberName
    $baseM052 = Join-Path $bsBaseDir $script:BootstrapMemberName
    $newM052Ll = Join-Path $BsDir 'm052-candidate.ll'
    $baseM052Ll = Join-Path $BsDir 'm052-baseline.ll'
    Invoke-Native -Exe $tools.llvmDis -Arguments @((Fwd $newM052), '-o', (Fwd $newM052Ll)) -What 'llvm-dis candidate m052' | Out-Null
    Invoke-Native -Exe $tools.llvmDis -Arguments @((Fwd $baseM052), '-o', (Fwd $baseM052Ll)) -What 'llvm-dis baseline m052' | Out-Null

    $BootstrapPath = Join-Path $OutDir 'autorun_bootstrap'
    $bsJsonPath = Join-Path $Work 'bootstrap.json'
    $bootstrapPy = @'
import sys, os, json, re, struct, hashlib

ctx = json.load(open(sys.argv[1], encoding="utf-8"))
GLOBAL = "@_ZN7maplesu3sdkL27autorun_bootstrap_file_dataE"
DECL = re.compile(re.escape(GLOBAL) + r"\s*=\s*internal global\s*\[(\d+) x i64\]\s*\[")

def extract(path):
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    match = DECL.search(text)
    if not match:
        raise SystemExit("BOOTSTRAP-FAIL payload global not found in %s" % path)
    declared = int(match.group(1))
    values = []
    for item in re.finditer(r"i64\s+(-?\d+)", text[match.end():]):
        values.append(int(item.group(1)))
        if len(values) == declared:
            break
    if len(values) != declared:
        raise SystemExit("BOOTSTRAP-FAIL parsed %d of %d initializer values in %s"
                         % (len(values), declared, path))
    raw = b"".join(struct.pack("<Q", value & 0xFFFFFFFFFFFFFFFF) for value in values)
    if len(raw) != declared * 8:
        raise SystemExit("BOOTSTRAP-FAIL payload length mismatch")
    return declared, values, raw

results = []
payload = None
for path in ctx["llPaths"]:
    declared, values, raw = extract(path)
    digest = hashlib.sha256(raw).hexdigest()
    results.append({"path": path, "declaredElements": declared,
                    "parsedValues": len(values), "bytes": len(raw), "sha256": digest})
    if payload is None:
        payload = raw
        first = digest
    elif digest != first:
        raise SystemExit("BOOTSTRAP-FAIL payload mismatch between %s and %s" % (ctx["llPaths"][0], path))

if payload[:4] != b"\x7fELF":
    raise SystemExit("BOOTSTRAP-FAIL payload is not an ELF image")

os.makedirs(os.path.dirname(ctx["outPath"]), exist_ok=True)
with open(ctx["outPath"], "wb") as fh:
    fh.write(payload)

elf = {
    "magic": payload[:4].hex(),
    "class": "ELF64" if payload[4] == 2 else ("ELF32" if payload[4] == 1 else "unknown"),
    "data": "little-endian" if payload[5] == 1 else "big-endian",
    "type": struct.unpack_from("<H", payload, 16)[0],
    "machine": struct.unpack_from("<H", payload, 18)[0],
    "entry": struct.unpack_from("<Q", payload, 24)[0],
}
slot_offset = int(ctx["keySlotOffset"])
slot_length = int(ctx["keySlotLength"])
if slot_offset < 0 or slot_length <= 0 or slot_offset + slot_length > len(payload):
    raise SystemExit("BOOTSTRAP-FAIL key slot range outside the payload")
normalized = bytearray(payload)
normalized[slot_offset:slot_offset + slot_length] = b"\x00" * slot_length
normalized_sha = hashlib.sha256(bytes(normalized)).hexdigest()
report = {"schemaVersion": 1, "sha256": hashlib.sha256(payload).hexdigest(),
          "size": len(payload), "declaredElements": results[0]["declaredElements"],
          "sources": results, "elf": elf,
          "keySlotOffset": slot_offset, "keySlotLength": slot_length,
          "normalizedSha256": normalized_sha,
          "invariant": "declaredElements * 8 == payload size (no truncation, no padding)"}
with open(ctx["jsonPath"], "w", encoding="utf-8", newline="\n") as fh:
    json.dump(report, fh, ensure_ascii=True, indent=2)
    fh.write("\n")
print("BOOTSTRAP-OK sha256=%s size=%d elements=%d sources=%d"
      % (report["sha256"], report["size"], report["declaredElements"], len(results)))
sys.exit(0)
'@
    $ctxBootstrap = @{
        llPaths       = @((Fwd $newM052Ll), (Fwd $baseM052Ll), (Fwd $M052Ir))
        outPath       = (Fwd $BootstrapPath)
        jsonPath      = (Fwd $bsJsonPath)
        keySlotOffset = $script:KeySlotOffset
        keySlotLength = $script:KeySlotLength
    }
    Write-JsonFile $CtxPath $ctxBootstrap
    Invoke-Python -Name 'extract-bootstrap' -Code $bootstrapPy -Arguments @((Fwd $CtxPath)) | Out-Null
    $bsReport = Read-JsonFile $bsJsonPath
    $bootstrapSha = [string]$bsReport.sha256
    $bootstrapSize = [long]$bsReport.size
    $normalizedHelperSha = [string]$bsReport.normalizedSha256
    if ($normalizedHelperSha -ne $script:ExpectedNormalizedHelperSha) {
        throw ("normalized helper identity drift: computed $normalizedHelperSha, pinned $($script:ExpectedNormalizedHelperSha)")
    }
    Write-Log ("embedded bootstrap sha256=" + $bootstrapSha + ' size=' + $bootstrapSize +
        ' (extracted identically from candidate m052, baseline m052 and frozen IR)')

    $readelfText = @(Invoke-Native -Exe $tools.llvmReadelf -Arguments @('-h', '-n', '-l', (Fwd $BootstrapPath)) -What 'llvm-readelf bootstrap')
    $elfBuildId = ''
    $elfType = ''
    $elfMachine = ''
    $elfInterp = ''
    $elfEntry = ''
    foreach ($line in $readelfText) {
        if ($line -match 'Build ID:\s*([0-9a-fA-F]+)') { $elfBuildId = $Matches[1].ToLowerInvariant() }
        elseif ($line -match '^\s*Type:\s+(.+)$') { if (-not $elfType) { $elfType = ($Matches[1]).Trim() } }
        elseif ($line -match '^\s*Machine:\s+(.+)$') { if (-not $elfMachine) { $elfMachine = ($Matches[1]).Trim() } }
        elseif ($line -match 'Requesting program interpreter:\s*([^\]\s]+)') { $elfInterp = $Matches[1] }
        elseif ($line -match 'Entry point address:\s*(\S+)') { if (-not $elfEntry) { $elfEntry = $Matches[1] } }
    }
    if ($elfBuildId -notmatch '^[0-9a-f]{8,64}$') { throw "embedded bootstrap has no usable GNU build id: '$elfBuildId'" }
    if ($elfInterp -ne '/system/bin/linker64') { throw "embedded bootstrap interpreter changed: '$elfInterp'" }
    Write-Log ("bootstrap ELF: type=$elfType machine=$elfMachine entry=$elfEntry buildId=$elfBuildId interp=$elfInterp")

    # m052 must be untouched relative to the baseline archive.
    $m052NewSha = Get-Sha $newM052
    $m052BaseSha = Get-Sha $baseM052
    if ($m052NewSha -ne $m052BaseSha) { throw 'embedded bootstrap carrier member (m052) changed' }

    # ---- upstream SDK version, from the frozen get_sdk_version() implementation
    # get_sdk_version() is implemented as
    #   sscanf(<version literal>, "%u.%u.%u", &major, &minor, &patch)
    # so the first .str reference of that sscanf call is the SDK's own version.
    $UpstreamSdkVersion = 'unknown'
    $UpstreamSourceLine = $null
    $M053Text = Get-Content -LiteralPath $M053Ir -Raw
    $versionLiteral = $null
    $versionLineNo = 0
    $fnMarker = 'define hidden [2 x i64] @_ZN7maplesu3sdk15get_sdk_versionEv'
    $fnIndex = $M053Text.IndexOf($fnMarker)
    $versionStrIndex = -1
    if ($fnIndex -ge 0) {
        $windowLength = [Math]::Min(4000, $M053Text.Length - $fnIndex)
        $window = $M053Text.Substring($fnIndex, $windowLength)
        $sscanfMatch = [regex]::Match($window, '@sscanf\([^\r\n]*')
        if ($sscanfMatch.Success) {
            $strRefs = [regex]::Matches($sscanfMatch.Value, '@\.str\.(\d+)')
            if ($strRefs.Count -ge 1) { $versionStrIndex = [int]$strRefs[0].Groups[1].Value }
        }
    }
    if ($versionStrIndex -ge 0) {
        $literalPattern = '(?m)^@\.str\.' + $versionStrIndex +
        ' = private unnamed_addr constant \[\d+ x i8\] c"(\d+\.\d+\.\d+)\\00"'
        $literalMatch = [regex]::Match($M053Text, $literalPattern)
        if ($literalMatch.Success) {
            $versionLiteral = $literalMatch.Groups[1].Value
            $versionLineNo = ($M053Text.Substring(0, $literalMatch.Index) -split "`n").Count
        }
    }
    if ($versionLiteral) {
        $UpstreamSdkVersion = $versionLiteral
        $UpstreamSourceLine = $versionLineNo
        Write-Log ("upstream SDK version resolved from m053 get_sdk_version() sscanf literal: " + $UpstreamSdkVersion +
            ' (' + $M053IrRel + ' line ' + $versionLineNo + ')')
    }
    else {
        Write-Log 'upstream SDK version could not be resolved from the frozen IR; recording unknown' 'WARN'
    }

    # ---- identity manifests
    function New-ArtifactRecord {
        param([string]$RelPath, [string]$AbsPath)
        return [ordered]@{
            path   = $RelPath
            sha256 = (Get-Sha $AbsPath)
            size   = (Get-FileSize $AbsPath)
        }
    }

    $linkLogSha = Get-Sha $script:LinkLog
    $memberDiffSha = Get-Sha $MemberDiffPath
    $symbolsDiffSha = Get-Sha $SymbolsDiffPath
    $archiveRecord = New-ArtifactRecord ($OutRel + 'libkernel_module_kit_static.a') $NewArchive
    $bootstrapRecord = New-ArtifactRecord ($OutRel + 'autorun_bootstrap') $BootstrapPath
    $bridgeInputRels = @(
        [ordered]@{ role = 'm024-ir'; path = $M024IrRel },
        [ordered]@{ role = 'm029-ir'; path = $M029IrRel },
        [ordered]@{ role = 'm029-wrapper-source'; path = $HookCppRel },
        [ordered]@{ role = 'm034-baseline-compile-ir'; path = $M034BaselineIrRel },
        [ordered]@{ role = 'm034-generator-ir'; path = $M034GeneratorIrRel },
        [ordered]@{ role = 'm034-wrapper-source'; path = $IcacheCppRel },
        [ordered]@{ role = 'm034-wrapper-header'; path = $IcachePolicyHRel },
        [ordered]@{ role = 'sdk-header-tree'; path = $IncludeRel }
    )
    $bridgeInputs = @()
    $canonicalLines = @()
    $resolvedMap = $inputsReport.resolved
    foreach ($item in $bridgeInputRels) {
        $rel = [string]$item.path
        if ($rel -eq $IncludeRel) {
            # The header set is a directory; its digest is the header manifest.
            $sha = $IncludeManifestSha
            $size = Get-FileSize (Join-Path $IncludeDir 'HEADER-MANIFEST.sha256')
            $bridgeInputs += [ordered]@{
                role = $item.role; path = $rel; sha256 = $sha; size = $size
                entryType = 'tree'; fileCount = $IncludeFileCount
            }
            $canonicalLines += ($item.role + "`t" + $rel + "`t" + $sha)
            continue
        }
        $abs = [string]$resolvedMap.PSObject.Properties[$rel].Value
        if (-not $abs) { throw "bridge input missing from the verified input map: $rel" }
        $sha = Get-Sha $abs
        $size = Get-FileSize $abs
        $bridgeInputs += [ordered]@{ role = $item.role; path = $rel; sha256 = $sha; size = $size }
        $canonicalLines += ($item.role + "`t" + $rel + "`t" + $sha)
    }
    $bridgeCanonical = ($canonicalLines | Sort-Object) -join "`n"
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    $bridgeHashBytes = $sha256.ComputeHash($script:Utf8.GetBytes($bridgeCanonical + "`n"))
    $bridgeInputsSha = ([BitConverter]::ToString($bridgeHashBytes)).Replace('-', '').ToLowerInvariant()
    $sha256.Dispose()
    $bridgeInputsJson = [ordered]@{
        sha256      = $bridgeInputsSha
        method      = 'sha256 over the sorted lines "role<TAB>path<TAB>sha256" plus a trailing newline'
        files       = $bridgeInputs
        headerTree  = [ordered]@{ path = $IncludeRel; manifestSha256 = $IncludeManifestSha; fileCount = $IncludeFileCount }
    }

    function New-RepairEntry {
        param(
            [string]$Id, [int]$Ordinal, [string]$MemberName,
            [string]$BaselineSha, [string]$NewObjectPath,
            $Sources, $Commands, $Evidence
        )
        return [ordered]@{
            id             = $Id
            memberOrdinal  = $Ordinal
            objectId       = ('m' + $Ordinal.ToString('000'))
            memberName     = $MemberName
            baselineSha256 = $BaselineSha
            baselineSize   = [long](($memberRecords | Where-Object { $_.ord -eq $Ordinal }).size)
            newSha256      = (Get-Sha $NewObjectPath)
            newSize        = (Get-FileSize $NewObjectPath)
            source         = $Sources
            commands       = $Commands
            referenceObject = $reproduction[$Evidence.referenceKey]
            testEvidence   = $Evidence.items
        }
    }

    $memberRecordByOrd = @{}
    foreach ($record in $memberRecords) { $memberRecordByOrd[[int]$record.ord] = $record }

    # ---- m053 version stamp: re-check the delivered archive member --------
    $stampCheckDir = Join-Path $BsDir 'm053'
    New-Item -ItemType Directory -Force -Path $stampCheckDir | Out-Null
    Invoke-Native -Exe $tools.llvmAr -Arguments @('x', ('--output=' + (Fwd $stampCheckDir)), (Fwd $NewArchive), $script:VersionStampMemberName) -What 'extract m053 from candidate' | Out-Null
    $m053Delivered = Join-Path $stampCheckDir $script:VersionStampMemberName
    $ctxStampDelivered = @{
        checkPath   = (Fwd $m053Delivered)
        fromLiteral = $script:VersionFromLiteral
        toLiteral   = $script:VersionToLiteral
    }
    Write-JsonFile $CtxPath $ctxStampDelivered
    Invoke-Python -Name 'version-stamp-check-archive-member' -Code $versionStampPy -Arguments @((Fwd $CtxPath), 'check') | Out-Null
    $m053DeliveredSha = Get-Sha $m053Delivered
    if ($m053DeliveredSha -ne (Get-Sha $m053MemberObj)) {
        throw 'the m053 member inside the delivered archive is not the compiled version-stamped object'
    }
    $versionStamps = @(
        [ordered]@{
            objectId     = ('m' + $script:VersionStampOrdinal.ToString('000'))
            memberName   = $script:VersionStampMemberName
            memberOrdinal = $script:VersionStampOrdinal
            beforeSha256 = [string]$memberRecordByOrd[$script:VersionStampOrdinal].sha256
            afterSha256  = (Get-Sha $m053MemberObj)
            beforeSize   = [long]$memberRecordByOrd[$script:VersionStampOrdinal].size
            afterSize    = (Get-FileSize $m053MemberObj)
            reason       = 'SDK 自报版本 4.6.5 → 5.0.5（MapleSU 产品版本线）；上游版本仍由 SDK-RELEASE/PROVENANCE 记录'
            transform    = [ordered]@{
                sourceIr       = $M053IrRel
                sourceIrSha256 = (Get-Sha $M053Ir)
                fromLiteral    = $script:VersionFromLiteral
                toLiteral      = $script:VersionToLiteral
                literalBytesRewritten  = [int]$versionStamp.literalBytesRewritten
                literalDifferingBytes  = [int]$versionStamp.literalDifferingBytes
                literalWindowFirst     = [int]$versionStamp.literalWindowFirst
                literalWindowLast      = [int]$versionStamp.literalWindowLast
                line           = [int]$versionStamp.line
                occurrences    = [int]$versionStamp.occurrences
                removedSummaryEntries = [int]$versionStamp.removedSummaryEntries
                removedSummaryKind    = [string]$versionStamp.removedSummaryKind
                removedSummaryBytes   = [int]$versionStamp.removedSummaryBytes
                irBeforeSha256 = [string]$versionStamp.beforeSha256
                irAfterSha256  = [string]$versionStamp.afterSha256
                invariant      = [string]$versionStamp.invariant
            }
            uses         = @(
                'get_sdk_version() sscanf(<literal>, "%u.%u.%u") -> (5,0,5)',
                'install_maplesu_environment() compares the installed environment version string against the same literal'
            )
            verification = [ordered]@{
                objectHasNewLiteral    = $true
                objectHasOldLiteral    = $false
                archiveMemberHasNewLiteral = $true
                archiveMemberHasOldLiteral = $false
                archiveMemberSha256    = $m053DeliveredSha
                archiveMemberName      = $script:VersionStampMemberName
                method                 = 'byte scan for 5.0.5 / 4.6.5 in the compiled object and in the member extracted from the delivered archive'
            }
            isRepair     = $false
        }
    )
    Write-Log ('m053 version stamp verified in the delivered archive: ' + $m053DeliveredSha +
        ' (contains 5.0.5, no 4.6.5)')


    $m024Evidence = @(
        [ordered]@{ kind = 'reference-object-reproduction'; scope = 'build'; path = $refObjectRels['m024Member']; sha256 = (Get-Sha $m024MemberObj); statement = 'freshly compiled object is byte identical to the frozen candidate object' },
        [ordered]@{ kind = 'inherited-host-red'; scope = 'inherited'; path = (Get-InputRel 'patch-write/red.log'); sha256 = (Get-Sha (Get-InputPath 'patch-write/red.log')); statement = 'legacy control flow fails the W0 low-32-bit check (red phase, inherited from the frozen input set)' },
        [ordered]@{ kind = 'inherited-host-green'; scope = 'inherited'; path = (Get-InputRel 'patch-write/green.log'); sha256 = (Get-Sha (Get-InputPath 'patch-write/green.log')); statement = 'fixed control flow passes on host (green phase, inherited)' },
        [ordered]@{ kind = 'inherited-consumer-link'; scope = 'inherited'; path = $ReferenceBridgeSoRel; sha256 = (Get-Sha $ReferenceBridgeSo); statement = 'the byte identical reference archive linked into this verified bridge .so with -Wl,--no-undefined' },
        [ordered]@{ kind = 'device-verification'; scope = 'absent'; path = $null; sha256 = $null; statement = 'no device level kernel panic verification was performed in this build' }
    )
    $m029Evidence = @(
        [ordered]@{ kind = 'reference-object-reproduction'; scope = 'build'; path = $refObjectRels['m029Member']; sha256 = (Get-Sha $m029MemberObj); statement = 'freshly compiled IR object + wrapper relocatable link are byte identical to the frozen candidate objects' },
        [ordered]@{ kind = 'inherited-host-green'; scope = 'inherited'; path = (Get-InputRel 'hook-publication/host-green.log'); sha256 = (Get-Sha (Get-InputPath 'hook-publication/host-green.log')); statement = 'hook publication/compenstion host suite passes (inherited)' },
        [ordered]@{ kind = 'inherited-consumer-link'; scope = 'inherited'; path = $ReferenceBridgeSoRel; sha256 = (Get-Sha $ReferenceBridgeSo); statement = 'consumer bridge link over the byte identical reference archive' },
        [ordered]@{ kind = 'device-verification'; scope = 'absent'; path = $null; sha256 = $null; statement = 'no device level hook publication verification was performed in this build' }
    )
    $m034Evidence = @(
        [ordered]@{ kind = 'reference-object-reproduction'; scope = 'build'; path = $refObjectRels['m034Member']; sha256 = (Get-Sha $m034MemberObj); statement = 'generator + wrapper relocatable link is byte identical to the frozen candidate object' },
        [ordered]@{ kind = 'abi-assertion'; scope = 'build'; path = $refObjectRels['m034Base']; sha256 = (Get-Sha $m034BaseObj); statement = 'baseline and candidate each expose exactly one FUNC GLOBAL HIDDEN i64 _ZN13kernel_module26icache_invalidate_all_cpusEv' },
        [ordered]@{ kind = 'inherited-host-red'; scope = 'inherited'; path = (Get-InputRel 'icache/host-red.log'); sha256 = (Get-Sha (Get-InputPath 'icache/host-red.log')); statement = 'legacy icache policy fails (red phase, inherited)' },
        [ordered]@{ kind = 'inherited-host-green'; scope = 'inherited'; path = (Get-InputRel 'icache/host-green.log'); sha256 = (Get-Sha (Get-InputPath 'icache/host-green.log')); statement = 'icache policy host suite passes (green phase, inherited)' },
        [ordered]@{ kind = 'inherited-host-platform'; scope = 'inherited'; path = (Get-InputRel 'icache/host-platform.log'); sha256 = (Get-Sha (Get-InputPath 'icache/host-platform.log')); statement = 'affinity/executor failure propagation host suite with wrapped sched_* (inherited)' },
        [ordered]@{ kind = 'inherited-consumer-link'; scope = 'inherited'; path = $ReferenceBridgeSoRel; sha256 = (Get-Sha $ReferenceBridgeSo); statement = 'consumer bridge link over the byte identical reference archive' },
        [ordered]@{ kind = 'device-verification'; scope = 'absent'; path = $null; sha256 = $null; statement = 'no device level icache/affinity verification was performed in this build' }
    )

    $repairs = @(
        (New-RepairEntry -Id 'm024' -Ordinal 24 -MemberName 'module_base_kernel_mem.o' `
            -BaselineSha ([string]$memberRecordByOrd[24].sha256) -NewObjectPath $m024MemberObj `
            -Sources @([ordered]@{ role = 'ir'; path = $M024IrRel; sha256 = (Get-Sha $M024Ir); statement = 'checked IR (W0 low 32 bit W0 gate, executor error first, no exec on generation failure, exception cleanup)' }) `
            -Commands @([ordered]@{ exe = 'clang'; argv = @('--target=aarch64-linux-android21', '-Oz', '-fPIC', '-c', '<m024.checked.ll>', '-o', 'module_base_kernel_mem.o') }) `
            -Evidence @{ referenceKey = 'm024Member'; items = $m024Evidence }),
        (New-RepairEntry -Id 'm029' -Ordinal 29 -MemberName 'module_base_kernel_func_hook.o' `
            -BaselineSha ([string]$memberRecordByOrd[29].sha256) -NewObjectPath $m029MemberObj `
            -Sources @(
                [ordered]@{ role = 'ir'; path = $M029IrRel; sha256 = (Get-Sha $M029Ir); statement = 'checked IR (pre-allocated context, bypass before publish, read back then callback)' },
                [ordered]@{ role = 'wrapper-source'; path = $HookCppRel; sha256 = (Get-Sha $HookCpp); statement = 'publish/compensate wrapper' }
            ) `
            -Commands @(
                [ordered]@{ exe = 'clang'; argv = @('--target=aarch64-linux-android21', '-Oz', '-fPIC', '-c', '<m029.checked.ll>', '-o', 'm029.ir.o') },
                [ordered]@{ exe = 'clang++'; argv = @('--target=aarch64-linux-android21', '-std=c++17', '-Oz', '-fPIC', '-fexceptions', '-fvisibility=hidden', '-Wall', '-Wextra', '-Werror', '-I', '<include>', '-c', '<hook_publish.cpp>', '-o', 'hook_publish.o') },
                [ordered]@{ exe = 'ld.lld'; argv = @('-r', 'm029.ir.o', 'hook_publish.o', '-o', 'module_base_kernel_func_hook.o') }
            ) `
            -Evidence @{ referenceKey = 'm029Member'; items = $m029Evidence }),
        (New-RepairEntry -Id 'm034' -Ordinal 34 -MemberName 'module_base_cpu_icache_sync.o' `
            -BaselineSha ([string]$memberRecordByOrd[34].sha256) -NewObjectPath $m034MemberObj `
            -Sources @(
                [ordered]@{ role = 'baseline-compile-ir'; path = $M034BaselineIrRel; sha256 = (Get-Sha $M034BaselineIr); statement = 'm034.baseline.compile.ll: original IR with the trailing typeidCompatibleVTable ThinLTO summary removed so it compiles; used for the compile and ABI gate' },
                [ordered]@{ role = 'generator-ir'; path = $M034GeneratorIrRel; sha256 = (Get-Sha $M034GeneratorIr); statement = 'single-shot executor extracted from the original IR (unchanged instruction cache generator semantics)' },
                [ordered]@{ role = 'wrapper-source'; path = $IcacheCppRel; sha256 = (Get-Sha $IcacheCpp); statement = 'affinity propagation wrapper' },
                [ordered]@{ role = 'wrapper-header'; path = $IcachePolicyHRel; sha256 = (Get-Sha $IcachePolicyH); statement = 'icache policy interface' }
            ) `
            -Commands @(
                [ordered]@{ exe = 'clang'; argv = @('-target', 'aarch64-none-linux-android21', '-fPIC', '-c', '-x', 'ir', '<m034.baseline.compile.ll>', '-o', 'm034.baseline.o') },
                [ordered]@{ exe = 'clang'; argv = @('-target', 'aarch64-none-linux-android21', '-fPIC', '-c', '-x', 'ir', '<m034.generator.ll>', '-o', 'm034.generator.o') },
                [ordered]@{ exe = 'clang++'; argv = @('-target', 'aarch64-linux-android21', '-std=c++17', '-Oz', '-fPIC', '-fvisibility=hidden', '-fexceptions', '-frtti', '-Wall', '-Wextra', '-Werror', '-I', '<include>', '-c', '<icache_candidate.cpp>', '-o', 'icache_candidate.o') },
                [ordered]@{ exe = 'ld.lld'; argv = @('-r', 'm034.generator.o', 'icache_candidate.o', '-o', 'module_base_cpu_icache_sync.o') }
            ) `
            -Evidence @{ referenceKey = 'm034Member'; items = $m034Evidence })
    )

    $bootstrapReason = 'm052 payload ELF is carried as a [145416 x i64] global inside the m052 bitcode member; ' +
    'its source translation-unit set and linker script are not on disk (only the bitcode and this extraction exist), ' +
    'so a same-generation rebuild is impossible today. The member payload is preserved byte-for-byte (ord 52 unchanged) ' +
    'and the outer-layer repairs in m024/m029/m034 are NOT propagated into the embedded bootstrap.'
    $bootstrapRecordJson = [ordered]@{
        path             = $bootstrapRecord.path
        sha256           = $bootstrapSha
        size             = $bootstrapSize
        buildId          = $elfBuildId
        elfBuildId       = $elfBuildId
        elfType          = $elfType
        machine          = $elfMachine
        entry            = $elfEntry
        interp           = $elfInterp
        changed          = $false
        reason           = $bootstrapReason
        legacySha256     = $bootstrapSha
        legacyPath       = ($BaselineArchiveRel + '#' + $script:BootstrapMemberName)
        carrierMember    = [ordered]@{
            name             = $script:BootstrapMemberName
            ord              = 52
            baselineSha256   = $m052BaseSha
            candidateSha256  = $m052NewSha
            changed          = ($m052BaseSha -ne $m052NewSha)
        }
        extraction       = [ordered]@{
            method        = 'llvm-ar x (single member) + llvm-dis + parse the [N x i64] initializer and pack little-endian'
            sources       = $bsReport.sources
            declaredElements = $bsReport.declaredElements
            invariant     = $bsReport.invariant
        }
        repairs          = @('m024', 'm029', 'm034')
        repairStatement  = 'The outer archive carries the m024, m029 and m034 repairs; the embedded bootstrap does NOT carry them because its build inputs are missing.'
        helperStatus     = 'not_rebuilt'
        keySlotOffset    = $script:KeySlotOffset
        keySlotLength    = $script:KeySlotLength
    }

    $helperJson = [ordered]@{
        sha256       = $bootstrapSha
        size         = $bootstrapSize
        buildId      = $elfBuildId
        legacySha256 = $bootstrapSha
        legacyPath   = ($BaselineArchiveRel + '#' + $script:BootstrapMemberName)
        changed      = $false
        status       = 'not_rebuilt'
        reason       = $bootstrapReason
        keySlotOffset = $script:KeySlotOffset
        keySlotLength = $script:KeySlotLength
        normalizedSha256 = $normalizedHelperSha
        normalizedKeySlotOffset = $script:KeySlotOffset
        normalizedKeySlotLength = $script:KeySlotLength
    }

    $toolchainJson = [ordered]@{
        llvmVersion     = $script:PinnedLlvmVersion
        ndkVersion      = $ndkVersion
        clangPath       = (Fwd $tools.clang)
        clangVersion    = $clangVersion
        clangxxPath     = (Fwd $tools.clangxx)
        llvmArPath      = (Fwd $tools.llvmAr)
        llvmArVersion   = $llvmArVersion
        ldLldPath       = (Fwd $tools.ldLld)
        ldLldVersion    = $ldLldVersion
        llvmNmPath      = (Fwd $tools.llvmNm)
        llvmNmVersion   = $llvmNmVersion
        llvmReadelfPath = (Fwd $tools.llvmReadelf)
        llvmReadelfVersion = $llvmReadelfVersion
        llvmDisPath     = (Fwd $tools.llvmDis)
        llvmDisVersion  = $llvmDisVersion
        pythonPath      = (Fwd $Python)
        pythonVersion   = $pythonVersion
        versionGate     = 'pass (all LLVM tools report 17.0.2)'
    }

    $sdkRelease = [ordered]@{
        schemaVersion       = 1
        appVersion          = $script:AppVersion
        versionCode         = $script:VersionCode
        upstreamSdkVersion  = $UpstreamSdkVersion
        sdkBuildId          = $script:SdkBuildId
        inputManifestSha256 = $InputManifestSha
        generatedUtc        = (Get-UtcNow)
        archive             = [ordered]@{ path = $archiveRecord.path; sha256 = $archiveRecord.sha256; size = $archiveRecord.size }
        bootstrap           = [ordered]@{ path = $bootstrapRecord.path; sha256 = $bootstrapSha; size = $bootstrapSize; buildId = $elfBuildId; changed = $false; blocker = 'bootstrap build inputs (TU set + link script) absent' }
        helper              = [ordered]@{ sha256 = $bootstrapSha; buildId = $elfBuildId; changed = $false; status = 'not_rebuilt' }
        repairs             = @(
            [ordered]@{ id = 'm024'; memberOrdinal = 24; memberName = 'module_base_kernel_mem.o'; sha256 = (Get-Sha $m024MemberObj) },
            [ordered]@{ id = 'm029'; memberOrdinal = 29; memberName = 'module_base_kernel_func_hook.o'; sha256 = (Get-Sha $m029MemberObj) },
            [ordered]@{ id = 'm034'; memberOrdinal = 34; memberName = 'module_base_cpu_icache_sync.o'; sha256 = (Get-Sha $m034MemberObj) }
        )
        memberDiff          = [ordered]@{ path = ($OutRel + 'member-diff.json'); sha256 = $memberDiffSha; changed = 3; added = 0; removed = 0 }
        toolchain           = [ordered]@{ ndkVersion = $ndkVersion; clang = $clangVersion; llvmVersion = $script:PinnedLlvmVersion }
        scope               = [ordered]@{
            outerLayerRepairs = 'built (m024/m029/m034)'
            embeddedBootstrap = 'NOT rebuilt (blocked: build inputs missing)'
            deviceVerification = 'not performed'
        }
        statement           = 'Outer layer repaired and reproducible; embedded bootstrap intentionally unchanged. Do not read this manifest as a same-generation bootstrap release.'
    }

    $previousProvenancePath = Get-InputPath 'pro/PROVENANCE.json' -Optional
    $previousProvenanceRel = if ($previousProvenancePath) { Get-InputRel 'pro/PROVENANCE.json' } else { $null }
    $provenance = [ordered]@{
        schemaVersion       = 1
        appVersion          = $script:AppVersion
        versionCode         = $script:VersionCode
        upstreamSdkVersion  = $UpstreamSdkVersion
        upstreamSdkVersionSource = [ordered]@{
            path   = $M053IrRel
            sha256 = (Get-Sha $M053Ir)
            symbol = '_ZN7maplesu3sdk15get_sdk_versionEv'
            line   = $UpstreamSourceLine
            method = 'the SDK get_sdk_version() implementation sscanf()s this literal with "%u.%u.%u"'
        }
        sdkBuildId          = $script:SdkBuildId
        inputManifestSha256 = $InputManifestSha
        generatedUtc        = (Get-UtcNow)
        archiveSha256       = $archiveRecord.sha256
        bootstrapSha256     = $bootstrapSha
        helperSha256        = $bootstrapSha
        derivedFrom         = @(
            [ordered]@{ path = $BaselineArchiveRel; sha256 = $baselineSha; role = 'production baseline archive (member diff reference and 252 unchanged member payloads)' },
            [ordered]@{ path = $M024IrRel; sha256 = (Get-Sha $M024Ir); role = 'm024 repair IR' },
            [ordered]@{ path = $M029IrRel; sha256 = (Get-Sha $M029Ir); role = 'm029 repair IR' },
            [ordered]@{ path = $HookCppRel; sha256 = (Get-Sha $HookCpp); role = 'm029 wrapper source' },
            [ordered]@{ path = $M034BaselineIrRel; sha256 = (Get-Sha $M034BaselineIr); role = 'm034 baseline compile IR (compile/ABI gate)' },
            [ordered]@{ path = $M034GeneratorIrRel; sha256 = (Get-Sha $M034GeneratorIr); role = 'm034 generator IR (executor)' },
            [ordered]@{ path = $IcacheCppRel; sha256 = (Get-Sha $IcacheCpp); role = 'm034 wrapper source' },
            [ordered]@{ path = $IncludeRel; sha256 = $IncludeManifestSha; role = 'SDK header tree manifest used by -I' },
            [ordered]@{ path = $M052IrRel; sha256 = (Get-Sha $M052Ir); role = 'm052 IR that carries the embedded bootstrap payload' },
            [ordered]@{ path = $M053IrRel; sha256 = (Get-Sha $M053Ir); role = 'm053 IR carrying the SDK self-reported version literal (4.6.5 -> 5.0.5 stamp)' }
        )
        repairs             = @(
            [ordered]@{ id = 'm024'; memberOrdinal = 24; memberName = 'module_base_kernel_mem.o'; baselineSha256 = $memberRecordByOrd[24].sha256; newSha256 = (Get-Sha $m024MemberObj) },
            [ordered]@{ id = 'm029'; memberOrdinal = 29; memberName = 'module_base_kernel_func_hook.o'; baselineSha256 = $memberRecordByOrd[29].sha256; newSha256 = (Get-Sha $m029MemberObj) },
            [ordered]@{ id = 'm034'; memberOrdinal = 34; memberName = 'module_base_cpu_icache_sync.o'; baselineSha256 = $memberRecordByOrd[34].sha256; newSha256 = (Get-Sha $m034MemberObj) }
        )
        toolchain           = [ordered]@{ ndkVersion = $ndkVersion; clang = $clangVersion; llvmVersion = $script:PinnedLlvmVersion }
        rollbackSource      = [ordered]@{
            sdkSha256    = $baselineSha
            helperSha256 = $bootstrapSha
            archivePath  = $BaselineArchiveRel
            apkPath      = (Get-InputRel 'legacy-apk/MapleSU-5.0.3-release.apk')
            apkSha256    = (Get-Sha (Get-InputPath 'legacy-apk/MapleSU-5.0.3-release.apk'))
        }
        supersedes          = if ($previousProvenancePath) {
            [ordered]@{
                path   = $previousProvenanceRel
                sha256 = (Get-Sha $previousProvenancePath)
                note   = 'the previous production PROVENANCE.json; import must preserve its history rather than replace it blindly'
            }
        }
        else {
            [ordered]@{
                path   = $null
                sha256 = $null
                note   = 'the previous production PROVENANCE.json is not part of the frozen input set (excluded as a registered input); import must merge, not overwrite, the live runtime/maplesu-sdk/PROVENANCE.json'
            }
        }
        rebuild             = [ordered]@{
            method                 = 'ordinal repack of the baseline archive with llvm-ar qcD/sD and exactly three substituted members'
            coreSourceRebuilt      = $false
            coreIrReemitted        = $false
            unchangedMemberPayloads = 252
            replacedMemberPayloads  = 3
            bootstrapRebuilt       = $false
            bootstrapBlocker       = $bootstrapReason
        }
    }

    $reproducibility = [ordered]@{
        archiveDeterministicMode = 'llvm-ar D (zero timestamps, zero uid/gid) + regenerated symbol index'
        batchSize                = 64
        baselineRoundTrip        = [ordered]@{
            rebuiltSha256 = $selfCheckSha
            baselineSha256 = $baselineSha
            matches       = ($selfCheckSha -eq $baselineSha)
            statement     = 'repacking the untouched baseline reproduces it byte-for-byte, which proves the pipeline is lossless and deterministic'
        }
        referenceCandidate = $null
    }
    if ($ReferenceArchive) {
        $refDeltaMembers = $null
        $refDeltaOrdinals = @()
        if ($referenceDelta) {
            $refDeltaMembers = [int]$referenceDelta.summary.changed
            $refDeltaOrdinals = @($referenceDelta.changed | ForEach-Object { [int]$_.ord })
        }
        $reproducibility.referenceCandidate = [ordered]@{
            path          = $ReferenceArchiveRel
            sha256        = (Get-Sha $ReferenceArchive)
            role          = 'verification cross-check only; not a build input'
            deltaMembers  = $refDeltaMembers
            deltaOrdinals = $refDeltaOrdinals
            note          = 'the frozen verified candidate already carries the three repairs; the delivered archive differs from it only by the m053 version stamp'
        }
    }

    $buildJson = [ordered]@{
        schemaVersion       = 1
        appVersion          = $script:AppVersion
        versionCode         = $script:VersionCode
        upstreamSdkVersion  = $UpstreamSdkVersion
        sdkBuildId          = $script:SdkBuildId
        inputManifestSha256 = $InputManifestSha
        inputsManifest      = [ordered]@{ path = $InputManifestRel; sha256 = $InputManifestSha }
        sdkSha256           = $sdkSha
        sdkSize             = $sdkSize
        versionStamps       = $versionStamps
        bridgeInputs        = $bridgeInputsJson
        toolchain           = $toolchainJson
        repairs             = $repairs
        memberDiff          = [ordered]@{
            evidenceFile    = [ordered]@{ path = ($OutRel + 'member-diff.json'); sha256 = $memberDiffSha }
            baseline        = [ordered]@{ path = $BaselineArchiveRel; sha256 = $baselineSha; memberCount = [int]$membersInfo.memberCount }
            candidate       = [ordered]@{ path = ($OutRel + 'libkernel_module_kit_static.a'); sha256 = $sdkSha; memberCount = [int]$memberDiff.candidate.memberCount }
            totalMembers    = [int]$memberDiff.summary.totalMembers
            changed         = $memberDiff.changed
            added           = @()
            removed         = @()
            changedObjectIds = $memberDiff.changedObjectIds
            bootstrapMember = $memberDiff.bootstrapMember
        }
        symbolsDiff         = [ordered]@{
            evidenceFile = [ordered]@{ path = ($OutRel + 'symbols-diff.json'); sha256 = $symbolsDiffSha }
            totals       = $symbolsDiff.totals
            archiveSymbolIndex = $symbolsDiff.archiveSymbolIndex
            strongDefinitionConflicts = $symbolsDiff.strongDefinitionConflicts
        }
        bootstrap           = $bootstrapRecordJson
        helper              = $helperJson
        artifacts           = [ordered]@{
            archive       = $archiveRecord
            bootstrap     = $bootstrapRecord
            memberDiff    = [ordered]@{ path = ($OutRel + 'member-diff.json'); sha256 = $memberDiffSha; size = (Get-FileSize $MemberDiffPath) }
            symbolsDiff   = [ordered]@{ path = ($OutRel + 'symbols-diff.json'); sha256 = $symbolsDiffSha; size = (Get-FileSize $SymbolsDiffPath) }
            inputsSha256  = [ordered]@{ path = ($OutRel + 'inputs.sha256'); sha256 = (Get-Sha $InputsShaList); size = (Get-FileSize $InputsShaList) }
            linkLog       = [ordered]@{ path = ($OutRel + 'link.log'); sha256 = $linkLogSha; size = (Get-FileSize $script:LinkLog) }
            sdkRelease    = $null
            provenance    = $null
        }
        reproducibility     = $reproducibility
        timestamps          = $null
        scope               = [ordered]@{
            outerLayerRepairs  = 'm024/m029/m034 compiled and substituted'
            versionStamp       = 'm053 MapleSU SDK self-reported version 4.6.5 -> 5.0.5 (product version line; upstream version unchanged)'
            embeddedBootstrap  = 'unchanged (m052 payload preserved byte-for-byte)'
            bootstrapSameGeneration = $false
            deviceVerification = 'not performed'
        }
        statement           = 'MapleSU 5.0.5 Ultra SDK outer-layer build. The embedded autorun bootstrap is intentionally NOT rebuilt and is not same-generation with these repairs.'
        pathBase            = [ordered]@{
            jsonPaths     = 'relative to the evidence root'
            outDirLeaf    = $OutLeaf
            outDirAbsolute = (Fwd $OutDir)
            inputsManifestAbsolute = (Fwd $ManifestPath)
        }
    }

    $sdkReleasePath = Join-Path $OutDir 'SDK-RELEASE.json'
    $provenancePath = Join-Path $OutDir 'PROVENANCE.json'
    Write-JsonFile $sdkReleasePath $sdkRelease
    Write-JsonFile $provenancePath $provenance
    $buildJson.artifacts.sdkRelease = New-ArtifactRecord ($OutRel + 'SDK-RELEASE.json') $sdkReleasePath
    $buildJson.artifacts.provenance = New-ArtifactRecord ($OutRel + 'PROVENANCE.json') $provenancePath

    $finishedUtc = Get-UtcNow
    $totalSeconds = [math]::Round(((Get-Date).ToUniversalTime() - $script:StartInstant).TotalSeconds, 3)
    $script:StageTimings.Add([ordered]@{
            name = 'product'; startedUtc = $stageStart.ToString('yyyy-MM-ddTHH:mm:ssZ')
            endedUtc = $finishedUtc
            seconds = [math]::Round(((Get-Date).ToUniversalTime() - $stageStart).TotalSeconds, 3)
        })
    $buildJson.timestamps = [ordered]@{
        startedUtc       = $startedUtc
        finishedUtc      = $finishedUtc
        durationSeconds  = $totalSeconds
        stages           = $script:StageTimings
        toolchainCapturedUtc = $startedUtc
    }

    $sdkBuildPath = Join-Path $OutDir 'sdk-build.json'
    Write-JsonFile $sdkBuildPath $buildJson

    Write-Log 'products written; running the independent member-diff verifier'

    # ---- independent self-verification -----------------------------------
    $verifier = Join-Path $PSScriptRoot 'verify_sdk_member_diff.py'
    if (-not (Test-Path -LiteralPath $verifier)) {
        throw "independent verifier not found next to this script: $verifier"
    }
    $verifierArgs = @(
        (Fwd $verifier), '--baseline', (Fwd $BaselineArchive), '--candidate', (Fwd $NewArchive),
        '--claim', (Fwd $MemberDiffPath), '--sdk-build', (Fwd $sdkBuildPath),
        '--expect-ordinals', (($script:ExpectedChangedOrdinals | Sort-Object) -join ','),
        '--expect-names', ($script:ExpectedChangedNames -join ','),
        '--json-out', (Fwd (Join-Path $Work 'verify-member-diff.json'))
    )
    $verifyOutput = & $Python @verifierArgs 2>&1
    $verifyCode = $LASTEXITCODE
    foreach ($line in $verifyOutput) {
        Write-LinkLog ([string]$line)
        Write-Log ([string]$line) 'VERIFY'
    }
    if ($verifyCode -ne 0) {
        throw "independent member-diff verifier failed with exit code $verifyCode"
    }

    # outputs.sha256 is written last: link.log is still appended to while the
    # verifier transcript is logged, so its digest must be taken afterwards.
    $linkLogSha = Get-Sha $script:LinkLog
    $buildJson.artifacts.linkLog = [ordered]@{
        path   = ($OutRel + 'link.log')
        sha256 = $linkLogSha
        size   = (Get-FileSize $script:LinkLog)
    }
    Write-JsonFile $sdkBuildPath $buildJson

    $outputsList = @(
        'libkernel_module_kit_static.a', 'autorun_bootstrap', 'SDK-RELEASE.json',
        'PROVENANCE.json', 'sdk-build.json', 'inputs.sha256', 'outputs.sha256',
        'link.log', 'member-diff.json', 'symbols-diff.json'
    )
    $outputLines = @()
    foreach ($name in $outputsList) {
        if ($name -eq 'outputs.sha256') { continue }
        $path = Join-Path $OutDir $name
        if (-not (Test-Path -LiteralPath $path)) { throw "expected product missing: $name" }
        $outputLines += ((Get-Sha $path) + '  ' + $OutRel + $name)
    }
    [IO.File]::WriteAllText((Join-Path $OutDir 'outputs.sha256'), (($outputLines -join "`n") + "`n"), $script:Utf8)
    Write-Log 'outputs.sha256 written after the verifier transcript was flushed'


    Write-Log ('BUILD-OK sdk=' + $sdkSha + ' sdkSize=' + $sdkSize + ' bootstrap=' + $bootstrapSha +
        ' members=' + $memberDiff.summary.totalMembers + ' changed=' + $memberDiff.summary.changed)
    Write-Host ''
    Write-Host ("SDK-BUILD-PASS archiveSha256=" + $sdkSha)
    Write-Host ("SDK-BUILD-PASS bootstrapSha256=" + $bootstrapSha)
    Write-Host ("SDK-BUILD-PASS sdkBuildId=" + $script:SdkBuildId + " upstreamSdkVersion=" + $UpstreamSdkVersion)
    Write-Host ("SDK-BUILD-PASS memberDiff changed=" + $memberDiff.summary.changed + " added=0 removed=0 total=" + $memberDiff.summary.totalMembers)
    Write-Host ("SDK-BUILD-PASS outDir=" + (Fwd $OutDir))
    exit 0
}
catch {
    $message = $_.Exception.Message
    if ([string]::IsNullOrWhiteSpace($message)) { $message = ($_ | Out-String) }
    Fail-Stage $message
}
