# Windows: split HONOR 70 board ZIP into GitHub Release assets and upload.
# This publishes the archive to a PUBLIC release if the repository is public.
# NEVER flash these files. Read-only analysis only.
[CmdletBinding()]
param(
    [string]$ZipPath = (Join-Path $env:USERPROFILE 'Downloads\Honor_70_FNE-AN00_1.0.0.34_220721_HMT.zip'),
    [string]$Repo = 'PetarM09/honor70-firmware-analysis',
    [string]$Tag = 'board-fne-an00-1.0.0.34-hmt',
    [int]$ChunkMiB = 900,
    [switch]$PrepareOnly
)
$ErrorActionPreference = 'Stop'
if ($ChunkMiB -lt 1 -or $ChunkMiB -gt 1024) { throw 'ChunkMiB must be in 1..1024.' }
$ZipPath = [System.IO.Path]::GetFullPath($ZipPath)
if (-not (Test-Path -LiteralPath $ZipPath -PathType Leaf)) { throw "Missing ZIP: $ZipPath. Pass -ZipPath." }
$source = Get-Item -LiteralPath $ZipPath
if ($source.Length -eq 0) { throw 'The source ZIP is empty.' }
$outdir = Join-Path $source.DirectoryName 'HONOR70_BOARD_HMT_RELEASE_PARTS'
New-Item -ItemType Directory -Force -Path $outdir | Out-Null
$base = 'HONOR70_BOARD_HMT'
$chunkBytes = [int64]$ChunkMiB * 1024 * 1024
$count = [int][Math]::Ceiling($source.Length / [double]$chunkBytes)
$parts = @()
Write-Host "SOURCE $ZipPath ($($source.Length) bytes) -> $count parts"
Write-Host "OUTPUT $outdir"
$inputStream = [System.IO.File]::OpenRead($ZipPath)
try {
    $buffer = New-Object byte[] (4 * 1024 * 1024)
    for ($i = 1; $i -le $count; $i++) {
        $name = '{0}_part_{1:D3}.bin' -f $base,$i
        $path = Join-Path $outdir $name
        $needed = [int64][Math]::Min($chunkBytes, $source.Length - $inputStream.Position)
        $partStream = [System.IO.File]::Open($path,[System.IO.FileMode]::Create,[System.IO.FileAccess]::Write,[System.IO.FileShare]::None)
        try {
            $remaining = $needed
            while ($remaining -gt 0) {
                $take = [int][Math]::Min([int64]$buffer.Length,$remaining)
                $got = $inputStream.Read($buffer,0,$take)
                if ($got -le 0) { throw "Unexpected end of source ZIP at part $i." }
                $partStream.Write($buffer,0,$got)
                $remaining -= $got
            }
        } finally { $partStream.Dispose() }
        $file = Get-Item -LiteralPath $path
        if ($file.Length -ne $needed) { throw "Wrong part size: $name" }
        $sha = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        $parts += [pscustomobject]@{name=$name;bytes=[int64]$file.Length;sha256=$sha}
        Write-Host "PART $i/$count $name SHA256=$sha"
    }
} finally { $inputStream.Dispose() }
$sourceSha = (Get-FileHash -LiteralPath $ZipPath -Algorithm SHA256).Hash.ToLowerInvariant()
$manifestPath = Join-Path $outdir ($base+'_SHA256_manifest.json')
[pscustomobject]@{
    format='consecutive-byte-split-v1'
    source=$source.Name
    source_bytes=[int64]$source.Length
    source_sha256=$sourceSha
    chunk_mib=$ChunkMiB
    part_count=$count
    parts=$parts
    safe_to_flash=$false
} | ConvertTo-Json -Depth 7 | Set-Content -LiteralPath $manifestPath -Encoding UTF8
Write-Host "SOURCE_SHA256 $sourceSha"
if ($PrepareOnly) {
    Write-Host 'PREPARE_ONLY_SUCCESS: no upload performed'
    exit 0
}
if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
    throw 'Install GitHub CLI via: winget install --id GitHub.cli --source winget. Then open new PowerShell.'
}
& gh auth status
if ($LASTEXITCODE -ne 0) { throw 'Run gh auth login --web before uploading.' }
$tags = @(& gh release list --repo $Repo --limit 100 --json tagName --jq '.[].tagName')
if ($LASTEXITCODE -ne 0) { throw 'Cannot list GitHub releases.' }
if (-not ($tags -contains $Tag)) {
    Write-Host "Creating GitHub release $Tag ..."
    & gh release create $Tag --repo $Repo --title 'Honor 70 FNE-AN00 BD 1.0.0.34 HMT' --notes 'Original board firmware split for read-only reverse engineering. DO NOT FLASH. See SHA256 manifest.' --prerelease --latest=false
    if ($LASTEXITCODE -ne 0) { throw 'Cannot create release.' }
}
$remoteNames = @(& gh release view $Tag --repo $Repo --json assets --jq '.assets[].name')
if ($LASTEXITCODE -ne 0) { throw 'Cannot inspect existing release assets.' }
$assets = @($parts | ForEach-Object { Join-Path $outdir $_.name })
$assets += $manifestPath
foreach ($asset in $assets) {
    $name = [System.IO.Path]::GetFileName($asset)
    if ($remoteNames -contains $name) {
        Write-Host "SKIP: already uploaded $name"
        continue
    }
    Write-Host "UPLOAD $name ..."
    & gh release upload $Tag $asset --repo $Repo
    if ($LASTEXITCODE -ne 0) { throw "Upload failed: $name. Re-run for retry." }
    $remoteNames += $name
}
Write-Host 'UPLOAD_COMPLETE'
Write-Host ("RELEASE_URL https://github.com/{0}/releases/tag/{1}" -f $Repo,$Tag)
