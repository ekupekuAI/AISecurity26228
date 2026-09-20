<#
  Build a portable, air-gapped Windows bundle of TrustVision.

  Produces  build\windows\TrustVision\  (a self-contained folder) and, unless -NoZip,
  build\TrustVision-Windows.zip. The folder carries its own Python+PyTorch and Node, so a
  teammate can extract it on any 64-bit Windows machine and double-click TrustVision.vbs with
  nothing to install.

  Usage (from the repo root):
    powershell -ExecutionPolicy Bypass -File deploy\windows\build-windows-app.ps1
    ... -RuntimeOnly   # only download/prepare the portable Python+Node (the slow part)
    ... -SkipRuntime   # reuse an already-prepared runtime, rebuild the app + rezip
    ... -Clean         # delete the previous bundle first
    ... -NoZip         # leave the folder, do not compress
#>
param([switch]$RuntimeOnly, [switch]$SkipRuntime, [switch]$Clean, [switch]$NoZip)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$repo    = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$out     = Join-Path $repo 'build\windows\TrustVision'
$runtime = Join-Path $out 'runtime'
$pyDir   = Join-Path $runtime 'python'
$nodeDir = Join-Path $runtime 'node'
$app     = Join-Path $out 'app'
$tpl     = Join-Path $PSScriptRoot 'templates'
$tmp     = Join-Path $env:TEMP ('tv-build-' + [Guid]::NewGuid().ToString('N').Substring(0,8))

function Say($m) { Write-Host "==> $m" -ForegroundColor Cyan }

if ($Clean -and (Test-Path $out)) { Say 'removing previous bundle'; Remove-Item -Recurse -Force $out }
New-Item -ItemType Directory -Force -Path $out, $runtime, $tmp | Out-Null

# ---------------------------------------------------------------- portable runtime
if (-not $SkipRuntime) {
  if (Test-Path (Join-Path $pyDir 'python.exe')) {
    Say 'portable Python already present, skipping download (use -Clean to redo)'
  } else {
    Say 'locating a portable CPython 3.12 (python-build-standalone)'
    $rel = Invoke-RestMethod 'https://api.github.com/repos/astral-sh/python-build-standalone/releases/latest' -Headers @{ 'User-Agent' = 'trustvision-build' }
    $asset = $rel.assets | Where-Object { $_.name -match '^cpython-3\.12\.\d+\+.*-x86_64-pc-windows-msvc-install_only\.tar\.gz$' } | Select-Object -First 1
    if (-not $asset) { throw 'could not find a cpython-3.12 windows install_only asset' }
    $tar = Join-Path $tmp 'python.tar.gz'
    Say ("downloading " + $asset.name)
    Invoke-WebRequest $asset.browser_download_url -OutFile $tar
    Say 'extracting Python'
    tar -xzf $tar -C $tmp
    Move-Item (Join-Path $tmp 'python') $pyDir
  }

  Say 'installing the engine dependencies (torch CPU + friends) into the portable Python'
  & (Join-Path $pyDir 'python.exe') -m pip install --disable-pip-version-check --no-warn-script-location `
    --extra-index-url https://download.pytorch.org/whl/cpu -r (Join-Path $repo 'ml-engine\requirements.txt')
  if ($LASTEXITCODE -ne 0) { throw 'pip install failed' }

  Say 'bundling the Node runtime'
  New-Item -ItemType Directory -Force -Path $nodeDir | Out-Null
  Copy-Item (Get-Command node).Source (Join-Path $nodeDir 'node.exe') -Force
}

if ($RuntimeOnly) { Say 'runtime ready (RuntimeOnly).'; Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue; return }

# ---------------------------------------------------------------- build the app
Push-Location $repo
try {
  if (-not (Test-Path (Join-Path $repo 'node_modules'))) { Say 'npm ci'; npm ci }
  Say 'building frontend + server (npm run build)'
  npm run build
  if ($LASTEXITCODE -ne 0) { throw 'npm run build failed' }
} finally { Pop-Location }

# ---------------------------------------------------------------- assemble
Say 'assembling the bundle'
if (Test-Path $app) { Remove-Item -Recurse -Force $app }
New-Item -ItemType Directory -Force -Path $app | Out-Null

Copy-Item (Join-Path $repo 'dist') (Join-Path $app 'dist') -Recurse -Force
# ml-engine minus caches/tests (not needed at runtime); keep assets (staged backbone).
robocopy (Join-Path $repo 'ml-engine') (Join-Path $app 'ml-engine') /E /NFL /NDL /NJH /NJS /NP /XD __pycache__ tests .pytest_cache .ruff_cache | Out-Null
Copy-Item (Join-Path $repo 'package.json') $app -Force
Copy-Item (Join-Path $repo 'package-lock.json') $app -Force

Say 'installing production-only Node dependencies into the bundle'
Push-Location $app
try { npm ci --omit=dev --no-audit --no-fund; if ($LASTEXITCODE -ne 0) { throw 'bundle npm ci failed' } } finally { Pop-Location }

# Launcher + docs + a writable data dir.
Copy-Item (Join-Path $tpl 'TrustVision.vbs') $out -Force
Copy-Item (Join-Path $tpl 'Stop TrustVision.vbs') $out -Force
Copy-Item (Join-Path $tpl 'README.txt') $out -Force
New-Item -ItemType Directory -Force -Path (Join-Path $out 'bin') | Out-Null
Copy-Item (Join-Path $tpl 'bin\*') (Join-Path $out 'bin') -Recurse -Force
New-Item -ItemType Directory -Force -Path (Join-Path $out 'data') | Out-Null

Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue

if (-not $NoZip) {
  $zip = Join-Path $repo 'build\TrustVision-Windows.zip'
  Say 'compressing to build\TrustVision-Windows.zip (this takes a while)'
  if (Test-Path $zip) { Remove-Item -Force $zip }
  Push-Location (Split-Path -Parent $out)
  try { tar -a -c -f $zip 'TrustVision' } finally { Pop-Location }
  $mb = [math]::Round((Get-Item $zip).Length / 1MB)
  Say "done: $zip  ($mb MB)"
} else {
  Say "done: $out"
}
