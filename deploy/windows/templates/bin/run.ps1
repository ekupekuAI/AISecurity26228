# TrustVision desktop launcher.
#
# Starts the Python assurance engine and the Node gateway locally (both hidden, no console
# windows), waits for them, then opens the console as an app window. Everything runs on this
# machine only, over loopback, with no internet access. Invoked hidden by TrustVision.vbs.
$ErrorActionPreference = 'SilentlyContinue'

$bin  = Split-Path -Parent $MyInvocation.MyCommand.Path
$root = Split-Path -Parent $bin
$app  = Join-Path $root 'app'
$data = Join-Path $root 'data'
New-Item -ItemType Directory -Force -Path $data | Out-Null

$py   = Join-Path $root 'runtime\python\python.exe'
$node = Join-Path $root 'runtime\node\node.exe'

# A per-install signing/auth secret, generated once and kept beside the data. Never shipped in
# the zip, so every installed copy has its own.
$secretFile = Join-Path $data 'auth_secret.txt'
if (-not (Test-Path $secretFile)) {
  $bytes = New-Object 'System.Byte[]' 48
  [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
  [Convert]::ToBase64String($bytes) | Out-File -Encoding ascii -NoNewline $secretFile
}
$env:AUTH_SECRET = (Get-Content $secretFile -Raw).Trim()

$env:AIA_DATA_DIR = $data
$env:ML_SERVICE_URL = 'http://127.0.0.1:8000'
$env:HOST = '127.0.0.1'
$env:PORT = '3000'
$env:AIA_ALLOW_WEIGHT_DOWNLOAD = 'false'   # air-gapped: never fetch weights at runtime
$env:AIA_DEMO_MODE = 'true'                # offer the read-only evaluation session
$env:AIA_BOOTSTRAP_USER = 'admin'
$env:AIA_BOOTSTRAP_PASSWORD = 'TrustVision#2026'   # documented default; change it in Settings
# NOTE: not production, so the session cookie is not 'Secure' and works over http://localhost.

function Up($url) { try { Invoke-WebRequest -UseBasicParsing $url -TimeoutSec 2 | Out-Null; $true } catch { $false } }

# Start both local services hidden, unless the console is already running. The Python engine
# (PyTorch) warms up much more slowly than the gateway -- on a first launch, torch import plus
# the on-access antivirus scan of its DLLs can take a minute or more. We deliberately do NOT
# block on it: waiting made the window take minutes to appear and look frozen. Instead we open
# the console the moment the *gateway* answers (a few seconds), and let the engine finish
# warming in the background. The console shows the engine's status and enables analysis the
# instant it comes online.
if (-not (Up 'http://127.0.0.1:3000/api/health')) {
  if (-not (Up 'http://127.0.0.1:8000/health')) {
    Start-Process -WindowStyle Hidden -FilePath $py -ArgumentList @(
      '-m','uvicorn','app:app','--app-dir',(Join-Path $app 'ml-engine'),
      '--host','127.0.0.1','--port','8000','--log-level','warning'
    )
  }
  Start-Process -WindowStyle Hidden -FilePath $node -ArgumentList @((Join-Path $app 'dist\server.cjs')) -WorkingDirectory $app
  # Wait only for the gateway, then open the window right away. The engine keeps warming.
  for ($i = 0; $i -lt 60; $i++) { if (Up 'http://127.0.0.1:3000/api/health') { break }; Start-Sleep 1 }
}

# Open as a chromeless app window via Edge (present on Windows 10/11); fall back to the
# default browser.
$edge = @(
  "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe",
  "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe"
) | Where-Object { Test-Path $_ } | Select-Object -First 1
if ($edge) { Start-Process $edge '--app=http://127.0.0.1:3000' } else { Start-Process 'http://127.0.0.1:3000' }
