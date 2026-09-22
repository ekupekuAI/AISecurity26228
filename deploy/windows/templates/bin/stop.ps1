# Stop TrustVision: terminate whatever is listening on the local gateway/engine ports.
$ErrorActionPreference = 'SilentlyContinue'
foreach ($port in 3787, 8787) {
  Get-NetTCPConnection -LocalPort $port -State Listen |
    Select-Object -ExpandProperty OwningProcess -Unique |
    ForEach-Object { Stop-Process -Id $_ -Force }
}
