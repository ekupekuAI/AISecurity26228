# Stop TrustVision: terminate whatever is listening on the local gateway/engine ports.
$ErrorActionPreference = 'SilentlyContinue'
foreach ($port in 3000, 8000) {
  Get-NetTCPConnection -LocalPort $port -State Listen |
    Select-Object -ExpandProperty OwningProcess -Unique |
    ForEach-Object { Stop-Process -Id $_ -Force }
}
