$ErrorActionPreference = "Stop"
$cert = Join-Path $PSScriptRoot "..\netbridge-lan-cert.pem"
$key = Join-Path $PSScriptRoot "..\netbridge-lan-key.pem"
if (-not (Get-Command mkcert -ErrorAction SilentlyContinue)) {
    throw "Install mkcert first, then run this script again. See README.md for setup notes."
}
mkcert -install
$ip = Get-NetIPAddress -AddressFamily IPv4 |
    Where-Object { $_.IPAddress -notlike "127.*" -and $_.InterfaceAlias -notmatch "Virtual|Loopback|WSL|Docker" } |
    Select-Object -First 1 -ExpandProperty IPAddress
if (-not $ip) { throw "Could not find a LAN IPv4 address." }
mkcert -cert-file $cert -key-file $key localhost 127.0.0.1 $ip
Write-Host "Created local development TLS files (ignored by Git): $cert and $key"
Write-Host "For Android camera access, install/trust the mkcert local CA on that device."
