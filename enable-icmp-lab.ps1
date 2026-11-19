# Habilita respuesta ICMP echo (ping) solo desde la red del laboratorio 192.168.50.0/24
# para que las VMs puedan verificar al analista (host Windows, 192.168.50.10).
$ErrorActionPreference = 'Stop'
$name = 'Lab-ICMPv4-Echo-In-192.168.50.0-24'
if (Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue) {
    Remove-NetFirewallRule -DisplayName $name
}
New-NetFirewallRule -DisplayName $name -Direction Inbound -Protocol ICMPv4 -IcmpType 8 -RemoteAddress 192.168.50.0/24 -Action Allow -Profile Any | Out-Null
Write-Output "Regla de firewall ICMP creada: $name"
