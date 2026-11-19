#!/usr/bin/env bash
# configurar_rol.sh <rol> - Configura una VM del laboratorio según su rol.
# Roles: gateway | web | dns | xmpp
# Ejecutar como root (o con sudo bash configurar_rol.sh <rol>).
set -euo pipefail

ROL="${1:-}"
case "$ROL" in
  gateway) IP="192.168.50.1";;
  web)     IP="192.168.50.20";;
  dns)     IP="192.168.50.53";;
  xmpp)    IP="192.168.50.30";;
  *) echo "Uso: $0 <gateway|web|dns|xmpp>"; exit 2;;
esac

echo "=== Configurando rol: $ROL (IP $IP) ==="

# 1. Zona horaria y NTP (sección 5 del informe)
timedatectl set-timezone America/Bogota
timedatectl set-ntp true

# 2. Hostname
hostnamectl set-hostname "$ROL"

# 2b. Deshabilitar el repo del cdrom (ISO desmontada) para evitar errores de apt
if [ -f /etc/apt/sources.list ]; then
  sed -i 's|^deb \[check-date=no\] file:///cdrom|#&|; s|^deb file:///cdrom|#&|' /etc/apt/sources.list
fi

# 3. Netplan: IP estática en enp0s8 (adaptador 2, solo-anfitrión)
#    enp0s3 (NAT) se mantiene con DHCP, pero SIN rutas: el DHCP de VirtualBox
#    inyecta rutas classless (opción 121) hacia 192.168.50.53/192.168.0.1 que
#    rompen el enrutamiento del laboratorio. use-routes:false lo evita.
rm -f /etc/netplan/50-cloud-init.yaml
cat > /etc/netplan/01-lab.yaml <<EOF
network:
  version: 2
  ethernets:
    enp0s3:
      dhcp4: true
      dhcp4-overrides:
        use-routes: false
    enp0s8:
      addresses: [$IP/24]
EOF
chmod 600 /etc/netplan/01-lab.yaml
netplan apply

# 4. Paquetes y configuración por rol
case "$ROL" in
  gateway)
    apt-get update
    apt-get install -y chrony nftables

    # Sin reenvío de paquetes (sección 6)
    echo "net.ipv4.ip_forward=0" > /etc/sysctl.d/99-lab.conf
    sysctl -p /etc/sysctl.d/99-lab.conf

    # Reglas base de nftables (sección 6)
    cat > /etc/nftables.conf <<'NFT'
table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;
    iif lo accept
    ct state established,related accept
    ip saddr 192.168.50.0/24 icmp type echo-request accept
    ip saddr 192.168.50.0/24 udp dport 123 accept
    ip saddr 192.168.50.0/24 tcp dport 22 accept
  }
  chain forward { type filter hook forward priority 0; policy drop; }
}
NFT
    systemctl enable --now chrony
    systemctl enable --now nftables
    ;;
  web)
    apt-get update
    apt-get install -y nginx
    systemctl enable --now nginx
    ;;
  dns)
    apt-get update
    apt-get install -y dnsmasq dnsutils
    cat > /etc/dnsmasq.d/lab.conf <<'DNS'
listen-address=192.168.50.53
bind-interfaces
no-resolv
address=/web.lab.local/192.168.50.20
DNS
    systemctl enable --now dnsmasq
    ;;
  xmpp)
    apt-get update
    apt-get install -y prosody
    systemctl enable --now prosody
    ;;
esac

echo "=== Configuración de $ROL completa ==="
ip -br addr
