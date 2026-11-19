#!/usr/bin/env bash
# Captura el estado/configuración de una VM según su rol (evidencia).
ROL="${1:-}"
echo "########## CAPTURA DE EVIDENCIA - rol: $ROL ##########"
echo "## hostname"
hostnamectl
echo
echo "## ip -br addr"
ip -br addr
echo
echo "## ip route"
ip route
echo
echo "## timedatectl"
timedatectl
echo
echo "## netplan /etc/netplan/01-lab.yaml"
cat /etc/netplan/01-lab.yaml
echo
case "$ROL" in
  gateway)
    echo "## nftables ruleset"
    nft list ruleset
    echo
    echo "## ip_forward"
    cat /proc/sys/net/ipv4/ip_forward
    echo
    echo "## chrony (allow/local)"
    grep -E '^(allow|local)' /etc/chrony/chrony.conf
    echo
    echo "## chronyc tracking"
    chronyc tracking 2>/dev/null
    ;;
  web)
    echo "## nginx -v"
    nginx -v 2>&1
    echo
    echo "## nginx listening"
    ss -lntu | grep ':80 '
    ;;
  dns)
    echo "## dnsmasq lab.conf"
    cat /etc/dnsmasq.d/lab.conf
    echo
    echo "## dig web.lab.local"
    dig +time=1 +tries=1 web.lab.local @192.168.50.53 +short
    ;;
  xmpp)
    echo "## prosody status"
    systemctl status prosody --no-pager -l | head -12
    echo
    echo "## c2s listening"
    ss -lntu | grep ':5222'
    ;;
esac
echo
echo "########## FIN CAPTURA $ROL ##########"
