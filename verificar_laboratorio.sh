#!/usr/bin/env bash
# verificar_laboratorio.sh <rol>
# Roles: gateway | web | dns | xmpp
# Ejecutar:  bash verificar_laboratorio.sh <rol>
set -u

ROL="${1:-}"

if [ -t 1 ]; then
  C_OK=$'\033[1;32m'; C_FAIL=$'\033[1;31m'; C_WARN=$'\033[1;33m'; C_INFO=$'\033[1;36m'; C_RESET=$'\033[0m'
else
  C_OK=''; C_FAIL=''; C_WARN=''; C_INFO=''; C_RESET=''
fi

ok()   { printf '%b[OK]%b   %s\n'   "$C_OK"   "$C_RESET" "$*"; }
fail() { printf '%b[FALTA]%b %s\n' "$C_FAIL" "$C_RESET" "$*"; }
warn() { printf '%b[?]%b    %s\n'   "$C_WARN" "$C_RESET" "$*"; }
info() { printf '%b--%b    %s\n'    "$C_INFO" "$C_RESET" "$*"; }

echo "=============================================="
echo " Verificación de laboratorio - rol: ${ROL:-(no indicado)}"
date
echo "=============================================="

# --- 1. Interfaces e IP ---
info "Interfaces de red:"
ip -br addr 2>/dev/null || ifconfig 2>/dev/null

case "$ROL" in
  gateway) IP_EXP="192.168.50.1";;
  web)     IP_EXP="192.168.50.20";;
  dns)     IP_EXP="192.168.50.53";;
  xmpp)    IP_EXP="192.168.50.30";;
  *)       IP_EXP="";;
esac

if [ -n "$IP_EXP" ]; then
  if ip -br addr 2>/dev/null | grep -q "$IP_EXP"; then
    ok "IP $IP_EXP configurada"
  else
    fail "IP $IP_EXP no configurada en ninguna interfaz"
  fi
fi

# --- 2. Conectividad ---
echo
info "Conectividad (ping, timeout 1s):"
ping_test() {
  local ip="$1" desc="$2"
  if ping -c 1 -W 1 "$ip" >/dev/null 2>&1; then
    ok "$desc ($ip) responde"
  else
    fail "$desc ($ip) NO responde"
  fi
}
ping_test 192.168.50.1  "gateway"
ping_test 192.168.50.10 "analista"
ping_test 192.168.50.20 "web"
ping_test 192.168.50.53 "dns"
ping_test 192.168.50.30 "xmpp"

# --- 3. Aislamiento ---
echo
info "Aislamiento (192.0.2.1 NO debe responder):"
if ping -c 1 -W 2 192.0.2.1 >/dev/null 2>&1; then
  fail "192.0.2.1 responde (posible salida a Internet)"
else
  ok "192.0.2.1 no responde (aislado)"
fi

# --- 4. Servicios por rol ---
echo
svc() {
  local name="$1"
  if systemctl is-active --quiet "$name" 2>/dev/null; then
    ok "servicio $name activo"
  else
    warn "servicio $name no activo o no instalado"
  fi
}
port() {
  local port="$1" desc="$2"
  if command -v ss >/dev/null 2>&1; then
    if ss -lntu 2>/dev/null | awk '{print $5}' | grep -qE ":$port$"; then
      ok "$desc escuchando (puerto $port)"
    else
      warn "$desc NO escuchando (puerto $port)"
    fi
  else
    warn "ss no disponible (omitida prueba de puerto $port)"
  fi
}

case "$ROL" in
  gateway)
    info "Chequeos de gateway:"
    svc chrony
    port 123 "NTP (chrony)"
    if command -v nft >/dev/null 2>&1 && [ -n "$(nft list ruleset 2>/dev/null)" ]; then
      ok "nftables activo con reglas"
    else
      warn "nftables sin reglas o no disponible"
    fi
    fwd=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)
    if [ "$fwd" = "0" ]; then
      ok "ip_forward=0 (sin reenvío)"
    else
      fail "ip_forward=$fwd (debería ser 0)"
    fi
    ;;
  web)
    info "Chequeos de web:"
    svc nginx
    port 80 "HTTP (nginx)"
    if command -v curl >/dev/null 2>&1; then
      if curl -s -m 3 http://192.168.50.20/ -o /dev/null 2>/dev/null; then
        ok "HTTP responde en http://192.168.50.20"
      else
        warn "HTTP no responde en http://192.168.50.20"
      fi
    fi
    ;;
  dns)
    info "Chequeos de dns:"
    svc dnsmasq
    port 53 "DNS (dnsmasq)"
    if command -v dig >/dev/null 2>&1; then
      if dig +time=1 +tries=1 web.lab.local @192.168.50.53 +short 2>/dev/null | grep -q "192.168.50.20"; then
        ok "resuelve web.lab.local -> 192.168.50.20"
      else
        warn "no resuelve web.lab.local vía 192.168.50.53"
      fi
    else
      warn "dig no instalado (omitida prueba de resolución)"
    fi
    ;;
  xmpp)
    info "Chequeos de xmpp:"
    svc prosody
    port 5222 "XMPP c2s (5222)"
    ;;
  *)
    info "Rol no reconocido. Uso: $0 <gateway|web|dns|xmpp>"
    ;;
esac

echo
echo "=============================================="
echo " Fin de la verificación"
date
echo "=============================================="
