#!/usr/bin/env bash
# capturar_pantallazos.sh - Inicia sesión en la consola de cada VM, ejecuta
# los comandos de evidencia clave y toma una captura (screenshot PNG).
set -u
VBM="/c/Program Files/Oracle/VirtualBox/VBoxManage.exe"
OUT="evidencia/pantallazos"
mkdir -p "$OUT"

USER="${LAB_USER:-lab}"
PASS="${LAB_PASS:?Defina LAB_PASS con la contraseña de las VMs}"

# Scan code Enter: 0x1c presionar, 0x9c soltar
enter() { "$VBM" controlvm "$VM" keyboardputscancode 1c 9c; }
str()   { "$VBM" controlvm "$VM" keyboardputstring "$1"; }

# login y espera de shell
login() {
  str "$USER"; enter; sleep 2
  str "$PASS"; enter; sleep 3
}

# ejecuta un comando; si lleva sudo, escribe la clave cuando pida
run_cmd() {
  local cmd="$1"
  str "$cmd"; enter; sleep 2
  case "$cmd" in
    sudo*) str "$PASS"; enter; sleep 3 ;;
  esac
}

do_vm() {
  VM="$1"; local rol="$2"; local png="$3"
  shift 3
  login
  run_cmd "clear"; sleep 1
  for c in "$@"; do
    run_cmd "$c"
  done
  sleep 1
  "$VBM" controlvm "$VM" screenshotpng "$OUT/$png" 2>&1
  echo "captura: $png"
}

case "$1" in
  gateway)
    do_vm lab-gateway gateway gateway-firewall.png \
      "sudo nft list ruleset" \
      "cat /proc/sys/net/ipv4/ip_forward"
    ;;
  web)
    do_vm lab-web web web-nginx.png \
      "ip -br addr" \
      "systemctl is-active nginx" \
      "curl -sI http://192.168.50.20/"
    ;;
  dns)
    do_vm lab-dns dns dns-resolucion.png \
      "ip -br addr" \
      "dig +short web.lab.local @192.168.50.53"
    ;;
  xmpp)
    do_vm lab-xmpp xmpp xmpp-prosody.png \
      "ip -br addr" \
      "systemctl is-active prosody" \
      "ss -lntu | grep 5222"
    ;;
  all)
    "$0" gateway
    "$0" web
    "$0" dns
    "$0" xmpp
    ;;
  *)
    echo "Uso: $0 <gateway|web|dns|xmpp|all>"
    exit 2
    ;;
esac
