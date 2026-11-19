#!/usr/bin/env python3
"""Caso 6 — Reflexión/amplificación UDP: PCAP didáctico.

- Tráfico normal: DNS (analista<->dns) y NTP (analista<->gateway).
- Ataque: el atacante (.100) envía 20 peticiones UDP pequeñas (48 B) al
  "reflector" (.200) con IP de origen suplantada = víctima (.20); el reflector
  responde 20 datagramas grandes (468 B) hacia la víctima (amplificación ~10x).
Todo se escribe a archivo; no se envía por la red real.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pcapgen as P

ANALISTA = "192.168.50.10"
VICTIMA = "192.168.50.20"
REFLECTOR = "192.168.50.200"
ATACANTE = "192.168.50.100"
DNS = "192.168.50.53"
GATEWAY = "192.168.50.1"
M_A = P.mac("08:00:27:00:00:0a")
M_V = P.mac("08:00:27:00:00:02")
M_R = P.mac("08:00:27:00:00:c8")
M_T = P.mac("08:00:27:00:00:64")
M_D = P.mac("08:00:27:00:00:03")
M_G = P.mac("08:00:27:00:00:01")

PEQ = b"\x00" * 48    # petición pequeña
GRANDE = b"\x00" * 468  # respuesta amplificada


def udp_frm(src_ip, src_mac, sport, dst_ip, dst_mac, dport, payload):
    return P.ip_frame(src_ip, dst_ip, 17,
                      P.udp(sport, dport, payload, src_ip=src_ip, dst_ip=dst_ip),
                      src_mac, dst_mac)


def main():
    out = os.path.abspath(os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "evidencia", "casos"))
    os.makedirs(out, exist_ok=True)
    w = P.PcapWriter(os.path.join(out, "caso06-reflexion-udp.pcap"))
    t = 0.0

    # 1. Tráfico normal
    dns_q = P.dns_query_name("web.lab.local")
    dns_hdr = P.struct.pack("!HHHHHH", 0x5000, 0x0100, 1, 0, 0, 0)
    w.write(udp_frm(ANALISTA, M_A, 44000, DNS, M_D, 53, dns_hdr + dns_q), t)
    # (respuesta DNS simplificada)
    w.write(udp_frm(DNS, M_D, 53, ANALISTA, M_A, 44000, dns_hdr + dns_q), t + 0.1)
    # NTP
    w.write(udp_frm(ANALISTA, M_A, 123, GATEWAY, M_G, 123, b"\x1b" + b"\x00" * 47), t + 0.5)
    w.write(udp_frm(GATEWAY, M_G, 123, ANALISTA, M_A, 123, b"\x1c" + b"\x00" * 47), t + 0.6)
    t += 1.0

    # 2. Ataque de amplificación: peticiones con origen suplantado = víctima
    for i in range(20):
        # petición: IP src = víctima (suplantada), MAC src = atacante
        w.write(udp_frm(VICTIMA, M_T, 52000 + i, REFLECTOR, M_R, 123, PEQ), t)
        t += 0.02
    # respuestas amplificadas del reflector hacia la víctima
    for i in range(20):
        w.write(udp_frm(REFLECTOR, M_R, 123, VICTIMA, M_V, 52000 + i, GRANDE), t)
        t += 0.02

    w.close()
    print("Generado:", os.path.join(out, "caso06-reflexion-udp.pcap"))


if __name__ == "__main__":
    main()
