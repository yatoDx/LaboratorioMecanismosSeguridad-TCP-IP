#!/usr/bin/env python3
"""Caso 8 — Escaneo de puertos (SYN scan): PCAP sintético.

El atacante (.100) envía SYN a múltiples puertos de web (.20) y xmpp (.30).
Lista SINTÉTICA PARCIAL: 25 SYN, 24 números de puerto únicos, 4 SYN-ACK y
21 RST. Se modelan 80/22 en web y 5222/5269 en xmpp. No incluye SSH :22
de .30 (observado en caso3); no es descubrimiento real de exposición.
Todo se escribe a archivo; no se envía por la red.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pcapgen as P

ATT = "192.168.50.100"
WEB = "192.168.50.20"
XMPP = "192.168.50.30"
M_T = P.mac("08:00:27:00:00:64")
M_W = P.mac("08:00:27:00:00:02")
M_X = P.mac("08:00:27:00:00:04")

# puertos a sondear en web: 80 y 22 abiertos, resto cerrados
WEB_PORTS = [21, 22, 23, 25, 53, 80, 111, 135, 139, 443, 445, 500, 1433, 3306,
             3389, 5432, 5900, 6379, 8000, 8080]
OPEN_WEB = {22, 80}
# puertos en xmpp
XMPP_PORTS = [80, 5222, 5269, 5223, 5280]
OPEN_XMPP = {5222, 5269}


def frm(src_ip, src_mac, sport, dst_ip, dst_mac, dport, flags, seq, ack):
    return P.ip_frame(src_ip, dst_ip, 6,
                      P.tcp(sport, dport, seq, ack, flags,
                            src_ip=src_ip, dst_ip=dst_ip),
                      src_mac, dst_mac)


def scan(w, dst, dst_mac, ports, open_set, start_t):
    t = start_t
    seq = 500000
    sport = 45000
    for p in ports:
        w.write(frm(ATT, M_T, sport, dst, dst_mac, p, P.TCP_SYN, seq, 0), t)
        if p in open_set:
            w.write(frm(dst, dst_mac, p, ATT, M_T, sport, P.TCP_SYN | P.TCP_ACK, 600000 + p, seq + 1), t + 0.001)
        else:
            w.write(frm(dst, dst_mac, p, ATT, M_T, sport, P.TCP_RST | P.TCP_ACK, 0, seq + 1), t + 0.001)
        t += 0.01
        seq += 1
        sport += 1
    return t


def main():
    out = os.path.abspath(os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "evidencia", "casos"))
    os.makedirs(out, exist_ok=True)
    w = P.PcapWriter(os.path.join(out, "caso08-portscan.pcap"))
    t = scan(w, WEB, M_W, WEB_PORTS, OPEN_WEB, 0.0)
    t = scan(w, XMPP, M_X, XMPP_PORTS, OPEN_XMPP, t + 0.2)
    w.close()
    print("Generado:", os.path.join(out, "caso08-portscan.pcap"))


if __name__ == "__main__":
    main()
