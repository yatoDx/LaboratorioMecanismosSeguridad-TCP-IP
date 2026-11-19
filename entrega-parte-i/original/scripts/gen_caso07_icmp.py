#!/usr/bin/env python3
"""Caso 7 — ICMP: PCAP sintético con tráfico normal y payloads atípicos.

- Ping sintético: analista -> 4 VMs (echo request/reply, payload 9 B).
- Ráfaga sintética: .100 -> web (.20), 50 requests en ~5 s, payload 64 B.
- Cinco requests con payload artificial 1289 B (trama 1331 B).
  El tamaño no demuestra túnel, exfiltración ni impacto DoS.
Todo se escribe a archivo; no se envía por la red real.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pcapgen as P

ANALISTA = "192.168.50.10"
ATT = "192.168.50.100"
M_A = P.mac("08:00:27:00:00:0a")
M_T = P.mac("08:00:27:00:00:64")
VMS = {
    "192.168.50.1": P.mac("08:00:27:00:00:01"),
    "192.168.50.20": P.mac("08:00:27:00:00:02"),
    "192.168.50.53": P.mac("08:00:27:00:00:03"),
    "192.168.50.30": P.mac("08:00:27:00:00:04"),
}


def icmp_frm(src_ip, src_mac, dst_ip, dst_mac, itype, ident, seq, payload):
    return P.ip_frame(src_ip, dst_ip, 1,
                      P.icmp(itype, 0, ident, seq, payload), src_mac, dst_mac)


def main():
    out = os.path.abspath(os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "evidencia", "casos"))
    os.makedirs(out, exist_ok=True)
    w = P.PcapWriter(os.path.join(out, "caso07-icmp.pcap"))
    t = 0.0

    # 1. Ping normal hacia las 4 VMs
    for i, (ip, mac) in enumerate(VMS.items()):
        w.write(icmp_frm(ANALISTA, M_A, ip, mac, 8, 1, i, b"ping-ping"), t)
        w.write(icmp_frm(ip, mac, ANALISTA, M_A, 0, 1, i, b"ping-ping"), t + 0.05)
        t += 0.5

    # 2. Flood ICMP: 50 requests en ~5 s
    for i in range(50):
        w.write(icmp_frm(ATT, M_T, "192.168.50.20", VMS["192.168.50.20"],
                         8, 2, i, b"F" * 64), t)
        t += 0.1

    # 3. Payload artificial grande; no prueba de un túnel real
    for i in range(5):
        w.write(icmp_frm(ATT, M_T, "192.168.50.20", VMS["192.168.50.20"],
                         8, 3, i, b"DATA-" + bytes(range(256)) * 5 + b"-END"), t)
        t += 0.2

    w.close()
    print("Generado:", os.path.join(out, "caso07-icmp.pcap"))


if __name__ == "__main__":
    main()
