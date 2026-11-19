#!/usr/bin/env python3
"""Caso 2 — PCAP sintético con nombres legibles y etiquetas hex aleatorias.

Las etiquetas bajo .exfil.lab.local simulan un patrón para una heurística;
no contienen datos robados ni demuestran un túnel/exfiltración real.
Todo se escribe a archivo; no se envía por la red real.
"""
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pcapgen as P

CLIENTE = "192.168.50.10"
DNS = "192.168.50.53"
M_C = P.mac("08:00:27:00:00:0a")
M_D = P.mac("08:00:27:00:00:03")


def dns_header(txid, qd=1, flags=0x0100):
    return P.struct.pack("!HHHHHH", txid, flags, qd, 0, 0, 0)


def dns_question(qname, qtype=1, qclass=1):
    return P.dns_query_name(qname) + P.struct.pack("!HH", qtype, qclass)


def dns_pkt(txid, qname, flags=0x0100):
    return dns_header(txid, flags=flags) + dns_question(qname)


def query(w, sport, qname, offset, txid):
    payload = dns_pkt(txid, qname)
    frame = P.ip_frame(CLIENTE, DNS, 17,
                       P.udp(sport, 53, payload, src_ip=CLIENTE, dst_ip=DNS),
                       M_C, M_D)
    w.write(frame, offset)


def main():
    out_dir = os.path.abspath(os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "evidencia", "casos"))
    os.makedirs(out_dir, exist_ok=True)

    random.seed(42)
    normal = ["web.lab.local", "xmpp.lab.local", "gateway.lab.local", "dns.lab.local"]

    w = P.PcapWriter(os.path.join(out_dir, "caso02-dns-tunneling.pcap"))
    offset = 0.0
    txid = 0x1000

    # 1. Tráfico normal: varias consultas legítimas
    for i, name in enumerate(normal * 3):
        sport = 40000 + i
        query(w, sport, name, offset, txid)
        offset += 0.5
        txid += 1

    # 2. Patrón didáctico: etiquetas hex aleatorias bajo .exfil.lab.local
    for i in range(25):
        chunk = "".join(random.choice("0123456789abcdef") for _ in range(random.randint(24, 52)))
        qname = f"{chunk}.exfil.lab.local"
        sport = 41000 + (i % 20)
        query(w, sport, qname, offset, txid)
        offset += 0.2
        txid += 1

    w.close()
    print("Generado:", os.path.join(out_dir, "caso02-dns-tunneling.pcap"))


if __name__ == "__main__":
    main()
