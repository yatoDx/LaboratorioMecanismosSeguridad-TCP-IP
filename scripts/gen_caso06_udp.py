#!/usr/bin/env python3
"""Caso 6: modelo offline de asimetría UDP genérica, NO protocolo NTP.

Un par DNS válido y 20 pares UDP en puerto didáctico 40000. Los payloads
48/468 B son datos artificiales, no peticiones/respuestas de amplificador real.
Las direcciones y la suplantación son parte del guion, sin tráfico de red.
"""
import os
import pcapgen as P

ANALISTA = "192.168.50.10"
VICTIMA = "192.168.50.20"
REFLECTOR = "192.168.50.200"
DNS = "192.168.50.53"
PORT = 40000
M_A = P.mac("08:00:27:00:00:0a")
M_V = P.mac("08:00:27:00:00:02")
M_R = P.mac("08:00:27:00:00:c8")
M_T = P.mac("08:00:27:00:00:64")
M_D = P.mac("08:00:27:00:00:03")
PEQ = b"SIMULATED-REQUEST".ljust(48, b".")
GRANDE = b"SIMULATED-RESPONSE".ljust(468, b".")


def udp_frm(src_ip, src_mac, sport, dst_ip, dst_mac, dport, payload):
    return P.ip_frame(src_ip, dst_ip, 17,
                      P.udp(sport, dport, payload, src_ip=src_ip, dst_ip=dst_ip),
                      src_mac, dst_mac)


def dns_messages():
    question = P.dns_query_name("web.lab.local") + P.struct.pack("!HH", 1, 1)
    query = P.struct.pack("!HHHHHH", 0x5000, 0x0100, 1, 0, 0, 0) + question
    # QR=1, RD=1, NOERROR, 1 pregunta y 1 respuesta A; nombre comprimido a offset12.
    answer = b"\xc0\x0c" + P.struct.pack("!HHIH", 1, 1, 60, 4) + P.socket.inet_aton(VICTIMA)
    response = P.struct.pack("!HHHHHH", 0x5000, 0x8100, 1, 1, 0, 0) + question + answer
    return query, response


def main():
    out = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "evidencia", "casos"))
    w = P.PcapWriter(os.path.join(out, "caso06-reflexion-udp.pcap"))
    query, response = dns_messages()
    w.write(udp_frm(ANALISTA, M_A, 44000, DNS, M_D, 53, query), 0.0)
    w.write(udp_frm(DNS, M_D, 53, ANALISTA, M_A, 44000, response), 0.1)
    # Un puerto cliente por par, para excluir el DNS y correlacionar el modelo.
    for i in range(20):
        w.write(udp_frm(VICTIMA, M_T, 52000 + i, REFLECTOR, M_R, PORT, PEQ), 1.0 + i * 0.02)
    for i in range(20):
        w.write(udp_frm(REFLECTOR, M_R, PORT, VICTIMA, M_V, 52000 + i, GRANDE), 1.4 + i * 0.02)
    w.close()
    print("Generado offline:", os.path.join(out, "caso06-reflexion-udp.pcap"))


if __name__ == "__main__":
    main()
