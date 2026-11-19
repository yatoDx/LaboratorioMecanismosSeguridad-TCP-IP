#!/usr/bin/env python3
"""Caso 5 — RST TCP: PCAP didáctico con resets de conexiones.

Escenarios:
  1. Conexión normal analista -> web:80 (GET/200) terminada con RST del servidor.
  2. Conexión analista -> xmpp:5222 terminada con RST del cliente.
  3. Cuatro RST de .100 con tuplas ajenas a los flujos anteriores: fuera de flujo,
     NO inyección efectiva ni prueba de falsificación. ACK=0 con flag ACK ausente
     no es por sí solo ilegítimo; estos escenarios no involucran sockets reales.
Todo se escribe a archivo; no se envía por la red real.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pcapgen as P

ANALISTA = "192.168.50.10"
WEB = "192.168.50.20"
XMPP = "192.168.50.30"
ATT = "192.168.50.100"
M_A = P.mac("08:00:27:00:00:0a")
M_W = P.mac("08:00:27:00:00:02")
M_X = P.mac("08:00:27:00:00:04")
M_T = P.mac("08:00:27:00:00:64")

GET = b"GET / HTTP/1.1\r\nHost: 192.168.50.20\r\n\r\n"
OK = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"
XMPP_OPEN = b"<stream:stream to='lab.local'>"


def frm(src_ip, src_mac, sport, dst_ip, dst_mac, dport, flags, seq, ack, payload=b""):
    return P.ip_frame(src_ip, dst_ip, 6,
                      P.tcp(sport, dport, seq, ack, flags, payload,
                            src_ip=src_ip, dst_ip=dst_ip),
                      src_mac, dst_mac)


def main():
    out = os.path.abspath(os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "evidencia", "casos"))
    os.makedirs(out, exist_ok=True)
    w = P.PcapWriter(os.path.join(out, "caso05-rst.pcap"))
    t = 0.0

    # --- 1. Web: handshake + GET/200 + RST del servidor ---
    cseq, sseq = 1000, 90000
    w.write(frm(ANALISTA, M_A, 31000, WEB, M_W, 80, P.TCP_SYN, cseq, 0), t); t += 0.1
    w.write(frm(WEB, M_W, 80, ANALISTA, M_A, 31000, P.TCP_SYN | P.TCP_ACK, sseq, cseq + 1), t); t += 0.1
    w.write(frm(ANALISTA, M_A, 31000, WEB, M_W, 80, P.TCP_ACK, cseq + 1, sseq + 1), t); t += 0.1
    w.write(frm(ANALISTA, M_A, 31000, WEB, M_W, 80, P.TCP_PSH | P.TCP_ACK, cseq + 1, sseq + 1, GET), t); t += 0.1
    w.write(frm(WEB, M_W, 80, ANALISTA, M_A, 31000, P.TCP_PSH | P.TCP_ACK, sseq + 1, cseq + 1 + len(GET), OK), t); t += 0.1
    # RST del servidor
    w.write(frm(WEB, M_W, 80, ANALISTA, M_A, 31000, P.TCP_RST, sseq + 1 + len(OK), cseq + 1 + len(GET)), t); t += 1.0

    # --- 2. XMPP: handshake + apertura de stream + RST del cliente ---
    cseq, sseq = 2000, 70000
    w.write(frm(ANALISTA, M_A, 32000, XMPP, M_X, 5222, P.TCP_SYN, cseq, 0), t); t += 0.1
    w.write(frm(XMPP, M_X, 5222, ANALISTA, M_A, 32000, P.TCP_SYN | P.TCP_ACK, sseq, cseq + 1), t); t += 0.1
    w.write(frm(ANALISTA, M_A, 32000, XMPP, M_X, 5222, P.TCP_ACK, cseq + 1, sseq + 1), t); t += 0.1
    w.write(frm(ANALISTA, M_A, 32000, XMPP, M_X, 5222, P.TCP_PSH | P.TCP_ACK, cseq + 1, sseq + 1, XMPP_OPEN), t); t += 0.1
    # RST del cliente (abortar sesión)
    w.write(frm(ANALISTA, M_A, 32000, XMPP, M_X, 5222, P.TCP_RST, cseq + 1 + len(XMPP_OPEN), sseq + 1), t); t += 1.0

    # --- 3. RST de un tercero: 4-tupla diferente, sin conexión observada ---
    for i in range(4):
        w.write(frm(ATT, M_T, 41000 + i, WEB, M_W, 80, P.TCP_RST, 400000 + i * 100, 0), t); t += 0.05

    w.close()
    print("Generado:", os.path.join(out, "caso05-rst.pcap"))


if __name__ == "__main__":
    main()
