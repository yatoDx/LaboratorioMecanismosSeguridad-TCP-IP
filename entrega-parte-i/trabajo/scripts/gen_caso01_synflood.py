#!/usr/bin/env python3
"""Caso 1 — SYN flood: genera dos PCAP sintéticos (sin y con límite de tasa).

- Tráfico normal: 3 handshakes TCP completos analista -> web:80 (GET /).
- Ataque: 200 SYN desde 192.168.50.100 hacia web:80, sin completar (half-open).
- Versión "mitigada": el mismo ataque sujeto a un límite de ~10 SYN/s (simulado).

Nada se envía por la red real: solo se escribe a archivo.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pcapgen as P

ANALISTA = "192.168.50.10"
WEB = "192.168.50.20"
ATT = "192.168.50.100"
M_A = P.mac("08:00:27:00:00:0a")
M_W = P.mac("08:00:27:00:00:02")
M_T = P.mac("08:00:27:00:00:64")

GET = b"GET / HTTP/1.1\r\nHost: 192.168.50.20\r\nUser-Agent: curl/8.5\r\n\r\n"
OK = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: text/html\r\n\r\nOK"


def frm(src_ip, src_mac, sport, dst_ip, dst_mac, dport, flags, seq, ack, payload=b""):
    return P.ip_frame(src_ip, dst_ip, 6,
                      P.tcp(sport, dport, seq, ack, flags, payload,
                            src_ip=src_ip, dst_ip=dst_ip),
                      src_mac, dst_mac)


def handshake(w, src_ip, src_mac, base_sport, dst_ip, dst_mac, dport, seq, offset, with_http=True):
    """Handshake TCP completo y opcionalmente un GET/200."""
    sport = base_sport
    w.write(frm(src_ip, src_mac, sport, dst_ip, dst_mac, dport, P.TCP_SYN, seq, 0), offset)
    srv_seq = 400000 + sport
    w.write(frm(dst_ip, dst_mac, dport, src_ip, src_mac, sport, P.TCP_SYN | P.TCP_ACK, srv_seq, seq + 1), offset + 0.001)
    w.write(frm(src_ip, src_mac, sport, dst_ip, dst_mac, dport, P.TCP_ACK, seq + 1, srv_seq + 1), offset + 0.002)
    if with_http:
        w.write(frm(src_ip, src_mac, sport, dst_ip, dst_mac, dport, P.TCP_PSH | P.TCP_ACK, seq + 1, srv_seq + 1, GET), offset + 0.003)
        w.write(frm(dst_ip, dst_mac, dport, src_ip, src_mac, sport, P.TCP_PSH | P.TCP_ACK, srv_seq + 1, seq + 1 + len(GET), OK), offset + 0.004)
        w.write(frm(src_ip, src_mac, sport, dst_ip, dst_mac, dport, P.TCP_ACK, seq + 1 + len(GET), srv_seq + 1 + len(OK)), offset + 0.005)
    # cierre
    w.write(frm(src_ip, src_mac, sport, dst_ip, dst_mac, dport, P.TCP_FIN | P.TCP_ACK, seq + 1 + len(GET), srv_seq + 1 + len(OK)), offset + 0.006)
    w.write(frm(dst_ip, dst_mac, dport, src_ip, src_mac, sport, P.TCP_FIN | P.TCP_ACK, srv_seq + 1 + len(OK), seq + 2 + len(GET)), offset + 0.007)
    w.write(frm(src_ip, src_mac, sport, dst_ip, dst_mac, dport, P.TCP_ACK, seq + 2 + len(GET), srv_seq + 2 + len(OK)), offset + 0.008)


class TokenBucket:
    """Modelo offline: créditos continuos, capacidad burst, sin acceso a red."""

    def __init__(self, rate=10.0, burst=20):
        if rate <= 0 or burst < 1:
            raise ValueError("rate debe ser positivo y burst >= 1")
        self.rate, self.burst = rate, burst
        self.tokens = float(burst)
        self.last = None

    def allow(self, timestamp):
        if self.last is not None:
            if timestamp < self.last:
                raise ValueError("timestamps no monótonos")
            self.tokens = min(self.burst, self.tokens + (timestamp - self.last) * self.rate)
        self.last = timestamp
        if self.tokens + 1e-9 < 1:
            return False
        self.tokens = max(0.0, self.tokens - 1)
        return True


def flood(w, n_syn, start, end, rate_limit=None):
    """Vista posterior al filtro simulado, no captura de nftables ni prueba DoS."""
    bucket = TokenBucket(rate_limit, 20) if rate_limit is not None else None
    accepted = 0
    for i in range(n_syn):
        offset = start + (end - start) * (i / max(n_syn - 1, 1))
        if bucket is not None and not bucket.allow(offset):
            continue
        # Conservar identidad de los mismos paquetes en ambas variantes.
        seq, sport = 100000 + i, 40000 + i
        w.write(frm(ATT, M_T, sport, WEB, M_W, 80, P.TCP_SYN, seq, 0), offset)
        w.write(frm(WEB, M_W, 80, ATT, M_T, sport, P.TCP_SYN | P.TCP_ACK, 500000 + i, seq + 1), offset + 0.001)
        accepted += 1
    return accepted


def main():
    out_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "evidencia", "casos")
    out_dir = os.path.abspath(out_dir)
    os.makedirs(out_dir, exist_ok=True)

    # Sin limitación
    w = P.PcapWriter(os.path.join(out_dir, "caso01-synflood.pcap"))
    for i in range(3):
        handshake(w, ANALISTA, M_A, 30000 + i, WEB, M_W, 80, 1000 + i * 100, 1.0 + i * 2.0)
    flood(w, 200, 12.0, 22.0)
    w.close()

    # Modelo token bucket 10/s, burst 20 inicialmente lleno: 120/200 aceptados.
    # Solo modela la ráfaga .100; los 3 handshakes previos no consumen el bucket.
    w = P.PcapWriter(os.path.join(out_dir, "caso01-synflood-ratelimit.pcap"))
    for i in range(3):
        handshake(w, ANALISTA, M_A, 30000 + i, WEB, M_W, 80, 1000 + i * 100, 1.0 + i * 2.0)
    flood(w, 200, 12.0, 22.0, rate_limit=10)
    w.close()

    print("Generados:", os.path.join(out_dir, "caso01-synflood.pcap"),
          "y", os.path.join(out_dir, "caso01-synflood-ratelimit.pcap"))


if __name__ == "__main__":
    main()
