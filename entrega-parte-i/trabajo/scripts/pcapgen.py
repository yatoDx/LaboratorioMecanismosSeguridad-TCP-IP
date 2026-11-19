#!/usr/bin/env python3
"""Generador de PCAP sintéticos (solo stdlib).

Construye tramas Ethernet/IPv4/TCP/UDP/ICMP con checksums correctos y las
escribe en un archivo PCAP (linktype Ethernet). Pensado para producir tráfico
DIDÁCTICO/SINTÉTICO "a archivo, sin enviarlo" por la red real del laboratorio.
"""
import socket
import struct
import time

# Constantes
ETHERTYPE_IPV4 = 0x0800

TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10
TCP_URG = 0x20

ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY = 0
ICMP_DEST_UNREACH = 3


def mac(s: str) -> bytes:
    return bytes.fromhex(s.replace(":", "").replace("-", ""))


def cksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def ipv4(src, dst, proto, payload, ident=0, ttl=64, dscp=0):
    ver_ihl = 0x45
    tos = (dscp << 2) & 0xFF
    total = 20 + len(payload)
    flags_frag = 0x4000  # DF
    hdr = struct.pack("!BBHHHBBH4s4s",
                      ver_ihl, tos, total, ident & 0xFFFF, flags_frag, ttl, proto, 0,
                      socket.inet_aton(src), socket.inet_aton(dst))
    hdr = hdr[:10] + struct.pack("!H", cksum(hdr)) + hdr[12:]
    return hdr + payload


def tcp(srcp, dstp, seq, ack, flags, payload=b"", window=64240,
        src_ip="192.168.50.10", dst_ip="192.168.50.20"):
    data_offset = 5
    hdr = struct.pack("!HHIIBBHHH",
                      srcp, dstp, seq, ack, (data_offset << 4), flags, window, 0, 0)
    total = 20 + len(payload)
    pseudo = socket.inet_aton(src_ip) + socket.inet_aton(dst_ip) + \
        struct.pack("!BBH", 0, 6, total)
    hdr = hdr[:16] + struct.pack("!H", cksum(pseudo + hdr + payload)) + hdr[18:]
    return hdr + payload


def udp(srcp, dstp, payload, src_ip="192.168.50.10", dst_ip="192.168.50.53"):
    total = 8 + len(payload)
    pseudo = socket.inet_aton(src_ip) + socket.inet_aton(dst_ip) + \
        struct.pack("!BBH", 0, 17, total)
    hdr = struct.pack("!HHHH", srcp, dstp, total, 0)
    c = cksum(pseudo + hdr + payload)
    if c == 0:
        c = 0xFFFF
    hdr = struct.pack("!HHHH", srcp, dstp, total, c)
    return hdr + payload


def icmp(itype, code, ident, seq, payload=b""):
    hdr = struct.pack("!BBHHH", itype, code, 0, ident, seq)
    c = cksum(hdr + payload)
    hdr = struct.pack("!BBHHH", itype, code, c, ident, seq)
    return hdr + payload


def eth(dst, src, ethertype, payload):
    return struct.pack("!6s6sH", dst, src, ethertype) + payload


def ip_frame(src, dst, proto, payload, src_mac, dst_mac, **kw):
    p = ipv4(src, dst, proto, payload, **kw)
    return eth(dst_mac, src_mac, ETHERTYPE_IPV4, p)


class PcapWriter:
    def __init__(self, path):
        self.f = open(path, "wb")
        # global header: magic, v2.4, thiszone, sigfigs, snaplen, network=1
        self.f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        self._t0 = time.time()

    def write(self, frame, offset=0.0):
        ts = self._t0 + offset
        sec = int(ts)
        usec = int((ts - sec) * 1e6)
        self.f.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
        self.f.write(frame)

    def close(self):
        self.f.close()


def dns_query_name(qname: str) -> bytes:
    """Codifica un nombre DNS en formato de etiquetas."""
    out = b""
    for label in qname.split("."):
        out += bytes([len(label)]) + label.encode("ascii", "replace")
    return out + b"\x00"
