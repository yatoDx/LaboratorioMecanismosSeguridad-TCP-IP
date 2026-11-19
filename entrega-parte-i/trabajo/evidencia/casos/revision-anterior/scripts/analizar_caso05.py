#!/usr/bin/env python3
"""Caso 5 — Análisis de resets TCP: tabla de flujos afectados."""
import collections
import os
import subprocess

TSHARK = r"C:\Program Files\Wireshark\tshark.exe"
BASE = os.path.dirname(os.path.abspath(__file__))
CASOS = os.path.abspath(os.path.join(BASE, "..", "evidencia", "casos"))
PCAP = os.path.join(CASOS, "caso05-rst.pcap")

out = subprocess.run(
    [TSHARK, "-r", PCAP, "-T", "fields",
     "-e", "frame.time_relative", "-e", "ip.src", "-e", "tcp.srcport",
     "-e", "ip.dst", "-e", "tcp.dstport", "-e", "tcp.seq", "-e", "tcp.ack",
     "-Y", "tcp.flags.reset == 1"],
    capture_output=True, text=True)

rows = []
for line in out.stdout.splitlines():
    f = line.split("\t")
    if len(f) < 7:
        continue
    rows.append(dict(t=float(f[0]), src=f[1], sport=f[2], dst=f[3], dport=f[4],
                     seq=f[5], ack=f[6]))

flows = collections.Counter((r["src"], r["sport"], r["dst"], r["dport"]) for r in rows)

lines = ["CASO 5 — RST TCP (análisis)", "=" * 60, ""]
lines.append(f"Total paquetes RST: {len(rows)}")
lines.append("")
lines.append("Flujos afectados (origen:puerto -> destino:puerto | #RST):")
for (src, sport, dst, dport), n in sorted(flows.items(), key=lambda kv: -kv[1]):
    lines.append(f"  {src}:{sport} -> {dst}:{dport}  |  {n}")
lines.append("")
lines.append("Detalle de paquetes RST:")
for r in rows:
    lines.append(f"  t={r['t']:.3f}s  {r['src']}:{r['sport']} -> {r['dst']}:{r['dport']}  seq={r['seq']} ack={r['ack']}")

report = "\n".join(lines)
with open(os.path.join(CASOS, "caso05-analisis.txt"), "w", encoding="utf-8") as f:
    f.write(report + "\n")
print(report)
