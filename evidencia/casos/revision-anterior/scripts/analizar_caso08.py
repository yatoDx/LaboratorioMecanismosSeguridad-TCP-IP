#!/usr/bin/env python3
"""Caso 8 — Análisis de escaneo de puertos: puertos únicos por origen y exposición."""
import collections
import os
import subprocess

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

TSHARK = r"C:\Program Files\Wireshark\tshark.exe"
BASE = os.path.dirname(os.path.abspath(__file__))
CASOS = os.path.abspath(os.path.join(BASE, "..", "evidencia", "casos"))
PCAP = os.path.join(CASOS, "caso08-portscan.pcap")

out = subprocess.run(
    [TSHARK, "-r", PCAP, "-T", "fields",
     "-e", "ip.src", "-e", "ip.dst", "-e", "tcp.dstport", "-e", "tcp.srcport",
     "-e", "tcp.flags.syn", "-e", "tcp.flags.ack", "-e", "tcp.flags.reset",
     "-Y", "tcp"],
    capture_output=True, text=True)

syn_by_src = collections.defaultdict(set)   # puertos destino por origen
open_by_server = collections.defaultdict(set)  # puertos abiertos por servidor (SYN-ACK)
for line in out.stdout.splitlines():
    f = line.split("\t")
    if len(f) < 7:
        continue
    src, dst, dport, sport = f[0], f[1], f[2], f[3]
    syn, ack, rst = f[4] in ("1", "True"), f[5] in ("1", "True"), f[6] in ("1", "True")
    if syn and not ack:
        syn_by_src[src].add(dport)
    if syn and ack:
        # el SYN-ACK viene del servidor (ip.src) y su puerto es tcp.srcport
        open_by_server[src].add(sport)

lines = ["CASO 8 — ESCANEO DE PUERTOS (análisis)", "=" * 60, ""]
lines.append("Puertos únicos sondeados por origen (SYN):")
for src, ports in sorted(syn_by_src.items()):
    lines.append(f"  {src:<16} -> {len(ports):>3} puertos: {', '.join(sorted(ports, key=int))}")
lines.append("")
lines.append("Lista de exposición (puertos que respondieron SYN-ACK = abiertos):")
for srv, ports in sorted(open_by_server.items()):
    lines.append(f"  {srv:<16} : {', '.join(sorted(ports, key=int))}")

report = "\n".join(lines)
with open(os.path.join(CASOS, "caso08-analisis.txt"), "w", encoding="utf-8") as f:
    f.write(report + "\n")
print(report)

# Gráfica: puertos sondeados por origen
fig, ax = plt.subplots(figsize=(8, 4))
labels = list(syn_by_src.keys())
ax.bar(labels, [len(syn_by_src[s]) for s in labels], color="#8e44ad")
ax.set_ylabel("Puertos únicos sondeados")
ax.set_title("Caso 8 — Puertos únicos por origen (escaneo)")
ax.grid(True, alpha=0.3)
fig.tight_layout()
fig.savefig(os.path.join(CASOS, "caso08-portscan.png"), dpi=130)
print("\nGráfica guardada en evidencia/casos/caso08-portscan.png")
