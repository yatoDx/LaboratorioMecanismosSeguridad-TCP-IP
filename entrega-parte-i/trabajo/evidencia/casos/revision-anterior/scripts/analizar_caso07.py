#!/usr/bin/env python3
"""Caso 7 — Análisis ICMP: tamaños y frecuencias por IP origen."""
import collections
import os
import subprocess

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

TSHARK = r"C:\Program Files\Wireshark\tshark.exe"
BASE = os.path.dirname(os.path.abspath(__file__))
CASOS = os.path.abspath(os.path.join(BASE, "..", "evidencia", "casos"))
PCAP = os.path.join(CASOS, "caso07-icmp.pcap")

out = subprocess.run(
    [TSHARK, "-r", PCAP, "-T", "fields",
     "-e", "frame.time_relative", "-e", "ip.src", "-e", "ip.dst",
     "-e", "icmp.type", "-e", "frame.len",
     "-Y", "icmp"],
    capture_output=True, text=True)

rows = []
for line in out.stdout.splitlines():
    f = line.split("\t")
    if len(f) < 5:
        continue
    try:
        t = float(f[0])
        length = int(f[4])
    except ValueError:
        continue
    rows.append((t, f[1], f[2], f[3], length))

by_src = collections.defaultdict(list)
for r in rows:
    by_src[r[1]].append(r)

lines = ["CASO 7 — ICMP (análisis)", "=" * 60, ""]
lines.append(f"Total paquetes ICMP: {len(rows)}")
lines.append("")
lines.append("Tabla por IP origen (n, tamaño min/med/max, tipo):")
for src, rs in sorted(by_src.items(), key=lambda kv: -len(kv[1])):
    lens = [r[4] for r in rs]
    types = collections.Counter(r[3] for r in rs)
    lines.append(f"  {src:<16} n={len(rs):>3}  min={min(lens):>4} med={sorted(lens)[len(lens)//2]:>4} "
                 f"max={max(lens):>4}  tipos={dict(types)}")
lines.append("")
lines.append("Muestras de payloads atípicos (frame.len > 200):")
for r in [x for x in rows if x[4] > 200][:3]:
    lines.append(f"  t={r[0]:.1f}s  {r[1]} -> {r[2]}  len={r[4]}  tipo={r[3]}")

report = "\n".join(lines)
with open(os.path.join(CASOS, "caso07-analisis.txt"), "w", encoding="utf-8") as f:
    f.write(report + "\n")
print(report)

# Frecuencia por IP origen en el tiempo (hist)
fig, ax = plt.subplots(figsize=(8, 4))
for src in sorted(by_src):
    ts = [r[0] for r in by_src[src]]
    ax.hist(ts, bins=20, alpha=0.6, label=src)
ax.set_xlabel("Tiempo (s)")
ax.set_ylabel("Paquetes ICMP")
ax.set_title("Caso 7 — Frecuencia de ICMP por origen")
ax.legend()
ax.grid(True, alpha=0.3)
fig.tight_layout()
fig.savefig(os.path.join(CASOS, "caso07-icmp-freq.png"), dpi=130)
print("\nGráfica guardada en evidencia/casos/caso07-icmp-freq.png")
