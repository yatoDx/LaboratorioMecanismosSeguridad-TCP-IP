#!/usr/bin/env python3
"""Caso 6 — Reflexión UDP: paquetes/bytes por segundo y factor de amplificación."""
import os
import subprocess

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

TSHARK = r"C:\Program Files\Wireshark\tshark.exe"
BASE = os.path.dirname(os.path.abspath(__file__))
CASOS = os.path.abspath(os.path.join(BASE, "..", "evidencia", "casos"))
PCAP = os.path.join(CASOS, "caso06-reflexion-udp.pcap")

out = subprocess.run(
    [TSHARK, "-r", PCAP, "-T", "fields",
     "-e", "frame.time_relative", "-e", "ip.src", "-e", "ip.dst",
     "-e", "udp.length", "-e", "frame.len",
     "-Y", "udp"],
    capture_output=True, text=True)

rows = []
for line in out.stdout.splitlines():
    f = line.split("\t")
    if len(f) < 4:
        continue
    try:
        t = float(f[0])
        ulen = int(f[3] or 0)
        flen = int(f[4] or 0)
    except ValueError:
        continue
    rows.append((t, f[1], f[2], ulen, flen))

# ventanas de 0.5 s
dur = max(r[0] for r in rows)
nb = int(dur // 0.5) + 1
pkts = [0] * nb
byts = [0] * nb
for r in rows:
    i = int(r[0] // 0.5)
    pkts[i] += 1
    byts[i] += r[4]

# Factor de amplificación: bytes hacia la víctima / bytes de petición
victima = "192.168.50.20"
req_bytes = sum(r[4] for r in rows if r[1] == victima)   # "peticiones" (suplantadas)
resp_bytes = sum(r[4] for r in rows if r[2] == victima)  # respuestas hacia la víctima
amp = (resp_bytes / req_bytes) if req_bytes else 0.0

lines = ["CASO 6 — REFLEXIÓN/AMPLIFICACIÓN UDP (análisis)", "=" * 60, ""]
lines.append(f"Total datagramas UDP: {len(rows)}")
lines.append(f"Bytes enviados con origen suplantado (víctima): {req_bytes}")
lines.append(f"Bytes recibidos por la víctima (respuestas):    {resp_bytes}")
lines.append(f"Factor de amplificación: {amp:.1f}x")
lines.append("")
lines.append("Paquetes/bytes por segundo (ventana 0.5 s):")
for i in range(nb):
    lines.append(f"  t={i*0.5:>4.1f}s : {pkts[i]:>3} pkt  {byts[i]:>6} bytes")

report = "\n".join(lines)
with open(os.path.join(CASOS, "caso06-analisis.txt"), "w", encoding="utf-8") as f:
    f.write(report + "\n")
print(report)

x = [i * 0.5 for i in range(nb)]
fig, (a1, a2) = plt.subplots(2, 1, figsize=(9, 5.5), sharex=True)
a1.bar(x, pkts, width=0.4, color="#3498db")
a1.set_ylabel("Paquetes/s")
a1.set_title("Caso 6 — Reflexión UDP: paquetes y bytes por segundo")
a2.bar(x, byts, width=0.4, color="#c0392b")
a2.set_ylabel("Bytes/s")
a2.set_xlabel("Tiempo (s)")
for ax in (a1, a2):
    ax.grid(True, alpha=0.3)
fig.tight_layout()
fig.savefig(os.path.join(CASOS, "caso06-udp-rate.png"), dpi=130)
print("\nGráfica guardada en evidencia/casos/caso06-udp-rate.png")
