#!/usr/bin/env python3
"""Caso 1 — Análisis de SYN flood sobre los PCAP sintéticos.

Cuenta SYN / SYN-ACK / ACK, calcula la tasa por ventana de 1 s y genera una
gráfica comparando el tráfico sin limitación vs. con límite de tasa.
"""
import os
import subprocess
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

TSHARK = r"C:\Program Files\Wireshark\tshark.exe"
BASE = os.path.dirname(os.path.abspath(__file__))
CASOS = os.path.abspath(os.path.join(BASE, "..", "evidencia", "casos"))


def flags(pcap):
    """Devuelve lista de (t, syn, ack) por paquete TCP."""
    out = subprocess.run(
        [TSHARK, "-r", pcap, "-T", "fields",
         "-e", "frame.time_relative", "-e", "tcp.flags.syn", "-e", "tcp.flags.ack",
         "-Y", "tcp"],
        capture_output=True, text=True)
    rows = []
    for line in out.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        t = float(parts[0])
        syn = parts[1] in ("1", "True")
        ack = parts[2] in ("1", "True")
        rows.append((t, syn, ack))
    return rows


def clasificar(rows):
    syn = sum(1 for _, s, a in rows if s and not a)
    synack = sum(1 for _, s, a in rows if s and a)
    ack = sum(1 for _, s, a in rows if a)
    return syn, synack, ack


def tasa_syn(rows, window=1.0, dur=None):
    """Cuenta SYN (sin ACK) por ventana de 'window' segundos."""
    if dur is None:
        dur = max((t for t, _, _ in rows), default=0.0)
    nb = int(dur // window) + 2
    counts = [0] * nb
    for t, s, a in rows:
        if s and not a:
            counts[int(t // window)] += 1
    return counts


def main():
    sin = os.path.join(CASOS, "caso01-synflood.pcap")
    con = os.path.join(CASOS, "caso01-synflood-ratelimit.pcap")

    r1 = flags(sin)
    r2 = flags(con)
    s1, sa1, a1 = clasificar(r1)
    s2, sa2, a2 = clasificar(r2)

    lines = []
    lines.append("CASO 1 — SYN FLOOD (análisis)")
    lines.append("=" * 60)
    lines.append("")
    lines.append("Sin limitación (caso01-synflood.pcap):")
    lines.append(f"  SYN      : {s1}")
    lines.append(f"  SYN-ACK  : {sa1}")
    lines.append(f"  ACK      : {a1}")
    lines.append(f"  Total TCP: {len(r1)}")
    lines.append("")
    lines.append("Con límite de tasa 10 SYN/s (caso01-synflood-ratelimit.pcap):")
    lines.append(f"  SYN      : {s2}")
    lines.append(f"  SYN-ACK  : {sa2}")
    lines.append(f"  ACK      : {a2}")
    lines.append(f"  Total TCP: {len(r2)}")
    lines.append("")
    lines.append("Tasa de SYN (por segundo), sin limitación:")
    for i, c in enumerate(tasa_syn(r1)):
        lines.append(f"  t={i:>2}-{i+1:>2}s : {'#' * c} {c}")
    lines.append("")
    lines.append("Tasa de SYN (por segundo), con límite de tasa:")
    for i, c in enumerate(tasa_syn(r2)):
        lines.append(f"  t={i:>2}-{i+1:>2}s : {'#' * c} {c}")

    report = "\n".join(lines)
    with open(os.path.join(CASOS, "caso01-analisis.txt"), "w", encoding="utf-8") as f:
        f.write(report + "\n")
    print(report)

    # Gráfica comparativa
    c1 = tasa_syn(r1)
    c2 = tasa_syn(r2)
    n = max(len(c1), len(c2))
    c1 += [0] * (n - len(c1))
    c2 += [0] * (n - len(c2))
    x = list(range(n))
    fig, ax = plt.subplots(figsize=(9, 4))
    ax.plot(x, c1, marker="o", label="Sin limitación", color="#c0392b")
    ax.plot(x, c2, marker="s", label="Con límite 10 SYN/s", color="#27ae60")
    ax.set_xlabel("Tiempo (s)")
    ax.set_ylabel("SYN por segundo")
    ax.set_title("Caso 1 — Tasa de SYN antes y después del límite de tasa")
    ax.legend()
    ax.grid(True, alpha=0.3)
    fig.tight_layout()
    fig.savefig(os.path.join(CASOS, "caso01-syn-rate.png"), dpi=130)
    print("\nGráfica guardada en evidencia/casos/caso01-syn-rate.png")


if __name__ == "__main__":
    main()
