#!/usr/bin/env python3
"""Caso 2 — Análisis de DNS tunneling sobre el PCAP sintético.

Extrae las consultas DNS (udp.port==53), calcula longitud máxima de etiqueta y
entropía por nombre consultado, y construye una tabla por host/dominio.
"""
import collections
import math
import os
import subprocess

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

TSHARK = r"C:\Program Files\Wireshark\tshark.exe"
BASE = os.path.dirname(os.path.abspath(__file__))
CASOS = os.path.abspath(os.path.join(BASE, "..", "evidencia", "casos"))


def shannon(s: str) -> float:
    if not s:
        return 0.0
    counts = collections.Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def main():
    pcap = os.path.join(CASOS, "caso02-dns-tunneling.pcap")
    out = subprocess.run(
        [TSHARK, "-r", pcap, "-T", "fields",
         "-e", "frame.time_relative", "-e", "ip.src", "-e", "dns.qry.name",
         "-Y", "dns.flags.response == 0 && dns.qry.name"],
        capture_output=True, text=True)

    rows = []
    for line in out.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < 3 or not parts[2]:
            continue
        t = float(parts[0])
        src = parts[1]
        qname = parts[2].rstrip(".")
        labels = qname.split(".")
        maxlab = max(len(l) for l in labels)
        domain = ".".join(labels[-3:]) if len(labels) >= 3 else qname
        rows.append((t, src, qname, maxlab, domain, shannon(qname)))

    # Clasificación heurística
    def clase(r):
        _, _, _, maxlab, _, ent = r
        return "TUNEL" if (maxlab > 30 or ent > 3.5) else "NORMAL"

    lines = ["CASO 2 — DNS TUNNELING (análisis)", "=" * 60, ""]
    lines.append(f"Total consultas DNS: {len(rows)}")
    lines.append("")

    by_domain = collections.defaultdict(list)
    for r in rows:
        by_domain[r[4]].append(r)

    lines.append("Tabla por dominio (2LD) y clasificación:")
    lines.append(f"{'dominio':<24} {'n':>4} {'max_etiqueta':>13} {'entropia':>9}  clase")
    for dom, rs in sorted(by_domain.items(), key=lambda kv: -len(kv[1])):
        maxlabs = [r[3] for r in rs]
        ents = [shannon(r[2]) for r in rs]
        cls = "TUNEL" if (max(maxlabs) > 30 or max(ents) > 3.5) else "NORMAL"
        lines.append(f"{dom:<24} {len(rs):>4} {max(maxlabs):>13} {max(ents):>9.3f}  {cls}")
    lines.append("")

    by_host = collections.defaultdict(list)
    for r in rows:
        by_host[r[1]].append(r)
    lines.append("Tabla por host origen:")
    lines.append(f"{'origen':<18} {'n':>4} {'tunel':>6} {'normal':>7}")
    for h, rs in sorted(by_host.items()):
        tunel = sum(1 for r in rs if clase(r) == "TUNEL")
        lines.append(f"{h:<18} {len(rs):>4} {tunel:>6} {len(rs)-tunel:>7}")
    lines.append("")

    lines.append("Muestras de etiquetas tunelizadas (más largas):")
    for r in sorted(rows, key=lambda x: -x[3])[:5]:
        lines.append(f"  {r[3]:>3} chars, ent={shannon(r[2]):.3f}  {r[2]}")

    report = "\n".join(lines)
    with open(os.path.join(CASOS, "caso02-analisis.txt"), "w", encoding="utf-8") as f:
        f.write(report + "\n")
    print(report)

    # Scatter: longitud máx. de etiqueta vs entropía
    norm = [(r[3], shannon(r[2])) for r in rows if clase(r) == "NORMAL"]
    tun = [(r[3], shannon(r[2])) for r in rows if clase(r) == "TUNEL"]
    fig, ax = plt.subplots(figsize=(8, 5))
    if norm:
        ax.scatter([a for a, b in norm], [b for a, b in norm], c="#27ae60", label="Normal", alpha=0.7)
    if tun:
        ax.scatter([a for a, b in tun], [b for a, b in tun], c="#c0392b", label="Tunelizado", alpha=0.7)
    ax.axhline(3.5, color="gray", ls="--", lw=0.8, label="umbral entropía 3.5")
    ax.axvline(30, color="gray", ls=":", lw=0.8, label="umbral etiqueta 30")
    ax.set_xlabel("Longitud máxima de etiqueta (chars)")
    ax.set_ylabel("Entropía de Shannon (bits/símbolo)")
    ax.set_title("Caso 2 — Longitud y entropía de etiquetas DNS")
    ax.legend()
    ax.grid(True, alpha=0.3)
    fig.tight_layout()
    fig.savefig(os.path.join(CASOS, "caso02-dns-entropy.png"), dpi=130)
    print("\nGráfica guardada en evidencia/casos/caso02-dns-entropy.png")


if __name__ == "__main__":
    main()
