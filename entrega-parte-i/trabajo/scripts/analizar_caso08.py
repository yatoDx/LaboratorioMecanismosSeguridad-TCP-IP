#!/usr/bin/env python3
"""Caso 8: cardinalidad por ventana/origen/destino, no escaneo real."""
import collections
from analizar_caso01 import CASOS, categoria, clasificar, flags, indice_ventana
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


def cardinalidad(rows, window=1.0):
    if window <= 0:
        raise ValueError("Ventana debe ser positiva")
    groups = collections.defaultdict(lambda: dict(syn=0, ports=set()))
    for row in rows:
        if categoria(row) == "SYN":
            key = indice_ventana(row["t"], window), row["src"], row["dst"]
            groups[key]["syn"] += 1
            groups[key]["ports"].add(row["dport"])
    return dict(groups)


def main():
    rows = flags(CASOS / "caso08-portscan.pcap")
    counts = clasificar(rows)
    syn = [r for r in rows if categoria(r) == "SYN"]
    lines = ["CASO 8 — LISTA SINTÉTICA PARCIAL, NO DESCUBRIMIENTO REAL",
             f"SYN={counts['SYN']}; puertos destino únicos globales={len({r['dport'] for r in syn})}; "
             f"pares destino/puerto={len({(r['dst'], r['dport']) for r in syn})}; RST={counts['RST']}; SYN-ACK={counts['SYN_ACK']}",
             "Puerto 80 repetido entre .20 y .30: 25 sondeos pero 24 números únicos."]
    for width in (0.1, 1.0):
        lines.append(f"Ventanas fijas [inicio,fin), ancho={width}s; por origen/destino (solo ventanas no vacías):")
        for (index, src, dst), group in sorted(cardinalidad(rows, width).items()):
            lines.append(f"  [{index*width:.1f},{(index+1)*width:.1f}) {src} -> {dst}: SYN={group['syn']}; "
                         f"cardinalidad={len(group['ports'])}; puertos={sorted(group['ports'])}")
    replies = collections.defaultdict(set)
    for row in rows:
        if categoria(row) == "SYN_ACK":
            replies[row["src"]].add(row["sport"])
    lines.append("Respuestas programadas SYN-ACK en el guion, no exposición confirmada:")
    for server, ports in sorted(replies.items()):
        lines.append(f"  {server}: {sorted(ports)}")
    lines.extend([".30:22 SSH no fue sondeado en este escenario; sí figura en ss real del caso3.",
                  "25 SYN no implican 25 puertos únicos, ni un contador de SYN equivale a cardinalidad.",
                  "Umbral propuesto para revisión: >=20 puertos distintos por origen/destino en 1s.",
                  "No clasifica intención ni demuestra intrusión; ventanas fijas pueden partir un escaneo.",
                  "nft solo registra SYN con límite antes de log; cardinalidad se calcula aquí, sin policy drop general."])
    report = "\n".join(lines) + "\n"
    (CASOS / "caso08-analisis.txt").write_text(report, encoding="utf-8")
    print(report)
    groups = sorted(cardinalidad(rows).items())
    fig, ax = plt.subplots(figsize=(9, 4.5))
    labels = [f"{src}\n→ {dst}\n[{index},{index+1})s" for (index, src, dst), _ in groups]
    ax.bar(labels, [len(g['ports']) for _, g in groups], color="#8e44ad")
    ax.set(ylabel="Puertos destino distintos", title="Caso 8 — Cardinalidad por origen/destino y ventana 1s (sintético)")
    ax.grid(axis="y", alpha=.3)
    fig.tight_layout()
    fig.savefig(CASOS / "caso08-portscan.png", dpi=130)
    plt.close(fig)


if __name__ == "__main__":
    main()
