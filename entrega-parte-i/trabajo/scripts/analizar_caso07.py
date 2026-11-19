#!/usr/bin/env python3
"""Caso 7: ICMP echo IPv4, comparación explícita con captura baseline real."""
import collections
import statistics
from analizar_caso01 import BASELINE, CASOS, campos, duracion, ventanas
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


def payload_echo(ip_len, ip_header_len):
    length = ip_len - ip_header_len - 8
    if length < 0:
        raise ValueError("Longitud ICMP echo inválida")
    return length


def leer(pcap):
    fields = ["frame.time_relative", "ip.src", "ip.dst", "icmp.type", "frame.len", "ip.len", "ip.hdr_len"]
    return [dict(t=float(r[0]), src=r[1], dst=r[2], type=int(r[3]), frame=int(r[4]),
                 payload=payload_echo(int(r[5]), int(r[6])))
            for r in campos(pcap, fields, "ip && (icmp.type == 0 || icmp.type == 8) && ip.flags.mf == 0 && ip.frag_offset == 0")]


def resumen(rows, duration):
    groups = collections.defaultdict(list)
    for row in rows:
        groups[row["src"], row["dst"], row["type"]].append(row)
    lines = []
    for (src, dst, typ), rs in sorted(groups.items()):
        sizes = [r["payload"] for r in rs]
        frames = [r["frame"] for r in rs]
        freq = ventanas([r["t"] for r in rs], dur=duration)
        lines.append(f"  {src} -> {dst} tipo={typ} n={len(rs)}; "
                     f"payload min/med/max={min(sizes)}/{statistics.median(sizes):g}/{max(sizes)} B; "
                     f"frame min/med/max={min(frames)}/{statistics.median(frames):g}/{max(frames)} B; "
                     f"media captura={len(rs)/duration if duration else 0:.4f}/s; máximo ventana1s={max(freq)}/s")
    return lines


def main():
    datasets = [("SINTÉTICO", CASOS / "caso07-icmp.pcap"), ("BASELINE REAL", BASELINE)]
    lines = ["CASO 7 — ICMP ECHO IPv4: TAMAÑO Y FRECUENCIA",
             "Payload = ip.len - ip.hdr_len - 8 (echo sin fragmentación); frame.len incluye cabeceras, no es payload.",
             "Solo tipos 0/8, sin fragmentos; otros ICMP e IPv6 excluidos.",
             "Ventanas 1s desde inicio de cada captura, incluyen silencios; última potencialmente parcial.",
             "Grandes payloads/frecuencia son señales para revisión, NO prueba de exfiltración o degradación."]
    fig, axes = plt.subplots(2, 1, figsize=(10, 7))
    for ax, (label, path) in zip(axes, datasets):
        rows = leer(path)
        duration = duracion(path)
        lines.extend(["", f"{label}: {path.name}; duración={duration:.6f}s; echo={len(rows)}"])
        lines.extend(resumen(rows, duration))
        lines.append(f"  Requests payload>200B={sum(r['type']==8 and r['payload']>200 for r in rows)} (umbral propuesto, no validado)")
        requests = [r for r in rows if r["type"] == 8]
        for src in sorted({r["src"] for r in requests}):
            freq = ventanas([r["t"] for r in requests if r["src"] == src], dur=duration)
            ax.step(range(len(freq)), freq, where="post", label=src)
        # Guardar todas las ventanas del host protegido; no sustituir baseline por guion.
        protected = [r["t"] for r in requests if r["dst"] == "192.168.50.20"]
        counts = ventanas(protected, dur=duration)
        lines.append("  Requests a .20 por ventanas 1s (índice=inicio): " + str(counts))
        ax.set(xlabel="Tiempo relativo de su captura (s)", ylabel="Echo-request/s", title=label)
        if requests:
            ax.legend()
        ax.grid(alpha=.3)
    lines.append("Baseline acotado a esta captura: no valida umbrales universales de ataque.")
    report = "\n".join(lines) + "\n"
    (CASOS / "caso07-analisis.txt").write_text(report, encoding="utf-8")
    print(report)
    fig.tight_layout()
    fig.savefig(CASOS / "caso07-icmp-freq.png", dpi=130)
    plt.close(fig)


if __name__ == "__main__":
    main()
