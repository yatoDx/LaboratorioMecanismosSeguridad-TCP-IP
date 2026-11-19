#!/usr/bin/env python3
"""Caso 1: categorías excluyentes, handshakes correlacionados y baseline real.

Las utilidades de lectura/ventanas también las usan los casos de esta revisión.
Solo lectura de PCAP; nunca se captura ni transmite tráfico.
"""
import collections
from decimal import Decimal
import math
import os
from pathlib import Path
import shutil
import subprocess

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

TSHARK = os.environ.get("TSHARK") or shutil.which("tshark") or r"C:\Program Files\Wireshark\tshark.exe"
CASOS = Path(__file__).resolve().parents[1] / "evidencia" / "casos"
BASELINE = CASOS.parent / "baseline-normal.pcapng"


def campos(pcap, fields, filtro=None):
    cmd = [TSHARK, "-n", "-r", str(pcap), "-T", "fields", "-E", "occurrence=f"]
    for field in fields:
        cmd.extend(["-e", field])
    if filtro:
        cmd.extend(["-Y", filtro])
    result = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if result.returncode:
        raise RuntimeError(f"tshark falló ({pcap}): {result.stderr.strip()}")
    rows = []
    for line in result.stdout.splitlines():
        row = line.split("\t")
        if len(row) != len(fields):
            raise ValueError(f"Fila incompleta en {pcap}: {line!r}")
        rows.append(row)
    return rows


def duracion(pcap):
    """Duración de toda la captura, no solo del filtro de interés."""
    return max((float(r[0]) for r in campos(pcap, ["frame.time_relative"])), default=0.0)


def indice_ventana(t, window):
    # Decimales de tshark: evita 0.3//0.1 == 2 por redondeo binario.
    return int(Decimal(str(t)) // Decimal(str(window)))


def ventanas(times, window=1.0, dur=None):
    """Conteos en [k*w,(k+1)*w); incluye ventanas vacías hasta dur.

    Tasas = conteo / ancho nominal. La última ventana puede estar parcialmente
    observada; no confundir el ancho nominal con duración exacta de captura.
    """
    times = list(times)
    if window <= 0 or any(t < 0 or not math.isfinite(t) for t in times):
        raise ValueError("Ventana positiva y tiempos finitos no negativos requeridos")
    end = max(times, default=0.0) if dur is None else dur
    if end < 0 or not math.isfinite(end) or any(t > end + 1e-6 for t in times):
        raise ValueError("Duración incompatible")
    counts = [0] * (indice_ventana(end, window) + 1)
    for t in times:
        counts[indice_ventana(t, window)] += 1
    return counts


def flags(pcap, filtro="tcp && ip"):
    names = ["frame.time_relative", "ip.src", "tcp.srcport", "ip.dst", "tcp.dstport",
             "tcp.flags", "tcp.seq_raw", "tcp.ack_raw", "tcp.len", "tcp.stream"]
    return [dict(t=float(r[0]), src=r[1], sport=int(r[2]), dst=r[3], dport=int(r[4]),
                 flags=int(r[5], 16), seq=int(r[6]), ack=int(r[7]), length=int(r[8]),
                 stream=int(r[9])) for r in campos(pcap, names, filtro)]


def categoria(row):
    f = row["flags"]
    if f & 4:
        return "RST"
    if f & 2:
        return "SYN_ACK" if f & 16 else "SYN"
    if f & 1:
        return "FIN"
    if f & 16:
        return "ACK_sin_SYN_FIN_RST"
    return "OTRO"


def clasificar(rows):
    return collections.Counter(categoria(r) for r in rows)


def tupla(row):
    return row["src"], row["sport"], row["dst"], row["dport"]


def inversa(key):
    return key[2], key[3], key[0], key[1]


def handshakes(rows, timeout=10.0):
    """Correlaciona stream+4-tupla+ISN y seq/ack raw; deduplica retransmisiones.

    Completado significa tres segmentos observados, no estado interno del host.
    SYN anteriores al comienzo de la captura no pueden recuperarse aquí.
    """
    attempts = {}
    for r in sorted(rows, key=lambda p: p["t"]):
        key, stream = tupla(r), r["stream"]
        cat = categoria(r)
        if cat == "SYN":
            identity = stream, key, r["seq"]
            attempts.setdefault(identity, dict(src=r["src"], dst=r["dst"], start=r["t"],
                                               synack=None, completed=None, closed=False))
        elif cat == "SYN_ACK":
            identity = stream, inversa(key), (r["ack"] - 1) % 2**32
            a = attempts.get(identity)
            if a and not a["closed"] and 0 <= r["t"] - a["start"] <= timeout:
                if a["synack"] is None:
                    a["synack"] = (r["seq"], r["t"])
        elif cat in ("RST", "FIN"):
            for (s, k, _), a in attempts.items():
                if s == stream and k in (key, inversa(key)):
                    a["closed"] = True
        elif cat == "ACK_sin_SYN_FIN_RST":
            identity = stream, key, (r["seq"] - 1) % 2**32
            a = attempts.get(identity)
            if (a and not a["closed"] and a["completed"] is None and a["synack"]
                    and a["synack"][1] <= r["t"] <= a["start"] + timeout
                    and r["ack"] == (a["synack"][0] + 1) % 2**32):
                a["completed"] = r["t"]
    return list(attempts.values())


def tasa_syn(rows, window=1.0, dur=None):
    return [n / window for n in ventanas((r["t"] for r in rows if categoria(r) == "SYN"), window, dur)]


def main():
    datasets = [
        ("Sintético sin filtro", CASOS / "caso01-synflood.pcap"),
        ("Sintético token bucket 10/s burst20", CASOS / "caso01-synflood-ratelimit.pcap"),
        ("Baseline REAL HTTP web", BASELINE),
    ]
    lines = ["CASO 1 — ANÁLISIS OFFLINE", "Categorías excluyentes; ACK no incluye SYN-ACK ni FIN/RST.",
             "Handshake: stream+4-tupla+seq/ack raw, timeout 10s, retransmisiones deduplicadas.",
             "No se midió agotamiento, disponibilidad ni eficacia real de nftables.",
             "Ventanas 1s desde inicio de cada captura; última potencialmente parcial.",
             "Comparación HTTP: tcp && ip.addr == 192.168.50.20 && tcp.port == 80."]
    fig, axes = plt.subplots(2, 1, figsize=(10, 7))
    for index, (label, path) in enumerate(datasets):
        rows = flags(path, "tcp && ip.addr == 192.168.50.20 && tcp.port == 80")
        duration = duracion(path)
        counts = clasificar(rows)
        attempts = handshakes(rows)
        complete = sum(a["completed"] is not None for a in attempts)
        rates = tasa_syn(rows, dur=duration)
        lines.extend(["", f"{label}: {path.name}; duración total={duration:.6f}s",
                      f"TCP={len(rows)}; categorías={dict(counts)}",
                      f"Intentos únicos={len(attempts)}; handshakes completos={complete}; sin completar observado={len(attempts)-complete}",
                      f"SYN/s media captura={counts['SYN']/duration if duration else 0:.4f}; máximo ventana={max(rates):.1f}"])
        if not attempts:
            lines.append("No se observó inicio SYN en este ámbito: cero handshakes correlacionables NO significa ausencia de sesiones.")
            lines.append("La captura puede comenzar con sesiones existentes; no permite calibrar un umbral de establecimiento normal.")
        for i, rate in enumerate(rates):
            lines.append(f"  [{i},{i+1})s: SYN={int(rate)}; SYN/s={rate:.1f}")
        axes[0 if index < 2 else 1].step(range(len(rates)), rates, where="post", label=label)
    for ax in axes:
        ax.set_xlabel("Tiempo relativo de su propia captura (s)")
        ax.set_ylabel("SYN/s (ventanas 1s)")
        ax.legend()
        ax.grid(alpha=0.3)
    axes[0].set_title("Modelo offline: no prueba de mitigación en VM")
    axes[1].set_title("Baseline real leído, no los 3 handshakes sintéticos")
    fig.tight_layout()
    fig.savefig(CASOS / "caso01-syn-rate.png", dpi=130)
    plt.close(fig)
    report = "\n".join(lines) + "\n"
    (CASOS / "caso01-analisis.txt").write_text(report, encoding="utf-8")
    print(report)


if __name__ == "__main__":
    main()
