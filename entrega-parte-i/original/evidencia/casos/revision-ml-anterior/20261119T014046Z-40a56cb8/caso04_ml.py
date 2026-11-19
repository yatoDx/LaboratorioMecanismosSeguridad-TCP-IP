#!/usr/bin/env python3
"""Caso 4 — Detección de anomalías con IsolationForest vs línea base estadística.

Pipeline reproducible:
  1. Extrae características agregadas por ventana de tiempo desde PCAP (tshark).
  2. Construye el dataset etiquetado: baseline = normal, ataques = anomalía.
  3. Entrena IsolationForest sobre las ventanas normales.
  4. Compara con una línea base estadística (z-score) y reporta métricas
     (accuracy, precision, recall, F1) y matriz de confusión.

Características por ventana: n_pkts, n_bytes, n_flows, n_syn, n_reset,
n_distinct_dports, syn_ratio, bytes_per_flow.
"""
import collections
import os
import subprocess

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score,
                             precision_score, recall_score, ConfusionMatrixDisplay)

TSHARK = r"C:\Program Files\Wireshark\tshark.exe"
BASE = os.path.dirname(os.path.abspath(__file__))
CASOS = os.path.abspath(os.path.join(BASE, "..", "evidencia", "casos"))
BASELINE = os.path.abspath(os.path.join(BASE, "..", "evidencia", "baseline-normal.pcapng"))

FEATURES = ["n_pkts", "n_bytes", "n_flows", "n_syn", "n_reset",
            "n_dst_ports", "syn_ratio", "bytes_per_flow"]


def load_packets(pcap):
    """Devuelve una lista de dicts por paquete con los campos de interés."""
    out = subprocess.run(
        [TSHARK, "-r", pcap, "-T", "fields",
         "-E", "separator=|", "-E", "occurrence=a",
         "-e", "frame.time_relative", "-e", "ip.proto",
         "-e", "ip.src", "-e", "ip.dst",
         "-e", "tcp.srcport", "-e", "tcp.dstport",
         "-e", "udp.srcport", "-e", "udp.dstport",
         "-e", "frame.len", "-e", "tcp.flags.syn", "-e", "tcp.flags.reset"],
        capture_output=True, text=True)
    rows = []
    for line in out.stdout.splitlines():
        f = line.split("|")
        if len(f) < 11:
            continue
        try:
            t = float(f[0])
        except ValueError:
            continue
        proto = f[1]
        src, dst = f[2], f[3]
        sport = f[4] or f[6] or "0"
        dport = f[5] or f[7] or "0"
        length = int(f[8] or 0)
        syn = f[9] in ("1", "True")
        rst = f[10] in ("1", "True")
        rows.append(dict(t=t, proto=proto, src=src, dst=dst,
                         sport=sport, dport=dport, length=length,
                         syn=syn, rst=rst))
    return rows


def aggregate(rows, window):
    """Agrega por ventana de 'window' segundos y devuelve lista de dicts."""
    if not rows:
        return []
    dur = max(r["t"] for r in rows)
    nb = int(dur // window) + 1
    buckets = [[] for _ in range(nb)]
    for r in rows:
        buckets[int(r["t"] // window)].append(r)

    feats = []
    for b in buckets:
        if not b:
            continue
        n_pkts = len(b)
        n_bytes = sum(r["length"] for r in b)
        flows = set((r["src"], r["dst"], r["sport"], r["dport"], r["proto"]) for r in b)
        n_flows = len(flows)
        n_syn = sum(1 for r in b if r["syn"])
        n_reset = sum(1 for r in b if r["rst"])
        n_dst_ports = len(set(r["dport"] for r in b))
        syn_ratio = n_syn / max(n_pkts, 1)
        bytes_per_flow = n_bytes / max(n_flows, 1)
        feats.append(dict(n_pkts=n_pkts, n_bytes=n_bytes, n_flows=n_flows,
                          n_syn=n_syn, n_reset=n_reset,
                          n_dst_ports=n_dst_ports, syn_ratio=syn_ratio,
                          bytes_per_flow=bytes_per_flow))
    return feats


def build_dataset():
    norm = aggregate(load_packets(BASELINE), window=15.0)
    anom = []
    anom += aggregate(load_packets(os.path.join(CASOS, "caso01-synflood.pcap")), window=5.0)
    anom += aggregate(load_packets(os.path.join(CASOS, "caso02-dns-tunneling.pcap")), window=3.0)

    X = pd.DataFrame(norm + anom)
    y = np.array([0] * len(norm) + [1] * len(anom))
    return X, y, len(norm), len(anom)


def main():
    X, y, n_norm, n_anom = build_dataset()
    X.to_csv(os.path.join(CASOS, "caso04-dataset.csv"), index=False)

    lines = ["CASO 4 — ANOMALÍAS CON ML (IsolationForest vs línea base)",
             "=" * 60, ""]
    lines.append(f"Ventanas normales (baseline): {n_norm}")
    lines.append(f"Ventanas anómalas (ataques):  {n_anom}")
    lines.append(f"Características: {', '.join(FEATURES)}")
    lines.append("")

    # Línea base estadística (z-score sobre las normales)
    norm = X[y == 0]
    mean = norm.mean()
    std = norm.std().replace(0, 1e-9)
    z = (X - mean) / std
    z_anom = (z.abs() > 3).any(axis=1).astype(int).to_numpy()

    # IsolationForest entrenado sobre las normales
    clf = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
    clf.fit(X[y == 0])
    pred = clf.predict(X)  # -1 anomalía, 1 normal
    pred_bin = (pred == -1).astype(int)

    def metrics(name, p):
        lines.append(f"{name}:")
        lines.append(f"  accuracy  : {accuracy_score(y, p):.3f}")
        lines.append(f"  precision : {precision_score(y, p, zero_division=0):.3f}")
        lines.append(f"  recall    : {recall_score(y, p, zero_division=0):.3f}")
        lines.append(f"  F1        : {f1_score(y, p, zero_division=0):.3f}")
        lines.append(f"  matriz de confusión (filas=real, col=pred):")
        cm = confusion_matrix(y, p, labels=[0, 1])
        lines.append(f"    [[{cm[0,0]:>3} {cm[0,1]:>3}]")
        lines.append(f"     [{cm[1,0]:>3} {cm[1,1]:>3}]]")
        lines.append("")
        return cm

    cm_z = metrics("Línea base estadística (|z|>3)", z_anom)
    cm_i = metrics("IsolationForest", pred_bin)

    report = "\n".join(lines)
    with open(os.path.join(CASOS, "caso04-metricas.txt"), "w", encoding="utf-8") as f:
        f.write(report + "\n")
    print(report)

    # Matriz de confusión del IsolationForest
    fig, ax = plt.subplots(figsize=(5, 4))
    ConfusionMatrixDisplay(cm_i, display_labels=["Normal", "Anomalía"]).plot(
        ax=ax, cmap="Blues", colorbar=False)
    ax.set_title("Caso 4 — Matriz de confusión (IsolationForest)")
    fig.tight_layout()
    fig.savefig(os.path.join(CASOS, "caso04-matriz-confusion.png"), dpi=130)

    # Scatter de dos características
    fig2, ax2 = plt.subplots(figsize=(7, 4.5))
    ax2.scatter(X["n_syn"][y == 0], X["n_pkts"][y == 0], c="#27ae60", label="Normal", alpha=0.7)
    ax2.scatter(X["n_syn"][y == 1], X["n_pkts"][y == 1], c="#c0392b", label="Anomalía", alpha=0.7)
    ax2.set_xlabel("SYN por ventana")
    ax2.set_ylabel("Paquetes por ventana")
    ax2.set_title("Caso 4 — Separación normal vs anomalía")
    ax2.legend()
    ax2.grid(True, alpha=0.3)
    fig2.tight_layout()
    fig2.savefig(os.path.join(CASOS, "caso04-scatter.png"), dpi=130)
    print("\nArtefactos: caso04-dataset.csv, caso04-metricas.txt, "
          "caso04-matriz-confusion.png, caso04-scatter.png")


if __name__ == "__main__":
    main()
