#!/usr/bin/env python3
"""Caso 3 — Matriz de riesgo/criticidad de los servicios expuestos."""
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Rectangle

BASE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.abspath(os.path.join(BASE, "..", "evidencia", "casos", "caso03-riesgo.png"))

# (servicio, probabilidad de explotación 1-5, impacto 1-5)
servicios = [
    ("ssh (4 VMs)", 2, 3),
    ("nginx :80 sin TLS", 2, 3),
    ("prosody c2s :5222", 2, 3),
    ("prosody s2s :5269", 3, 3),
    ("dnsmasq :53", 1, 4),
    ("chrony NTP :123", 1, 2),
    ("systemd-resolve (loopback)", 1, 1),
]

fig, ax = plt.subplots(figsize=(7.5, 6))
ax.set_xlim(0, 5)
ax.set_ylim(0, 5)
ax.set_xticks(range(1, 6))
ax.set_yticks(range(1, 6))
ax.set_xticklabels(["Muy baja", "Baja", "Media", "Alta", "Muy alta"], fontsize=8)
ax.set_yticklabels(["Muy bajo", "Bajo", "Medio", "Alto", "Muy alto"], fontsize=8)
ax.set_xlabel("Probabilidad de explotación")
ax.set_ylabel("Impacto")

# Cuadrantes
for (x0, x1, c, lab) in [(0, 2.5, "#27ae60", "Bajo"), (2.5, 5, "#f39c12", "Medio")]:
    ax.add_patch(Rectangle((x0, 0), x1 - x0, 2.5, color=c, alpha=0.08))
for (y0, y1, c, lab) in [(0, 2.5, "#27ae60", "Bajo"), (2.5, 5, "#f39c12", "Medio")]:
    ax.add_patch(Rectangle((0, y0), 5, y1 - y0, color=c, alpha=0.05))

colors = {"ssh (4 VMs)": "#3498db", "nginx :80 sin TLS": "#3498db",
          "prosody c2s :5222": "#3498db", "prosody s2s :5269": "#c0392b",
          "dnsmasq :53": "#27ae60", "chrony NTP :123": "#27ae60",
          "systemd-resolve (loopback)": "#7f8c8d"}

for name, p, i in servicios:
    ax.scatter(p, i, s=180, c=colors[name], edgecolors="black", zorder=3)
    ax.annotate(name, (p, i), textcoords="offset points", xytext=(10, 5), fontsize=9)

ax.set_title("Caso 3 — Matriz de riesgo de servicios expuestos")
ax.grid(True, alpha=0.3)
fig.tight_layout()
fig.savefig(OUT, dpi=130)
print("Guardada:", OUT)
