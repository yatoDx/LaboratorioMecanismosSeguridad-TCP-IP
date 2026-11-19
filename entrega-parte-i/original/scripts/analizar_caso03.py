#!/usr/bin/env python3
"""Caso 3: inventario observado y valoración cualitativa, no accesibilidad."""
import re
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

CASOS = Path(__file__).resolve().parents[1] / "evidencia" / "casos"


def inventario_host(text):
    """Conservar PID observado; NO atribuir producto/servicio por número de puerto."""
    rows = []
    for line in text.splitlines():
        match = re.match(r"\s*TCP\s+(\S+):(139|445|5432)\s+\S+\s+LISTENING\s+(\d+)", line)
        if match:
            address, port, pid = match.groups()
            rows.append((address, int(port), int(pid)))
    return rows


def main():
    host = inventario_host((CASOS / "caso03-netstat-host.txt").read_text(encoding="utf-8"))
    auth = (CASOS / "caso03-auth-events.txt").read_text(encoding="utf-8")
    print("Sockets observados del host (IP, puerto, PID numérico; proceso sin atribuir):", host)
    print("Fragmento auth: Accepted password=", auth.count("Accepted password"),
          "; Failed password=", auth.count("Failed password"),
          "; no prueba ausencia global de fallos.")
    print("Escucha != accesibilidad. El gateway no filtra peers de la misma subred.")
    # Valoraciones didácticas propuestas, no probabilidades medidas de explotación.
    services = [
        ("SSH :22 (4 VMs)", 2, 3),
        ("HTTP :80 (web)", 2, 3),
        ("XMPP c2s :5222", 2, 3),
        ("XMPP s2s :5269", 3, 3),
        ("DNS :53 (.53)", 2, 4),
        ("NTP :123 (gateway)", 2, 2),
        ("Resolvedores loopback", 1, 1),
        ("Host :139 (sin atribuir)", 2, 3),
        ("Host :445 (sin atribuir)", 2, 3),
        ("Host :5432 (sin atribuir)", 2, 3),
    ]
    # Una fila por servicio evita etiquetas superpuestas al compartir puntuaciones.
    fig, axes = plt.subplots(1, 2, figsize=(11, 6), sharey=True)
    positions = list(range(len(services)))
    for ax, column, title, color in [(axes[0], 1, "Probabilidad propuesta", "#3498db"),
                                      (axes[1], 2, "Impacto propuesto", "#c0392b")]:
        ax.barh(positions, [s[column] for s in services], color=color, height=0.65)
        ax.set_xlim(0, 5)
        ax.set_xticks(range(1, 6))
        ax.set_title(title)
        ax.grid(axis="x", alpha=0.3)
    axes[0].set_yticks(positions, [s[0] for s in services], fontsize=9)
    axes[0].invert_yaxis()
    fig.suptitle("Caso 3 — Escalas ordinales 1–5, no riesgo/accesibilidad demostrados")
    fig.text(0.5, 0.02, "Sockets reales; host sin mapeo PID→proceso. Verificar acceso y ACL por endpoint.", ha="center", fontsize=9)
    fig.tight_layout(rect=(0, 0.05, 1, 0.96))
    fig.savefig(CASOS / "caso03-riesgo.png", dpi=130)
    plt.close(fig)


if __name__ == "__main__":
    main()
