#!/usr/bin/env python3
"""Caso 2: heurística de etiqueta más larga, separada de logs reales."""
import collections
import math
import re

from analizar_caso01 import CASOS, campos, ventanas
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


def shannon(s):
    if not s:
        return 0.0
    return -sum((n / len(s)) * math.log2(n / len(s)) for n in collections.Counter(s).values())


def caracteristicas(qname):
    labels = qname.rstrip(".").lower().split(".")
    # Empates: primera etiqueta de máxima longitud, de forma determinista.
    longest = max(labels, key=len)
    suffix = ".".join(labels[-3:])  # Agrupación didáctica, NO cálculo eTLD+1/2LD.
    return longest, len(longest), shannon(longest), suffix


def sospechosa(length, entropy):
    return length > 30 or entropy > 3.5


def consultas_log(text):
    return re.findall(r"query\[[^\]]+\]\s+(\S+)\s+from\s+(\S+)", text)


def main():
    rows = []
    for t, src, qname in campos(CASOS / "caso02-dns-tunneling.pcap",
                                ["frame.time_relative", "ip.src", "dns.qry.name"],
                                "dns.flags.response == 0 && dns.qry.name"):
        label, length, entropy, suffix = caracteristicas(qname)
        rows.append(dict(t=float(t), src=src, qname=qname, label=label, length=length,
                         entropy=entropy, suffix=suffix, suspicious=sospechosa(length, entropy)))
    lines = ["CASO 2 — HEURÍSTICA OFFLINE, NO EXFILTRACIÓN CONFIRMADA",
             "Regla propuesta, no validada: longitud etiqueta más larga >30 O Shannon(etiqueta)>3.5.",
             "Un qname normalizado no es wire format DNS; no usar byte_test en dns.query como longitud.",
             f"PCAP SINTÉTICO: {len(rows)} consultas; sospechosas={sum(r['suspicious'] for r in rows)}",
             "Agrupación por origen + últimas 3 etiquetas (no 2LD/eTLD+1):"]
    grouped = collections.defaultdict(list)
    for row in rows:
        grouped[row["src"], row["suffix"]].append(row)
    for (src, suffix), rs in sorted(grouped.items()):
        rates = ventanas([r["t"] for r in rs])
        lines.append(f"  {src} / {suffix}: n={len(rs)}; longitud={min(r['length'] for r in rs)}..{max(r['length'] for r in rs)}; "
                     f"H_etiqueta={min(r['entropy'] for r in rs):.3f}..{max(r['entropy'] for r in rs):.3f}; "
                     f"sospechosas={sum(r['suspicious'] for r in rs)}; máximo consultas/1s={max(rates)}")
    lines.extend(["", "LOG REAL independiente: caso02-dnsmasq-log.txt (fragmento histórico, no alterado)."])
    real = consultas_log((CASOS / "caso02-dnsmasq-log.txt").read_text(encoding="utf-8"))
    long_queries = [(q, src) for q, src in real if q.endswith(".exfil.lab.local")]
    lines.append(f"Consultas reales al sufijo demostrativo: {len(long_queries)}")
    synthetic_names = {r["qname"] for r in rows}
    for q, src in long_queries:
        label, length, entropy, _ = caracteristicas(q)
        lines.append(f"  origen={src}; etiqueta={label}; longitud={length}; H_etiqueta={entropy:.3f}; nombre={q}; "
                     f"mismo nombre en PCAP={q in synthetic_names}")
    lines.extend(["El log registra una consulta demostrativa desde DNS .53; el PCAP usa .10.",
                  "No hay correlación real de transacciones/tiempos con los 25 nombres sintéticos.",
                  "REFUSED en el fragmento real no confirma exfiltración ni una prueba de mitigación."])
    fig, ax = plt.subplots(figsize=(8, 5))
    for state, color, label in [(False, "#27ae60", "Sin señal heurística"), (True, "#c0392b", "Sospechosa (sintética)")]:
        subset = [r for r in rows if r["suspicious"] == state]
        ax.scatter([r["length"] for r in subset], [r["entropy"] for r in subset], c=color, label=label, alpha=0.7)
    ax.axhline(3.5, color="gray", linestyle="--", linewidth=0.8)
    ax.axvline(30, color="gray", linestyle=":", linewidth=0.8)
    ax.set(xlabel="Longitud de etiqueta más larga (caracteres)", ylabel="Shannon de esa etiqueta (bits/símbolo)",
           title="Caso 2 — Datos sintéticos; umbrales propuestos")
    ax.legend()
    ax.grid(alpha=0.3)
    fig.tight_layout()
    fig.savefig(CASOS / "caso02-dns-entropy.png", dpi=130)
    plt.close(fig)
    report = "\n".join(lines) + "\n"
    (CASOS / "caso02-analisis.txt").write_text(report, encoding="utf-8")
    print(report)


if __name__ == "__main__":
    main()
