#!/usr/bin/env python3
"""Caso 6: tasas normalizadas y cocientes del modelo UDP genérico."""
from analizar_caso01 import CASOS, campos, duracion, indice_ventana, ventanas
from gen_caso06_udp import PORT, REFLECTOR, VICTIMA
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


def tasas(rows, window=0.5, duration=None):
    counts = ventanas([r["t"] for r in rows], window, duration)
    byte_counts = [0] * len(counts)
    for r in rows:
        byte_counts[indice_ventana(r["t"], window)] += r["frame"]
    return counts, byte_counts, [n / window for n in counts], [n / window for n in byte_counts]


def pares_modelo(rows):
    requests = {}
    pairs = []
    for row in sorted(rows, key=lambda r: r["t"]):
        if row["src"] == VICTIMA and row["dst"] == REFLECTOR and row["dport"] == PORT:
            requests[row["sport"]] = row
        elif row["src"] == REFLECTOR and row["dst"] == VICTIMA and row["sport"] == PORT:
            request = requests.pop(row["dport"], None)
            if request is not None:
                pairs.append((request, row))
    return pairs


def main():
    pcap = CASOS / "caso06-reflexion-udp.pcap"
    rows = [dict(t=float(r[0]), src=r[1], dst=r[2], sport=int(r[3]), dport=int(r[4]),
                 payload=int(r[5])-8, frame=int(r[6]))
            for r in campos(pcap, ["frame.time_relative", "ip.src", "ip.dst", "udp.srcport",
                                  "udp.dstport", "udp.length", "frame.len"], "udp && ip")]
    pairs = pares_modelo(rows)
    req_frame = sum(req["frame"] for req, _ in pairs)
    res_frame = sum(res["frame"] for _, res in pairs)
    req_payload = sum(req["payload"] for req, _ in pairs)
    res_payload = sum(res["payload"] for _, res in pairs)
    counts, byte_counts, pps, bps = tasas(rows, duration=duracion(pcap))
    lines = ["CASO 6 — SIMULACIÓN UDP GENÉRICA, NO ATAQUE/AMPLIFICADOR NTP REAL",
             f"Total UDP={len(rows)}; pares modelo en puerto {PORT}={len(pairs)}; DNS excluido de cocientes.",
             f"Tramas capturadas (sin FCS/padding): petición={req_frame} B; respuesta={res_frame} B; cociente={res_frame/req_frame if req_frame else 0:.3f}x",
             f"Payload UDP: petición={req_payload} B; respuesta={res_payload} B; cociente={res_payload/req_payload if req_payload else 0:.3f}x",
             "El guion asigna origen .20/MAC .100; no es evidencia real de spoofing ni entrega.",
             "Ventanas nominales 0.5s [inicio,fin); última parcialmente observada. Tasas=conteo/0.5."]
    for i, (n, b, p, rate) in enumerate(zip(counts, byte_counts, pps, bps)):
        lines.append(f"  [{i*.5:.1f},{(i+1)*.5:.1f})s: n={n}; bytes={b}; paquetes/s={p:.1f}; bytes/s={rate:.1f}")
    lines.extend(["EVIDENCIA REAL: caso06-openresolver.txt conservado sin cambios, incompleto: no retuvo stderr/REFUSED.",
                  "El bind privado .53 no demuestra ACL de clientes, recursión deshabilitada ni ausencia de resolver abierto.",
                  "El REFUSED de caso02-dnsmasq-log.txt pertenece a otras consultas/instante; no repara esta prueba.",
                  "Prueba nueva separada: caso06-openresolver-revision.txt (stdout, stderr y código de salida).",
                  "2026-11-18 20:47:31 -05: dig desde .53 a .53, example.com A, REFUSED/EDE14; stderr vacío, exit0.",
                  "Solo demuestra rechazo de esa consulta/origen/instante; no ausencia universal de resolver abierto.",
                  "No se verificaron reflectores ni eficacia anti-spoofing; sin cambios de VM."])
    report = "\n".join(lines) + "\n"
    (CASOS / "caso06-analisis.txt").write_text(report, encoding="utf-8")
    print(report)
    fig, axes = plt.subplots(2, 1, figsize=(9, 5.5), sharex=True)
    for ax, values, label in [(axes[0], pps, "Paquetes/s"), (axes[1], bps, "Bytes de trama/s")]:
        ax.bar([i*.5 for i in range(len(values))], values, width=.45, align="edge")
        ax.set_ylabel(label)
        ax.grid(alpha=.3)
    axes[0].set_title("Caso 6 — UDP simulado; conteos divididos entre 0.5 s")
    axes[1].set_xlabel("Tiempo relativo (s), última ventana parcial")
    fig.tight_layout()
    fig.savefig(CASOS / "caso06-udp-rate.png", dpi=130)
    plt.close(fig)


if __name__ == "__main__":
    main()
