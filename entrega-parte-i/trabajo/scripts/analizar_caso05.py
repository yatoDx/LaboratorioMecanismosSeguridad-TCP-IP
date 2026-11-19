#!/usr/bin/env python3
"""Caso 5: RST con contexto de tupla, no atribución por ACK=0."""
from analizar_caso01 import CASOS, categoria, flags, handshakes, inversa, tupla


def clasificar_resets(rows):
    results = []
    previous = []
    for row in sorted(rows, key=lambda r: r["t"]):
        if categoria(row) == "RST":
            key = tupla(row)
            context = [r for r in previous if r["stream"] == row["stream"]
                       and tupla(r) in (key, inversa(key))]
            completed = any(a["completed"] is not None for a in handshakes(context))
            results.append((row, "tupla con handshake observado" if completed else "fuera de flujo observado"))
        previous.append(row)
    return results


def main():
    resets = clasificar_resets(flags(CASOS / "caso05-rst.pcap"))
    lines = ["CASO 5 — RST SINTÉTICOS, ANÁLISIS OFFLINE",
             f"Total RST={len(resets)}; con handshake previo={sum('con handshake' in state for _, state in resets)}; "
             f"fuera de flujo={sum(state == 'fuera de flujo observado' for _, state in resets)}",
             "Seq y ack siguientes son RAW; tcp.seq mostrado por Wireshark puede ser relativo."]
    for row, state in resets:
        lines.append(f"t={row['t']:.6f}s {row['src']}:{row['sport']} -> {row['dst']}:{row['dport']} "
                     f"stream={row['stream']} seq_raw={row['seq']} ack_raw={row['ack']} "
                     f"ACK_flag={bool(row['flags'] & 16)}; {state}")
    lines.extend(["Los cuatro RST de .100 no tienen la 4-tupla .10:31000 <-> .20:80: no son inyección efectiva.",
                  "RST sin ACK puede ser legítimo; el campo ack no es significativo sin ese flag.",
                  "Tupla y secuencia coherentes no prueban entrega/aceptación, falsificación o identidad real.",
                  "LOG REAL separado: caso05-logs-correlacion.txt contiene fragmentos nginx/prosody históricos.",
                  "No se correlacionan temporalmente ni por sesión con este PCAP generado; su ausencia no prueba inyección.",
                  "Sin prueba de interrupción de sesiones reales ni eficacia de firewall."])
    report = "\n".join(lines) + "\n"
    (CASOS / "caso05-analisis.txt").write_text(report, encoding="utf-8")
    print(report)


if __name__ == "__main__":
    main()
