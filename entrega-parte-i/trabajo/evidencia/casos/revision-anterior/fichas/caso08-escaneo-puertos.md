# Ficha de hallazgo — CASO-08: Escaneo de puertos

## Los 9 campos

1. **ID del caso:** `CASO-08`
2. **Título:** Escaneo de puertos TCP (SYN scan)
3. **Fecha y analista:** 2026-11-18 · Analista (host Windows, 192.168.50.10)
4. **Categoría / técnica:** Reconocimiento · Capa 4 (TCP, técnica *half-open* /
   SYN scan: SYN → SYN-ACK/RST sin completar handshake).
5. **Descripción del hallazgo:** el PCAP sintético muestra a `192.168.50.100`
   enviando SYN a 24 puertos distintos de `192.168.50.20` (web) y `192.168.50.30`
   (xmpp) en ráfaga. Solo los puertos abiertos responden SYN-ACK (web: 22, 80;
   xmpp: 5222, 5269); el resto responde RST.
6. **Severidad:** **Media** — fase de reconocimiento previa a un ataque; por sí
   sola no degrada el servicio pero revela la superficie expuesta.
7. **Evidencia asociada:**
   - `evidencia/casos/caso08-portscan.pcap`
   - `evidencia/casos/caso08-analisis.txt`
   - `evidencia/casos/caso08-portscan.png`
   - `evidencia/casos/caso08-regla-portscan.nft`
   - `evidencia/casos/caso08-wireshark.png`
8. **Observables (IoC):**
   - Origen `192.168.50.100`; 24 puertos únicos sondeados en ~0.4 s
   - Patrón SYN → (SYN-ACK | RST) sin ACK de cierre
   - Puertos expuestos detectados: web 22/80, xmpp 5222/5269
9. **Clasificación / estado:** Malicioso (simulado) · Confirmado por cardinalidad
   de puertos y por el patrón half-open.

## Indicadores

- 24 puertos únicos por origen en < 1 s (un cliente normal usa 1–3 puertos).
- Respuestas: 4 SYN-ACK (abiertos) + 20 RST (cerrados).
- Exposición confirmada coherente con el inventario del caso 3 (22, 80, 5222, 5269).

## Análisis

- Filtro de aislamiento: `tcp.flags.syn == 1 && tcp.flags.ack == 0`.
- La cardinalidad de puertos destino por origen es el indicador discriminante;
  la gráfica `caso08-portscan.png` lo resume.
- La lista de exposición (SYN-ACK) coincide con el inventario real de servicios
  (`ss -tulpn` del caso 3): valida la técnica.

## Controles / mitigación

- **Preventivo:** el firewall ya aplica `policy drop`; restringir puertos de
  gestión (SSH) por origen.
- **Detectivo:** log de SYN a puertos cerrados (nftables `log`) + alerta por
  cardinalidad (regla adjunta).
- **Correctivo:** bloqueo temporal del origen escaneante.

## Preguntas de análisis

1. *¿Por qué un SYN scan es "silencioso"?* — No completa el handshake, por lo que
   muchas aplicaciones no registran la conexión; por eso la detección debe darse
   en la capa de red (firewall/IDS).
2. *¿Cómo se distingue del tráfico normal?* — Por la cantidad de puertos
   distintos tocados desde un mismo origen en poco tiempo.
3. *¿Qué confirma la exposición detectada?* — Coincide con los servicios reales
   en escucha (`ss -tulpn`): web 22/80 y xmpp 5222/5269.

## Regla de detección

```nft
tcp flags & (syn | ack) == syn log prefix "scan-syn: " limit rate 5/second
```

```
alert tcp any any -> any any (flags:S,12;
  threshold: type threshold, track by_src, count 20, seconds 10;
  sid:1000009; rev:1; msg:"Posible escaneo de puertos (SYN)";)
```
