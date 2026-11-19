# Ficha de hallazgo — CASO-01: SYN flood

## Los 9 campos

1. **ID del caso:** `CASO-01`
2. **Título:** Inundación SYN (SYN flood) contra el servidor web
3. **Fecha y analista:** 2026-11-18 · Analista (host Windows, 192.168.50.10)
4. **Categoría / técnica:** Denegación de servicio (DoS) por agotamiento de
   recursos · Capa 4 (TCP), técnica *half-open* (SYN sin completar el handshake).
5. **Descripción del hallazgo:** en el PCAP sintético se observa una ráfaga
   sostenida de ~20 paquetes SYN por segundo desde `192.168.50.100` hacia el
   puerto 80 de `192.168.50.20`, sin que el origen complete el *three-way
   handshake* (los SYN-ACK del servidor nunca reciben ACK). En total, 200 SYN
   del atacante frente a 3 handshakes legítimos del analista.
6. **Severidad:** **Alta** — puede agotar la tabla de conexiones del servidor y
   dejar el servicio HTTP sin disponibilidad; no hay impacto lateral en otras VMs.
7. **Evidencia asociada:**
   - `evidencia/casos/caso01-synflood.pcap` (SHA-256 en `evidencia.log`)
   - `evidencia/casos/caso01-synflood-ratelimit.pcap`
   - `evidencia/casos/caso01-analisis.txt`
   - `evidencia/casos/caso01-syn-rate.png`
   - `evidencia/casos/caso01-netstat-host.txt`
8. **Observables (IoC):**
   - IP origen: `192.168.50.100`; IP destino: `192.168.50.20:80`
   - Tasa de SYN ≈ 20/seg durante ~10 s (línea base ≈ 1/seg)
   - Predominio de `tcp.flags.syn==1 && tcp.flags.ack==0` sin ACK posterior
9. **Clasificación / estado:** Malicioso (simulado) · Confirmado por tasa y
   ausencia de handshake completo.

## Indicadores

- Conteo de SYN por ventana de 1 s: 1 (línea base) → 20 (ataque).
- Total SYN = 203 (3 legítimos + 200 de ataque); SYN-ACK = 203; ACK = 224.
- Ratio SYN/ACK de cierre: los 200 SYN del atacante quedan *half-open*.
- `netstat -ano` en el host no muestra conexiones SYN_RECEIVED (el tráfico es
  sintético, generado a archivo y no atravesó la red real).

## Análisis

- Filtro de aislamiento del ataque:
  `tcp.flags.syn == 1 && tcp.flags.ack == 0 && ip.src == 192.168.50.100`.
- La estadística `io,stat,1` de tshark muestra el salto de 1 a 20 SYN/s en el
  instante t≈11 s (gráfica `caso01-syn-rate.png`).
- Con la regla de límite de tasa (10 SYN/s) la versión mitigada solo deja pasar
  100 SYN en la misma ventana (103 totales), lo que evita el agotamiento.

## Controles / mitigación

- **Preventivo:** `syncookies` (net.ipv4.tcp_syncookies=1) en el servidor web.
- **Detectivo:** alarma cuando `SYN/s` supera N× la línea base (aquí N=10).
- **Correctivo:** regla nftables de límite de tasa (ver `caso01-regla.nft`).

## Preguntas de análisis

1. *¿Cómo se distingue el ataque del tráfico legítimo?* — Por la tasa sostenida
   (~20 SYN/s) y por la ausencia de ACK finales: los SYN legítimos completan el
   handshake, los del ataque no.
2. *¿Qué efecto tiene la regla de límite de tasa?* — Reduce los SYN aceptados de
   200 a 100 en la misma ventana, descartando el exceso con `counter drop`.
3. *¿Qué limitación tiene detectar solo por conteo?* — Un ataque distribuido a
   baja tasa por origen puede quedar por debajo del umbral; conviene combinar
   con reputación de IP y `syncookies`.

## Regla de detección

```nft
ip saddr 192.168.50.0/24 tcp dport 80 \
    tcp flags & (syn | ack) == syn \
    limit rate 10/second burst 20 packets counter drop
```

Equivalente Suricata-like (referencia):

```
alert tcp any any -> 192.168.50.20 80 (flags:S,12; threshold: type both, \
  track by_src, count 10, seconds 1; sid:1000001; msg:"SYN flood web";)
```
