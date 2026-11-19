# Ficha de hallazgo — CASO-07: ICMP

## Los 9 campos

1. **ID del caso:** `CASO-07`
2. **Título:** Abuso de ICMP (flood y túnel de datos)
3. **Fecha y analista:** 2026-11-18 · Analista (host Windows, 192.168.50.10)
4. **Categoría / técnica:** DoS por inundación + canal encubierto · Capa 3
   (ICMP, tipos 8/0).
5. **Descripción del hallazgo:** el PCAP sintético mezcla 4 pings normales
   (51 B) con 50 echo-request del atacante (`192.168.50.100`) en ~5 s (10/s) y
   5 echo-request de 1331 B con datos embebidos (posible túnel ICMP).
6. **Severidad:** **Media-Alta** — el flood degrada la red; el túnel ICMP
   permite exfiltración encubierta por un protocolo habitualmente permitido.
7. **Evidencia asociada:**
   - `evidencia/casos/caso07-icmp.pcap`
   - `evidencia/casos/caso07-analisis.txt`
   - `evidencia/casos/caso07-icmp-freq.png`
   - `evidencia/casos/caso07-regla-icmp.nft`
   - `evidencia/casos/caso07-wireshark.png`
8. **Observables (IoC):**
   - `192.168.50.100` → 55 ICMP (50 de 106 B + 5 de 1331 B)
   - Tasa de echo-request ≈ 10/s (línea base: pings esporádicos de 51 B)
   - Payload > 200 B (túnel): 5 paquetes de 1331 B
9. **Clasificación / estado:** Malicioso (simulado) · Confirmado por frecuencia
   y por tamaño atípico de payload.

## Indicadores

- Frecuencia por origen: atacante 55 ICMP vs. analista 4 (pings legítimos).
- Tamaño: normal 51 B (mediana) vs. 106 B (flood) y 1331 B (túnel).
- Tipos: solo 8 (echo request) del atacante; los 4 pings normales tienen reply.

## Análisis

- Filtro de aislamiento: `icmp`. La tabla por IP origen separa al atacante por
  volumen y por tamaño máximo de paquete.
- El PCAP base (`baseline-normal.pcapng`) sirve de referencia: contiene ICMP
  esporádico de baja frecuencia y tamaño estándar, lo que valida el umbral.

## Controles / mitigación

- **Preventivo:** limitar ICMP echo-request por segundo (regla nftables adjunta).
- **Detectivo:** alertar ante ICMP con payload > 200 B (túnel) y ante ráfagas.
- **Correctivo:** descartar el exceso y bloquear el origen.

## Preguntas de análisis

1. *¿Por qué el ICMP es un canal de túnel atractivo?* — Porque suele estar
   permitido en los cortafuegos para diagnóstico y no se inspecciona el payload.
2. *¿Qué umbral separa lo normal de lo anómalo?* — Frecuencia (>5/s) y tamaño
   (payload > 200 B frente a los ~56 B de un ping estándar).
3. *¿Qué aporta el PCAP base?* — La línea de referencia para fijar el umbral
   de frecuencia y tamaño.

## Regla de detección

```nft
icmp type echo-request limit rate 5/second burst 10 packets counter accept
```

```
alert icmp any any -> any any (msg:"Posible túnel ICMP (payload grande)";
  itype:8; dsize:>200; sid:1000007; rev:1;)
```
