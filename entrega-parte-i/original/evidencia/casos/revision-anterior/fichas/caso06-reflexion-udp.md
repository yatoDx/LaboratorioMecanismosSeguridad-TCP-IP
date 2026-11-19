# Ficha de hallazgo — CASO-06: Reflexión/amplificación UDP

## Los 9 campos

1. **ID del caso:** `CASO-06`
2. **Título:** Reflexión y amplificación UDP (ataque DDoS reflectivo)
3. **Fecha y analista:** 2026-11-18 · Analista (host Windows, 192.168.50.10)
4. **Categoría / técnica:** Denegación de servicio distribuida reflectiva ·
   Capa 4 (UDP), suplantación de dirección de origen (spoofing) + amplificación.
5. **Descripción del hallazgo:** el PCAP didáctico muestra 20 peticiones UDP
   pequeñas (48 B) cuyo origen se suplanta como la víctima (`192.168.50.20`) hacia
   un reflector (`192.168.50.200:123`), el cual responde 20 datagramas de 468 B
   hacia la víctima. La víctima recibe ~10 KB de tráfico que nunca solicitó.
6. **Severidad:** **Alta** — amplificación de ancho de banda hacia una víctima
   involuntaria; en el mundo real se explota con NTP/DNS públicos.
7. **Evidencia asociada:**
   - `evidencia/casos/caso06-reflexion-udp.pcap`
   - `evidencia/casos/caso06-analisis.txt`
   - `evidencia/casos/caso06-udp-rate.png`
   - `evidencia/casos/caso06-openresolver.txt` (dnsmasq no es resolvedor abierto)
   - `evidencia/casos/caso06-wireshark.png`
8. **Observables (IoC):**
   - Origen suplantado: peticiones con `ip.src=192.168.50.20` hacia `192.168.50.200:123`
   - Respuestas `192.168.50.200:123 → 192.168.50.20` (datagramas de 468 B)
   - Factor de amplificación ≈ 5.7x (payload 48→468 B ≈ 9.75x)
   - dnsmasq (192.168.50.53) **refusa** dominios externos: no es reflector.
9. **Clasificación / estado:** Malicioso (simulado) · Confirmado por la
   asimetría petición/respuesta y el origen suplantado.

## Indicadores

- 20 peticiones de 90 B (con cabeceras) → 20 respuestas de 510 B: ~5.7x total.
- Ráfaga sostenida: 25 pkt/0.5 s (t=1.0 s) y 15 pkt/0.5 s (t=1.5 s).
- Volumen hacia la víctima: 10 200 B sin petición legítima previa.

## Análisis

- Filtro de aislamiento: `udp`; la gráfica `caso06-udp-rate.png` muestra el salto
  de tráfico UDP en el instante del ataque (barras).
- La correlación origen→destino evidencia el spoofing: las "peticiones" de la
  víctima no tienen MAC del host víctima (en un entorno real se validaría con la
  tabla ARP); aquí el PCAP es sintético y lo documenta como tal.
- Verificación de reflectores: dnsmasq responde `REFUSED` a `google.com`
  (`no-resolv` sin upstream) y escucha solo en `192.168.50.53` → no es resolvedor
  abierto; chrony no implementa `monlist` (no es reflector NTP).

## Controles / mitigación

- **Preventivo:** filtrar paquetes con origen de otra subred (anti-spoofing,
  uRPF) en el gateway; limitar quién puede usar los servicios UDP.
- **Detectivo:** alertar ante ráfagas de UDP hacia un mismo destino y ante
  asimetría petición/respuesta.
- **Correctivo:** descartar respuestas UDP no solicitadas (`ct state`).

## Preguntas de análisis

1. *¿Por qué se llama "reflexión"?* — El atacante no ataca directo: hace que un
   tercero (reflector) envíe el tráfico a la víctima usando una IP falsa.
2. *¿Qué servicios UDP del laboratorio podrían amplificar?* — Ninguno en la
   práctica: dnsmasq no es resolvedor abierto y chrony no tiene `monlist`.
3. *¿Cómo se detecta el origen suplantado?* — Verificando que la MAC de origen
   corresponda a la IP (ARP) y aplicando filtrado anti-spoofing.

## Regla de detección

```nft
# Anti-spoofing en el gateway: descartar paquetes entrantes cuya IP de origen
# no pertenezca a la subred esperada (uRPF estricto).
table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;
    iif != "lo" ip saddr 192.168.50.20 fib saddr type != { local, unicast } drop
  }
}
```

Alerta Suricata-like:

```
alert udp any any -> 192.168.50.20 any (msg:"Posible reflexión UDP";
  threshold: type both, track by_dst, count 20, seconds 1; sid:1000006; rev:1;)
```
