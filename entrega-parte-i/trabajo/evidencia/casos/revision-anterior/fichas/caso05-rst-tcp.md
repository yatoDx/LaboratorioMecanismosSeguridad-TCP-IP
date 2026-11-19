# Ficha de hallazgo — CASO-05: RST TCP

## Los 9 campos

1. **ID del caso:** `CASO-05`
2. **Título:** Resets TCP (RST) y terminación anómala de conexiones
3. **Fecha y analista:** 2026-11-18 · Analista (host Windows, 192.168.50.10)
4. **Categoría / técnica:** Terminación forzada de sesiones / ataque de reset ·
   Capa 4 (TCP, flag RST).
5. **Descripción del hallazgo:** el PCAP didáctico muestra 6 paquetes RST en 3
   escenarios: (a) RST del servidor web tras una petición completa, (b) RST del
   cliente en una sesión XMPP, y (c) 4 RST forjados desde `192.168.50.100` hacia
   `192.168.50.20:80` (intento de derribar conexiones de terceros).
6. **Severidad:** **Media** — un RST forjado puede interrumpir sesiones
   legítimas (ataque de des-autenticación TCP); requiere conocer los números de
   secuencia para ser efectivo.
7. **Evidencia asociada:**
   - `evidencia/casos/caso05-rst.pcap`
   - `evidencia/casos/caso05-analisis.txt`
   - `evidencia/casos/caso05-logs-correlacion.txt` (nginx + prosody)
   - `evidencia/casos/caso05-wireshark.png`
8. **Observables (IoC):**
   - `tcp.flags.reset == 1` (6 paquetes)
   - Origen de los RST forjados: `192.168.50.100` (4 paquetes, puertos 41000–41003)
   - Flujos afectados: `web:80→analista:31000`, `analista:32000→xmpp:5222`
9. **Clasificación / estado:** Mixto — (a) y (b) son terminaciones normales;
   (c) es actividad maliciosa (reset forjado, simulado).

## Indicadores

- 6 RST en total; 4 provienen de un mismo origen en ráfaga (0.05 s de separación).
- RST forjados con `seq=1, ack=0` (sin contexto de una conexión real).
- Los logs reales de nginx muestran solo `GET / 200` completos; prosody muestra
  desconexiones limpias (`Client disconnected: connection closed`), es decir, los
  RST del PCAP sintético no tienen contraparte en los logs de servicio.

## Análisis

- Filtro de aislamiento: `tcp.flags.reset == 1`.
- Correlación con logs: los RST forjados del atacante **no** aparecen como
  peticiones en `access.log` ni como sesiones en `prosody.log`, lo que indica
  tráfico inyectado sin una sesión de aplicación subyacente.
- La efectividad de un RST forjado depende de acertar el número de secuencia
  (ventana), por eso los RST con `seq=1, ack=0` son detectables como anómalos.

## Controles / mitigación

- **Preventivo:** el firewall del gateway ya descarta tráfico no establecido
  (`ct state established,related`); validar que no se acepten RST fuera de
  conexiones rastreadas.
- **Detectivo:** alertar ante ráfagas de RST desde un mismo origen (umbral) y
  ante RST con `ack=0` en conexiones establecidas.
- **Correctivo:** bloqueo del origen que emite RST forjados.

## Preguntas de análisis

1. *¿Qué distingue un RST legítimo de uno forjado?* — El legítimo pertenece a un
   flujo con secuencia/ack coherentes; el forjado suele tener `ack=0` o secuencia
   fuera de la ventana.
2. *¿Cómo se correlaciona con los logs de aplicación?* — Un RST inyectado no
   produce entradas de aplicación (ni `200` en nginx ni sesión en prosody).
3. *¿Qué límite tiene la evidencia?* — Al ser un PCAP sintético, no hay logs
   reales que coincidan; la correlación demuestra la *metodología* de cruce.

## Regla de detección

```
alert tcp any any -> any any (flags:R,12; ack:0; threshold: type both, \
  track by_src, count 5, seconds 1; sid:1000005; \
  msg:"Posible reset TCP forjado (ack=0)" ;)
```
