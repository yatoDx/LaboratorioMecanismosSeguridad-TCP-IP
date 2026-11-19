# Ficha de hallazgo — CASO-02: DNS tunneling

## Los 9 campos

1. **ID del caso:** `CASO-02`
2. **Título:** Tunelización de datos vía DNS (DNS tunneling)
3. **Fecha y analista:** 2026-11-18 · Analista (host Windows, 192.168.50.10)
4. **Categoría / técnica:** Exfiltración / C2 encubierto · Capa 7 (DNS, puerto 53/UDP),
   técnica de etiquetas largas de alta entropía bajo un subdominio.
5. **Descripción del hallazgo:** en el PCAP sintético, 25 de 37 consultas DNS usan
   una única etiqueta de 24–52 caracteres hexadecimales (alta entropía) bajo el
   dominio `.exfil.lab.local`, frente a consultas legítimas (`web.lab.local`,
   `xmpp.lab.local`, etc.) con etiquetas ≤ 7 caracteres y baja entropía.
6. **Severidad:** **Alta** — canal de exfiltración/C2 que elude controles basados
   solo en puertos, ya que el 53/UDP suele estar permitido.
7. **Evidencia asociada:**
   - `evidencia/casos/caso02-dns-tunneling.pcap`
   - `evidencia/casos/caso02-analisis.txt`
   - `evidencia/casos/caso02-dns-entropy.png`
   - `evidencia/casos/caso02-dnsmasq-log.txt` (verificación con `log-queries`)
   - `evidencia/casos/caso02-regla-dns.nft`
8. **Observables (IoC):**
   - Dominio `exfil.lab.local`; etiqueta máx. 52 chars; entropía 4.26 bits/símbolo
   - Origen `192.168.50.10` → `192.168.50.53:53`
   - 25 consultas del patrón en ~5 s (≈ 5/s)
9. **Clasificación / estado:** Malicioso (simulado) · Confirmado por longitud de
   etiqueta y entropía; verificado en el log de dnsmasq.

## Indicadores

- Longitud máxima de etiqueta: `exfil` 52 vs. `web` 5, `xmpp` 5, `gateway` 7.
- Entropía de Shannon: 4.26 (exfil) vs. 2.87–3.22 (normal).
- Frecuencia: 25 consultas tunelizadas en ~5 s.
- Log de dnsmasq (`log-queries`): registra `query[A] <etiqueta-larga>.exfil.lab.local`.

## Análisis

- Filtro de aislamiento: `udp.port == 53 && dns.flags.response == 0`.
- La heurística `max_etiqueta > 30 OR entropía > 3.5` separa limpiamente las dos
  poblaciones (ver gráfica `caso02-dns-entropy.png`).
- El log de dnsmasq confirma que el servidor DNS interno **vio** las consultas
  (respondió `REFUSED` por `no-resolv` sin upstream), lo que demuestra que la
  detección debe darse en el plano DNS, no solo en el tráfico de red.

## Controles / mitigación

- **Preventivo:** DNS *split-horizon* + lista blanca de dominios internos; bloquear
  subdominios no autorizados; limitar quién puede consultar el DNS interno.
- **Detectivo:** regla de etiqueta larga + umbral de volumen/entropía (regla adjunta).
- **Correctivo:** denegar y alertar ante etiquetas > 30 y entropía alta.

## Preguntas de análisis

1. *¿Por qué el tunneling DNS es difícil de bloquear con cortafuegos de puerto?* —
   Porque el 53/UDP es indispensable para la resolución normal y suele estar
   abierto; el atacante transporta datos dentro del propio protocolo DNS.
2. *¿Qué métrica distingue mejor las consultas tunelizadas?* — La combinación de
   longitud de etiqueta (muy larga) y entropía (cercana a 4 bits/símbolo frente a
   ~3 de los nombres legibles).
3. *¿Qué confirmó el log de dnsmasq?* — Que el servidor recibió y registró las
   consultas largas (`query[A] ...exfil.lab.local`), validando el hallazgo con una
   fuente independiente del PCAP.

## Regla de detección

Ver `evidencia/casos/caso02-regla-dns.nft`. Resumen:

```
# Etiqueta larga (primer byte de dns.query > 30)
alert udp any any -> 192.168.50.53 53 (msg:"Posible DNS tunneling - etiqueta larga";
  dns.query; byte_test:1,>,30,0; sid:1000002; rev:1;)
```
