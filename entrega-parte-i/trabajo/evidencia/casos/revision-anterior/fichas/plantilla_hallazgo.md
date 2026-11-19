# Plantilla de ficha de hallazgo — Taller 2

> **Nota sobre los 9 campos:** la guía del taller define los 9 campos en su
> apartado 7. Al no disponer del texto literal de la guía, se adoptan los 9
> campos estándar siguientes (identificación y metadatos del hallazgo). Si el
> docente indica un orden o nomenclatura distinta, basta con renombrarlos.

## Los 9 campos

1. **ID del caso** — identificador único (p. ej. `CASO-01`).
2. **Título** — nombre del hallazgo / técnica analizada.
3. **Fecha y analista** — fecha de análisis y rol/analista responsable.
4. **Categoría / técnica** — tipo (DoS, exfiltración, escaneo, anomalía…) y
   protocolo/capa OSI implicados.
5. **Descripción del hallazgo** — qué se observa en la evidencia, de forma objetiva.
6. **Severidad** — Crítica / Alta / Media / Baja, con justificación.
7. **Evidencia asociada** — archivo(s) + hash SHA-256 (y enlace a `evidencia.log`).
8. **Observables (IoC)** — IPs, puertos, patrones, umbrales concretos observados.
9. **Clasificación / estado** — benigno vs. malicioso; confirmado / sospechoso.

## Indicadores

- Lista de indicadores cuantitativos y cualitativos que sustentan el hallazgo.

## Análisis

- Interpretación técnica de la evidencia (filtros Wireshark/tshark, tablas,
  gráficas, correlaciones).

## Controles / mitigación

- Controles preventivos, detectivos y correctivos; reglas propuestas.

## Preguntas de análisis

- Respuesta explícita a cada pregunta de análisis planteada por el caso.

## Regla de detección

- Regla reutilizable (nftables / Suricata-like / pseudo-código) para detectar el
  patrón en tráfico futuro.
