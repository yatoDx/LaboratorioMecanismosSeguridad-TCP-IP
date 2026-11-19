# Ficha de hallazgo — CASO-04: Anomalías con ML (IsolationForest)

## Los 9 campos

1. **ID del caso:** `CASO-04`
2. **Título:** Detección de anomalías con aprendizaje de máquina no supervisado
3. **Fecha y analista:** 2026-11-18 · Analista (host Windows, 192.168.50.10)
4. **Categoría / técnica:** Detección de anomalías · ML no supervisado
   (IsolationForest, scikit-learn) sobre características de tráfico agregadas.
5. **Descripción del hallazgo:** se construyó un dataset de 28 ventanas de
   tráfico (20 normales del PCAP base + 8 anómalas de los casos 1 y 2) con 8
   características por ventana. Un IsolationForest entrenado solo con tráfico
   normal detectó 5 de 8 anomalías (recall 0.625), mientras que la línea base
   estadística (z-score > 3) detectó las 8 (recall 1.000).
6. **Severidad:** **Media** (hallazgo metodológico) — demuestra la utilidad y
   las limitaciones del ML para anomalías de red.
7. **Evidencia asociada:**
   - `evidencia/casos/caso04-dataset.csv`
   - `evidencia/casos/caso04-metricas.txt`
   - `evidencia/casos/caso04-matriz-confusion.png`
   - `evidencia/casos/caso04-scatter.png`
   - `evidencia/casos/caso04-consola.png`
   - Script reproducible: `scripts/caso04_ml.py`
8. **Observables (IoC):** características discriminantes: `n_syn` (SYN por
   ventana), `syn_ratio`, `n_dst_ports` y `bytes_per_flow` separan los ataques
   (SYN flood, DNS tunneling) del tráfico normal.
9. **Clasificación / estado:** Análisis reproducible; los ataques quedan
   separados de la línea base en el espacio de características.

## Indicadores

- Dataset: 28 ventanas · 8 características · etiqueta binaria normal/anomalía.
- Línea base estadística: accuracy 0.964, recall 1.000, F1 0.941 (1 falso positivo).
- IsolationForest: accuracy 0.857, recall 0.625, F1 0.714 (3 falsos negativos).
- Las ventanas anómalas de baja tasa (inicio de los ataques) son las más difíciles.

## Análisis

- **Pipeline reproducible** (ver `scripts/caso04_ml.py`):
  extracción tshark → agregación por ventana → dataset → IsolationForest vs z-score.
- La línea base estadística supera al modelo ML en este dataset pequeño, lo que
  evidencia que con pocas muestras un umbral simple es más robusto; el
  IsolationForest necesita más datos de entrenamiento y mejor ingeniería de
  características para generalizar.
- `n_syn` y `n_dst_ports` muestran separación clara en el scatter
  (`caso04-scatter.png`).

## Controles / mitigación

- **Preventivo:** línea base continua de tráfico (perfilado) y reentrenamiento.
- **Detectivo:** doble detector — regla estadística rápida (z-score) + modelo ML
  como confirmación; alerta solo cuando ambos coinciden (reduce falsos positivos).
- **Correctivo:** aislamiento del host origen y bloqueo temporal en nftables.

## Preguntas de análisis

1. *¿Por qué el ML puro no es suficiente aquí?* — Con 20 muestras normales el
   modelo no aprende la frontera completa; los ataques de baja tasa caen dentro
   de la zona "normal".
2. *¿Qué papel cumple la línea base estadística?* — Es el detector primario
   (rápido, explicable) y calibra los umbrales del modelo ML.
3. *¿Cómo se evalúa objetivamente?* — Con matriz de confusión y métricas
   (accuracy, precision, recall, F1) sobre ventanas etiquetadas.

## Regla de detección

Umbral estadístico (equivalente a regla de alerta):

```
alert if any(|x_i - mean_i| / std_i) > 3  for i in FEATURES
```

Regla nftables asociada (bloqueo correctivo tras la alerta):

```nft
# Bloquear temporalmente un origen anómalo (ej. atacante)
ip saddr 192.168.50.100 drop
```
