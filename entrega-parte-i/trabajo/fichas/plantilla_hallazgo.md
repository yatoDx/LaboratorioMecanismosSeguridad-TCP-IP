# Plantilla PROVISIONAL de hallazgo — Parte I

No se dispone del texto literal de la guía ni de sus preguntas originales.
Estos nueve campos son una **propuesta de trabajo**, no una transcripción ni
una certificación de cumplimiento del apartado 7. El líder/docente deberá
cotejar campos, orden, rúbrica y preguntas con la guía antes de entregar.

## Nueve campos propuestos

1. **ID del caso** — identificador.
2. **Título** — observación concreta, evitando afirmar un ataque no probado.
3. **Fecha y analista** — fecha, rol y ámbito del análisis.
4. **Categoría / técnica** — técnica estudiada; distinguir simulación de incidente.
5. **Descripción** — hechos medidos, origen y límites de la evidencia.
6. **Severidad** — valoración provisional e impacto potencial frente a impacto medido.
7. **Evidencias** — rutas, procedencia real/sintética, tiempos y hash de la revisión vigente.
8. **Observables** — métricas con unidades, ventanas, filtros y denominadores.
9. **Estado** — observado / hipótesis / sintético / no comprobado, con justificación.

## Indicadores y análisis reproducible

- Comando offline, filtro, versión de herramienta y resultado.
- Baseline leído realmente, duración completa, ventanas vacías y parciales.
- No confundir trama con payload, conteo con cardinalidad ni socket con acceso.
- Correlación solo cuando coinciden fuentes, tuplas, identificadores y tiempos.
- Umbrales propuestos no equivalen a ataques o controles probados.

## Controles propuestos y validación

- Indicar host/hook y alcance topológico. Un gateway no filtra tráfico directo
  entre peers de la misma subred.
- Sin cambios de infraestructura ni aplicación de reglas durante esta revisión.
- Diferenciar comprobación `nft -c` de ensayo funcional/eficacia del control.

## Preguntas PROPUESTAS de análisis

Las preguntas y respuestas redactadas en estas fichas son propuestas didácticas,
**no preguntas originales de la guía**. Pendiente cotejo por el líder/docente.

## Trazabilidad y pendientes

- Antes de editar, respaldar byte a byte en `evidencia/casos/revision-anterior/`,
  conservando rutas relativas y sin sobrescribir backups.
- No alterar logs ni screenshots históricos para hacerlos coincidir con un PCAP nuevo.
- Los hashes anteriores de `evidencia.log` corresponden a versiones históricas;
  el líder debe rehashar los working artifacts corregidos, sin borrar el registro.
- Enumerar screenshots a recapturar y comprobaciones aún no realizadas.
