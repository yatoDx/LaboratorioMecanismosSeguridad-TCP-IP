# Casos 1, 4 y 7 repetidos con la línea base limpia

Se repitieron los análisis de los casos 1, 4 y 7 sustituyendo `evidencia/baseline-normal.pcapng` por
`evidencia/baseline-normal-limpia.pcapng` (720 paquetes, SHA-256 `6fbe5c79…4b4427`, solo IPv4 dentro de
192.168.50.0/24). Se hizo en una copia temporal del repositorio con la limpia guardada con el nombre de la
original, por eso los textos de salida dicen `baseline-normal.pcapng`; el hash que registran
(Caso 4: `6fbe5c79…`) identifica la captura limpia. Los resultados vigentes de `evidencia/casos/` no se
modificaron ni el paquete `entrega-parte-i/`: esta carpeta es complementaria y no forma parte del manifiesto.

| Caso | Con la línea base original | Con la limpia | Lectura |
|---|---|---|---|
| 1 SYN flood | 0 SYN en la base, duración 296,67 s | 0 SYN, duración 293,26 s | Sin cambio: la base nunca tuvo SYN |
| 7 ICMP | 152 echo, máx. 1/s, 0 requests > 200 B | 152 echo, máx. 1/s, 0 requests > 200 B | Sin cambio; solo cambia la duración |
| 4 ML, z-score (solo normales de test) | 1 falso positivo de 11 (FPR 0,091) | 0 de 11 (FPR 0,000) | Mejora: el falso positivo venía del tráfico ajeno del anfitrión |
| 4 ML, IsolationForest | 5 falsos positivos de 11 (FPR 0,455) | 5 de 11 (FPR 0,455) | Sin cambio |
| 4 ML, sintéticas | 22 de 22 detectadas | 22 de 22 detectadas | Sin cambio |

Conclusión: limpiar la línea base no altera las conclusiones de los casos 1 y 7 y elimina un falso positivo del
z-score en el Caso 4. Las métricas siguen midiendo el generador sintético sobre una muestra pequeña, no una
detección real. Los límites declarados en las fichas se mantienen.
