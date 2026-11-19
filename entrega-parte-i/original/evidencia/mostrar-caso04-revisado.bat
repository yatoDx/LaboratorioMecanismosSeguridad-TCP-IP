@echo off
title EVIDENCIA-CASO04-REVISION-FINAL
set PYTHONIOENCODING=utf-8
chcp 65001 >nul
python scripts\caso04_ml.py --self-test
echo.
python -c "import json; from pathlib import Path; m=json.loads(Path('evidencia/casos/caso04-metricas.json').read_text(encoding='utf-8')); print('METRICAS GUARDADAS - ventanas de 10 s; train 17, embargo 1, test normal 11'); print('Anomalias: 22 variantes TABULARES SINTETICAS, no ataques reales'); [print(g, model, 'CM=', v['confusion_matrix'], 'FPR=', v['false_positive_rate'], 'recall=', v['recall']) for g, models in m.items() if g in ('real_normal_only', 'mixed_didactic_NOT_independent') for model,v in models.items()]; print('Muestra pequena y dependiente: no demuestra generalizacion.')"
pause
