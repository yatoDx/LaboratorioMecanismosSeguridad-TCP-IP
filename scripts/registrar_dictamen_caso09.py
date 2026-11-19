"""Registra el dictamen HUMANO del Caso 9 (correlación). No decide nada por usted.

Antes de ejecutarlo, una persona del grupo debe revisar evidencia/casos/caso09-alerta.txt,
caso09-alertas.json y caso09-scores.txt, y comprobar que la alerta (score 49 sobre la
IP 192.168.50.100, escenario SINTÉTICO) corresponde a lo que muestran los logs de
caso09-escenario-sintetico.jsonl. Luego:

    python scripts/registrar_dictamen_caso09.py --revisor "Nombre Apellido" \
        --dictamen confirma|confirma_con_reservas|rechaza --nota "motivo breve"
"""
import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

RUTA = Path(__file__).resolve().parents[1] / 'evidencia' / 'casos' / 'caso09-validacion-humana.json'


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--revisor', required=True)
    ap.add_argument('--dictamen', required=True, choices=['confirma', 'confirma_con_reservas', 'rechaza'])
    ap.add_argument('--nota', required=True, help='motivo de la decisión, en una o dos frases')
    ap.add_argument('--llm-externo', choices=['no', 'si'], required=True,
                    help='¿se envió algún log a un LLM externo durante la revisión?')
    a = ap.parse_args()
    previo = json.loads(RUTA.read_text(encoding='utf-8'))
    registro = dict(
        estado='revisado_por_humano', revisor=a.revisor,
        fecha=datetime.now(timezone.utc).isoformat(timespec='seconds'),
        dictamen=a.dictamen, nota=a.nota, logs_enviados_a_llm_externo=(a.llm_externo == 'si'),
        alcance='Escenario sintético de 21 eventos + 168 eventos reales del laboratorio; no certifica un ataque real.',
        estado_previo=previo.get('estado'))
    RUTA.write_bytes((json.dumps(registro, ensure_ascii=False, indent=2) + '\n').encode('utf-8'))
    print('Dictamen registrado en', RUTA.relative_to(RUTA.parents[2]))


if __name__ == '__main__':
    main()
