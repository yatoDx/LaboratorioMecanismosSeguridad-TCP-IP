"""Restaura los saltos de línea CRLF originales de la evidencia.

Git (con autocrlf) guardó la evidencia con LF; el manifiesto SHA-256 se calculó
sobre los archivos con CRLF. Para cada archivo cuyo hash no coincide se prueba
la versión CRLF y, si coincide con el manifiesto, se restaura. Lo que no se
puede reproducir se informa (no se modifica).

    python scripts/reparar_evidencia.py            # solo informa
    python scripts/reparar_evidencia.py --aplicar  # escribe los archivos restaurados
    python scripts/reparar_evidencia.py --aplicar --enmendar
        # además: los archivos que no se pueden reproducir (saltos de línea mixtos
        # perdidos por Git) se registran en el manifiesto como ENMIENDAS, con su
        # huella registrada originalmente y la actual. No se oculta la diferencia.
"""
import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PAQUETE = ROOT / 'entrega-parte-i'


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def crlf(data: bytes) -> bytes:
    return data.replace(b'\r\n', b'\n').replace(b'\n', b'\r\n')


def candidatos(data: bytes):
    yield data
    yield crlf(data)
    yield data.replace(b'\r\n', b'\n')


def revisar(path: Path, esperado: str, aplicar: bool):
    """Devuelve 'ok', 'reparado' o 'irrecuperable'."""
    if not path.is_file():
        return 'irrecuperable'
    data = path.read_bytes()
    for i, cand in enumerate(candidatos(data)):
        if sha(cand) == esperado:
            if i == 0:
                return 'ok'
            if aplicar:
                path.write_bytes(cand)
            return 'reparado'
    return 'irrecuperable'


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--aplicar', action='store_true')
    ap.add_argument('--enmendar', action='store_true')
    ap.add_argument('--paquete', type=Path, default=PAQUETE)
    a = ap.parse_args()
    paquete = a.paquete
    cuenta = {'ok': 0, 'reparado': 0, 'irrecuperable': 0}
    malos = []
    # 1) el manifiesto, contra su huella registrada
    huella = (paquete / 'manifiesto-sha256.txt').read_text(encoding='utf-8-sig').split()[0]
    r = revisar(paquete / 'manifiesto-sha256.json', huella, a.aplicar)
    cuenta[r] += 1
    if r == 'irrecuperable':
        raise SystemExit('El manifiesto no se puede reproducir con ningún salto de línea: no se continúa.')
    manifiesto = json.loads((paquete / 'manifiesto-sha256.json').read_bytes().decode('utf-8'))
    # 2) cada archivo, en las dos copias
    rotos = {}
    for item in manifiesto['archivos']:
        for copia in ('original', 'trabajo'):
            ruta = paquete / copia / item['ruta']
            r = revisar(ruta, item['sha256'], a.aplicar)
            cuenta[r] += 1
            if r == 'irrecuperable':
                malos.append(f'{copia}/{item["ruta"]}')
                rotos.setdefault(item['ruta'], item)
    modo = 'aplicado' if a.aplicar else 'solo informe'
    print(f'[{modo}] correctos: {cuenta["ok"]} · restaurables con CRLF: {cuenta["reparado"]} · irrecuperables: {cuenta["irrecuperable"]}')
    for m in malos:
        print('  irrecuperable:', m)
    if malos and a.aplicar and a.enmendar:
        enmiendas = manifiesto.setdefault('enmiendas', [])
        for ruta, item in rotos.items():
            o, t = paquete / 'original' / ruta, paquete / 'trabajo' / ruta
            if not (o.is_file() and t.is_file() and o.read_bytes() == t.read_bytes()):
                raise SystemExit(f'Las dos copias de {ruta} difieren entre sí: no se enmienda.')
            actual = o.read_bytes()
            enmiendas.append(dict(
                ruta=ruta, sha256_registrado_al_cierre=item['sha256'], bytes_registrados=item['bytes'],
                sha256_actual=sha(actual), bytes_actuales=len(actual),
                motivo='Saltos de línea mixtos (CRLF/LF) alterados por Git en Windows; no reproducibles desde el repositorio'))
            item['sha256'], item['bytes'] = sha(actual), len(actual)
        mpath = paquete / 'manifiesto-sha256.json'
        mpath.write_bytes((json.dumps(manifiesto, ensure_ascii=False, indent=2) + '\n').encode('utf-8'))
        (paquete / 'manifiesto-sha256.txt').write_bytes(
            (sha(mpath.read_bytes()) + '  manifiesto-sha256.json\n').encode('utf-8'))
        print(f'Enmendados {len(rotos)} archivos (registrados en "enmiendas" del manifiesto).')
        raise SystemExit(0)
    raise SystemExit(1 if malos else 0)


if __name__ == '__main__':
    main()
