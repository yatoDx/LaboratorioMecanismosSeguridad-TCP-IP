import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / 'entrega-parte-i'


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def status(path):
    if any(part.startswith('revision-') for part in path.parts):
        return 'historico_no_vigente'
    if path.name in {'caso04-consola.png', 'caso09-escenario-sintetico.json'}:
        return 'historico_no_vigente'
    if path.suffix == '.png' and path.with_stem(path.stem + '-final').exists():
        return 'historico_no_vigente'
    return 'vigente_o_contexto; consultar_ficha'


def inputs():
    selected = {ROOT / 'informe-laboratorio.md', ROOT / 'hash_evidencia.py',
                ROOT / 'evidencia' / 'baseline-normal.pcapng'}
    for directory in ('fichas', 'scripts', 'evidencia/casos'):
        selected.update(p for p in (ROOT / directory).rglob('*')
                        if p.is_file() and '__pycache__' not in p.parts)
    for pattern in ('capturar-consola.ps1', 'capturar_pcap_wireshark.ps1', 'mostrar-*.bat'):
        selected.update((ROOT / 'evidencia').glob(pattern))
    return sorted(selected)


def verify(destination):
    manifest_path = destination / 'manifiesto-sha256.json'
    expected = (destination / 'manifiesto-sha256.txt').read_text(encoding='utf-8').split()[0]
    if digest(manifest_path) != expected:
        raise RuntimeError('El manifiesto no coincide con su huella registrada')
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    for item in manifest['archivos']:
        for copy in ('original', 'trabajo'):
            base = (destination / copy).resolve()
            path = (base / item['ruta']).resolve()
            if not path.is_relative_to(base):
                raise ValueError('Ruta fuera del paquete')
            if path.stat().st_size != item['bytes'] or digest(path) != item['sha256']:
                raise RuntimeError(f'Copia modificada: {copy}/{item["ruta"]}')
    print(f'Integridad OK: {len(manifest["archivos"])} archivos en cada copia; manifiesto OK.')


def close():
    sources = inputs()
    for source in sources:
        if not source.is_file() or source.is_symlink():
            raise ValueError(f'Fuente ausente o enlace no admitido: {source}')
    DEST.mkdir(exist_ok=False)
    records = []
    for source in sources:
        relative = source.relative_to(ROOT)
        expected = digest(source)
        for copy in ('original', 'trabajo'):
            target = DEST / copy / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
            if digest(target) != expected:
                raise RuntimeError(f'Copia no coincide: {target}')
        records.append(dict(ruta=relative.as_posix(), bytes=source.stat().st_size,
                            sha256=expected, estado=status(source)))
    original = DEST / 'original'
    for start in range(0, len(records), 40):
        result = subprocess.run(
            [sys.executable, 'hash_evidencia.py', '--salida', 'registro-hashes-cierre.log',
             *[record['ruta'] for record in records[start:start + 40]]],
            cwd=original, capture_output=True, encoding='utf-8', errors='replace',
            timeout=120, check=True)
        if '[FALTA]' in result.stdout:
            raise RuntimeError(result.stdout)
    closure_log = original / 'registro-hashes-cierre.log'
    with (ROOT / 'evidencia.log').open('ab') as stream:
        stream.write(closure_log.read_bytes())
    shutil.copy2(ROOT / 'evidencia.log', original / 'evidencia.log')
    for name in ('registro-hashes-cierre.log', 'evidencia.log'):
        source = original / name
        shutil.copy2(source, DEST / 'trabajo' / name)
        records.append(dict(ruta=name, bytes=source.stat().st_size,
                            sha256=digest(source), estado='registro_de_integridad'))
    for source, item in zip(sources, records):
        if digest(source) != item['sha256']:
            raise RuntimeError(f'La fuente cambió durante el cierre: {source}')
    manifest = dict(
        fecha_utc=datetime.now(timezone.utc).isoformat(), algoritmo='SHA-256',
        alcance='Cierre tecnico de Parte I; no certificacion academica ni firma humana',
        original='Copia maestra al cierre, no adquisicion inmutable inicial; sin WORM ni cambio de permisos',
        trabajo='Copia identica para consulta; modificarla hara fallar esta verificacion',
        historicos='Se preservan revisiones y hashes anteriores, incluso inconsistencias C0',
        exclusiones=['vmctl.py: contiene credenciales; permanece solo en el repositorio local',
                     'claves privadas TLS, instalaciones y maquinas virtuales',
                     'Parte II y aprobaciones externas'],
        archivos=records)
    path = DEST / 'manifiesto-sha256.json'
    path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    (DEST / 'manifiesto-sha256.txt').write_text(
        digest(path) + '  manifiesto-sha256.json\n', encoding='utf-8')
    verify(DEST)
    print(f'Paquete: {DEST}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--verificar', action='store_true')
    parser.add_argument('--paquete', type=Path, default=DEST)
    args = parser.parse_args()
    if args.verificar:
        verify(args.paquete.resolve())
    else:
        close()
