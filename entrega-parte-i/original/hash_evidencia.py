#!/usr/bin/env python3
"""hash_evidencia.py - Cálculo de hashes de evidencia (caso C0).

Uso:
  python hash_evidencia.py <archivo> [archivo2 ...]
  python hash_evidencia.py --dir <directorio>
  python hash_evidencia.py --salida evidencia.log <archivo...>

Calcula SHA-256, SHA-1 y MD5, con tamaño y fecha de modificación.
"""
import argparse
import datetime
import hashlib
import os
import sys


def hash_file(path):
    h_sha256 = hashlib.sha256()
    h_sha1 = hashlib.sha1()
    h_md5 = hashlib.md5()
    size = 0
    with open(path, "rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            h_sha256.update(chunk)
            h_sha1.update(chunk)
            h_md5.update(chunk)
    st = os.stat(path)
    return {
        "path": path,
        "size": size,
        "mtime": datetime.datetime.fromtimestamp(st.st_mtime).isoformat(sep=" "),
        "sha256": h_sha256.hexdigest(),
        "sha1": h_sha1.hexdigest(),
        "md5": h_md5.hexdigest(),
    }


def main():
    ap = argparse.ArgumentParser(description="Hashes de evidencia (caso C0)")
    ap.add_argument("archivos", nargs="*", help="Archivos a procesar")
    ap.add_argument("--dir", help="Procesar todos los archivos de un directorio (no recursivo)")
    ap.add_argument("--salida", help="Anexar resultados a un archivo de log")
    args = ap.parse_args()

    targets = list(args.archivos)
    if args.dir:
        if not os.path.isdir(args.dir):
            print(f"[ERROR] directorio no existe: {args.dir}", file=sys.stderr)
            sys.exit(2)
        targets += [
            os.path.join(args.dir, f)
            for f in sorted(os.listdir(args.dir))
            if os.path.isfile(os.path.join(args.dir, f))
        ]

    if not targets:
        ap.print_help()
        sys.exit(1)

    lines = []
    sep = "-" * 70
    lines.append("=" * 70)
    lines.append(f" Evidencia - {datetime.datetime.now().isoformat(sep=' ')}")
    lines.append("=" * 70)
    for t in targets:
        if not os.path.isfile(t):
            lines.append(f"[FALTA] no es archivo: {t}")
            lines.append(sep)
            continue
        r = hash_file(t)
        lines.append(f"archivo : {r['path']}")
        lines.append(f"tamano  : {r['size']} bytes")
        lines.append(f"mtime   : {r['mtime']}")
        lines.append(f"sha256  : {r['sha256']}")
        lines.append(f"sha1    : {r['sha1']}")
        lines.append(f"md5     : {r['md5']}")
        lines.append(sep)
    lines.append("fin")

    out = "\n".join(lines)
    print(out)
    if args.salida:
        with open(args.salida, "a", encoding="utf-8") as f:
            f.write(out + "\n")
        print(f"\n[OK] resultados anexados a {args.salida}")


if __name__ == "__main__":
    main()
