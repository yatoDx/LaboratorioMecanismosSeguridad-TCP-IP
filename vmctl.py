#!/usr/bin/env python3
"""vmctl.py - helper SSH para administrar las VMs del laboratorio.

Uso:
  python vmctl.py run <host> <puerto> <comando...>
  python vmctl.py put <host> <puerto> <archivo_local> <ruta_remota>

Credenciales: se leen de las variables de entorno LAB_USER (por defecto 'lab')
y LAB_PASS (obligatoria). Ejemplo en PowerShell:
  $env:LAB_PASS = '<contraseña de las VMs>'
"""
import os
import sys

import paramiko

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

USER = os.environ.get("LAB_USER", "lab")
PASSWORD = os.environ.get("LAB_PASS", "")


def _require_password():
    if not PASSWORD:
        sys.exit("Defina la variable de entorno LAB_PASS con la contraseña de las VMs.")


def connect(host, port):
    _require_password()
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(
        host,
        port=int(port),
        username=USER,
        password=PASSWORD,
        timeout=20,
        allow_agent=False,
        look_for_keys=False,
    )
    return c


def do_run(c, args):
    cmd = " ".join(args)
    use_sudo = cmd.startswith("sudo ")
    if use_sudo:
        cmd = cmd[len("sudo "):]
        cmd = f"echo {PASSWORD} | sudo -S {cmd}"
    _stdin, stdout, stderr = c.exec_command(cmd, timeout=600)
    out = stdout.read().decode(errors="replace")
    err = stderr.read().decode(errors="replace")
    if out:
        sys.stdout.write(out)
    if err.strip():
        sys.stderr.write(err)


def do_put(c, args):
    local, remote = args[0], args[1]
    sftp = c.open_sftp()
    sftp.put(local, remote)
    sftp.close()
    print(f"[OK] {local} -> {remote}")


def main():
    if len(sys.argv) < 4:
        print(__doc__)
        sys.exit(2)
    op, host, port = sys.argv[1], sys.argv[2], sys.argv[3]
    rest = sys.argv[4:]
    c = connect(host, port)
    try:
        if op == "run":
            do_run(c, rest)
        elif op == "put":
            do_put(c, rest)
        else:
            print(f"operacion desconocida: {op}", file=sys.stderr)
            sys.exit(2)
    finally:
        c.close()


if __name__ == "__main__":
    main()
