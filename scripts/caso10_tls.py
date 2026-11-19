#!/usr/bin/env python3
"""Evidencia TLS real; aprovisionamiento local opcional y explícito."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shlex
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import vmctl

OUT = ROOT / 'evidencia' / 'casos'
OPENSSL = Path('C:/Program Files/Git/usr/bin/openssl.exe')
HOST = '192.168.50.30'
NAME = 'xmpp.lab.local'
PUBLIC_CERT = OUT / 'caso10-certificado.pem'


def remote(client, command, sudo=False):
    full = 'sudo -S -p "" sh -c ' + shlex.quote(command) if sudo else command
    stdin, stdout, stderr = client.exec_command(full, timeout=45)
    if sudo:
        stdin.write(vmctl.PASSWORD + '\n')
        stdin.flush()
    stdin.channel.shutdown_write()
    text = stdout.read().decode('utf-8', errors='replace')
    err = stderr.read().decode('utf-8', errors='replace')
    code = stdout.channel.recv_exit_status()
    return {'command': command, 'exit_code': code, 'stdout': text, 'stderr': err}


def save(name, value):
    (OUT / name).write_text(json.dumps(value, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')


def provision(client):
    before = [remote(client, 'date -Iseconds; prosodyctl check certs', True),
              remote(client, 'timeout 10 openssl s_client -starttls xmpp -xmpphost localhost -connect 192.168.50.30:5222 -servername localhost -showcerts </dev/null')]
    path = OUT / 'caso10-antes.json'
    if not path.exists():
        save(path.name, before)
    command = r'''set -eu
conf=/etc/prosody/conf.d/taller-tls.cfg.lua
crt=/etc/prosody/certs/xmpp.lab.local.crt
key=/etc/prosody/certs/xmpp.lab.local.key
test ! -e "$conf"
test ! -e "$crt"
test ! -e "$key"
umask 077
openssl req -x509 -newkey rsa:2048 -sha256 -noenc -days 30 -keyout "$key" -out "$crt" -subj '/CN=xmpp.lab.local/O=Taller TCPIP laboratorio' -addext 'subjectAltName=DNS:xmpp.lab.local' -addext 'extendedKeyUsage=serverAuth'
chown root:prosody "$key" "$crt"
chmod 640 "$key"
chmod 644 "$crt"
printf '%s\n' 'VirtualHost "xmpp.lab.local"' '    authentication = "internal_hashed"' '    c2s_require_encryption = true' '    allow_unencrypted_plain_auth = false' '    ssl = {' '        certificate = "/etc/prosody/certs/xmpp.lab.local.crt";' '        key = "/etc/prosody/certs/xmpp.lab.local.key";' '    }' > "$conf"
chown root:prosody "$conf"
chmod 640 "$conf"
prosodyctl check config
systemctl restart prosody
systemctl is-active prosody
'''
    result = remote(client, command, True)
    save('caso10-aprovisionamiento.json', result)
    if result['exit_code']:
        raise RuntimeError(result['stderr'] + result['stdout'])


def local_probe(extra, xmpphost=NAME):
    args = [str(OPENSSL), 's_client', '-starttls', 'xmpp', '-xmpphost', xmpphost,
            '-connect', HOST + ':5222', '-servername', NAME, '-showcerts', *extra]
    stream = (f"<stream:stream to='{xmpphost}' xmlns='jabber:client' "
              "xmlns:stream='http://etherx.jabber.org/streams' version='1.0'></stream:stream>").encode()
    result = subprocess.run(args, input=stream, capture_output=True, timeout=20)
    return {'command': subprocess.list2cmdline(args), 'exit_code': result.returncode,
            'stdout': result.stdout.decode('utf-8', errors='replace'),
            'stderr': result.stderr.decode('utf-8', errors='replace')}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--provisionar', action='store_true')
    args = ap.parse_args()
    client = vmctl.connect(HOST, 22)
    try:
        if args.provisionar:
            provision(client)
        cert = remote(client, 'openssl x509 -in /etc/prosody/certs/xmpp.lab.local.crt -outform PEM', True)
        if cert['exit_code']:
            raise RuntimeError(cert['stderr'])
        PUBLIC_CERT.write_text(cert['stdout'], encoding='ascii')
        observations = [remote(client, 'date -Iseconds; openssl version; ss -lnt; systemctl is-active prosody'),
                        remote(client, 'prosodyctl check config; prosodyctl check certs', True),
                        remote(client, 'journalctl -u prosody --no-pager -n 30; tail -n 35 /var/log/prosody/prosody.log', True)]
        save('caso10-estado-servicio.json', observations)
        checks = {
            'confianza_explicita': local_probe(['-CAfile', str(PUBLIC_CERT), '-verify_hostname', NAME, '-verify_return_error']),
            'sin_confianza_local': local_probe(['-verify_hostname', NAME, '-verify_return_error']),
            'nombre_incorrecto': local_probe(['-CAfile', str(PUBLIC_CERT), '-verify_hostname', 'otro.lab.local', '-verify_return_error'])}
        save('caso10-pruebas.json', checks)
        info = subprocess.run([str(OPENSSL), 'x509', '-in', str(PUBLIC_CERT), '-noout', '-subject', '-issuer', '-dates', '-ext', 'subjectAltName', '-fingerprint', '-sha256'], capture_output=True, text=True, check=True)
        (OUT / 'caso10-certificado.txt').write_text(info.stdout, encoding='utf-8')
        for label, result in checks.items():
            (OUT / f'caso10-{label}.txt').write_text(result['command'] + '\n' + result['stdout'] + result['stderr'], encoding='utf-8')
        assert checks['confianza_explicita']['exit_code'] == 0, checks['confianza_explicita']
        assert checks['sin_confianza_local']['exit_code'] != 0
        assert checks['nombre_incorrecto']['exit_code'] != 0
        summary = ['CASO 10 - XMPP STARTTLS REAL', datetime.now(timezone.utc).isoformat(),
                   f'Destino {HOST}:5222; VirtualHost {NAME}',
                   'Certificado autofirmado: confianza explicita solo con -CAfile; NO confianza publica.',
                   info.stdout.strip(),
                   *[f'{k}: exit={v["exit_code"]}' for k, v in checks.items()],
                   'Prueba correcta exige exit=0, certificado, nombre y cifrado; Verify return code aislado no basta.',
                   'No se crearon cuentas ni se enviaron mensajes personales.',
                   f'SHA256 certificado: {hashlib.sha256(PUBLIC_CERT.read_bytes()).hexdigest()}']
        (OUT / 'caso10-resumen.txt').write_text('\n'.join(summary) + '\n', encoding='utf-8')
        print('\n'.join(summary))
    finally:
        client.close()


if __name__ == '__main__':
    main()
