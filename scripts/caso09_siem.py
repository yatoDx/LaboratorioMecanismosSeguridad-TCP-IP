#!/usr/bin/env python3
"""Correlación local con trazabilidad y separación de evidencia real/sintética."""
import collections
import csv
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch

CASOS = Path(__file__).resolve().parents[1] / 'evidencia' / 'casos'
LOGS = CASOS / 'caso09-logs'
TZ = timezone(timedelta(hours=-5))
YEAR = 2026
HOSTS = {'gateway': '192.168.50.1', 'web': '192.168.50.20', 'dns': '192.168.50.53', 'xmpp': '192.168.50.30'}
FILES = {'nginx-web.log': ('web', 'nginx'), 'dnsmasq-dns.log': ('dns', 'dnsmasq'),
         'prosody-xmpp.log': ('xmpp', 'prosody'), 'auth-gateway.log': ('gateway', 'auth'),
         'sistema-gateway.log': ('gateway', 'sistema'), 'nftables-gateway.log': ('gateway', 'nftables')}
MONTHS = {m: i for i, m in enumerate('Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec'.split(), 1)}


def timestamp(line, source):
    if source == 'nginx':
        match = re.search(r'\[(\d{2})/(\w{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-]\d{4})\]', line)
        if not match:
            return None
        day, month, year, hour, minute, second, offset = match.groups()
        delta = timedelta(hours=int(offset[1:3]), minutes=int(offset[3:]))
        tz = timezone(delta if offset[0] == '+' else -delta)
        return datetime(int(year), MONTHS[month], int(day), int(hour), int(minute), int(second), tzinfo=tz)
    match = re.match(r'(\w{3})\s+(\d+)\s+(\d{2}):(\d{2}):(\d{2})', line)
    if not match or match[1] not in MONTHS:
        return None
    month, day, hour, minute, second = match.groups()
    return datetime(YEAR, MONTHS[month], int(day), int(hour), int(minute), int(second), tzinfo=TZ)


def parse(line, host, source):
    ts = timestamp(line, source)
    if ts is None:
        return None
    event, src, dport, detail = '', '', '', ''
    if source == 'nginx':
        match = re.search(r'^(\S+) .*?"(\S+) (\S+) [^"]+" (\d{3})', line)
        if match:
            src, method, path, code = match.groups()
            event = 'HTTP_5XX' if int(code) >= 500 else 'HTTP_OTHER'
            detail = f'{method} {path} {code}'
    elif source == 'dnsmasq':
        match = re.search(r'query\[[^]]+\] (\S+) from (\S+)', line)
        if match:
            detail, src = match.groups()
            event = 'DNS_LONG_LABEL' if max(map(len, detail.split('.'))) > 30 else 'DNS_QUERY'
        elif 'config error is REFUSED' in line:
            event = 'DNS_REFUSED_UNATTRIBUTED'
        elif ' is ' in line:
            event = 'DNS_OTHER'
    elif source == 'prosody':
        if 'Client disconnected' in line:
            event = 'XMPP_DISCONNECT'
        elif 'Client connected' in line:
            event = 'XMPP_CONNECT'
    elif source == 'auth':
        match = re.search(r'(Failed|Accepted) (?:password|publickey) for (?:invalid user )?\S+ from (\S+)', line)
        if match:
            outcome, src = match.groups()
            event = 'AUTH_FAIL' if outcome == 'Failed' else 'AUTH_SUCCESS'
        elif 'sudo[' in line:
            event = 'SUDO_CONTEXT'
        elif 'CRON[' in line:
            event = 'CRON_CONTEXT'
    elif source == 'nftables':
        fields = dict(re.findall(r'\b(SRC|DST|DPT|PROTO)=(\S+)', line))
        if 'SRC' in fields and 'DPT' in fields:
            src, dport = fields['SRC'], fields['DPT']
            event = 'NFT_SYN' if re.search(r'\bSYN\b', line) else 'NFT_OTHER'
            detail = f"dst={fields.get('DST', '')} proto={fields.get('PROTO', '')}"
    else:
        event = 'SYSTEM_CONTEXT'
    if not event:
        return None
    return dict(timestamp=ts.isoformat(), reporting_host=host, source=source, event_type=event,
                src_ip=src, dst_port=dport, detail=detail)


def normalize():
    events, coverage = [], {}
    for fname, (host, source) in FILES.items():
        path = LOGS / fname
        raw = path.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        lines = raw.decode('utf-8-sig', errors='replace').splitlines()
        count = 0
        for number, line in enumerate(lines, 1):
            ev = parse(line, host, source)
            if ev:
                ev.update(evidence_kind='real', source_file=fname, source_line=number, source_sha256=digest)
                events.append(ev)
                count += 1
        coverage[fname] = {'lines': len(lines), 'parsed': count, 'unparsed': len(lines) - count, 'sha256': digest}
    return events, coverage


def synthetic_events():
    definitions = []
    for i in range(6):
        definitions.append(('gateway', 'auth', f'Nov 18 20:30:{i:02} gateway sshd[999]: Failed password for lab from 192.168.50.100 port 41000 ssh2'))
    for i in range(3):
        definitions.append(('web', 'nginx', f'192.168.50.100 - - [18/Nov/2026:20:30:{10+i:02} -0500] "GET /demo HTTP/1.1" 503 0'))
    for i in range(12):
        definitions.append(('gateway', 'nftables', f'Nov 18 20:30:{20+i:02} gateway kernel: scan-syn: SRC=192.168.50.100 DST=192.168.50.1 PROTO=TCP DPT={8000+i} SYN'))
    records = [dict(reporting_host=host, source=source, raw=line, evidence_kind='sintetica')
               for host, source, line in definitions]
    content = ''.join(json.dumps(record, ensure_ascii=False) + '\n' for record in records)
    digest = hashlib.sha256(content.encode('utf-8')).hexdigest()
    events = []
    for number, (host, source, line) in enumerate(definitions, 1):
        ev = parse(line, host, source)
        ev.update(evidence_kind='sintetica', source_file='caso09-escenario-sintetico.jsonl', source_line=number,
                  source_sha256=digest)
        events.append(ev)
    return events, records


def correlate(events):
    groups = collections.defaultdict(list)
    for ev in events:
        ts = datetime.fromisoformat(ev['timestamp']).astimezone(timezone.utc)
        minute = ts.replace(second=0, microsecond=0).isoformat()
        subject = ev['src_ip'] or f"sin_atribuir@{ev['reporting_host']}"
        groups[(ev['evidence_kind'], subject, minute)].append(ev)
    results = []
    for (kind, subject, minute), entries in sorted(groups.items()):
        counts = collections.Counter(e['event_type'] for e in entries)
        ports = {e['dst_port'] for e in entries if e['event_type'] == 'NFT_SYN'}
        factors = {}
        if counts['AUTH_FAIL'] >= 3:
            factors['fallos_autenticacion'] = counts['AUTH_FAIL'] * 5
        if counts['HTTP_5XX'] >= 3:
            factors['errores_http_5xx'] = counts['HTTP_5XX'] * 3
        if len(ports) >= 10:
            factors['diez_puertos_distintos'] = 10
        if counts['DNS_LONG_LABEL'] >= 3:
            factors['etiquetas_dns_largas'] = 6
        score = sum(factors.values())
        results.append(dict(evidence_kind=kind, subject=subject, window_utc=minute, window_seconds=60,
                            reporting_hosts=sorted({e['reporting_host'] for e in entries}),
                            sources=sorted({e['source'] for e in entries}), counts=dict(counts),
                            distinct_dst_ports=len(ports), score=score, factors=factors,
                            alert=score >= 10,
                            evidence_refs=[f"{e['source_file']}:{e['source_line']}" for e in entries],
                            recommendation='Revisar evidencia y contexto; no bloquear automáticamente.'))
    return results


def write_json(name, data):
    (CASOS / name).write_text(json.dumps(data, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


def main():
    real, coverage = normalize()
    synthetic, records = synthetic_events()
    (CASOS / 'caso09-escenario-sintetico.jsonl').write_text(
        ''.join(json.dumps(record, ensure_ascii=False) + '\n' for record in records), encoding='utf-8', newline='\n')
    events = real + synthetic
    with (CASOS / 'caso09-eventos-normalizados.csv').open('w', encoding='utf-8', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=list(events[0]))
        writer.writeheader()
        writer.writerows(events)
    scores = correlate(events)
    alerts = [s for s in scores if s['alert']]
    write_json('caso09-cobertura.json', coverage)
    write_json('caso09-caracteristicas.json', scores)
    write_json('caso09-alertas.json', alerts)
    report = ['CASO 9 - Correlacion por sujeto y minuto (UTC)',
              f'Eventos reales: {len(real)}; sinteticos: {len(synthetic)}; ventanas: {len(scores)}',
              f'Alertas reales: {sum(a["evidence_kind"] == "real" for a in alerts)}; sinteticas: {sum(a["evidence_kind"] == "sintetica" for a in alerts)}',
              'Reglas: >=3 fallos auth (5/pieza), >=3 HTTP 5xx (3/pieza), >=10 puertos (10), >=3 DNS largas (6).',
              'Umbral: 10. DNS REFUSED sin origen no se atribuye a otro evento.',
              'Ano 2026 y zona -05:00 inferidos del laboratorio para logs syslog sin ano/zona.',
              'No se enviaron datos a un LLM ni se ejecutaron bloqueos.']
    for a in alerts:
        report.append(f'{a["evidence_kind"]}: {a["subject"]}, {a["window_utc"]}, score={a["score"]}, {a["factors"]}')
    text = '\n'.join(report) + '\n'
    (CASOS / 'caso09-scores.txt').write_text(text, encoding='utf-8')
    (CASOS / 'caso09-alerta.txt').write_text(json.dumps(alerts, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    validation = CASOS / 'caso09-validacion-humana.json'
    if not validation.exists():
        write_json(validation.name, {'estado': 'pendiente', 'revisor': None, 'fecha': None,
                                    'dictamen': None, 'nota': 'La ejecución automática no constituye revisión humana.'})
    fig, ax = plt.subplots(figsize=(12, 3))
    ax.set_xlim(0, 12)
    ax.set_ylim(0, 3)
    ax.axis('off')
    labels = ['Logs reales\n+ escenario separado', 'Normalizar\nUTC + procedencia', 'Sujeto + minuto\nconteos / puertos', 'Puntaje explicable\nreferencias evidencia', 'Revision humana\nPENDIENTE']
    for i, label in enumerate(labels):
        x = i * 2.4
        ax.add_patch(FancyBboxPatch((x + 0.1, 1), 2, 1, boxstyle='round,pad=0.06', facecolor='#e5eef6'))
        ax.text(x + 1.1, 1.5, label, ha='center', va='center', fontsize=9)
        if i < 4:
            ax.annotate('', xy=(x + 2.48, 1.5), xytext=(x + 2.13, 1.5), arrowprops={'arrowstyle': '->'})
    ax.set_title('Caso 9 - Pipeline local de correlacion; sin LLM ni bloqueo automatico')
    fig.savefig(CASOS / 'caso09-pipeline.png', dpi=150, bbox_inches='tight')
    plt.close(fig)
    print(text)


if __name__ == '__main__':
    main()
