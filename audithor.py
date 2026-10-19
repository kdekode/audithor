#!/usr/bin/env python3
"""Audithor: inspección local, secuencial y de solo lectura. Python 3.9+."""
import argparse
import collections
import contextlib
import datetime as dt
import gzip
import ipaddress
import os
import re
import stat
import sys
import time
import zlib
import html
import secrets
import subprocess
from email.message import EmailMessage
from email.policy import SMTP
from urllib.parse import unquote
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

BANNER = r"""
    _   _   _ ____ ___ _____ _   _  ___  ____
   / \ | | | |  _ \_ _|_   _| | | |/ _ \|  _ \
  / _ \| | | | | | | |  | | | |_| | | | | |_) |
 / ___ \ |_| | |_| | |  | | |  _  | |_| |  _ <
/_/   \_\___/|____/___| |_| |_| |_|\___/|_| \_\
                    steev anderson
"""
DOMAIN = re.compile(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
LOAD_PER_CPU = 1.0
PAGE_SIZE = 5
VERSION = '0.7.0'
MAIL_TO = 'notificacion@indexeomarketing.com'
ACCESS = re.compile(rb'^(\S+) \S+ \S+ \[([^\]]+)\] "([A-Z]+) ([^" ]+) HTTP/[0-9.]+" ([1-5][0-9]{2}) (\d+|-) "(?:[^"\\]|\\.)*" "((?:[^"\\]|\\.)*)"')
MONTHS = {m: i+1 for i, m in enumerate(('Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'))}
STAMP = re.compile(r'^(\d{2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-])(\d{2})(\d{2})$')
BOT = re.compile(r'bot|crawler|spider|slurp|bingpreview', re.I)
AUTO = re.compile(r'curl|wget|python|sqlmap|nikto|go-http-client|headless|selenium', re.I)
BROWSER = re.compile(r'Mozilla/5\.0.*(?:Firefox/|Chrome/|Safari/|Edg/)', re.I)
SENSITIVE = re.compile(r'(?:^|/)(?:\.env|\.git|wp-login\.php|xmlrpc\.php|phpmyadmin)(?:[/.]|$)', re.I)
BAN = re.compile(r'^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[,.]\d+)?\s+fail2ban\.actions\s+(?:\[\d+\])?:?\s+[A-Z]+\s+\[([^\]]{1,120})\]\s+Ban\s+(\S+)\s*$')


def clean(value, limit=180):
    """No permitir controles de terminal ni cadenas ilimitadas procedentes de logs."""
    return ''.join(c if c.isprintable() else '?' for c in str(value))[:limit]


def safe_path(raw):
    path = raw.split('?', 1)[0].split('#', 1)[0]
    if not path.startswith('/'):
        return '[destino no relativo]'
    path = re.sub(r'[^/]*@[^/]+|(?<=/)[A-Za-z0-9_%=-]{32,}', ':redactado', path)
    return clean(path, 180)


def parse(line, zone):
    m = ACCESS.match(line)
    if not m:
        return None
    try:
        ipaddress.ip_address(m[1].decode('ascii'))
        t = STAMP.fullmatch(m[2].decode('ascii'))
        if not t:
            return None
        d, mon, y, h, minute, sec, sign, oh, om = t.groups()
        if int(oh) > 23 or int(om) > 59:
            return None
        delta = dt.timedelta(hours=int(oh), minutes=int(om)) * (1 if sign == '+' else -1)
        stamp = dt.datetime(int(y), MONTHS[mon], int(d), int(h), int(minute), int(sec),
                            tzinfo=dt.timezone(delta)).astimezone(zone)
        path = safe_path(m[4].decode('utf-8', 'replace'))
        ua = m[7].decode('utf-8', 'replace')[:512]
        kind = ('bot' if BOT.search(ua) or AUTO.search(ua) else
                'probable' if BROWSER.search(ua) and not SENSITIVE.search(path) else 'unknown')
        return (stamp.date(), path, int(m[5]), int(m[6]) if m[6] != b'-' else 0, kind,
                str(ipaddress.ip_address(m[1].decode('ascii'))), stamp.strftime('%Y-%m-%d %H:%M %z'))
    except (ValueError, KeyError, UnicodeError, OverflowError):
        return None


def directory(path, start=None):
    """openat + O_NOFOLLOW en cada componente (Linux), sin resolver enlaces."""
    if not hasattr(os, 'O_NOFOLLOW'):
        raise RuntimeError('La ejecución está soportada en Linux con O_NOFOLLOW.')
    absolute = os.path.isabs(path)
    fd = os.open('/' if absolute else '.', os.O_RDONLY | os.O_DIRECTORY) if start is None else os.dup(start)
    try:
        for piece in path.split('/'):
            if piece in ('', '.'):
                continue
            if piece == '..':
                raise ValueError('No se permite .. en las rutas.')
            new = os.open(piece, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = new
        return fd
    except BaseException:
        os.close(fd)
        raise


@contextlib.contextmanager
def regular(parent, name):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError('Se rechazó un archivo no regular.')
        stream = os.fdopen(fd, 'rb', buffering=8192)
    except BaseException:
        os.close(fd)
        raise
    with stream:
        yield stream


def names(fd, maximum):
    out = []
    with os.scandir(fd) as entries:
        for entry in entries:
            if len(out) >= maximum:
                raise RuntimeError('Demasiadas entradas; se cancela sin presentar un inventario incompleto.')
            out.append(entry.name)
    return out


def sources(fd, compressed, historical=False):
    entries = names(fd, 4096)
    def matching(prefix):
        return [n for n in entries if any(re.fullmatch(re.escape(p) + r'(?:\.processed)?(?:\.\d+)?(?:\.gz)?', n) for p in prefix)]
    # Solo una capa; sumar nginx y Apache duplicaría peticiones.
    proxy = matching(('proxy_access_log', 'proxy_access_ssl_log'))
    apache = matching(('access_log', 'access_ssl_log'))
    # Plesk puede conservar solo Apache rotado y mantener nginx únicamente activo.
    # Para fechas pasadas, preferir la capa con históricos, sin sumar las dos.
    def retention(files):
        return (any(re.search(r'\.\d+(?:\.gz)?$', n) for n in files),
                any('.processed' in n or n.endswith('.gz') for n in files))
    use_apache = bool(apache) and (not proxy or (historical and retention(apache) > retention(proxy)))
    selected = apache if use_apache else proxy
    if len(selected) > 128:
        raise RuntimeError('Más de 128 logs por dominio; selecciona/revisa los históricos fuera de Audithor.')
    skipped = sum(n.endswith('.gz') for n in selected) if not compressed else 0
    selected = [n for n in selected if compressed or not n.endswith('.gz')]
    return sorted(selected), skipped, 'apache' if use_apache else 'nginx'


def discover(root):
    rows = []
    deadline = time.monotonic() + 15
    for name in names(root, 10000):
        if time.monotonic() > deadline:
            raise RuntimeError('Inventario supera 15 segundos. Consulta un dominio concreto para evitar más carga.')
        if not DOMAIN.fullmatch(name):
            continue
        try:
            fd = directory(name + '/logs', root)
            try:
                files, _, _ = sources(fd, True)
                mt = max((os.stat(n, dir_fd=fd, follow_symlinks=False).st_mtime for n in files), default=0)
            finally:
                os.close(fd)
            rows.append((name, mt))
        except OSError:
            rows.append((name, 0))
    return [name for name, _ in sorted(rows, key=lambda r: (-r[1], r[0]))]


def wait_for_capacity(gentle=False):
    """Esperar conservando el estado en memoria; no aumentar los umbrales."""
    announced = False
    next_notice = 0
    while True:
        reason = pressure(gentle)
        if not reason:
            if announced:
                print('  Carga recuperada: continúo desde el mismo punto.', flush=True)
            return
        if time.monotonic() >= next_notice:
            print('  PAUSA: ' + reason + ' Recompruebo cada 5 s; Ctrl+C para salir.', flush=True)
            next_notice = time.monotonic() + 30
            announced = True
        time.sleep(5)


class Budget:
    def __init__(self, seconds, mib, gentle=False, continuous=False):
        self.end = time.monotonic() + seconds
        self.maximum = mib * 1024 * 1024
        self.read = 0
        self.steps = 0
        self.pressure = None
        self.gentle = gentle
        self.continuous = continuous
        self.window_seconds = seconds
        self.window_bytes = self.maximum

    def exhausted(self):
        if self.continuous:
            if self.steps % 100 == 0:
                wait_for_capacity(self.gentle)
            if self.read >= self.maximum or time.monotonic() >= self.end:
                print(f'  Progreso: {self.read/1048576:.2f} MiB leídos; {self.steps:,} líneas/fragmentos. Continúo…', flush=True)
                time.sleep(1)
                wait_for_capacity(self.gentle)
                self.end = time.monotonic() + self.window_seconds
                self.maximum = self.read + self.window_bytes
            return False
        if self.steps % 250 == 0:
            self.pressure = pressure(self.gentle)
        if self.pressure:
            return True
        return self.read >= self.maximum or time.monotonic() >= self.end

    def tick(self, size):
        self.read += size
        self.steps += 1
        # Pausa también en fragmentos descartados o descomprimidos.
        time.sleep(.01 if self.gentle else .001)


def host_status():
    with open('/proc/meminfo', 'r', encoding='ascii') as stream:
        info = stream.read(8192)
    available = re.search(r'^MemAvailable:\s+(\d+) kB$', info, re.M)
    if not available:
        raise ValueError('MemAvailable no está disponible.')
    return max(1, os.cpu_count() or 1), os.getloadavg(), int(available[1]) / 1024


def pressure_reason(status, gentle=False):
    cpus, loads, available = status
    factor = LOAD_PER_CPU
    limit = cpus * factor
    if loads[0] > limit:
        return (f'Carga media 1 min: {loads[0]:.2f}; umbral: {limit:.2f} '
                f'({cpus} CPU lógicas × {factor:g}). Análisis aplazado. Usa --diagnose para ver el estado.')
    if available < 256:
        return f'Memoria disponible: {available:.0f} MiB; mínimo: 256 MiB. Análisis aplazado.'
    return None


def pressure(gentle=False):
    """Guardas aproximadas del host; no son métricas por dominio."""
    try:
        return pressure_reason(host_status(), gentle)
    except (OSError, AttributeError, ValueError):
        return 'No se pudo comprobar la presión del host; análisis aplazado. Usa --diagnose.'


def scan(parent, name, budget, state):
    with regular(parent, name) as raw:
        initial = os.fstat(raw.fileno())
        key = (initial.st_dev, initial.st_ino)
        if key in state['inodes']:
            return
        state['inodes'].add(key)
        packed = name.endswith('.gz')
        stream = gzip.GzipFile(fileobj=raw, mode='rb') if packed else raw
        try:
            while not budget.exhausted():
                # Captura un tamaño fijo: no perseguir indefinidamente un log activo.
                remaining = initial.st_size - raw.tell() if not packed else 16384
                if remaining <= 0:
                    break
                allowance = 16384 if budget.continuous else budget.maximum - budget.read
                cap = min(16384, remaining, allowance)
                line = stream.readline(cap)
                if not line:
                    break
                budget.tick(len(line))
                if not line.endswith(b'\n'):
                    state['notes'].add('Línea larga/incompleta o límite de lectura; cobertura parcial.')
                    # No analizar fragmentos como si fuesen peticiones completas.
                    while line and not line.endswith(b'\n') and not budget.exhausted():
                        cap = 16384 if budget.continuous else min(16384, budget.maximum - budget.read)
                        line = stream.readline(cap)
                        budget.tick(len(line))
                    continue
                yield line
            if budget.exhausted():
                state['notes'].add((budget.pressure or 'Límite de tiempo/bytes alcanzado.') + ' Resultado PARCIAL.')
            if os.fstat(raw.fileno()).st_size < initial.st_size:
                state['notes'].add('El log se truncó durante la lectura; resultado PARCIAL.')
        finally:
            if packed:
                stream.close()


def increment(table, key, value=1, overflow='[otras rutas: límite de memoria]'):
    if key not in table and len(table) >= 2000:
        key = overflow
    table[key] += value


def error_event(line):
    """Solo fecha y categoría; nunca imprimir mensajes internos ni secretos."""
    text = line.decode('utf-8', 'replace')
    nginx = re.match(r'^(\d{4})/(\d{2})/(\d{2}) ', text)
    apache = re.match(r'^\[[A-Za-z]{3} ([A-Za-z]{3})\s+(\d{1,2}) [0-9:.]+ (\d{4})\]', text)
    try:
        if nginx:
            day = dt.date(*map(int, nginx.groups()))
        elif apache:
            mon, d, y = apache.groups()
            day = dt.date(int(y), MONTHS[mon], int(d))
        else:
            return None
    except (KeyError, ValueError):
        return None
    low = text.lower()
    category = next((label for needle, label in (
        ('fatal error', 'PHP fatal'), ('php warning', 'PHP warning'),
        ('upstream timed out', 'Timeout de upstream'), ('permission denied', 'Permiso denegado'),
        ('primary script unknown', 'Script PHP no encontrado'),
        ('[error]', 'Error del servidor'), ('[warn]', 'Aviso del servidor'),
        (':error]', 'Error del servidor'), (':warn]', 'Aviso del servidor')) if needle in low), 'Otros mensajes internos')
    return day, category


def parse_ban(line):
    text = line.decode('utf-8', 'replace').strip()
    match = BAN.fullmatch(text)
    if not match:
        return None
    try:
        return dt.date.fromisoformat(text[:10]), clean(match[1], 80), str(ipaddress.ip_address(match[2]))
    except ValueError:
        return None


def historical_order(files, fd, historical):
    # No filtrar por mtime: solo priorizar; no equivale a la fecha del contenido.
    def key(name):
        rotation = re.search(r'\.(\d+)(?:\.gz)?$', name)
        mtime = os.stat(name, dir_fd=fd, follow_symlinks=False).st_mtime
        if historical:
            # .1 antes que .2/.10 y antes del .processed que puede contener solo hoy.
            group = 0 if rotation else 1 if '.processed' in name or name.endswith('.gz') else 2
            return (group, int(rotation[1]) if rotation else 0, -mtime)
        return (0, 0, -mtime)
    return sorted(files, key=key)


def read_fail2ban(args):
    result = dict(ips=set(), jails=collections.Counter(), events=0, notes=set(), inodes=set(),
                  day_seen=False, read=0)
    if args.no_fail2ban:
        result['notes'].add('Integración Fail2Ban desactivada por --no-fail2ban.')
        return result
    budget = Budget(min(args.seconds, 30), min(args.max_mib, 16), args.gentle)
    parent, basename = os.path.split(os.path.abspath(args.fail2ban_log))
    fd = None
    try:
        fd = directory(parent)
        files = [n for n in names(fd, 10000) if re.fullmatch(re.escape(basename) + r'(?:\.\d+)?(?:\.gz)?', n)]
        if len(files) > 128:
            raise ValueError('Demasiados históricos Fail2Ban.')
        if not files:
            result['notes'].add('No se encontró el log de Fail2Ban. Puede usar journald/syslog u otra ruta.')
        for name in historical_order(files, fd, args.historical):
            if name.endswith('.gz') and not args.gzip:
                result['notes'].add('Históricos gzip de Fail2Ban omitidos para hoy; usa --gzip para incluirlos.')
                continue
            if budget.exhausted():
                result['notes'].add('Lectura Fail2Ban incompleta por presupuesto o carga.')
                break
            try:
                for line in scan(fd, name, budget, result):
                    # Fail2Ban suele registrar hora local sin offset; no inventar una conversión.
                    if line[:10] == args.day.isoformat().encode() and b'fail2ban.' in line:
                        result['day_seen'] = True
                    event = parse_ban(line)
                    if not event or event[0] != args.day:
                        continue
                    _, jail, ip = event
                    result['events'] += 1
                    if ip in result['ips'] or len(result['ips']) < 20000:
                        result['ips'].add(ip)
                    else:
                        result['notes'].add('Límite de 20 000 IP Fail2Ban: coincidencias y únicas son parciales.')
                    if jail not in result['jails'] and len(result['jails']) >= 100:
                        jail = '[otras jails]'
                    result['jails'][jail] += 1
            except (OSError, EOFError, ValueError, zlib.error):
                result['notes'].add('No se pudo completar un histórico de Fail2Ban.')
    except (OSError, ValueError, RuntimeError) as exc:
        result['notes'].add('Fail2Ban no disponible: ' + clean(str(exc), 180))
    finally:
        if fd is not None:
            os.close(fd)
    result['read'] = budget.read
    return result


def show_fail2ban(result, day):
    print('\n' + '=' * 80)
    print(f' FAIL2BAN · SERVIDOR · {day}')
    print('=' * 80)
    if result['day_seen']:
        print(f'  Eventos Ban observados: {result["events"]:,}    IP únicas observadas: {len(result["ips"]):,}')
        for jail, count in result['jails'].most_common(8):
            print(f'  {jail:<36} {count:>10,} eventos')
    else:
        print('  N/D: no se leyeron mensajes de Fail2Ban para esta fecha.')
    print('  Histórico declarado por Fail2Ban; no indica bloqueos actualmente activos.')
    print('  Hora local escrita en el log. Cobertura y retención no garantizadas.')
    for note in sorted(result['notes']):
        print('  AVISO: ' + note)
    print()


def signals(result):
    total = result['total']
    findings = []
    if result.get('sensitive4', 0) >= 20:
        findings.append('Rutas sensibles con respuesta 4xx: ' + str(result['sensitive4']))
    if total >= 100 and result.get('http4', 0) / total >= .5:
        findings.append('Al menos 50% de respuestas 4xx')
    if total >= 20 and result.get('http5', 0) / total >= .1:
        findings.append('Al menos 10% de respuestas 5xx')
    return findings


def activity_level(peak):
    return 'BAJA' if peak < 60 else 'MODERADA' if peak < 600 else 'ALTA' if peak < 3000 else 'MUY ALTA'


def analyze(root, domain, day, zone, args):
    detailed = bool(args.domain or getattr(args, 'report', False) or getattr(args, 'send', False))
    state = dict(inodes=set(), notes=set(), counts=collections.Counter(), urls=collections.Counter(),
                 bytes_urls=collections.Counter(), errors=collections.Counter(), statuses=collections.Counter(),
                 internal=collections.Counter(),
                 ip_counts=collections.Counter(), minutes=collections.Counter(), sensitive_urls=collections.Counter(),
                 f2b_seen=set(), sensitive=0, sensitive4=0, http4=0, http5=0, peak=0, peak_minute=None,
                 total=0, bytes=0, invalid=0, earliest=None, latest=None)
    bans = getattr(args, 'bans', None)
    state['f2b_matches'] = 0 if bans and bans['day_seen'] else None
    budget = Budget(args.seconds, args.max_mib, args.gentle, continuous=not getattr(args, 'sample', False))
    try:
        fd = directory(domain + '/logs', root)
    except OSError as exc:
        state['notes'].add('No se puede abrir logs: ' + clean(exc.strerror))
        return state
    try:
        files, skipped, layer = sources(fd, args.gzip, args.historical)
        state['layer'] = layer
        if skipped:
            state['notes'].add(f'{skipped} archivos gzip omitidos; usa --gzip para incluirlos.')
        if not files:
            state['notes'].add('No hay logs de acceso legibles seleccionados.')
        # Más reciente primero: útil para hoy con presupuesto acotado.
        files = historical_order(files, fd, args.historical)
        for name in files:
            if budget.exhausted():
                state['notes'].add((budget.pressure or 'Quedan archivos sin leer.') + ' Resultado PARCIAL.')
                break
            try:
                for line in scan(fd, name, budget, state):
                    event = parse(line, zone)
                    if event is None:
                        state['invalid'] += 1
                        continue
                    date, path, status, size, kind, ip, minute = event
                    state['earliest'] = min(date, state['earliest'] or date)
                    state['latest'] = max(date, state['latest'] or date)
                    if date != day:
                        continue
                    state['total'] += 1
                    state['bytes'] += size
                    state['counts'][kind] += 1
                    state['statuses'][status] += 1
                    state['http4'] += int(400 <= status < 500)
                    state['http5'] += int(status >= 500)
                    probe = bool(SENSITIVE.search(unquote(path)))
                    state['sensitive'] += int(probe)
                    state['sensitive4'] += int(probe and 400 <= status < 500)
                    # Un día tiene <=1500 minutos con cambio horario; límite defensivo.
                    if minute in state['minutes'] or len(state['minutes']) < 1600:
                        state['minutes'][minute] += 1
                        if state['minutes'][minute] > state['peak']:
                            state['peak'] = state['minutes'][minute]
                            state['peak_minute'] = minute
                    if bans and ip in bans['ips']:
                        state['f2b_seen'].add(ip)
                    if detailed:
                        increment(state['ip_counts'], ip, overflow='[otras IP: límite de memoria]')
                        if probe:
                            increment(state['sensitive_urls'], path)
                    if detailed:
                        increment(state['urls'], path)
                        increment(state['bytes_urls'], path, size)
                        if status >= 400:
                            increment(state['errors'], str(status) + ' ' + path)
            except (OSError, EOFError, ValueError, zlib.error) as exc:
                state['notes'].add('No se pudo completar ' + clean(name) + ': ' + clean(str(exc)))
        if detailed:
            errorfiles = [n for n in names(fd, 4096) if re.fullmatch(r'(?:proxy_error_log|error_log)(?:\.\d+)?(?:\.gz)?', n)]
            if len(errorfiles) > 128:
                state['notes'].add('Demasiados logs internos; no se analizaron.')
            else:
                for name in errorfiles:
                    if name.endswith('.gz') and not args.gzip:
                        state['notes'].add('Históricos internos gzip omitidos; usa --gzip.')
                        continue
                    if budget.exhausted():
                        state['notes'].add('Sin presupuesto para completar los logs internos.')
                        break
                    try:
                        for line in scan(fd, name, budget, state):
                            event = error_event(line)
                            if event and event[0] == day:
                                state['internal'][event[1]] += 1
                    except (OSError, EOFError, ValueError, zlib.error):
                        state['notes'].add('No se pudo completar un log interno.')
    finally:
        os.close(fd)
    state['read'] = budget.read
    if state['f2b_matches'] is not None:
        state['f2b_matches'] = len(state['f2b_seen']) if state['read'] else None
    if state['invalid']:
        state['notes'].add(f"{state['invalid']} líneas no interpretadas; cobertura parcial.")
    return state


def table(headers, rows, widths):
    def row(values):
        cells = []
        for value, width in zip(values, widths):
            text = clean(value, 1000)
            if len(text) > width:
                text = text[:width-3] + '...'
            cells.append(text.ljust(width))
        return '  '.join(cells)
    print('  ' + row(headers))
    print('  ' + '  '.join('-' * width for width in widths))
    for values in rows:
        print('  ' + row(values))


def show(domain, day, result, detail=False):
    total = result['total']
    known = bool(result.get('read', 0))
    pct = lambda k: f"{100 * result['counts'][k] / total:.1f}%" if total else 'N/D'
    count_pct = lambda n: f'{n:,} ({100*n/total:.1f}% de las leídas)' if total else 'Sin accesos de la fecha'
    f2b = result.get('f2b_matches')
    print('\n' + '=' * 80)
    print(' ' + domain)
    print(f' Fecha: {day}   |   Datos observados, cobertura del día no garantizada')
    if result.get('layer'):
        print(' Fuente de accesos: ' + result['layer'].upper() + ' (una sola capa)')
    print('=' * 80 + '\n')
    metrics = [
        ('Peticiones de la fecha leídas', f'{total:,}' if known else 'N/D'),
        ('Contenido enviado (según log)', f'{result["bytes"]/1048576:.2f} MiB' if known else 'N/D'),
        ('Bots / automatización probable', pct('bot')),
        ('Humano probable / desconocido', pct('probable') + ' / ' + pct('unknown')),
        ('Respuestas 4xx (ej. 403 / 404)', count_pct(result.get('http4', 0))),
        ('Respuestas 5xx (ej. 500 / 503)', count_pct(result.get('http5', 0))),
        ('Accesos a rutas sensibles', f'{result.get("sensitive", 0):,}' if total else 'N/D'),
        ('Pico en un minuto registrado', f'{result.get("peak", 0):,} peticiones' if total else 'N/D'),
    ]
    if detail:
        metrics.append(('IP coincidentes con Fail2Ban', f'{f2b:,}' if f2b is not None else 'N/D'))
    table(('QUÉ SE HA MEDIDO', 'RESULTADO'), metrics, (37, 37))
    print('\n  Una petición es un recurso solicitado: página, imagen, CSS, API, etc.')
    print('  El contenido enviado suma tamaños de respuesta; no mide RAM ni CPU.')
    print('  4xx: solicitudes rechazadas/no encontradas. 5xx: errores del servidor.')
    print('  Los porcentajes 4xx/5xx usan todas las peticiones leídas de esta fecha.')
    peak = result.get('peak', 0)
    if total:
        level = activity_level(peak)
        print(f'\n  ACTIVIDAD {level}: pico observado de {peak:,}/min (~{peak/60:.1f}/s).')
        if result.get('peak_minute'):
            print('  Minuto del pico: ' + result['peak_minute'])
        print('  Nivel orientativo por volumen; no compara con el historial de esta web.')
        print('  Un pico alto puede ser normal. Incluye recursos y bots, no personas.')
    if detail:
        print('\n  F2B: IP vistas en esta web y con evento Ban en el servidor ese día.')
        print('       Coincidencia; no demuestra que esta web originara el bloqueo.')
    findings = signals(result)
    if findings:
        print('\n  REVISAR · Indicadores orientativos; no confirman un ataque:')
        for finding in findings:
            print('    - ' + finding)
    elif known and total:
        print('\n  Sin umbrales de alerta activados en la muestra; no descarta un ataque.')
    else:
        print('\n  Sin datos suficientes para valorar señales en esta fecha.')
    if not total:
        print('  No se observaron accesos de esta fecha; no confirma tráfico cero.')
    if result['earliest']:
        print(f'  Fechas encontradas: {result["earliest"]} a {result["latest"]}.')
    if result['notes']:
        print('\n  AVISOS DE LECTURA')
        for note in sorted(result['notes']):
            print('    - ' + note)
    if detail:
        for title, key, unit in [('URLs con más peticiones', 'urls', 'PETICIONES'),
                                 ('URLs con más transferencia (no mide CPU)', 'bytes_urls', 'BYTES'),
                                 ('Errores HTTP 4xx/5xx por URL', 'errors', 'PETICIONES'),
                                 ('Accesos a rutas sensibles (incluye usos legítimos)', 'sensitive_urls', 'PETICIONES'),
                                 ('IP con más peticiones (dirección registrada)', 'ip_counts', 'PETICIONES')]:
            print('\n  ' + title + '\n')
            rows = [(f'{count:,}', path) for path, count in result[key].most_common(10)]
            table((unit, 'RUTA / IP'), rows, (12, 62))
            if not rows:
                print('  Sin datos observados.')
        print('\n  Mensajes internos PHP/nginx/Apache (fecha local del log)\n')
        table(('MENSAJES', 'CATEGORÍA'), [(str(count), category) for category, count in result['internal'].most_common()], (12, 62))
        if not result['internal']:
            print('  Sin mensajes interpretados para la fecha; revisa la cobertura.')
        print('\n  Las IP pueden ser proxies/CDN. No se verifica su identidad ni se bloquean.')
    print()


def compact_summary(result):
    """Retener solo cifras por dominio; nunca tablas de rutas o referencias al estado."""
    summary = {key: result[key] for key in ('total', 'bytes', 'earliest', 'latest')}
    summary['read'] = result.get('read', 0)
    summary['layer'] = result.get('layer')
    for key in ('http4', 'http5', 'sensitive', 'sensitive4', 'peak'):
        summary[key] = result.get(key, 0)
    summary['peak_minute'] = result.get('peak_minute')
    summary['f2b_matches'] = result.get('f2b_matches')
    summary['counts'] = collections.Counter({key: result['counts'][key] for key in ('bot', 'probable', 'unknown')})
    notes = sorted(result['notes'])
    summary['notes'] = [clean(note, 240) for note in notes[:8]]
    if len(notes) > 8:
        summary['notes'].append(f'{len(notes) - 8} avisos adicionales omitidos del resumen.')
    return summary


def review_key(row):
    domain, result = row
    available = bool(result.get('read') and result['total'])
    return (not available, -len(signals(result)), -result.get('sensitive4', 0),
            -result.get('http5', 0), -result.get('http4', 0), -result['total'], domain)


def show_review_page(rows, start=1):
    table(('Nº', 'DOMINIO', 'REVISIÓN', '4xx', '5xx', 'SENS.4xx'), [
        (str(number), domain,
         ('Sin datos' if not result.get('read') or not result['total'] else
          f'{len(signals(result))} señales' if signals(result) else 'Sin umbrales'),
         str(result.get('http4', 0)) if result['total'] else 'N/D',
         str(result.get('http5', 0)) if result['total'] else 'N/D',
         str(result.get('sensitive4', 0)) if result['total'] else 'N/D')
        for number, (domain, result) in enumerate(rows, start)
    ], (3, 28, 12, 8, 8, 9))
    for domain, result in rows:
        findings = signals(result)
        if findings:
            print('\n  ' + domain + ':')
            for finding in findings:
                print('    - ' + finding)
        if result['notes']:
            print('  ' + domain + ': tiene avisos de lectura; revisa su informe anterior.')
    print(flush=True)


def next_batch(args):
    if getattr(args, 'once', False):
        return False
    if getattr(args, 'report', False) or getattr(args, 'send', False):
        return True
    if not sys.stdin.isatty():
        print('Sin terminal interactiva: termino tras cinco dominios. Usa --report para auditar todos.')
        return False
    while True:
        command = input('\nEscribe start para analizar los siguientes 5; q para terminar > ').strip().lower()
        if command == 'start':
            return True
        if command in ('q', 'salir'):
            return False
        print('No he iniciado otra tanda. Escribe start o q.')


def html_table(headers, rows):
    escape = lambda value: html.escape(clean(value, 1000), quote=True)
    return ('<table><thead><tr>' + ''.join('<th>' + escape(h) + '</th>' for h in headers) +
            '</tr></thead><tbody>' + ''.join('<tr>' + ''.join('<td>' + escape(c) + '</td>' for c in row) +
            '</tr>' for row in rows) + '</tbody></table>')


def html_section(domain, result, args):
    esc = lambda value: html.escape(clean(value, 1000), quote=True)
    total = result['total']
    pct = lambda value: f'{100*value/total:.1f}%' if total else 'N/D'
    metrics = [
        ('Peticiones observadas', total if result.get('read') else 'N/D'),
        ('Contenido enviado según el log', f'{result["bytes"]/1048576:.2f} MiB'),
        ('Bots / automatización probable', pct(result['counts']['bot'])),
        ('Humano probable', pct(result['counts']['probable'])),
        ('Desconocido', pct(result['counts']['unknown'])),
        ('Respuestas 4xx', f'{result.get("http4", 0):,} ({pct(result.get("http4", 0))})'),
        ('Respuestas 5xx', f'{result.get("http5", 0):,} ({pct(result.get("http5", 0))})'),
        ('Rutas sensibles / con respuesta 4xx', f'{result.get("sensitive", 0)} / {result.get("sensitive4", 0)}'),
        ('Pico de peticiones/minuto', result.get('peak', 0)),
        ('Actividad orientativa por volumen del pico', activity_level(result.get('peak', 0)) if total else 'N/D'),
        ('Minuto del pico', result.get('peak_minute') or 'N/D'),
        ('IP coincidentes con eventos Ban del día', result.get('f2b_matches') if result.get('f2b_matches') is not None else 'N/D'),
        ('Fuente de accesos', result.get('layer', 'N/D')),
        ('Fechas encontradas en los logs', f'{result.get("earliest")} a {result.get("latest")}'),
    ]
    output = '<section><h2>' + esc(domain) + '</h2>' + html_table(('Métrica', 'Resultado'), metrics)
    findings = signals(result)
    output += '<h3>Indicadores para revisar</h3><ul>' + ''.join('<li>' + esc(f) + '</li>' for f in findings) + '</ul>'
    if not findings:
        output += '<p>Sin umbrales activados en los datos leídos; no descarta un ataque.</p>'
    for title, key in [('URLs con más peticiones', 'urls'), ('URLs con más bytes de respuesta', 'bytes_urls'),
                       ('Errores HTTP por ruta', 'errors'), ('Rutas sensibles consultadas', 'sensitive_urls'),
                       ('IP con más peticiones', 'ip_counts'), ('Mensajes internos por categoría', 'internal'),
                       ('Códigos HTTP', 'statuses')]:
        values = result.get(key, collections.Counter())
        output += '<h3>' + esc(title) + '</h3>'
        output += html_table(('Ruta / IP / categoría', 'Valor'), values.most_common(20))
    output += '<h3>Avisos de lectura</h3><ul>' + ''.join('<li>' + esc(note) + '</li>' for note in sorted(result['notes'])) + '</ul></section>'
    return output


def create_report_file(day, base=None):
    base = base or os.path.dirname(os.path.abspath(__file__))
    parent = directory(base)
    try:
        try:
            os.mkdir('reports', 0o700, dir_fd=parent)
        except FileExistsError:
            pass
        folder = directory('reports', parent)
    finally:
        os.close(parent)
    try:
        info = os.fstat(folder)
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise ValueError('reports debe pertenecer al usuario actual y tener permisos 700.')
        name = f'audithor-{day}-{secrets.token_hex(6)}.html'
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=folder)
    finally:
        os.close(folder)
    return os.fdopen(fd, 'w', encoding='utf-8', newline='\n'), os.path.join(base, 'reports', name)


class HtmlAudit:
    """Un único HTML por ejecución, escrito dominio a dominio y con tamaño acotado."""
    MAX_BYTES = 2 * 1024 * 1024

    def __init__(self, args, total):
        self.args = args
        self.total = total
        self.written = 0
        self.domains = 0
        self.truncated = False
        self.finished = False
        self.stream, self.path = create_report_file(args.day)
        self.write('''<!doctype html><html lang="es"><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>Audithor · auditoría de tráfico</title>
<style>body{font:16px/1.6 system-ui,sans-serif;max-width:1050px;margin:auto;padding:24px;background:#f1f5f9;color:#172033}section{background:white;padding:24px;margin:24px 0;border:1px solid #cbd5e1;border-radius:10px}table{width:100%;border-collapse:collapse;overflow-wrap:anywhere}th,td{text-align:left;padding:10px;border-bottom:1px solid #ddd}th{background:#e2e8f0}h1,h2,h3{line-height:1.3}small{color:#475569}</style><body>
<h1>Audithor · auditoría de tráfico</h1><p>Creado por steev anderson.</p>''')
        self.write('<p>Fecha analizada: ' + html.escape(str(args.day)) + ' · Zona: ' + html.escape(args.timezone) +
                   f' · Dominios seleccionados: {total} · Versión: {VERSION}</p>')
        self.write('<p>Informe de logs disponibles. Una petición puede ser una página, imagen, CSS o API; no equivale a una persona. '
                   'Transferencia es el tamaño de respuestas registrado; 4xx son rechazos/no encontrados y 5xx errores del servidor. '
                   'Los porcentajes usan las peticiones leídas de la fecha. Bots y humanos son estimaciones. '
                   'Un pico no confirma un ataque. Actividad: baja &lt;60/min, moderada 60–599, alta 600–2999, muy alta &gt;=3000; no compara con el historial de cada web. RAM/CPU históricas por dominio no están disponibles. '
                   'Rankings limitados a 2000 valores; se muestran los 20 primeros. Retención, rotación y formatos pueden limitar la cobertura.</p>')
        if args.sample:
            self.write('<p><strong>MODO MUESTRA: cada dominio puede contener solo parte de sus registros.</strong></p>')
        bans = getattr(args, 'bans', None)
        if bans:
            figures = ('Eventos Ban observados: ' + str(bans['events']) + ' · IP únicas observadas: ' + str(len(bans['ips']))) if bans['day_seen'] else 'N/D: no se leyeron mensajes para esta fecha'
            self.write('<h2>Fail2Ban · servidor</h2><p>' + figures +
                       '. No indica bloqueos actualmente activos ni qué dominio los originó. '
                       'Fechas locales de Fail2Ban sin offset; se presupone la zona elegida.</p>')
            self.write(html_table(('Jail', 'Eventos observados'), bans['jails'].most_common(20)))
            self.write('<ul>' + ''.join('<li>' + html.escape(clean(n, 500)) + '</li>' for n in sorted(bans['notes'])) + '</ul>')

    def write(self, text, closing=False):
        size = len(text.encode('utf-8'))
        reserve = 0 if closing else 64 * 1024
        if self.written + size > self.MAX_BYTES - reserve:
            self.truncated = True
            return False
        self.stream.write(text)
        self.stream.flush()
        self.written += size
        return True

    def append(self, domain, result):
        if self.write(html_section(domain, result, self.args)):
            self.domains += 1

    def finish(self, rows):
        complete = len(rows) == self.total and self.domains == self.total and not self.truncated
        status = 'Recorrido terminado' if complete else 'INFORME PARCIAL: recorrido interrumpido o límite de tamaño alcanzado'
        footer = '<section><h2>Resumen final · ' + status + '</h2><p>' + str(len(rows)) + '/' + str(self.total) + ' dominios consultados.</p>'
        footer += '<p>Orden orientativo de revisión: número de umbrales, rutas sensibles con 4xx, errores 5xx/4xx y tráfico. No mide ataques ni daños.</p>'
        footer += html_table(('Dominio', 'Umbrales', '4xx', '5xx'), [
            (domain, str(len(signals(result))) if result['total'] else 'Sin accesos de la fecha',
             result.get('http4', 0), result.get('http5', 0)) for domain, result in sorted(rows, key=review_key)[:100]])
        footer += '<p>Se muestran hasta 100 dominios en este resumen.</p></section></body></html>'
        self.write(footer, closing=True)
        self.stream.close()
        self.finished = True
        return complete and not self.truncated

    def close(self):
        if not self.finished:
            self.write('<p>INFORME INTERRUMPIDO. No se ha completado la auditoría.</p></body></html>', closing=True)
            self.stream.close()
            self.finished = True


def send_audit(path, day):
    """Solo se llama con --send. No instala/configura el MTA ni usa una shell."""
    mailer = '/usr/sbin/sendmail'
    if not os.path.isfile(mailer) or not os.access(mailer, os.X_OK):
        raise RuntimeError('No existe /usr/sbin/sendmail operativo. HTML guardado; no se ha instalado ni configurado correo.')
    parent = directory(os.path.dirname(path))
    try:
        with regular(parent, os.path.basename(path)) as stream:
            payload = stream.read(HtmlAudit.MAX_BYTES + 1)
    finally:
        os.close(parent)
    if len(payload) > HtmlAudit.MAX_BYTES:
        raise ValueError('El HTML supera el límite de 2 MiB para correo.')
    message = EmailMessage(policy=SMTP)
    message['From'] = MAIL_TO
    message['To'] = MAIL_TO
    message['Subject'] = f'Audithor · auditoría de tráfico · {day}'
    message.set_content('Adjunto el informe HTML de los logs disponibles. Las señales son orientativas; revisa los avisos de cobertura.')
    message.add_attachment(payload, maintype='text', subtype='html', filename=os.path.basename(path))
    try:
        result = subprocess.run([mailer, '-oi', '-t'], input=message.as_bytes(),
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                timeout=20, check=False, env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C'})
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError('No se confirmó la aceptación del correo; no se reintentó. El HTML sigue guardado.') from exc
    if result.returncode:
        raise RuntimeError(f'El correo local devolvió código {result.returncode}. El HTML sigue guardado.')
    print(f'Correo aceptado por el servicio local para {MAIL_TO}; esto no confirma su entrega final.', flush=True)


def finish_audit(args, rows):
    if not getattr(args, 'audit', None):
        return
    complete = args.audit.finish(rows)
    print('\nHTML privado guardado en: ' + args.audit.path, flush=True)
    if args.send:
        if complete:
            send_audit(args.audit.path, args.day)
        else:
            print('No envío correo: el informe quedó interrumpido o alcanzó el límite de tamaño.')


def collect_ranked(root, domains, day, zone, args):
    rows = []
    print('\nMostraré cada dominio al terminar su lectura y un resumen ordenado al final.', flush=True)
    for number, domain in enumerate(domains, 1):
        try:
            if number > 1 and (number - 1) % PAGE_SIZE == 0 and not next_batch(args):
                break
            if getattr(args, 'sample', False):
                reason = pressure(args.gentle)
                if reason:
                    print(f'\nRecorrido incompleto: {reason}', flush=True)
                    break
            else:
                wait_for_capacity(args.gentle)
            print(f'  [{number}/{len(domains)}] Leyendo {domain}…', flush=True)
            result = analyze(root, domain, day, zone, args)
            if getattr(args, 'audit', None):
                args.audit.append(domain, result)
            summary = compact_summary(result)
            rows.append((domain, summary))
            show(domain, day, summary)
            sys.stdout.flush()
            del result
        except KeyboardInterrupt:
            print('\nLectura interrumpida: mostraré el resumen de los dominios ya terminados.', flush=True)
            break
    rows.sort(key=review_key)
    print('\n' + '=' * 80)
    print(f' RESUMEN FINAL · PRIORIDAD DE REVISIÓN · {len(rows)}/{len(domains)} dominios')
    print('=' * 80)
    print('Orden: más umbrales activados; después rutas sensibles con 4xx, 5xx y 4xx.')
    print('El tráfico desempata. Sin accesos de la fecha: al final, sin valoración.')
    print('No es una medición de ataques: incluye errores y accesos legítimos.')
    print('Las lecturas parciales/avisos pueden alterar este orden.')
    if len(rows) < len(domains):
        print(f'{len(domains) - len(rows)} dominios pendientes; no están incluidos en el ranking.')
    return rows


def arguments(argv=None):
    parser = argparse.ArgumentParser(description='Audithor — steev anderson. Informes progresivos y resumen final de revisión.')
    parser.add_argument('--version', action='version', version='Audithor ' + VERSION)
    parser.add_argument('domain', nargs='?', help='Dominio exacto para informe detallado')
    dates = parser.add_mutually_exclusive_group()
    dates.add_argument('--yesterday', action='store_true', help='Ayer en la zona horaria elegida')
    dates.add_argument('--date', help='Fecha YYYY-MM-DD; solo si quedan logs')
    parser.add_argument('--timezone', default='Europe/Madrid')
    parser.add_argument('--root', default='/var/www/vhosts/system', help='Raíz de logs Plesk; no se modifica')
    parser.add_argument('--gzip', action='store_true', help='Incluir históricos comprimidos dentro del mismo presupuesto')
    parser.add_argument('--no-fail2ban', action='store_true', help='Omitir lectura del historial Fail2Ban')
    parser.add_argument('--fail2ban-log', default='/var/log/fail2ban.log', help='Archivo de historial Fail2Ban, sin modificarlo')
    parser.add_argument('--report', action='store_true', help='Auditar todos y guardar un HTML detallado privado, sin correo')
    parser.add_argument('--send', action='store_true', help='Auditar todos, guardar HTML y solicitar envío al correo configurado')
    parser.add_argument('--seconds', type=int, default=30, help='Segundos por tanda; límite total por dominio solo con --sample (1–1800)')
    parser.add_argument('--max-mib', type=int, default=64, help='MiB descomprimidos por tanda; límite total solo con --sample (1–1024)')
    parser.add_argument('--once', action='store_true', help='Analizar únicamente la primera tanda de cinco dominios')
    parser.add_argument('--diagnose', action='store_true', help='Mostrar carga, CPU lógicas y memoria; sin analizar dominios')
    parser.add_argument('--gentle', action='store_true', help='Modo lento: pausa 10 ms/línea, umbral de carga 1 por CPU lógica')
    parser.add_argument('--sample', action='store_true', help='Solo muestra acotada por dominio; sin esta opción continúa hasta acabar')
    args = parser.parse_args(argv)
    if args.report or args.send:
        args.gentle = True
    if args.domain and not DOMAIN.fullmatch(args.domain):
        parser.error('Dominio no válido. Usa su nombre ASCII exacto, sin URL ni rutas.')
    if not 1 <= args.seconds <= 1800 or not 1 <= args.max_mib <= 1024:
        parser.error('Límites fuera de rango.')
    try:
        args.zone = ZoneInfo(args.timezone)
        today = dt.datetime.now(args.zone).date()
        if args.date and not re.fullmatch(r'\d{4}-\d{2}-\d{2}', args.date):
            parser.error('La fecha debe tener formato YYYY-MM-DD.')
        args.day = dt.date.fromisoformat(args.date) if args.date else today - dt.timedelta(days=int(args.yesterday))
        if args.day > today:
            parser.error('No se pueden analizar fechas futuras.')
        args.historical = args.day < today
        # --yesterday debe buscar automáticamente en los históricos comprimidos.
        args.gzip = args.gzip or args.historical
    except (ValueError, ZoneInfoNotFoundError):
        parser.error('Fecha o zona horaria no válida. Comprueba los datos tzdata del sistema.')
    return args


def main(argv=None):
    args = arguments(argv)
    if args.diagnose:
        cpus, loads, available = status = host_status()
        print(BANNER)
        print(f'CPU lógicas detectadas: {cpus}')
        print('Carga media 1/5/15 min: ' + ' / '.join(f'{load:.2f}' for load in loads))
        factor = LOAD_PER_CPU
        print(f'Umbral de Audithor: {cpus * factor:.2f} ({factor:g} por CPU lógica)')
        print(f'MemAvailable: {available:.0f} MiB; mínimo: 256 MiB')
        print('La carga media NO es un porcentaje de CPU; puede incluir espera de disco.')
        print(pressure_reason(status, args.gentle) or 'Las guardas actuales permiten iniciar el análisis.')
        print('Diagnóstico de solo lectura; no se han abierto logs de dominios.')
        return 0
    # Cambia únicamente la prioridad y los límites de ESTE proceso.
    try:
        os.nice(19)
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_AS)
        cap = min(128 * 1024 * 1024, hard) if hard != resource.RLIM_INFINITY else 128 * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (min(soft, cap) if soft != resource.RLIM_INFINITY else cap, hard))
    except (AttributeError, ImportError, OSError, ValueError) as exc:
        raise RuntimeError('No se pudieron aplicar los límites locales: ' + str(exc))
    print(BANNER)
    print('Audithor ' + VERSION)
    print(f'Fecha: {args.day} ({args.timezone}). Secuencial; memoria virtual máxima 128 MiB.')
    print(f'Tandas de {args.seconds}s/{args.max_mib} MiB. ' + ('MUESTRA limitada por dominio.' if args.sample else 'LECTURA CONTINUA: descansa y continúa hasta finalizar los archivos seleccionados.'))
    print('Logs en solo lectura. Sin instalaciones, cron ni cambios en Plesk, servicios o permisos de las webs.')
    if args.report or args.send:
        print('Modo auditoría: todos los dominios seleccionados, sin esperar start; HTML privado en reports/.')
    if args.send:
        print('Correo solicitado a ' + MAIL_TO + ' usando únicamente /usr/sbin/sendmail ya instalado.')
        if not os.path.isfile('/usr/sbin/sendmail') or not os.access('/usr/sbin/sendmail', os.X_OK):
            print('AVISO: no se detecta correo local operativo; el HTML se guardará, pero el envío no podrá realizarse.')
    print('Bots y humanos son estimaciones. Las señales no confirman ataques.')
    if args.historical:
        print('Fecha histórica: gzip incluido automáticamente; prioridad a logs rotados.')
    if args.gentle:
        print('Modo lento: pausa de 10 ms por línea/fragmento (aprox. máximo 100/s); umbral 1 por CPU lógica.')
    if args.sample:
        reason = pressure(args.gentle)
        if reason:
            raise RuntimeError(reason)
    else:
        wait_for_capacity(args.gentle)
    root = directory(args.root)
    args.audit = None
    try:
        domains = [args.domain] if args.domain else discover(root)
        if not domains:
            print('No se encontraron dominios accesibles.')
            return 0
        args.bans = None
        if args.domain or args.report or args.send:
            print('\nLeyendo historial Fail2Ban…', flush=True)
            args.bans = read_fail2ban(args)
            if args.domain:
                show_fail2ban(args.bans, args.day)
        if args.report or args.send:
            args.audit = HtmlAudit(args, len(domains))
            print('Creando informe privado: ' + args.audit.path, flush=True)
        if args.domain:
            print('\nLeyendo ' + args.domain + '…', flush=True)
            result = analyze(root, args.domain, args.day, args.zone, args)
            show(args.domain, args.day, result, True)
            if args.audit:
                args.audit.append(args.domain, result)
                finish_audit(args, [(args.domain, compact_summary(result))])
            return 0
        rows = collect_ranked(root, domains, args.day, args.zone, args)
        finish_audit(args, rows)
        for offset in range(0, len(rows), PAGE_SIZE):
            show_review_page(rows[offset:offset+PAGE_SIZE], offset+1)
            if offset + PAGE_SIZE >= len(rows) or args.once or args.report or args.send or not sys.stdin.isatty():
                break
            if input(f'\nEnter: siguientes {PAGE_SIZE} | q + Enter: salir > ').strip().lower() in ('q', 'salir'):
                break
    finally:
        if args.audit:
            args.audit.close()
        os.close(root)
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (KeyboardInterrupt, EOFError):
        print('\nAudithor detenido; no se ha modificado el servidor.')
        sys.exit(130)
    except (OSError, RuntimeError, ValueError, MemoryError) as error:
        print('Audithor: ' + clean(str(error)), file=sys.stderr)
        sys.exit(1)
