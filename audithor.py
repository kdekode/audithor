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


class Budget:
    def __init__(self, seconds, mib, gentle=False):
        self.end = time.monotonic() + seconds
        self.maximum = mib * 1024 * 1024
        self.read = 0
        self.steps = 0
        self.pressure = None
        self.gentle = gentle

    def exhausted(self):
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
                cap = min(16384, remaining, budget.maximum - budget.read)
                line = stream.readline(cap)
                if not line:
                    break
                budget.tick(len(line))
                if not line.endswith(b'\n'):
                    state['notes'].add('Línea larga/incompleta o límite de lectura; cobertura parcial.')
                    # No analizar fragmentos como si fuesen peticiones completas.
                    while line and not line.endswith(b'\n') and not budget.exhausted():
                        cap = min(16384, budget.maximum - budget.read)
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
    if result.get('sensitive', 0) >= 20:
        findings.append('Accesos a rutas sensibles: ' + str(result['sensitive']))
    if total >= 100 and result.get('http4', 0) / total >= .5:
        findings.append('Al menos 50% de respuestas 4xx')
    if total >= 20 and result.get('http5', 0) / total >= .1:
        findings.append('Al menos 10% de respuestas 5xx')
    if result.get('peak', 0) >= 300:
        findings.append('Pico observado de al menos 300 peticiones/minuto')
    return findings


def analyze(root, domain, day, zone, args):
    state = dict(inodes=set(), notes=set(), counts=collections.Counter(), urls=collections.Counter(),
                 bytes_urls=collections.Counter(), errors=collections.Counter(), statuses=collections.Counter(),
                 internal=collections.Counter(),
                 ip_counts=collections.Counter(), minutes=collections.Counter(), sensitive_urls=collections.Counter(),
                 f2b_seen=set(), sensitive=0, http4=0, http5=0, peak=0,
                 total=0, bytes=0, invalid=0, earliest=None, latest=None)
    bans = getattr(args, 'bans', None)
    state['f2b_matches'] = 0 if bans and bans['day_seen'] else None
    budget = Budget(args.seconds, args.max_mib, args.gentle)
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
                    # Un día tiene <=1500 minutos con cambio horario; límite defensivo.
                    if minute in state['minutes'] or len(state['minutes']) < 1600:
                        state['minutes'][minute] += 1
                        state['peak'] = max(state['peak'], state['minutes'][minute])
                    if bans and ip in bans['ips']:
                        state['f2b_seen'].add(ip)
                    if args.domain:
                        increment(state['ip_counts'], ip, overflow='[otras IP: límite de memoria]')
                        if probe:
                            increment(state['sensitive_urls'], path)
                    if args.domain:
                        increment(state['urls'], path)
                        increment(state['bytes_urls'], path, size)
                        if status >= 400:
                            increment(state['errors'], str(status) + ' ' + path)
            except (OSError, EOFError, ValueError, zlib.error) as exc:
                state['notes'].add('No se pudo completar ' + clean(name) + ': ' + clean(str(exc)))
        if args.domain:
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
    count_pct = lambda n: f'{n:,} / {100*n/total:.1f}%' if total else 'N/D'
    f2b = result.get('f2b_matches')
    print('\n' + '=' * 80)
    print(' ' + domain)
    print(f' Fecha: {day}   |   Datos observados, cobertura del día no garantizada')
    if result.get('layer'):
        print(' Fuente de accesos: ' + result['layer'].upper() + ' (una sola capa)')
    print('=' * 80 + '\n')
    table(('TRÁFICO', 'VALOR', 'SEÑALES', 'VALOR'), [
        ('Peticiones', f'{total:,}' if known else 'N/D', 'HTTP 4xx', count_pct(result.get('http4', 0))),
        ('Transferencia', f'{result["bytes"]/1048576:.2f} MiB' if known else 'N/D', 'HTTP 5xx', count_pct(result.get('http5', 0))),
        ('Bots/automatización', pct('bot'), 'Rutas sensibles', f'{result.get("sensitive", 0):,}' if known else 'N/D'),
        ('Humano probable', pct('probable'), 'Pico peticiones/min', f'{result.get("peak", 0):,}' if known else 'N/D'),
        ('Desconocido', pct('unknown'), 'IP coincidentes F2B', f'{f2b:,}' if f2b is not None else 'N/D'),
    ], (22, 14, 22, 14))
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
    for key in ('http4', 'http5', 'sensitive', 'peak'):
        summary[key] = result.get(key, 0)
    summary['f2b_matches'] = result.get('f2b_matches')
    summary['counts'] = collections.Counter({key: result['counts'][key] for key in ('bot', 'probable', 'unknown')})
    notes = sorted(result['notes'])
    summary['notes'] = [clean(note, 240) for note in notes[:8]]
    if len(notes) > 8:
        summary['notes'].append(f'{len(notes) - 8} avisos adicionales omitidos del resumen.')
    return summary


def collect_ranked(root, domains, day, zone, args):
    rows = []
    print('\nPreparando ranking global: se leerán los dominios uno a uno antes de mostrar las tandas.', flush=True)
    for number, domain in enumerate(domains, 1):
        reason = pressure(args.gentle)
        if reason:
            print(f'\nRanking incompleto: {reason}', flush=True)
            break
        print(f'  [{number}/{len(domains)}] Leyendo {domain}…', flush=True)
        result = analyze(root, domain, day, zone, args)
        rows.append((domain, compact_summary(result)))
        del result
    # Peticiones descendentes; bytes desempatan, nombre estabiliza el orden.
    # La falta de lectura se coloca al final, sin confundirla con tráfico cero.
    rows.sort(key=lambda row: (not bool(row[1]['read']), -row[1]['total'], -row[1]['bytes'], row[0]))
    print(f'\nRanking por peticiones OBSERVADAS: {len(rows)}/{len(domains)} dominios consultados.')
    print('No mide CPU/RAM. Lecturas parciales o históricos ausentes pueden alterar el orden real.')
    if len(rows) < len(domains):
        print(f'{len(domains) - len(rows)} dominios pendientes; no están incluidos en el ranking.')
    return rows


def arguments(argv=None):
    parser = argparse.ArgumentParser(description='Audithor — steev anderson. Logs Plesk, solo lectura, cinco dominios por tanda.')
    parser.add_argument('domain', nargs='?', help='Dominio exacto para informe detallado')
    dates = parser.add_mutually_exclusive_group()
    dates.add_argument('--yesterday', action='store_true', help='Ayer en la zona horaria elegida')
    dates.add_argument('--date', help='Fecha YYYY-MM-DD; solo si quedan logs')
    parser.add_argument('--timezone', default='Europe/Madrid')
    parser.add_argument('--root', default='/var/www/vhosts/system', help='Raíz de logs Plesk; no se modifica')
    parser.add_argument('--gzip', action='store_true', help='Incluir históricos comprimidos dentro del mismo presupuesto')
    parser.add_argument('--no-fail2ban', action='store_true', help='Omitir lectura del historial Fail2Ban')
    parser.add_argument('--fail2ban-log', default='/var/log/fail2ban.log', help='Archivo de historial Fail2Ban, sin modificarlo')
    parser.add_argument('--seconds', type=int, default=30, help='Tiempo máximo por dominio (1–1800, defecto 30)')
    parser.add_argument('--max-mib', type=int, default=64, help='Lectura máxima descomprimida por dominio (1–1024, defecto 64)')
    parser.add_argument('--once', action='store_true', help='Mostrar solo el top 5; la vista global analiza antes todos los dominios')
    parser.add_argument('--diagnose', action='store_true', help='Mostrar carga, CPU lógicas y memoria; sin analizar dominios')
    parser.add_argument('--gentle', action='store_true', help='Modo lento: pausa 10 ms/línea, umbral de carga 1 por CPU lógica')
    args = parser.parse_args(argv)
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
    print(f'Fecha: {args.day} ({args.timezone}). Secuencial; {args.seconds}s/{args.max_mib} MiB por dominio; memoria virtual máxima 128 MiB.')
    print('Solo lectura. Sin instalaciones, cron, procesos externos, conexiones de red ni cambios de permisos.')
    print('Bots y humanos son estimaciones. Las señales no confirman ataques.')
    if args.historical:
        print('Fecha histórica: gzip incluido automáticamente; prioridad a logs rotados.')
    if args.gentle:
        print('Modo lento: pausa de 10 ms por línea/fragmento (aprox. máximo 100/s); umbral 1 por CPU lógica.')
    reason = pressure(args.gentle)
    if reason:
        raise RuntimeError(reason)
    root = directory(args.root)
    try:
        domains = [args.domain] if args.domain else discover(root)
        if not domains:
            print('No se encontraron dominios accesibles.')
            return 0
        print('\nLeyendo historial Fail2Ban una sola vez…', flush=True)
        args.bans = read_fail2ban(args)
        show_fail2ban(args.bans, args.day)
        if args.domain:
            print('\nLeyendo ' + args.domain + '…', flush=True)
            show(args.domain, args.day, analyze(root, args.domain, args.day, args.zone, args), True)
            return 0
        rows = collect_ranked(root, domains, args.day, args.zone, args)
        for offset in range(0, len(rows), PAGE_SIZE):
            for position, (domain, summary) in enumerate(rows[offset:offset+PAGE_SIZE], offset+1):
                print(f'\nPuesto {position}')
                show(domain, args.day, summary)
            if offset + PAGE_SIZE >= len(rows) or args.once or not sys.stdin.isatty():
                break
            if input(f'\nEnter: siguientes {PAGE_SIZE} | q + Enter: salir > ').strip().lower() in ('q', 'salir'):
                break
    finally:
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
