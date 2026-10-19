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
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

BANNER = r"""+    _   _   _ ____ ___ _____ _   _  ___  ____
   / \ | | | |  _ \_ _|_   _| | | |/ _ \|  _ \
  / _ \| | | | | | | |  | | | |_| | | | | |_) |
 / ___ \ |_| | |_| | |  | | |  _  | |_| |  _ <
/_/   \_\___/|____/___| |_| |_| |_|\___/|_| \_\
                    steev anderson
"""
DOMAIN = re.compile(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
ACCESS = re.compile(rb'^(\S+) \S+ \S+ \[([^\]]+)\] "([A-Z]+) ([^" ]+) HTTP/[0-9.]+" ([1-5][0-9]{2}) (\d+|-) "(?:[^"\\]|\\.)*" "((?:[^"\\]|\\.)*)"')
MONTHS = {m: i+1 for i, m in enumerate(('Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'))}
STAMP = re.compile(r'^(\d{2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-])(\d{2})(\d{2})$')
BOT = re.compile(r'bot|crawler|spider|slurp|bingpreview', re.I)
AUTO = re.compile(r'curl|wget|python|sqlmap|nikto|go-http-client|headless|selenium', re.I)
BROWSER = re.compile(r'Mozilla/5\.0.*(?:Firefox/|Chrome/|Safari/|Edg/)', re.I)
SENSITIVE = re.compile(r'(?:^|/)(?:\.env|\.git|wp-login\.php|xmlrpc\.php|phpmyadmin)(?:[/.]|$)', re.I)


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
        return stamp.date(), path, int(m[5]), int(m[6]) if m[6] != b'-' else 0, kind
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


def sources(fd, compressed):
    entries = names(fd, 4096)
    def matching(prefix):
        return [n for n in entries if any(re.fullmatch(re.escape(p) + r'(?:\.processed)?(?:\.\d+)?(?:\.gz)?', n) for p in prefix)]
    # Solo una capa; sumar nginx y Apache duplicaría peticiones.
    proxy = matching(('proxy_access_log', 'proxy_access_ssl_log'))
    selected = proxy or matching(('access_log', 'access_ssl_log'))
    if len(selected) > 128:
        raise RuntimeError('Más de 128 logs por dominio; selecciona/revisa los históricos fuera de Audithor.')
    skipped = sum(n.endswith('.gz') for n in selected) if not compressed else 0
    selected = [n for n in selected if compressed or not n.endswith('.gz')]
    return sorted(selected), skipped, 'nginx' if proxy else 'apache'


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
    def __init__(self, seconds, mib):
        self.end = time.monotonic() + seconds
        self.maximum = mib * 1024 * 1024
        self.read = 0
        self.steps = 0
        self.pressure = None

    def exhausted(self):
        if self.steps % 250 == 0:
            self.pressure = pressure()
        if self.pressure:
            return True
        return self.read >= self.maximum or time.monotonic() >= self.end

    def tick(self, size):
        self.read += size
        self.steps += 1
        # Aproximadamente <= 1000 líneas/s; nada de procesos paralelos.
        time.sleep(.001)


def host_status():
    with open('/proc/meminfo', 'r', encoding='ascii') as stream:
        info = stream.read(8192)
    available = re.search(r'^MemAvailable:\s+(\d+) kB$', info, re.M)
    if not available:
        raise ValueError('MemAvailable no está disponible.')
    return max(1, os.cpu_count() or 1), os.getloadavg(), int(available[1]) / 1024


def pressure_reason(status):
    cpus, loads, available = status
    limit = cpus * .8
    if loads[0] > limit:
        return (f'Carga media 1 min: {loads[0]:.2f}; umbral: {limit:.2f} '
                f'({cpus} CPU lógicas × 0,8). Análisis aplazado. Usa --diagnose para ver el estado.')
    if available < 256:
        return f'Memoria disponible: {available:.0f} MiB; mínimo: 256 MiB. Análisis aplazado.'
    return None


def pressure():
    """Guardas aproximadas del host; no son métricas por dominio."""
    try:
        return pressure_reason(host_status())
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


def increment(table, key, value=1):
    if key not in table and len(table) >= 2000:
        key = '[otras rutas: límite de memoria]'
    table[key] += value


def error_event(line):
    """Solo fecha y categoría; nunca imprimir mensajes internos ni secretos."""
    text = line.decode('utf-8', 'replace')
    nginx = re.match(r'^(\d{4})/(\d{2})/(\d{2}) ', text)
    apache = re.match(r'^\[[A-Za-z]{3} ([A-Za-z]{3}) (\d{1,2}) [0-9:.]+ (\d{4})\]', text)
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


def analyze(root, domain, day, zone, args):
    state = dict(inodes=set(), notes=set(), counts=collections.Counter(), urls=collections.Counter(),
                 bytes_urls=collections.Counter(), errors=collections.Counter(), statuses=collections.Counter(),
                 internal=collections.Counter(),
                 total=0, bytes=0, invalid=0, earliest=None, latest=None)
    budget = Budget(args.seconds, args.max_mib)
    try:
        fd = directory(domain + '/logs', root)
    except OSError as exc:
        state['notes'].add('No se puede abrir logs: ' + clean(exc.strerror))
        return state
    try:
        files, skipped, layer = sources(fd, args.gzip)
        state['layer'] = layer
        if skipped:
            state['notes'].add(f'{skipped} archivos gzip omitidos; usa --gzip para incluirlos.')
        if not files:
            state['notes'].add('No hay logs de acceso legibles seleccionados.')
        # Más reciente primero: útil para hoy con presupuesto acotado.
        files.sort(key=lambda n: os.stat(n, dir_fd=fd, follow_symlinks=False).st_mtime, reverse=True)
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
                    date, path, status, size, kind = event
                    state['earliest'] = min(date, state['earliest'] or date)
                    state['latest'] = max(date, state['latest'] or date)
                    if date != day:
                        continue
                    state['total'] += 1
                    state['bytes'] += size
                    state['counts'][kind] += 1
                    state['statuses'][status] += 1
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
    if state['invalid']:
        state['notes'].add(f"{state['invalid']} líneas no interpretadas; cobertura parcial.")
    return state


def show(domain, day, result, detail=False):
    total = result['total']
    pct = lambda k: f"{100 * result['counts'][k] / total:.1f}%" if total else 'N/D'
    print(f'\n{domain} | {day} | {total:,} peticiones observadas | {result["bytes"]/1048576:.2f} MiB enviados')
    print(f'  Bots/automatización probable: {pct("bot")} | humano probable: {pct("probable")} | desconocido: {pct("unknown")}')
    print('  IP bloqueadas del día: N/D | RAM diaria: N/D | CPU diaria: N/D')
    if not total:
        print('  Sin peticiones observadas para esta fecha; NO confirma ausencia de tráfico.')
    if result['earliest']:
        print(f'  Fechas observadas en la lectura: {result["earliest"]} a {result["latest"]}.')
    print('  Cobertura del día no garantizada: depende de retención, formato y rotación de logs.')
    for note in sorted(result['notes']):
        print('  AVISO: ' + note)
    if detail:
        for title, key, unit in [('URLs con más peticiones', 'urls', 'peticiones'),
                                 ('URLs con más transferencia (no equivale a CPU)', 'bytes_urls', 'bytes'),
                                 ('Errores HTTP 4xx/5xx por URL', 'errors', 'peticiones')]:
            print('\n  ' + title)
            for path, count in result[key].most_common(10):
                print(f'    {count:>12,} {unit}  {clean(path, 200)}')
            if not result[key]:
                print('    Sin datos observados.')
        print('\n  Mensajes internos PHP/nginx/Apache (fecha local escrita en el log)')
        for category, count in result['internal'].most_common():
            print(f'    {count:>12,}  {category}')
        if not result['internal']:
            print('    Sin mensajes interpretados para la fecha; revisa los avisos de cobertura.')


def arguments(argv=None):
    parser = argparse.ArgumentParser(description='Audithor — steev anderson. Logs Plesk, solo lectura, tres dominios por tanda.')
    parser.add_argument('domain', nargs='?', help='Dominio exacto para informe detallado')
    dates = parser.add_mutually_exclusive_group()
    dates.add_argument('--yesterday', action='store_true', help='Ayer en la zona horaria elegida')
    dates.add_argument('--date', help='Fecha YYYY-MM-DD; solo si quedan logs')
    parser.add_argument('--timezone', default='Europe/Madrid')
    parser.add_argument('--root', default='/var/www/vhosts/system', help='Raíz de logs Plesk; no se modifica')
    parser.add_argument('--gzip', action='store_true', help='Incluir históricos comprimidos dentro del mismo presupuesto')
    parser.add_argument('--seconds', type=int, default=30, help='Tiempo máximo por dominio (1–1800, defecto 30)')
    parser.add_argument('--max-mib', type=int, default=64, help='Lectura máxima descomprimida por dominio (1–1024, defecto 64)')
    parser.add_argument('--once', action='store_true', help='Solo tres dominios, sin esperar Enter')
    parser.add_argument('--diagnose', action='store_true', help='Mostrar carga, CPU lógicas y memoria; sin analizar dominios')
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
        print(f'Umbral conservador de Audithor: {cpus * .8:.2f} (0,8 por CPU lógica)')
        print(f'MemAvailable: {available:.0f} MiB; mínimo: 256 MiB')
        print('La carga media NO es un porcentaje de CPU; puede incluir espera de disco.')
        print(pressure_reason(status) or 'Las guardas actuales permiten iniciar el análisis.')
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
    print('Bots y humanos son estimaciones; no hay registros históricos de CPU/RAM ni atribución de bloqueos.')
    reason = pressure()
    if reason:
        raise RuntimeError(reason)
    root = directory(args.root)
    try:
        domains = [args.domain] if args.domain else discover(root)
        if not domains:
            print('No se encontraron dominios accesibles.')
        for offset in range(0, len(domains), 3):
            for domain in domains[offset:offset+3]:
                print('\nLeyendo ' + domain + '…', flush=True)
                show(domain, args.day, analyze(root, domain, args.day, args.zone, args), bool(args.domain))
            if offset + 3 >= len(domains) or args.once or not sys.stdin.isatty():
                break
            if input('\nEnter: siguientes 3 | q + Enter: salir > ').strip().lower() in ('q', 'salir'):
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
