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
import math
import textwrap
import hashlib
import io
import signal
import subprocess
import selectors
import types
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
PAGE_SIZE = 70
VERSION = '0.12.1'
ACCESS = re.compile(rb'^(\S+) \S+ \S+ \[([^\]]+)\] "([A-Z]+) ([^" ]+) HTTP/[0-9.]+" ([1-5][0-9]{2}) (\d+|-) "(?:[^"\\]|\\.)*" "((?:[^"\\]|\\.)*)"')
MONTHS = {m: i+1 for i, m in enumerate(('Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'))}
STAMP = re.compile(r'^(\d{2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-])(\d{2})(\d{2})$')
BOT = re.compile(r'bot|crawler|spider|slurp|bingpreview', re.I)
AUTO = re.compile(r'curl|wget|python|sqlmap|nikto|go-http-client|headless|selenium', re.I)
BROWSER = re.compile(r'Mozilla/5\.0.*(?:Firefox/|Chrome/|Safari/|Edg/)', re.I)
SENSITIVE = re.compile(r'(?:^|/)(?:\.env|\.git|wp-login\.php|xmlrpc\.php|phpmyadmin)(?:[/.]|$)', re.I)
EXPOSURE = re.compile(r'(?:^|/)(?:\.env(?:[./]|$)|\.git(?:/|$)|wp-config\.php(?:[.~]|$)|(?:backup|database)\.(?:sql|zip)(?:$|/))', re.I)
BAN = re.compile(r'^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[,.]\d+)?\s+fail2ban\.actions\s+(?:\[\d+\])?:?\s+[A-Z]+\s+\[([^\]]{1,120})\]\s+Ban\s+(\S+)\s*$')


def clean(value, limit=180):
    """No permitir controles de terminal ni cadenas ilimitadas procedentes de logs."""
    return ''.join(c if c.isprintable() else '?' for c in str(value))[:limit]


def safe_path(raw):
    path = unquote(raw).split('?', 1)[0].split('#', 1)[0]
    if not path.startswith('/'):
        return '[destino no relativo]'
    path = re.sub(r'[^/]*@[^/]+|(?<=/)[A-Za-z0-9_%=-]{32,}', ':redactado', path)
    path = re.sub(r'(?i)(/(?:token|password|passwd|secret|api[_-]?key|authorization|session|reset)(?:/|=))[^/]+',
                  r'\1:redactado', path)
    return clean(path, 180)


def parse_stamp(raw, zone):
    match = STAMP.fullmatch(raw.decode('ascii'))
    if not match:
        raise ValueError('Fecha de log no reconocida.')
    d, mon, y, h, minute, sec, sign, oh, om = match.groups()
    if int(oh) > 23 or int(om) > 59:
        raise ValueError('Offset no válido.')
    delta = dt.timedelta(hours=int(oh), minutes=int(om)) * (1 if sign == '+' else -1)
    return dt.datetime(int(y), MONTHS[mon], int(d), int(h), int(minute), int(sec),
                       tzinfo=dt.timezone(delta)).astimezone(zone)


def normalized_ip(value):
    address = ipaddress.ip_address(value)
    return str(getattr(address, 'ipv4_mapped', None) or address)


def parse(line, zone):
    m = ACCESS.match(line)
    if not m:
        return None
    try:
        ip = normalized_ip(m[1].decode('ascii'))
        stamp = parse_stamp(m[2], zone)
        path = safe_path(m[4].decode('utf-8', 'replace'))
        ua = m[7].decode('utf-8', 'replace')[:512]
        # "probable" se conserva como clave interna para compatibilidad; solo apariencia.
        kind = ('bot' if BOT.search(ua) or AUTO.search(ua) else
                'probable' if BROWSER.search(ua) else 'unknown')
        return (stamp.date(), path, int(m[5]), int(m[6]) if m[6] != b'-' else 0, kind,
                ip, stamp.strftime('%Y-%m-%d %H:%M %z'))
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
        stream = io.BufferedReader(MeteredRaw(fd), buffer_size=8192) if RUN_GUARD else os.fdopen(fd, 'rb', buffering=8192)
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


def wait_for_capacity(gentle=False, deadline=None):
    """Esperar conservando el estado en memoria; no aumentar los umbrales."""
    announced = False
    next_notice = 0
    while True:
        if deadline is not None and time.monotonic() >= deadline:
            raise TimeoutError('Espera por carga agotada; lectura parcial.')
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


class SafetyLimit(BaseException):
    """No debe ser absorbido por la recuperación normal de archivos/logs."""
    pass


RUN_GUARD = None


class RunGuard:
    """Linux: flock, RLIMIT_AS/CPU y temporizador real. Solo recursos propios."""
    def __init__(self, args, lock_path='/tmp/audithor.lock'):
        self.args = args
        self.lock_path = lock_path
        self.read = 0
        self.raw_read = 0
        self.maximum = args.run_mib * 1048576
        self.lock_fd = None
        self.old_handlers = {}

    def __enter__(self):
        global RUN_GUARD
        if not sys.platform.startswith('linux'):
            raise RuntimeError('La ejecución protegida de Audithor requiere Linux; no se inicia sin flock/RLIMIT/señales.')
        import fcntl
        import resource
        try:
            fd = os.open(self.lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
            self.lock_fd = fd
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) & 0o077:
                raise SafetyLimit('Bloqueo inseguro o de otro usuario en /tmp/audithor.lock; no se modifica.')
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise SafetyLimit('Ya hay otra ejecución de Audithor; no se ha iniciado el análisis.')
            os.nice(19)
            for kind, maximum in ((resource.RLIMIT_AS, 128 * 1048576),
                                  (resource.RLIMIT_CPU, math.ceil(time.process_time()) + self.args.cpu_seconds)):
                soft, hard = resource.getrlimit(kind)
                cap = min(maximum, hard) if hard != resource.RLIM_INFINITY else maximum
                if soft != resource.RLIM_INFINITY:
                    cap = min(cap, soft)
                if kind == resource.RLIMIT_CPU:
                    hard = min(cap + 1, hard) if hard != resource.RLIM_INFINITY else cap + 1
                resource.setrlimit(kind, (cap, hard))
            def stop(signum, frame):
                raise SafetyLimit('Límite efectivo de tiempo/CPU alcanzado; auditoría interrumpida y parcial.')
            for sig in (signal.SIGALRM, signal.SIGXCPU):
                self.old_handlers[sig] = signal.signal(sig, stop)
            signal.setitimer(signal.ITIMER_REAL, self.args.run_seconds)
            RUN_GUARD = self
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def debit(self, size, raw=False):
        key = 'raw_read' if raw else 'read'
        value = getattr(self, key) + size
        if value > self.maximum:
            raise SafetyLimit('Límite total de lectura alcanzado; no se continúa.')
        setattr(self, key, value)

    def allowance(self, requested, raw=False):
        left = self.maximum - (self.raw_read if raw else self.read)
        if left <= 0:
            raise SafetyLimit('Límite total de lectura alcanzado; auditoría parcial.')
        return min(requested, left)

    def __exit__(self, *unused):
        global RUN_GUARD
        if RUN_GUARD is self:
            RUN_GUARD = None
        if self.old_handlers:
            signal.setitimer(signal.ITIMER_REAL, 0)
            for sig, handler in self.old_handlers.items():
                signal.signal(sig, handler)
        if self.lock_fd is not None:
            os.close(self.lock_fd)
            self.lock_fd = None
        # No borrar el archivo: unlink permitiría dos bloqueos sobre inodes distintos.


class MeteredRaw(io.RawIOBase):
    """Limita también bytes comprimidos leídos, antes del buffer/gzip."""
    def __init__(self, fd):
        super().__init__()
        self.fd = fd

    def readable(self):
        return True

    def seekable(self):
        return True

    def fileno(self):
        return self.fd

    def tell(self):
        return os.lseek(self.fd, 0, os.SEEK_CUR)

    def seek(self, offset, whence=0):
        return os.lseek(self.fd, offset, whence)

    def readinto(self, target):
        cap = RUN_GUARD.allowance(len(target), raw=True) if RUN_GUARD else len(target)
        data = os.read(self.fd, cap)
        if RUN_GUARD:
            RUN_GUARD.debit(len(data), raw=True)
        target[:len(data)] = data
        return len(data)

    def close(self):
        if not self.closed:
            os.close(self.fd)
        super().close()


class UniqueIPs:
    """Exacto hasta 1024 direcciones; después HLL fijo de 2048 registros."""
    def __init__(self):
        self.exact = set()
        self.registers = bytearray(2048)
        self.salt = secrets.token_bytes(16)

    def add(self, ip):
        if self.exact is not None and ip in self.exact:
            return
        value = hashlib.blake2b(ip.encode('ascii'), digest_size=8, key=self.salt).digest()
        number = int.from_bytes(value, 'big')
        index, rest = number >> 53, number & ((1 << 53) - 1)
        self.registers[index] = max(self.registers[index], 54 - rest.bit_length())
        if self.exact is not None:
            self.exact.add(ip)
            if len(self.exact) > 1024:
                self.exact = None

    def result(self):
        if self.exact is not None:
            return len(self.exact), False
        m = len(self.registers)
        raw = .7213 / (1 + 1.079 / m) * m * m / sum(2.0 ** -v for v in self.registers)
        zeros = self.registers.count(0)
        if raw <= 2.5 * m and zeros:
            raw = m * math.log(m / zeros)
        return round(raw), True


class Behavior:
    """Primeras 1024 IP, 32 rutas y 64 minutos/IP; sin porcentajes de humanidad."""
    def __init__(self):
        self.ips = {}
        self.partial = False

    def add(self, ip, path, status, minute, kind, sensitive):
        if ip not in self.ips:
            if len(self.ips) >= 1024:
                self.partial = True
                return
            self.ips[ip] = dict(total=0, bot=0, browser=0, sensitive=0, errors=0,
                                streak=0, max_streak=0, last=None, paths={}, minutes={})
        row = self.ips[ip]
        row['total'] += 1
        row['bot'] += int(kind == 'bot')
        row['browser'] += int(kind == 'probable')
        row['sensitive'] += int(sensitive)
        row['errors'] += int(status in (403, 404))
        # Racha solo dentro de un minuto y en orden observado, no secuencia global de red.
        row['streak'] = row['streak'] + 1 if status in (403, 404) and row['last'] == minute else int(status in (403, 404))
        row['last'] = minute
        row['max_streak'] = max(row['max_streak'], row['streak'])
        for key, limit, value in (('paths', 32, path), ('minutes', 64, minute)):
            counter = row[key]
            if value in counter or len(counter) < limit:
                counter[value] = counter.get(value, 0) + 1
            else:
                self.partial = True

    def findings(self):
        out = []
        for ip, row in self.ips.items():
            peak = max(row['minutes'].values(), default=0)
            repeated = max(row['paths'].values(), default=0)
            reasons = []
            if row['sensitive'] >= 20 and row['errors'] >= 10:
                reasons.append(f'{row["sensitive"]} accesos sensibles y {row["errors"]} respuestas 403/404')
            if peak >= 120 and repeated >= 50:
                reasons.append(f'ráfaga {peak}/min y al menos {repeated} repeticiones de una ruta')
            if row['max_streak'] >= 20 and len(row['paths']) >= 10:
                reasons.append(f'racha de {row["max_streak"]} rechazos en un minuto; al menos {len(row["paths"])} rutas')
            if reasons:
                out.append(dict(ip=ip, requests=row['total'], browser=row['browser'], bot=row['bot'],
                                peak=peak, reasons='; '.join(reasons)))
        return sorted(out, key=lambda r: (-r['browser'], -r['peak'], r['ip']))


# Lista oficial verificada el 2026-10-20: https://www.cloudflare.com/ips/
# Nunca se actualiza por red durante una auditoría. Una ausencia no descarta proxy/CDN.
CF_NETWORKS = tuple(ipaddress.ip_network(n) for n in (
    '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22', '104.16.0.0/13', '104.24.0.0/14',
    '108.162.192.0/18', '131.0.72.0/22', '141.101.64.0/18', '162.158.0.0/15', '172.64.0.0/13',
    '173.245.48.0/20', '188.114.96.0/20', '190.93.240.0/20', '197.234.240.0/22', '198.41.128.0/17',
    '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32', '2405:8100::/32',
    '2a06:98c0::/29', '2c0f:f248::/32'))


def cloudflare_ip(value):
    try:
        address = ipaddress.ip_address(value)
        if getattr(address, 'ipv4_mapped', None):
            address = address.ipv4_mapped
        return any(address.version == net.version and address in net for net in CF_NETWORKS)
    except ValueError:
        return False


def ip_label(ip):
    return ip + (' [red Cloudflare]' if cloudflare_ip(ip) else '')


def readonly_f2b_status(jail=None, timeout=1):
    """Única orden permitida: status. Salida y tiempo limitados, sin shell."""
    if jail is not None and not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,79}', jail):
        raise ValueError('Nombre de jail no válido.')
    executable = '/usr/bin/fail2ban-client'
    parent = directory('/usr/bin')
    try:
        with regular(parent, 'fail2ban-client') as file:
            info = os.fstat(file.fileno())
            if info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
                raise ValueError('Cliente Fail2Ban no confiable.')
    finally:
        os.close(parent)
    command = [executable, 'status'] + ([jail] if jail else [])
    def child_limits():
        import resource
        resource.setrlimit(resource.RLIMIT_CPU, (1, 1))
        # El cliente instalado puede necesitar más espacio virtual que un lector simple.
        resource.setrlimit(resource.RLIMIT_AS, (64 * 1048576, 64 * 1048576))
        resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
    process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, shell=False, close_fds=True,
                               env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'PYTHONDONTWRITEBYTECODE': '1',
                                    'PYTHONSAFEPATH': '1', 'PYTHONNOUSERSITE': '1'},
                               start_new_session=True, preexec_fn=child_limits)
    end = time.monotonic() + max(.01, timeout)
    data = bytearray()
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while time.monotonic() < end:
                if not selector.select(max(0, end - time.monotonic())):
                    break
                cap = min(8192, 65536 - len(data))
                if cap <= 0:
                    raise ValueError('Salida Fail2Ban demasiado grande; estado parcial.')
                if RUN_GUARD:
                    cap = min(RUN_GUARD.allowance(cap), RUN_GUARD.allowance(cap, raw=True))
                chunk = os.read(process.stdout.fileno(), cap)
                if RUN_GUARD:
                    RUN_GUARD.debit(len(chunk))
                    RUN_GUARD.debit(len(chunk), raw=True)
                if not chunk:
                    process.wait(timeout=max(.01, end - time.monotonic()))
                    if process.returncode:
                        raise ValueError('Fail2Ban no disponible o sin permisos para consultar status.')
                    return data.decode('utf-8', 'replace')
                data.extend(chunk)
        raise ValueError('Tiempo de consulta Fail2Ban agotado.')
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=2)
        process.stdout.close()


def read_active_fail2ban():
    result = dict(jails=[], ips=set(), notes=[], at=dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds'))
    deadline = time.monotonic() + 3
    try:
        status = readonly_f2b_status(timeout=min(1, max(.01, deadline - time.monotonic())))
        match = re.search(r'Jail list:\s*([^\n]*)', status)
        if not match:
            raise ValueError('No se pudo interpretar el inventario de jails.')
        jails = [n.strip() for n in match[1].split(',') if n.strip()]
        if len(jails) > 32:
            result['notes'].append('Estado parcial: máximo 32 jails.')
        for jail in jails[:32]:
            if time.monotonic() >= deadline:
                raise ValueError('Estado parcial por límite total de 3 s.')
            try:
                data = readonly_f2b_status(jail, timeout=min(.5, deadline - time.monotonic()))
                ips = re.search(r'IP list:\s*([^\n]*)', data)
                count = re.search(r'Currently banned:[ \t]*(\d{1,10})\b', data)
                if not ips or not count:
                    raise ValueError('Formato status no reconocido para ' + clean(jail))
                observed = []
                parsed = 0
                for raw in ips[1].split():
                    ip = normalized_ip(raw)
                    if len(result['ips']) >= 5000:
                        result['notes'].append('Estado parcial: máximo 5000 IP únicas.')
                        break
                    result['ips'].add(ip)
                    parsed += 1
                    if len(observed) < 20:
                        observed.append(ip_label(ip))
                result['jails'].append((jail, int(count[1]), ', '.join(observed) or 'ninguna'))
                if parsed != int(count[1]):
                    result['notes'].append('Listado parcial o cambiante en ' + clean(jail) + ': IP recibidas y contador actual no coinciden.')
            except (OSError, ValueError, subprocess.SubprocessError) as exc:
                result['notes'].append(clean(str(exc)))
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        result['notes'].append(clean(str(exc)))
    return result


def show_active_fail2ban(result):
    print('\nFAIL2BAN ACTIVO AHORA · ' + result['at'])
    table(('JAIL', 'BLOQUEADAS', 'HASTA 20 IP OBSERVADAS'), result['jails'], (26, 12, 70))
    print('  Estado actual, independiente del historial solicitado; no prueba quién causó el bloqueo.')
    print('  Etiqueta Cloudflare según lista oficial incluida (2026-10-20); posible proxy compartido, no atacante identificado.')
    for note in result['notes']:
        print('  N/D o parcial: ' + note)


def sensitive_rows(result):
    rows = []
    notfound = result.get('notfound_sizes', {})
    for path, value in result.get('sensitive_details', {}).items():
        codes = value['codes']
        exposure = bool(EXPOSURE.search(path) and codes.get(200))
        same_size = any(size in notfound for size in value['sizes'])
        note = ('POSIBLE EXPOSICIÓN; 200 no verificado' if exposure else 'Revisar contexto de la ruta')
        if exposure and same_size:
            note += '; tamaño coincide con 404, posible error personalizado'
        ips = ', '.join(ip_label(ip) + ':' + str(n) for ip, n in sorted(value['ips'].items(), key=lambda x: -x[1])[:5])
        rows.append((path, sum(codes.values()), codes.get(200, 0), codes.get(401, 0), codes.get(403, 0),
                     codes.get(404, 0), sum(n for c, n in codes.items() if c not in (200, 401, 403, 404)), ips, note))
    return sorted(rows, key=lambda r: (not bool(EXPOSURE.search(r[0]) and r[2]), -r[1], r[0]))


def coverage_text(result):
    days = result.get('observed_days', 0)
    return (f'Cobertura del período: DESCONOCIDA. Accesos observados en {days}/{result.get("period_days", 1)} fechas '
            f'y {len(result.get("minutes", {}))} minutos; no representa porcentaje de peticiones ni tiempo completamente cubierto.')


def unique_text(value):
    if value is None:
        return 'N/D'
    count, approx = value
    return ('~' if approx else '') + f'{count:,}'


def observation_rows(result):
    uniques = result.get('unique_ips') or {}
    return [('IP distintas observadas', unique_text(uniques.get('all'))),
            ('IP con automatización declarada', unique_text(uniques.get('bot'))),
            ('IP con navegador aparente', unique_text(uniques.get('probable'))),
            ('IP con tráfico no identificado', unique_text(uniques.get('unknown'))),
            ('Solicitudes de automatización declarada', str(result.get('counts', {}).get('bot', 0))),
            ('Peticiones de IP con señales (no declaradas)', str(result.get('suspect_requests', 'N/D'))),
            ('Solicitudes restantes indeterminadas', str(result.get('indeterminate_requests', 'N/D')))]


def show_observation_detail(result):
    print('\n  IP Y COMPORTAMIENTO · lo observado, sin visitantes ni probabilidades')
    table(('MEDIDA', 'RESULTADO'), observation_rows(result), (44, 25))
    print('  IP compartidas pueden incluir muchas personas; las categorías de IP se solapan y no se suman.')
    print('  ~ = HLL aproximado, error típico ~2,3%, sin garantía individual; exacto solo en la lectura hasta 1024 IP.')
    print('  Comportamiento: primeras 1024 IP; como máximo 20 hallazgos mostrados.')
    print('  ' + result.get('coverage', coverage_text(result)))
    table(('IP', 'PETICIONES', 'NAV.', 'PICO/MIN', 'SEÑALES'),
          [(ip_label(r['ip']), r['requests'], r['browser'], r['peak'], r['reasons']) for r in result.get('behavior', [])], (36, 10, 7, 9, 70))
    print('\n  Rutas sensibles · posibles exposiciones primero; 200 no verificado')
    table(('RUTA', 'TOTAL', '200', '401', '403', '404', 'OTROS', 'IP (CONTEO PARCIAL)', 'REVISIÓN'),
          sensitive_rows(result), (30, 7, 6, 6, 6, 6, 7, 38, 58))
    print('  Primeras 8 IP por ruta y hasta 64 rutas; el top de IP es parcial si se supera el límite.')
    print('  Coincidir en tamaño con un 404 solo sugiere un error personalizado; no verifica el contenido.')


class Budget:
    def __init__(self, seconds, mib, gentle=False, continuous=False, rapid=False):
        self.end = time.monotonic() + seconds
        self.maximum = int(mib * 1024 * 1024)
        self.read = 0
        self.steps = 0
        self.pressure = None
        self.gentle = gentle
        self.continuous = continuous
        self.window_seconds = seconds
        self.window_bytes = self.maximum
        self.rapid = rapid
        self.tail = False
        self.seek_day = None
        self.zone = None
        self.started = time.monotonic()
        self.cpu_mark = time.process_time()
        self.wall_mark = self.started
        self.high_load = False
        self.checked_step = -1
        self.hard_end = self.started + max(30, seconds)
        self.hard_maximum = max(64 * 1048576, self.maximum)

    def exhausted(self):
        if self.continuous:
            if self.read >= self.hard_maximum or time.monotonic() >= self.hard_end:
                self.pressure = 'Límite total del dominio alcanzado.'
                return True
            if self.steps % 100 == 0:
                wait_for_capacity(self.gentle, self.hard_end)
            if self.read >= self.maximum or time.monotonic() >= self.end:
                print(f'  Progreso: {self.read/1048576:.2f} MiB leídos; {self.steps:,} líneas/fragmentos. Continúo…', flush=True)
                time.sleep(1)
                wait_for_capacity(self.gentle, self.hard_end)
                self.end = time.monotonic() + self.window_seconds
                self.maximum = self.read + self.window_bytes
            return False
        if self.steps % 128 == 0 and self.steps != self.checked_step:
            self.checked_step = self.steps
            self.pressure = pressure(self.gentle, rapid=self.rapid)
            try:
                self.high_load = os.getloadavg()[0] > (os.cpu_count() or 1) * LOAD_PER_CPU
            except (AttributeError, OSError):
                pass
        if self.pressure:
            return True
        return self.read >= self.maximum or time.monotonic() >= self.end

    def tick(self, size):
        if RUN_GUARD:
            RUN_GUARD.debit(size)
        self.read += size
        self.steps += 1
        # Limitar trabajo por bloques, no dormir 10 ms en cada línea.
        if self.steps % 128 == 0:
            now = time.monotonic()
            cpu = time.process_time()
            duty = .02 if self.high_load else .05 if self.gentle else .10
            rate = 256 * 1024 if self.high_load else 512 * 1024 if self.gentle else 2 * 1024 * 1024
            delay = max(0, (cpu - self.cpu_mark) / duty - (now - self.wall_mark),
                        self.read / rate - (now - self.started))
            if delay:
                time.sleep(min(delay, .25))
            self.cpu_mark = time.process_time()
            self.wall_mark = time.monotonic()


def host_status():
    with open('/proc/meminfo', 'rb', buffering=0) as stream:
        data = stream.read(RUN_GUARD.allowance(8192, raw=True) if RUN_GUARD else 8192)
    if RUN_GUARD:
        RUN_GUARD.debit(len(data), raw=True)
    info = data.decode('ascii')
    available = re.search(r'^MemAvailable:\s+(\d+) kB$', info, re.M)
    if not available:
        raise ValueError('MemAvailable no está disponible.')
    return max(1, os.cpu_count() or 1), os.getloadavg(), int(available[1]) / 1024


def pressure_reason(status, gentle=False, rapid=False):
    cpus, loads, available = status
    factor = LOAD_PER_CPU
    limit = cpus * factor
    if rapid and loads[0] > max(4, cpus * 2):
        return f'Carga extrema del host: {loads[0]:.2f}; umbral de parada rápida: {max(4, cpus * 2):g}. Análisis aplazado.'
    if loads[0] > limit and not rapid:
        return (f'Carga media 1 min: {loads[0]:.2f}; umbral: {limit:.2f} '
                f'({cpus} CPU lógicas × {factor:g}). Análisis aplazado. Usa --diagnose para ver el estado.')
    if available < 256:
        return f'Memoria disponible: {available:.0f} MiB; mínimo: 256 MiB. Análisis aplazado.'
    return None


def pressure(gentle=False, rapid=False):
    """Guardas aproximadas del host; no son métricas por dominio."""
    try:
        return pressure_reason(host_status(), gentle, rapid)
    except (OSError, AttributeError, ValueError):
        return 'No se pudo comprobar la presión del host; análisis aplazado. Usa --diagnose.'


def seek_near_day(raw, size, day, zone, budget, state):
    """Búsqueda aproximada solo en texto; supone fechas cronológicas, siempre muestra."""
    low, high = 0, size
    for _ in range(14):
        if high - low <= 16384 or budget.exhausted():
            break
        middle = (low + high) // 2
        raw.seek(middle)
        chunk = raw.read(min(4096, size - middle, budget.maximum - budget.read))
        budget.tick(len(chunk))
        dates, _ = (local_log_probe if getattr(budget, 'local_dates', False) else probe_chunk)(
            chunk.split(b'\n', 1)[-1], zone)
        if not dates or any(a > b for a, b in zip(dates, dates[1:])):
            state['notes'].add('No se pudo localizar la fecha con búsqueda rápida; lectura desde el inicio.')
            raw.seek(0)
            return
        if dates[0] < day:
            low = middle
        else:
            high = middle
    position = max(0, low - 16384)
    raw.seek(position)
    if position:
        # Alinear sin interpretar un fragmento como una petición.
        while not budget.exhausted():
            fragment = raw.readline(min(16384, budget.maximum - budget.read))
            budget.tick(len(fragment))
            if not fragment or fragment.endswith(b'\n'):
                break
    state['notes'].add('Búsqueda rápida por fecha: supone orden cronológico y puede omitir entradas fuera de orden.')


def scan(parent, name, budget, state):
    with regular(parent, name) as raw:
        initial = os.fstat(raw.fileno())
        key = (initial.st_dev, initial.st_ino)
        if key in state['inodes']:
            return
        state['inodes'].add(key)
        packed = name.endswith('.gz')
        if budget.seek_day is not None and not packed:
            seek_near_day(raw, initial.st_size, budget.seek_day, budget.zone, budget, state)
        elif budget.tail and not packed and initial.st_size > budget.maximum - budget.read:
            raw.seek(max(0, initial.st_size - (budget.maximum - budget.read)))
            # Descartar la primera línea cortada dentro del mismo presupuesto.
            while not budget.exhausted():
                fragment = raw.readline(min(16384, budget.maximum - budget.read))
                budget.tick(len(fragment))
                if not fragment or fragment.endswith(b'\n'):
                    break
            state['notes'].add('Vista rápida: cola del log activo; no es el total del día.')
        stream = gzip.GzipFile(fileobj=raw, mode='rb') if packed else raw
        try:
            while not budget.exhausted():
                # Captura un tamaño fijo: no perseguir indefinidamente un log activo.
                remaining = initial.st_size - raw.tell() if not packed else 16384
                if remaining <= 0:
                    break
                allowance = min(budget.maximum, budget.hard_maximum) - budget.read
                cap = min(16384, remaining, allowance)
                if RUN_GUARD:
                    cap = RUN_GUARD.allowance(cap)
                line = stream.readline(cap)
                if not line:
                    break
                budget.tick(len(line))
                if not line.endswith(b'\n'):
                    state['notes'].add('Línea larga/incompleta o límite de lectura; cobertura parcial.')
                    # No analizar fragmentos como si fuesen peticiones completas.
                    while line and not line.endswith(b'\n') and not budget.exhausted():
                        cap = min(16384, min(budget.maximum, budget.hard_maximum) - budget.read)
                        if RUN_GUARD:
                            cap = RUN_GUARD.allowance(cap)
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
        ('max_children', 'Límite de procesos PHP-FPM'), ('maxclients', 'Límite de Apache'),
        ('maxrequestworkers', 'Límite de Apache'), ('too many connections', 'Límite de conexiones backend'),
        ('out of memory', 'Mensaje de falta de memoria'),
        ('fatal error', 'PHP fatal'), ('php warning', 'PHP warning'),
        ('upstream timed out', 'Timeout de upstream'), ('permission denied', 'Permiso denegado'),
        ('connection refused', 'Conexión backend rechazada'),
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
        return dt.date.fromisoformat(text[:10]), clean(match[1], 80), normalized_ip(match[2])
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


def quick_files(files, historical, day_offset=1, single_base=None):
    """Una rotación probable por familia HTTP/HTTPS; nunca inferir cobertura completa."""
    groups = collections.defaultdict(list)
    for name in files:
        match = re.match(r'^(?:proxy_)?access(?:_ssl)?_log', name)
        base = single_base or (match[0] if match else None)
        if base:
            groups[base].append(name)
    selected = set()
    for base, group in groups.items():
        rotations = [n for n in group if re.search(r'\.\d+(?:\.gz)?$', n)]
        if historical and rotations:
            selected.add(min(rotations, key=lambda n: (abs(int(re.search(r'\.(\d+)(?:\.gz)?$', n)[1]) - max(1, day_offset)), n)))
        elif historical and any('.processed' in n for n in group):
            selected.add(next(n for n in group if '.processed' in n))
        elif base in group:
            selected.add(base)
        else:
            selected.add(group[0])
    return [name for name in files if name in selected]


def probe_chunk(data, zone):
    dates = []
    combined = 0
    for line in data.splitlines(keepends=True):
        if not line.endswith(b'\n'):
            continue
        stamp = re.match(rb'^\S+ \S+ \S+ \[([^\]]{20,40})\]', line)
        if stamp:
            try:
                dates.append(parse_stamp(stamp[1], zone).date())
            except (ValueError, KeyError, UnicodeError, OverflowError):
                pass
        if parse(line, zone):
            combined += 1
    return dates, combined


def local_log_probe(data, zone=None):
    """Fechas locales de mensajes Fail2Ban; no convertir horas sin offset."""
    dates = []
    for line in data.splitlines(keepends=True):
        if line.endswith(b'\n') and re.match(rb'^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}.*fail2ban\.', line):
            try:
                dates.append(dt.date.fromisoformat(line[:10].decode('ascii')))
            except (ValueError, UnicodeError):
                pass
    return dates, 0


def dated_quick_files(parent, files, day, zone, budget, notes, day_offset=1, end_day=None, log_basename=None):
    """Elegir por fechas de extractos, no por una supuesta rotación diaria."""
    groups = collections.defaultdict(list)
    end_day = end_day or day
    for name in files:
        if log_basename:
            groups[log_basename].append(name)
            continue
        match = re.match(r'^(?:proxy_)?access(?:_ssl)?_log', name)
        if match:
            groups[match[0]].append(name)
    deadline = min(budget.end, time.monotonic() + 1)
    # Reservar la mayor parte del presupuesto para contar tráfico, no inspeccionarlo.
    probe_limit = min(budget.maximum, budget.read + min(256 * 1024, max(1, (budget.maximum - budget.read) // 8)))
    selected = set()
    cached_dates = {}
    def dates_in(name):
        if name in cached_dates:
            return cached_dates[name]
        if time.monotonic() >= deadline or budget.read >= probe_limit or budget.exhausted():
            return []
        try:
            with regular(parent, name) as raw:
                size = os.fstat(raw.fileno()).st_size
                cap = min(8192, probe_limit - budget.read)
                if RUN_GUARD:
                    cap = RUN_GUARD.allowance(cap)
                if name.endswith('.gz'):
                    with gzip.GzipFile(fileobj=raw, mode='rb') as stream:
                        first = stream.read(cap)
                    last = b''
                else:
                    first = raw.read(cap)
                    budget.tick(len(first))
                    last = b''
                    if size > len(first) and budget.read < probe_limit and not budget.exhausted():
                        raw.seek(max(len(first), size - 8192))
                        last_cap = min(8192, probe_limit - budget.read)
                        if RUN_GUARD:
                            last_cap = RUN_GUARD.allowance(last_cap)
                        last = raw.read(last_cap).split(b'\n', 1)[-1]
                    budget.tick(len(last))
                if name.endswith('.gz'):
                    budget.tick(len(first))
            probe = local_log_probe if log_basename else probe_chunk
            a, _ = probe(first, zone)
            b, _ = probe(last, zone)
            return a + b
        except (OSError, EOFError, ValueError, zlib.error):
            notes.add('No se pudo comprobar la fecha de ' + name)
            return []
    # Dar prioridad a los textos de ambas familias antes de gastar sondas en gzip.
    for name in (n for n in files if not n.endswith('.gz')):
        cached_dates[name] = dates_in(name)
    for base, group in groups.items():
        plain = [n for n in group if not n.endswith('.gz')]
        compatible = []
        covers_period = False
        for name in plain:
            dates = dates_in(name)
            if dates and min(dates) <= end_day and max(dates) >= day:
                compatible.append(name)
                covers_period = covers_period or (min(dates) <= day and max(dates) >= end_day)
        if compatible:
            selected.update(compatible)
            # El intervalo del texto no demuestra que los gzip no contengan más datos.
        # En gzip solo conocemos el inicio: el más reciente anterior al día es candidato.
        zipped = []
        for name in (n for n in group if n.endswith('.gz')):
            dates = dates_in(name)
            if dates and min(dates) <= end_day:
                zipped.append((min(dates), name))
        if zipped:
            preceding = [date for date, _ in zipped if date <= day]
            latest = max(preceding) if preceding else None
            candidates = [name for date, name in zipped if day <= date <= end_day or (date == latest and not covers_period)]
            selected.update(candidates)
            if candidates:
                notes.add('Candidato gzip elegido por fecha inicial; no se ha verificado su fecha final.')
            if covers_period:
                notes.add('Gzip anterior al período no recorrido si el texto cubre su intervalo: puede haber solapamientos no detectados; cobertura desconocida.')
        elif not compatible:
            selected.update(quick_files(group, True, day_offset, log_basename))
            notes.add('No se confirmó un archivo para la fecha en los extractos; selección provisional.')
    notes.add('Selección por fechas de extractos: un intervalo compatible no garantiza registros de todo el día.')
    return [name for name in files if name in selected]


def inspect_logs(root, args):
    """Metadatos y extractos pequeños; no imprime líneas, IP, URL ni User-Agent."""
    fd = directory(args.domain + '/logs', root)
    try:
        candidates = sorted(n for n in names(fd, 4096) if re.fullmatch(
            r'(?:proxy_)?access(?:_ssl)?_log(?:\.processed)?(?:\.\d+)?(?:\.gz)?', n))
        primary, _, layer = sources(fd, True, args.historical)
        probe_notes = set()
        chosen = set(primary if args.full else dated_quick_files(
            fd, historical_order(primary, fd, args.historical), getattr(args, 'start_day', args.day), args.zone,
            Budget(1, 2, rapid=True), probe_notes, args.day_offset, end_day=args.day))
        print(f'\nINSPECCIÓN DE LOGS · {args.domain} · período {getattr(args, "period_label", args.day)} · {args.timezone}')
        print(f'Fuente que usaría el análisis: {layer.upper()}. * = archivo seleccionado.')
        print('Cada fecha es SOLO del extracto leído; no demuestra la cobertura completa.')
        print('Gzip: inicio de hasta 16 KiB. Texto: inicio y final de hasta 16 KiB cada uno.')
        print('Fechas convertidas a la zona elegida. No se muestran IP, rutas ni agentes.\n')
        deadline = time.monotonic() + 3
        rows = []
        for name in candidates[:32]:
            if time.monotonic() > deadline:
                print('Inspección parcial: límite de 3 segundos alcanzado.')
                break
            try:
                with regular(fd, name) as raw:
                    size = os.fstat(raw.fileno()).st_size
                    if name.endswith('.gz'):
                        with gzip.GzipFile(fileobj=raw, mode='rb') as zipped:
                            first = zipped.read(16384)
                        last = b''
                    else:
                        first = raw.read(16384)
                        last = b''
                        if size > 16384:
                            raw.seek(max(16384, size - 16384))
                            last = raw.read(16384).split(b'\n', 1)[-1]
                dates, count = probe_chunk(first, args.zone)
                end_dates, end_count = probe_chunk(last, args.zone)
                range_text = lambda values: (str(min(values)) + '..' + str(max(values))) if values else 'Sin fechas en muestra'
                rows.append(('*' if name in chosen else '', name, f'{size/1048576:.2f}',
                             range_text(dates), range_text(end_dates) if not name.endswith('.gz') else 'No leído (gzip)',
                             str(count + end_count)))
            except (OSError, EOFError, ValueError, zlib.error) as exc:
                rows.append(('*' if name in chosen else '', name, 'N/D', clean(str(exc), 21), '-', '0'))
        table(('*', 'ARCHIVO', 'MiB', 'FECHAS INICIO', 'FECHAS FINAL', 'COMBINED'), rows, (1, 38, 8, 22, 22, 8))
        if len(candidates) > 32:
            print('Se omitieron archivos: máximo 32 por inspección.')
        print('\nCOMBINED = líneas de muestra que acepta el parser, no peticiones del día.')
        print('Sin fechas/COMBINED 0 puede significar archivo vacío, formato distinto o muestra insuficiente.')
        for note in sorted(probe_notes):
            print('Selección: ' + note)
    finally:
        os.close(fd)


def read_fail2ban(args):
    result = dict(ips=set(), jails=collections.Counter(), events=0, notes=set(), inodes=set(),
                  day_seen=False, read=0, selected_files=[], earliest=None, latest=None)
    if args.no_fail2ban:
        result['notes'].add('Integración Fail2Ban desactivada por --no-fail2ban.')
        return result
    budget = Budget(min(args.seconds, 3), min(args.max_mib, 2), args.gentle, rapid=True)
    start_day = getattr(args, 'start_day', args.day)
    parent, basename = os.path.split(os.path.abspath(args.fail2ban_log))
    fd = None
    try:
        fd = directory(parent)
        files = [n for n in names(fd, 10000) if re.fullmatch(re.escape(basename) + r'(?:\.\d+)?(?:\.gz)?', n)]
        if len(files) > 128:
            raise ValueError('Demasiados históricos Fail2Ban.')
        if not files:
            result['notes'].add('No se encontró el log de Fail2Ban. Puede usar journald/syslog u otra ruta.')
        files = historical_order(files, fd, args.historical)
        if not getattr(args, 'full', False):
            files = dated_quick_files(fd, files, start_day, None, budget, result['notes'],
                                     getattr(args, 'day_offset', 1), end_day=args.day, log_basename=basename)
            budget.local_dates = True
            budget.seek_day = start_day
        result['selected_files'] = files[:]
        for name in files:
            if name.endswith('.gz') and not args.gzip:
                result['notes'].add('Históricos gzip de Fail2Ban omitidos para hoy; usa --gzip para incluirlos.')
                continue
            if budget.exhausted():
                result['notes'].add('Lectura Fail2Ban incompleta por presupuesto o carga.')
                break
            try:
                for line in scan(fd, name, budget, result):
                    # Fail2Ban suele registrar hora local sin offset; no inventar una conversión.
                    if b'fail2ban.' in line:
                        try:
                            stamp_day = dt.date.fromisoformat(line[:10].decode('ascii'))
                            result['earliest'] = min(result['earliest'] or stamp_day, stamp_day)
                            result['latest'] = max(result['latest'] or stamp_day, stamp_day)
                            if start_day <= stamp_day <= args.day:
                                result['day_seen'] = True
                        except (ValueError, UnicodeError):
                            pass
                    event = parse_ban(line)
                    if not event or not start_day <= event[0] <= args.day:
                        continue
                    _, jail, ip = event
                    result['events'] += 1
                    if ip in result['ips'] or len(result['ips']) < 20000:
                        result['ips'].add(ip)
                        if cloudflare_ip(ip):
                            result['notes'].add('Hay IP de redes Cloudflare en el historial: pueden ser proxies compartidos; no identifican al atacante.')
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
    print('  Histórico declarado por Fail2Ban para el período; no indica bloqueos activos.')
    print('  Hora local escrita en el log. Cobertura y retención no garantizadas.')
    print('  Archivos seleccionados: ' + (', '.join(result.get('selected_files', [])) or 'ninguno'))
    print(f'  Leídos: {result.get("read", 0) / 1048576:.2f} MiB (incluye extractos de selección).')
    if result.get('earliest'):
        print(f'  Fechas de mensajes recorridos: {result["earliest"]} a {result["latest"]}.')
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


# Diagnóstico: solo contadores del recorrido existente, sin nuevas lecturas de logs.
THRESHOLDS = {
    'health_min': 20, 'health_review_count': 5, 'health_review_pct': 5,
    'health_critical_count': 20, 'health_critical_pct': 20,
    'sensitive_review': 20, 'sensitive_high': 100, 'bot_pct': 50,
    'sustained_rpm': 600, 'sustained_minutes': 3,
    'gateway_count': 5, 'slow_seconds': 2, 'slow_pct': 50,
    'timing_min': 20, 'timing_coverage_pct': 80,
    'shared_domains': 2, 'shared_5xx_count': 5, 'shared_5xx_pct': 10,
}
HTTP_CODES = (400, 401, 403, 404, 408, 429, 500, 502, 503, 504)
STATIC_PATH = re.compile(r'\.(?:css|js|png|jpe?g|gif|svg|ico|webp|woff2?|ttf|map|txt)$', re.I)
DYNAMIC_PATH = re.compile(r'\.php(?:/|$)|^/wp-json(?:/|$)|^/(?:api|cart|checkout)(?:/|$)', re.I)
SATURATION = ('Límite de procesos PHP-FPM', 'Límite de Apache', 'Límite de conexiones backend')


def timing_seconds(line):
    """Solo sufijo explícito request_time=SEGUNDOS; nunca adivinar columnas numéricas."""
    if b'request_time=' not in line:
        return None
    match = ACCESS.match(line)
    if not match:
        return None
    tail = line[match.end():].strip()
    value = re.fullmatch(rb'request_time=(\d{1,6}(?:\.\d{1,6})?)', tail)
    return float(value[1]) if value else None


def http_rows(result):
    total = result.get('total', 0)
    statuses = result.get('statuses', {})
    rows = []
    for code in HTTP_CODES:
        count = statuses.get(code, 0)
        rows.append((str(code), str(count) if total else 'N/D', f'{100*count/total:.1f}%' if total else 'N/D'))
    for group in (4, 5):
        count = sum(n for code, n in statuses.items() if code // 100 == group and code not in HTTP_CODES)
        rows.append((f'Otros {group}xx', str(count) if total else 'N/D', f'{100*count/total:.1f}%' if total else 'N/D'))
    return rows


def sustained_peak(minutes, threshold):
    """Mayor racha de minutos UTC consecutivos; ni huecos ni cambios DST se juntan."""
    values = []
    for label, count in minutes.items():
        if count >= threshold:
            stamp = dt.datetime.strptime(label, '%Y-%m-%d %H:%M %z')
            values.append(int(stamp.timestamp() // 60))
    longest = run = 0
    previous = None
    for minute in sorted(values):
        run = run + 1 if previous is not None and minute == previous + 1 else 1
        longest = max(longest, run)
        previous = minute
    return longest


def diagnose_domain(result, thresholds=None):
    t = thresholds or THRESHOLDS
    total = result.get('total', 0)
    health = suspicious = 'INDETERMINADO'
    impact = 'NO DETERMINADO'
    facts, hypotheses, actions = [], [], []
    partial = result.get('rapid', False) or bool(result.get('invalid')) or any(
        any(word in n.lower() for word in ('parcial', 'no se pudo', 'presupuesto', 'sin leer')) for n in result.get('notes', []))
    confidence = 'LIMITADA: muestra o lectura incompleta' if partial else 'MEDIA: solo logs conservados'
    if not total:
        return dict(health=health, suspicious=suspicious, impact=impact, facts=['Sin accesos del período analizado.'],
                    hypotheses=['No se puede valorar la salud ni el impacto.'], actions=['Revisar fechas, retención y avisos de lectura.'],
                    confidence='INSUFICIENTE', attention=False, priority=(0, 0, 0, 0), sustained=0)
    errors = result.get('http5', 0)
    error_pct = 100 * errors / total
    if total >= t['health_min']:
        health = 'OK'
        if errors >= t['health_review_count'] and error_pct >= t['health_review_pct']:
            health = 'REVISAR'
        if errors >= t['health_critical_count'] and error_pct >= t['health_critical_pct']:
            health = 'CRÍTICO'
    facts.append(f'{errors} respuestas 5xx de {total} peticiones ({error_pct:.1f}% de las leídas).')
    if health in ('REVISAR', 'CRÍTICO'):
        hypotheses.append('Posible fallo de aplicación o backend; los 5xx no demuestran saturación.')
        actions.append('En Plesk, revisar los logs de la web y PHP en los minutos indicados; distinguir 500 de 502/503/504.')
    bot_pct = 100 * result.get('counts', {}).get('bot', 0) / total
    sensitive = result.get('sensitive4', 0)
    run = sustained_peak(result.get('minutes', {}), t['sustained_rpm'])
    sustained = run >= t['sustained_minutes']
    suspicious = 'BAJO'
    if sensitive >= t['sensitive_review']:
        suspicious = 'MODERADO'
    if (sensitive >= t['sensitive_high'] and bot_pct >= t['bot_pct']) or (
            sustained and bot_pct >= t['bot_pct'] and result.get('http4', 0) >= total / 2):
        suspicious = 'ALTO'
    if suspicious != 'BAJO':
        facts.append(f'{sensitive} accesos sensibles con 4xx; automatización probable {bot_pct:.1f}%.')
        hypotheses.append('Posible exploración automatizada; ni los 4xx ni el User-Agent identifican por sí solos un ataque.')
        actions.append('Revisar rutas e IP de errores en Plesk. Si usas Cloudflare, estudiar desafíos limitados a rutas sensibles y tasas por IP antes de aplicar cambios.')
        actions.append('Comprobar intentos repetidos de login/XML-RPC y archivos internos; evitar reglas generales sobre WordPress, WooCommerce o APIs.')
    behavior = result.get('behavior', [])
    exposures = [row for row in sensitive_rows(result) if EXPOSURE.search(row[0]) and row[2]]
    if behavior:
        suspicious = 'MODERADO' if suspicious == 'BAJO' else suspicious
        facts.append(f'{result.get("suspect_ip_count", len(behavior))} IP observadas con ráfagas, repeticiones o exploración; cabeceras de navegador no prueban humanidad.')
        hypotheses.append('Automatización sospechosa, sin probabilidad calculada. NAT, proxies o CDN pueden reunir usuarios legítimos en una IP.')
        actions.append('Revisar las señales por IP y el proxy de confianza en Plesk; no bloquear por User-Agent ni por IP compartida sin contexto.')
    if exposures:
        facts.append(f'{len(exposures)} rutas de posibles archivos internos devolvieron 200 en la muestra.')
        hypotheses.append('Posible exposición NO CONFIRMADA: un 200 también puede ser una página de error personalizada o un front controller.')
        actions.append('Prioridad: comprobar en Plesk el archivo y la configuración de la ruta, sin descargar contenido confidencial; comparar con errores personalizados.')
    gateway = sum(result.get('statuses', {}).get(code, 0) for code in (502, 503, 504))
    saturation = sum(result.get('internal', {}).get(label, 0) for label in SATURATION)
    timings = result.get('timing_count', 0)
    coverage = 100 * timings / total
    slow = result.get('slow_count', 0)
    timing_known = timings >= t['timing_min'] and coverage >= t['timing_coverage_pct']
    if timing_known:
        slow_pct = 100 * slow / timings
        impact = 'POSIBLE' if slow_pct >= t['slow_pct'] else 'NO DETERMINADO'
        # Bajo solo describe señales de latencia suficientemente muestreadas, no CPU/RAM.
        if slow == 0 and not gateway and not saturation:
            impact = 'BAJO'
        if slow_pct >= t['slow_pct'] and sustained and gateway >= t['gateway_count']:
            impact = 'ALTO POTENCIAL'
        facts.append(f'Duración explícita en {timings} accesos ({coverage:.1f}%); {slow} de al menos {t["slow_seconds"]:g} s.')
    if saturation or (sustained and gateway >= t['gateway_count']):
        if impact != 'ALTO POTENCIAL':
            impact = 'POSIBLE'
    if run:
        facts.append(f'{run} minuto(s) consecutivos con al menos {t["sustained_rpm"]:g} peticiones/min.')
    if saturation:
        facts.append(f'{saturation} mensajes internos sobre límites de procesos o conexiones en el período.')
    if impact in ('POSIBLE', 'ALTO POTENCIAL'):
        hypotheses.append('Posible presión sobre aplicación/backend. No se ha medido consumo ni concurrencia por dominio.')
        actions.append('En Plesk, revisar límites y logs del pool PHP-FPM, colas/tiempos del backend y errores de conexiones de MySQL/MariaDB en esa franja.')
    if impact == 'NO DETERMINADO':
        hypotheses.append('Sin métricas suficientes de duración, concurrencia o límites alcanzados para atribuir carga.')
    hints = result.get('fourxx_hints', {})
    if result.get('http4'):
        facts.append(f'4xx por aspecto de la ruta: estática {hints.get("static", 0)}, dinámica {hints.get("dynamic", 0)}, desconocida {hints.get("unknown", 0)}.')
        hypotheses.append('Una ruta estática puede ser barata y una dinámica pasar por PHP; la ruta no demuestra qué proceso respondió ni su coste.')
        actions.append('Revisar redirecciones y reglas de la web: un 404 de WordPress puede ejecutar PHP; un 403 puede resolverse antes.')
    if errors:
        actions.append('Cloudflare no corrige fallos internos de aplicación; investigar primero el origen de los 5xx.')
    at_peak = result.get('error_minutes', {}).get(result.get('peak_minute'), (0, 0, 0))
    facts.append(f'Errores en el minuto de mayor tráfico: {at_peak[0]} 4xx y {at_peak[1]} 5xx (coincidencia, no causalidad).')
    attention = bool(exposures) or health in ('REVISAR', 'CRÍTICO') or suspicious != 'BAJO' or impact in ('POSIBLE', 'ALTO POTENCIAL')
    priority = (int(bool(exposures)), int(health == 'CRÍTICO') * 2 + int(health == 'REVISAR'),
                {'NO DETERMINADO': 0, 'BAJO': 0, 'POSIBLE': 1, 'ALTO POTENCIAL': 2}[impact],
                {'BAJO': 0, 'MODERADO': 1, 'ALTO': 2}[suspicious])
    return dict(health=health, suspicious=suspicious, impact=impact, facts=facts, hypotheses=hypotheses,
                actions=actions, confidence=confidence, attention=attention, priority=priority, sustained=run)


class SharedIncidents:
    """Una instancia por ejecución/servidor; memoria acotada, sin importar informes previos."""
    def __init__(self, thresholds=None):
        self.thresholds = thresholds or THRESHOLDS
        self.windows = {}
        self.partial = False

    def add(self, domain, result):
        t = self.thresholds
        # Solo guardamos ventanas con errores relevantes o picos, no todos los minutos.
        for minute, count in result.get('minutes', {}).items():
            e4, e5, gateway = result.get('error_minutes', {}).get(minute, (0, 0, 0))
            five = e5 >= t['shared_5xx_count'] and 100 * e5 / count >= t['shared_5xx_pct']
            peak = count >= t['sustained_rpm']
            if not five and not peak:
                continue
            if minute not in self.windows:
                if len(self.windows) >= 2048:
                    self.partial = True
                    continue
                self.windows[minute] = [set(), set(), set()]
            groups = self.windows[minute]
            for yes, group in zip((five, peak, five and gateway >= t['shared_5xx_count']), groups):
                if yes:
                    if len(group) < 8:
                        group.add(domain)
                    else:
                        self.partial = True

    def findings(self):
        out = []
        for minute, groups in sorted(self.windows.items()):
            for label, group in zip(('5xx coincidentes', 'Picos coincidentes', '502/503/504 coincidentes'), groups):
                if len(group) >= self.thresholds['shared_domains']:
                    out.append((minute, label, ', '.join(sorted(group))))
                    if len(out) == 20:
                        return out
        return out


def diagnosis_key(row):
    domain, result = row
    d = result.get('diagnosis') or diagnose_domain(result)
    return tuple(-v for v in d['priority']) + (-result.get('http5', 0), domain)


def attention_values(domain, result):
    d = result.get('diagnosis') or diagnose_domain(result)
    total = result.get('total', 0)
    return (domain, total, result.get('http4', 0), result.get('http5', 0),
            f'{100*result.get("http5", 0)/total:.1f}%' if total else 'N/D', result.get('peak', 0),
            d['health'], d['suspicious'], d['impact'])


ATTENTION_HEADERS = ('DOMINIO', 'PETICIONES', '4xx', '5xx', '%5xx', 'PICO/MIN', 'SALUD WEB', 'SOSPECHOSO', 'IMPACTO POTENCIAL')


def show_diagnosis(d):
    print('\n  DIAGNÓSTICO DEL PERÍODO LEÍDO')
    table(('INDICADOR', 'RESULTADO'), [('Salud web', d['health']), ('Tráfico sospechoso', d['suspicious']),
                                     ('Impacto potencial', d['impact'])], (26, 40))
    for label, key in (('Hechos', 'facts'), ('Hipótesis', 'hypotheses'), ('Qué revisar', 'actions')):
        print('\n  ' + label + ':')
        for item in d[key]:
            # Mantener legible el detalle en terminales de 90 columnas.
            print(textwrap.fill(item, width=88, initial_indent='    - ', subsequent_indent='      '))
    print('  Confianza: ' + d['confidence'])
    print('  OK/BAJO se refieren a lo leído; no certifican la web ni el servidor.')


def show_attention(rows, shared=None):
    print('\nDOMINIOS QUE REQUIEREN ATENCIÓN · solo esta ejecución y servidor')
    selected = sorted((r for r in rows if (r[1].get('diagnosis') or diagnose_domain(r[1]))['attention']), key=diagnosis_key)
    table(ATTENTION_HEADERS, [attention_values(*r) for r in selected[:100]], (32, 10, 7, 7, 7, 8, 13, 13, 17))
    if not selected:
        print('  Sin condiciones activadas en los datos leídos; no descarta problemas ni falta de cobertura.')
    for domain, result in selected[:100]:
        print('\n  ' + domain)
        show_diagnosis(result.get('diagnosis') or diagnose_domain(result))
    if len(selected) > 100:
        print('  Se muestran los primeros 100; consulta el detalle del resto por dominio.')
    if shared:
        findings = shared.findings()
        if findings:
            print('\nPOSIBLE INCIDENCIA COMPARTIDA DEL SERVIDOR')
            table(('MINUTO', 'HECHO OBSERVADO', 'DOMINIOS'), findings, (28, 28, 65))
            print('  Hipótesis: revisar servicios comunes en esa franja. Sin línea base no se demuestra un aumento ni una causa compartida.')
        else:
            print('\nSin coincidencias compartidas que alcancen los umbrales en la lectura.')
        print('  Correlación de accesos del mismo recorrido; no se mezclan servidores ni ejecuciones. Muestras pueden ocultar coincidencias.')
        if shared.partial:
            print('  Correlación PARCIAL: máximo 2048 minutos y 8 dominios por grupo; se muestran hasta 20 coincidencias.')


def current_resources():
    """Instantánea opcional /proc, sin sockets, comandos ni datos de otras fechas."""
    result = dict(values=[], notes=[])
    deadline = time.monotonic() + .5
    read = 0
    def small(path, maximum):
        nonlocal read
        if time.monotonic() >= deadline or read + maximum > 256 * 1024:
            raise ValueError('Límite de instantánea alcanzado.')
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            cap = RUN_GUARD.allowance(maximum, raw=True) if RUN_GUARD else maximum
            data = os.read(fd, cap)
            if RUN_GUARD:
                RUN_GUARD.debit(len(data), raw=True)
            read += len(data)
            return data.decode('ascii', 'replace')
        finally:
            os.close(fd)
    try:
        cpus, loads, available = host_status()
        result['values'].extend([('CPU lógicas', str(cpus)), ('Carga 1/5/15 min', ' / '.join(f'{v:.2f}' for v in loads)),
                                 ('Memoria disponible', f'{available:.0f} MiB')])
        read += 8192
    except (OSError, ValueError, AttributeError):
        result['notes'].append('Carga/memoria no disponibles.')
    for resource in ('cpu', 'memory', 'io'):
        try:
            data = small('/proc/pressure/' + resource, 4096)
            for line in data.splitlines():
                match = re.fullmatch(r'(some|full) avg10=([0-9.]+) avg60=([0-9.]+) avg300=([0-9.]+) total=\d+', line)
                if match:
                    result['values'].append((f'PSI {resource} {match[1]} (10/60/300 s)', ' / '.join(match.groups()[1:]) + ' %'))
        except (OSError, ValueError, AttributeError):
            result['notes'].append('PSI ' + resource + ': N/D (permisos o kernel sin soporte).')
    try:
        data = small('/proc/vmstat', 16384)
        match = re.search(r'^oom_kill (\d+)$', data, re.M)
        result['values'].append(('OOM kill acumulado desde arranque', match[1] if match else 'N/D'))
    except (OSError, ValueError, AttributeError):
        result['notes'].append('Contador OOM: N/D.')
    counts = collections.Counter()
    visited = 0
    partial = False
    try:
        with os.scandir('/proc') as entries:
            for entry in entries:
                if not entry.name.isascii() or not entry.name.isdecimal():
                    continue
                if visited >= 512 or time.monotonic() >= deadline:
                    partial = True
                    break
                visited += 1
                try:
                    comm = small('/proc/' + entry.name + '/comm', 64).strip()
                    label = ('PHP-FPM' if comm.startswith('php-fpm') else
                             'MySQL/MariaDB' if comm in ('mysqld', 'mariadbd') else
                             'nginx/Apache' if comm in ('nginx', 'apache2', 'httpd') else None)
                    if label:
                        counts[label] += 1
                except (OSError, ValueError, AttributeError):
                    partial = True
        for label in ('PHP-FPM', 'MySQL/MariaDB', 'nginx/Apache'):
            result['values'].append(('Procesos observados ' + label, str(counts[label]) + (' (parcial)' if partial else '')))
    except (OSError, AttributeError):
        result['notes'].append('Inventario de procesos: N/D.')
    result['notes'].extend([
        'Instantánea ACTUAL del servidor; no corresponde a ayer ni atribuye CPU/RAM a dominios.',
        'PSI indica tiempo de espera por recursos; carga media no es porcentaje de CPU.',
        'OOM es acumulado desde arranque: no identifica fechas, procesos ni la causa de un error HTTP.',
        'Contar procesos no mide concurrencia, colas ni saturación de pools PHP-FPM.',
        'Sin consultar sockets/HTTP ni credenciales: estado de pools y conexiones SQL N/D. Revisar logs y métricas ya disponibles en Plesk.',
        'Máximo 0,5 s cooperativos, 256 KiB y 512 procesos; archivos ausentes o sin permiso se omiten.',
    ])
    result['read'] = read
    return result


def show_current_resources():
    print('\nRECURSOS ACTUALES DEL SERVIDOR · ' + dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds'))
    data = current_resources()
    table(('MEDIDA', 'RESULTADO'), data['values'], (43, 38))
    for note in data['notes']:
        print('  ' + note)


def analyze(root, domain, day, zone, args):
    if not RUN_GUARD:
        return _analyze(root, domain, day, zone, args)
    # El límite global sigue activo y no se renueva al cambiar de dominio.
    remaining, interval = signal.getitimer(signal.ITIMER_REAL)
    local = (max(30, args.seconds) if not args.sample else args.seconds) + 4
    signal.setitimer(signal.ITIMER_REAL, min(remaining, local) if remaining else local)
    started = time.monotonic()
    try:
        return _analyze(root, domain, day, zone, args)
    finally:
        left = remaining - (time.monotonic() - started)
        signal.setitimer(signal.ITIMER_REAL, max(.001, left) if remaining else 0, interval)


def _analyze(root, domain, day, zone, args):
    detailed = bool(args.domain or getattr(args, 'report', False))
    state = dict(inodes=set(), notes=set(), counts=collections.Counter(), urls=collections.Counter(),
                 bytes_urls=collections.Counter(), errors=collections.Counter(), statuses=collections.Counter(),
                 internal=collections.Counter(),
                 error_clients=collections.Counter(), error_minutes={}, fourxx_hints=collections.Counter(),
                 timing_count=0, slow_count=0, timing_sum=0.0, timing_max=0.0,
                 ip_counts=collections.Counter(), minutes=collections.Counter(), sensitive_urls=collections.Counter(),
                 f2b_seen=set(), sensitive=0, sensitive4=0, http4=0, http5=0, peak=0, peak_minute=None,
                 total=0, bytes=0, invalid=0, earliest=None, latest=None)
    uniques = {kind: UniqueIPs() for kind in ('all', 'bot', 'probable', 'unknown')}
    behavior = Behavior()
    days_seen = set()
    state.update(sensitive_details={}, notfound_sizes=collections.Counter(), behavior_partial=False)
    start_day = getattr(args, 'start_day', day)
    period_days = (day - start_day).days + 1
    state['period_days'] = period_days
    state['period_label'] = str(start_day) + ' a ' + str(day) if period_days > 1 else str(day)
    bans = getattr(args, 'bans', None)
    state['f2b_matches'] = 0 if bans and bans['day_seen'] else None
    continuous = not getattr(args, 'sample', False)
    state['rapid'] = not continuous
    budget = Budget(args.seconds, args.max_mib, args.gentle, continuous=continuous, rapid=not continuous)
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
        if not continuous:
            chosen = dated_quick_files(fd, files, start_day, zone, budget, state['notes'], getattr(args, 'day_offset', 1), end_day=day)
            state['notes'].add('VISTA RÁPIDA: muestra de archivos probables; no es el total del día. Usa --full para ampliar.')
            if len(chosen) < len(files):
                state['notes'].add(f'Se omiten {len(files) - len(chosen)} archivos de otras rotaciones.')
            files = chosen
        state['selected_files'] = files if not continuous else []
        total_end, total_maximum = budget.end, budget.maximum
        for index, name in enumerate(files):
            if not continuous:
                budget.end, budget.maximum = total_end, total_maximum
            if budget.exhausted():
                state['notes'].add((budget.pressure or 'Quedan archivos sin leer.') + ' Resultado PARCIAL.')
                break
            if not continuous:
                # Repartir el presupuesto entre HTTP y HTTPS, no gastarlo en el primero.
                remaining_files = len(files) - index
                budget.end = time.monotonic() + max(0, total_end - time.monotonic()) / remaining_files
                budget.maximum = budget.read + max(1, (total_maximum - budget.read) // remaining_files)
                budget.tail = not args.historical
                budget.seek_day = start_day if args.historical and not name.endswith('.gz') else None
                budget.zone = zone
            try:
                for line in scan(fd, name, budget, state):
                    event = parse(line, zone)
                    if event is None:
                        state['invalid'] += 1
                        continue
                    date, path, status, size, kind, ip, minute = event
                    state['earliest'] = min(date, state['earliest'] or date)
                    state['latest'] = max(date, state['latest'] or date)
                    if not start_day <= date <= day:
                        continue
                    state['total'] += 1
                    state['bytes'] += size
                    state['counts'][kind] += 1
                    state['statuses'][status] += 1
                    state['http4'] += int(400 <= status < 500)
                    state['http5'] += int(status >= 500)
                    probe = bool(SENSITIVE.search(unquote(path)) or EXPOSURE.search(path))
                    uniques['all'].add(ip)
                    uniques[kind].add(ip)
                    days_seen.add(date)
                    behavior.add(ip, path, status, minute, kind, probe)
                    if status == 404 and (size in state['notfound_sizes'] or len(state['notfound_sizes']) < 64):
                        state['notfound_sizes'][size] += 1
                    if probe:
                        if path not in state['sensitive_details'] and len(state['sensitive_details']) >= 64:
                            if status == 200 and EXPOSURE.search(path):
                                discard = next((p for p, item in state['sensitive_details'].items()
                                                if not (EXPOSURE.search(p) and item['codes'].get(200))), None)
                                if discard is not None:
                                    del state['sensitive_details'][discard]
                            state['notes'].add('Rutas sensibles parciales: máximo 64 rutas.')
                        if path in state['sensitive_details'] or len(state['sensitive_details']) < 64:
                            sensitive = state['sensitive_details'].setdefault(path, dict(codes=collections.Counter(), ips={}, sizes=set()))
                            sensitive['codes'][status] += 1
                            if ip in sensitive['ips'] or len(sensitive['ips']) < 8:
                                sensitive['ips'][ip] = sensitive['ips'].get(ip, 0) + 1
                            else:
                                state['notes'].add('IP de rutas sensibles parciales: primeras 8 por ruta; ranking incompleto.')
                            if status == 200 and len(sensitive['sizes']) < 8:
                                sensitive['sizes'].add(size)
                    state['sensitive'] += int(probe)
                    state['sensitive4'] += int(probe and 400 <= status < 500)
                    # Un día tiene <=1500 minutos con cambio horario; límite defensivo.
                    if minute in state['minutes'] or len(state['minutes']) < 1600 * period_days:
                        state['minutes'][minute] += 1
                        if state['minutes'][minute] > state['peak']:
                            state['peak'] = state['minutes'][minute]
                            state['peak_minute'] = minute
                        if status >= 400:
                            counts = state['error_minutes'].setdefault(minute, [0, 0, 0])
                            counts[0] += int(status < 500)
                            counts[1] += int(status >= 500)
                            counts[2] += int(status in (502, 503, 504))
                    else:
                        state['notes'].add('Límite de minutos: distribución temporal y correlación parciales.')
                    if 400 <= status < 500:
                        hint = 'dynamic' if DYNAMIC_PATH.search(path) else 'static' if STATIC_PATH.search(path) else 'unknown'
                        state['fourxx_hints'][hint] += 1
                    duration = timing_seconds(line)
                    if duration is not None:
                        state['timing_count'] += 1
                        state['slow_count'] += int(duration >= getattr(args, 'thresholds', THRESHOLDS)['slow_seconds'])
                        state['timing_sum'] += duration
                        state['timing_max'] = max(state['timing_max'], duration)
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
                            increment(state['error_clients'], ip, overflow='[otras IP: límite de memoria]')
            except (OSError, EOFError, ValueError, zlib.error) as exc:
                state['notes'].add('No se pudo completar ' + clean(name) + ': ' + clean(str(exc)))
        if detailed:
            if not continuous:
                access_read = budget.read
                budget = Budget(min(args.seconds, 2), min(args.max_mib, 2), args.gentle, rapid=True)
            errorfiles = [n for n in names(fd, 4096) if re.fullmatch(r'(?:proxy_error_log|error_log)(?:\.\d+)?(?:\.gz)?', n)]
            if not continuous and errorfiles:
                errorbase = 'proxy_error_log' if layer == 'nginx' else 'error_log'
                errorfiles = [n for n in errorfiles if re.fullmatch(re.escape(errorbase) + r'(?:\.\d+)?(?:\.gz)?', n)]
                errorfiles = historical_order(errorfiles, fd, args.historical)
                errorfiles = quick_files(errorfiles, args.historical, getattr(args, 'day_offset', 1), errorbase)
                state['notes'].add('Errores internos: lectura rápida limitada a archivos seleccionados de la capa elegida.')
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
                            if event and start_day <= event[0] <= day:
                                state['internal'][event[1]] += 1
                    except (OSError, EOFError, ValueError, zlib.error):
                        state['notes'].add('No se pudo completar un log interno.')
            if not continuous:
                budget.read += access_read
    finally:
        os.close(fd)
    state['read'] = budget.read
    state['unique_ips'] = {kind: value.result() for kind, value in uniques.items()}
    state['observed_days'] = len(days_seen)
    state['coverage'] = coverage_text(state)
    all_findings = behavior.findings()
    state['behavior'] = all_findings[:20]
    state['suspect_ip_count'] = len(all_findings)
    suspect_ips = {row['ip'] for row in all_findings}
    # Sin probabilidades: clasificación orientativa y parcial de solicitudes observadas.
    state['suspect_requests'] = sum(row['total'] - row['bot'] for ip, row in behavior.ips.items() if ip in suspect_ips)
    state['indeterminate_requests'] = state['total'] - state['counts']['bot'] - state['suspect_requests']
    state['behavior_partial'] = behavior.partial
    active = getattr(args, 'active_bans', None)
    state['active_matches'] = len(set(behavior.ips).intersection(active['ips'])) if active and active['jails'] else None
    if behavior.partial:
        state['notes'].add('Comportamiento parcial: primeras 1024 IP, hasta 32 rutas y 64 minutos por IP; no descarta automatización fuera de la muestra.')
    if any(approx for value, approx in state['unique_ips'].values()):
        state['notes'].add('IP únicas aproximadas con HLL (2048 registros); error estadístico típico ~2,3%, no cota garantizada.')
    if state['f2b_matches'] is not None:
        state['f2b_matches'] = len(state['f2b_seen']) if state['read'] else None
    if state['invalid']:
        state['notes'].add(f"{state['invalid']} líneas no interpretadas; cobertura parcial.")
    state['diagnosis'] = diagnose_domain(state, getattr(args, 'thresholds', THRESHOLDS))
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
    print(f' Período: {result.get("period_label") or day}   |   Datos observados, cobertura no garantizada')
    if result.get('rapid'):
        print(' VISTA RÁPIDA · MUESTRA: las cifras no son el total del período.')
    if result.get('layer'):
        print(' Fuente de accesos: ' + result['layer'].upper() + ' (una sola capa)')
    for name in result.get('selected_files', []):
        print(' Archivo seleccionado: ' + clean(name, 56))
    print('=' * 80 + '\n')
    metrics = [
        ('Peticiones del período leídas', f'{total:,}' if known else 'N/D'),
        ('Contenido enviado (según log)', f'{result["bytes"]/1048576:.2f} MiB' if known else 'N/D'),
        ('Bots / automatización probable', pct('bot')),
        ('Navegador aparente / no identificado', pct('probable') + ' / ' + pct('unknown')),
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
    print('  Los porcentajes 4xx/5xx usan todas las peticiones leídas de este período.')
    peak = result.get('peak', 0)
    if total:
        level = activity_level(peak)
        print(f'\n  ACTIVIDAD {level}: pico observado de {peak:,}/min (~{peak/60:.1f}/s).')
        if result.get('peak_minute'):
            print('  Minuto del pico: ' + result['peak_minute'])
        print('  Nivel orientativo por volumen; no compara con el historial de esta web.')
        print('  Un pico alto puede ser normal. Incluye recursos y bots, no personas.')
    if detail:
        print('\n  F2B: IP vistas en esta web y con evento Ban en el servidor en el período.')
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
        show_observation_detail(result)
        if result.get('active_matches') is not None:
            print(f'  IP de esta lectura coincidentes con bloqueos ACTIVOS AHORA: {result["active_matches"]} (solo IP rastreadas; no bloqueos del período).')
        show_diagnosis(result.get('diagnosis') or diagnose_domain(result))
        print('\n  Códigos HTTP: porcentaje sobre todas las peticiones leídas del período\n')
        table(('CÓDIGO', 'RESPUESTAS', '% PETICIONES'), http_rows(result), (12, 14, 18))
        temporal_rows = sorted(result.get('error_minutes', {}).items(), key=lambda item: (-sum(item[1][:2]), item[0]))[:10]
        print('\n  Minutos con más errores (no toda la distribución)\n')
        table(('MINUTO', '4xx', '5xx', '502/503/504', 'PETICIONES'),
              [(m, e[0], e[1], e[2], result['minutes'][m]) for m, e in temporal_rows], (28, 7, 7, 12, 12))
        for title, key, unit in [('URLs con más peticiones', 'urls', 'PETICIONES'),
                                 ('URLs con más transferencia (no mide CPU)', 'bytes_urls', 'BYTES'),
                                 ('Errores HTTP 4xx/5xx por URL', 'errors', 'PETICIONES'),
                                 ('Accesos a rutas sensibles (incluye usos legítimos)', 'sensitive_urls', 'PETICIONES'),
                                 ('IP con más peticiones (dirección registrada)', 'ip_counts', 'PETICIONES'),
                                 ('IP con más respuestas de error', 'error_clients', 'ERRORES')]:
            print('\n  ' + title + '\n')
            rows = [(f'{count:,}', ip_label(path) if key in ('ip_counts', 'error_clients') else path) for path, count in result.get(key, collections.Counter()).most_common(10)]
            table((unit, 'RUTA / IP'), rows, (12, 62))
            if not rows:
                print('  Sin datos observados.')
        print('\n  Mensajes internos PHP/nginx/Apache (fecha local del log)\n')
        table(('MENSAJES', 'CATEGORÍA'), [(str(count), category) for category, count in result['internal'].most_common()], (12, 62))
        if not result['internal']:
            print('  Sin mensajes interpretados para la fecha; revisa la cobertura.')
        print('\n  Las IP pueden ser proxies/CDN. No se verifica su identidad ni se bloquean.')
        if 'watch_history' in result:
            try:
                watch_module().show_history(result['watch_history'], result.get('watch_zone', dt.timezone.utc), sys.modules[__name__])
            except (OSError, RuntimeError, ValueError):
                print('  Incidencias guardadas no disponibles; no implica ausencia de errores.')
    print()


def compact_summary(result):
    """Retener solo cifras por dominio; nunca tablas de rutas o referencias al estado."""
    summary = {key: result[key] for key in ('total', 'bytes', 'earliest', 'latest')}
    summary['read'] = result.get('read', 0)
    summary['layer'] = result.get('layer')
    summary['rapid'] = result.get('rapid', False)
    summary['period_label'] = result.get('period_label')
    summary['period_days'] = result.get('period_days', 1)
    summary['selected_files'] = result.get('selected_files', [])
    for key in ('http4', 'http5', 'sensitive', 'sensitive4', 'peak'):
        summary[key] = result.get(key, 0)
    summary['peak_minute'] = result.get('peak_minute')
    summary['f2b_matches'] = result.get('f2b_matches')
    summary['diagnosis'] = result.get('diagnosis') or diagnose_domain(result)
    for key in ('unique_ips', 'observed_days', 'coverage', 'suspect_requests', 'indeterminate_requests', 'behavior_partial', 'suspect_ip_count'):
        summary[key] = result.get(key)
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


def traffic_key(row):
    domain, result = row
    available = bool(result.get('read') and result['total'])
    return (not available, -result['total'], -result['bytes'], domain)


OVERVIEW_COLUMNS = (
    ('DOMINIO', 32), ('PETICIONES', 10), ('MiB', 9), ('IP ÚNICAS', 10), ('BOTS %', 7),
    ('NAV. %', 7), ('DESC. %', 7), ('4xx (#)', 7), ('5xx (#)', 7),
    ('PICO/MIN', 8), ('ESTADO', 14),
)


def overview_line(values):
    cells = []
    for index, (value, (_, width)) in enumerate(zip(values, OVERVIEW_COLUMNS)):
        text = clean(value, 1000)
        if len(text) > width:
            text = text[:width-3] + '...'
        cells.append(text.ljust(width) if index in (0, 9) else text.rjust(width))
    return '  '.join(cells)


def show_overview_header():
    print('\n' + overview_line([title for title, _ in OVERVIEW_COLUMNS]))
    print('  '.join('-' * width for _, width in OVERVIEW_COLUMNS), flush=True)


def show_overview_row(domain, result):
    total = result['total']
    known = bool(result.get('read', 0))
    percent = lambda key: f'{100*result["counts"][key]/total:.1f}' if total else 'N/D'
    flags = []
    if not known or not total:
        flags.append('SIN FECHA')
    elif signals(result):
        flags.append('REV:' + str(len(signals(result))))
    else:
        flags.append(activity_level(result.get('peak', 0)))
    if result.get('rapid'):
        flags.append('M')
    ordinary = ('VISTA RÁPIDA:', 'Se omiten ', 'Vista rápida: cola', 'Límite de tiempo/bytes', 'Quedan archivos sin leer',
                'Selección por fechas de extractos:', 'Búsqueda rápida por fecha:', 'Candidato gzip elegido por fecha inicial;')
    if any(not note.startswith(ordinary) for note in result['notes']):
        flags.append('A')
    print(overview_line((domain, f'{total:,}' if known and total else 'N/D',
                         f'{result["bytes"]/1048576:.2f}' if known and total else 'N/D',
                         unique_text((result.get('unique_ips') or {}).get('all')) if total else 'N/D',
                         percent('bot'), percent('probable'), percent('unknown'),
                         f'{result.get("http4", 0):,}' if total else 'N/D',
                         f'{result.get("http5", 0):,}' if total else 'N/D',
                         f'{result.get("peak", 0):,}' if total else 'N/D', '/'.join(flags))), flush=True)


def overview_progress(text=''):
    # Mantener las filas limpias; el indicador temporal solo se usa en terminal.
    if sys.stderr.isatty():
        sys.stderr.write('\r' + ' ' * 110 + '\r' + clean(text, 100))
        sys.stderr.flush()


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
    if getattr(args, 'report', False):
        return True
    if not sys.stdin.isatty():
        print(f'Sin terminal interactiva: termino tras {PAGE_SIZE} dominios. Usa --report para auditar todos.')
        return False
    while True:
        command = input(f'\nEscribe start para analizar los siguientes {PAGE_SIZE}; q para terminar > ').strip().lower()
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
        ('Navegador aparente (no humanidad)', pct(result['counts']['probable'])),
        ('Desconocido', pct(result['counts']['unknown'])),
        ('Respuestas 4xx', f'{result.get("http4", 0):,} ({pct(result.get("http4", 0))})'),
        ('Respuestas 5xx', f'{result.get("http5", 0):,} ({pct(result.get("http5", 0))})'),
        ('Rutas sensibles / con respuesta 4xx', f'{result.get("sensitive", 0)} / {result.get("sensitive4", 0)}'),
        ('Pico de peticiones/minuto', result.get('peak', 0)),
        ('Actividad orientativa por volumen del pico', activity_level(result.get('peak', 0)) if total else 'N/D'),
        ('Minuto del pico', result.get('peak_minute') or 'N/D'),
        ('IP coincidentes con eventos Ban del período', result.get('f2b_matches') if result.get('f2b_matches') is not None else 'N/D'),
        ('Fuente de accesos', result.get('layer', 'N/D')),
        ('Archivos de la muestra', ', '.join(result.get('selected_files', [])) or 'Lectura ampliada / sin selección disponible'),
        ('Fechas encontradas en los logs', f'{result.get("earliest")} a {result.get("latest")}'),
    ]
    output = '<section><h2>' + esc(domain) + '</h2>' + html_table(('Métrica', 'Resultado'), metrics)
    output += '<h3>IP únicas y comportamiento</h3>' + html_table(('Medida', 'Valor'), observation_rows(result))
    output += '<p>' + esc(result.get('coverage', coverage_text(result))) + '</p>'
    output += '<p>IP no equivale a visitante. Categorías de IP solapadas. ~ = estimación HLL (2048 registros, error típico ~2,3%, no garantizado). Exacto hasta 1024 IP de la lectura. Comportamiento: primeras 1024 IP, 32 rutas/64 minutos por IP; hasta 20 hallazgos. No hay probabilidades de humanidad.</p>'
    output += html_table(('IP', 'Peticiones', 'Navegador aparente', 'Pico/min', 'Señales'),
                         [(ip_label(r['ip']), r['requests'], r['browser'], r['peak'], r['reasons']) for r in result.get('behavior', [])])
    output += '<h3>Rutas sensibles: posibles exposiciones primero</h3>' + html_table(
        ('Ruta', 'Total', '200', '401', '403', '404', 'Otros', 'IP y conteo', 'Revisión'), sensitive_rows(result))
    output += '<p>HTTP 200 no verifica contenido: posibles errores personalizados/front controller. No se descarga nada. Hasta 64 rutas y primeras 8 IP por ruta; ranking parcial si se rebasa el límite.</p>'
    d = result.get('diagnosis') or diagnose_domain(result, getattr(args, 'thresholds', THRESHOLDS))
    output += '<h3>Diagnóstico del período leído</h3>' + html_table(
        ('Salud web', 'Tráfico sospechoso', 'Impacto potencial'), [(d['health'], d['suspicious'], d['impact'])])
    output += '<p>Confianza: ' + esc(d['confidence']) + '. OK/BAJO solo describen lo leído.</p>'
    for title, key in (('Hechos medidos', 'facts'), ('Hipótesis', 'hypotheses'), ('Qué revisar en Plesk', 'actions')):
        output += '<h3>' + title + '</h3><ul>' + ''.join('<li>' + esc(item) + '</li>' for item in d[key]) + '</ul>'
    output += '<h3>Códigos HTTP · porcentaje de todas las peticiones leídas</h3>' + html_table(
        ('Código', 'Respuestas', '% peticiones'), http_rows(result))
    windows = sorted(result.get('error_minutes', {}).items(), key=lambda item: (-sum(item[1][:2]), item[0]))[:20]
    output += '<h3>Minutos con más errores (distribución limitada)</h3>' + html_table(
        ('Minuto', '4xx', '5xx', '502/503/504', 'Peticiones'),
        [(m, e[0], e[1], e[2], result.get('minutes', {}).get(m, 0)) for m, e in windows])
    findings = signals(result)
    output += '<h3>Indicadores para revisar</h3><ul>' + ''.join('<li>' + esc(f) + '</li>' for f in findings) + '</ul>'
    if not findings:
        output += '<p>Sin umbrales activados en los datos leídos; no descarta un ataque.</p>'
    for title, key in [('URLs con más peticiones', 'urls'), ('URLs con más bytes de respuesta', 'bytes_urls'),
                       ('Errores HTTP por ruta', 'errors'), ('Rutas sensibles consultadas', 'sensitive_urls'),
                       ('IP con más peticiones', 'ip_counts'), ('IP con más respuestas de error', 'error_clients'),
                       ('Mensajes internos por categoría', 'internal'),
                       ('Códigos HTTP', 'statuses')]:
        values = result.get(key, collections.Counter())
        output += '<h3>' + esc(title) + '</h3>'
        output += html_table(('Ruta / IP / categoría', 'Valor'), values.most_common(20))
    output += '<h3>Avisos de lectura</h3><ul>' + ''.join('<li>' + esc(note) + '</li>' for note in sorted(result['notes'])) + '</ul>'
    if 'watch_history' in result:
        try:
            output += watch_module().history_html(result['watch_history'], args.zone, sys.modules[__name__])
        except (OSError, RuntimeError, ValueError):
            output += '<p>Incidencias guardadas no disponibles; no implica ausencia de errores.</p>'
    return output + '</section>'


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
        self.write('<p>Período analizado: ' + html.escape(str(getattr(args, 'period_label', args.day))) + ' · Zona: ' + html.escape(args.timezone) +
                   f' · Dominios seleccionados: {total} · Versión: {VERSION}</p>')
        self.write('<p>Servidor de esta ejecución: ' + html.escape(getattr(args, 'server_label', 'servidor local')) +
                   '. Correlación limitada a este recorrido; no se importan resultados de otros servidores.</p>')
        self.write('<p>Umbrales de diagnóstico: ' + html.escape(', '.join(f'{k}={v:g}' for k, v in getattr(args, 'thresholds', THRESHOLDS).items())) + '</p>')
        self.write('<p>Informe de logs disponibles. Una petición puede ser una página, imagen, CSS o API; no equivale a una persona. '
                   'Transferencia es el tamaño de respuestas registrado; 4xx son rechazos/no encontrados y 5xx errores del servidor. '
                   'Los porcentajes usan las peticiones leídas de la fecha. User-Agent de navegador no demuestra humanidad. '
                   'Un pico no confirma un ataque. Actividad: baja &lt;60/min, moderada 60–599, alta 600–2999, muy alta &gt;=3000; no compara con el historial de cada web. RAM/CPU históricas por dominio no están disponibles. '
                   'Rankings limitados a 2000 valores; se muestran los 20 primeros. Retención, rotación y formatos pueden limitar la cobertura.</p>')
        if args.sample:
            self.write('<p><strong>MODO MUESTRA: cada dominio puede contener solo parte de sus registros.</strong></p>')
        self.write('<p><strong>Hasta que figure un resumen final de recorrido terminado, considera este informe parcial.</strong></p>')
        active = getattr(args, 'active_bans', None)
        if active:
            self.write('<h2>Fail2Ban ACTIVO AHORA · ' + html.escape(active['at']) + '</h2>' +
                       html_table(('Jail', 'Actualmente bloqueadas', 'Hasta 20 IP'), active['jails']))
            self.write('<p>Instantánea actual independiente del período histórico. Cloudflare: lista oficial incluida, verificada 2026-10-20. No se cambian bloqueos.</p><ul>' +
                       ''.join('<li>' + html.escape(note) + '</li>' for note in active['notes']) + '</ul>')
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
        footer += '<h3>DOMINIOS QUE REQUIEREN ATENCIÓN</h3><p>Prioridad: salud web, impacto potencial y tráfico sospechoso; después número de 5xx. Hechos, hipótesis y pasos de revisión en el apartado de cada dominio.</p>'
        attention = sorted((r for r in rows if (r[1].get('diagnosis') or diagnose_domain(r[1]))['attention']), key=diagnosis_key)
        footer += html_table(ATTENTION_HEADERS, [attention_values(*row) for row in attention[:100]])
        if not attention:
            footer += '<p>Sin condiciones activadas en la lectura; no descarta problemas ni falta de datos.</p>'
        shared = getattr(self.args, 'shared', None)
        if shared and shared.findings():
            footer += '<h3>POSIBLE INCIDENCIA COMPARTIDA DEL SERVIDOR</h3>' + html_table(
                ('Minuto', 'Hecho observado', 'Dominios'), shared.findings())
            footer += '<p>Hipótesis para investigar servicios comunes; no demuestra un aumento ni una causa compartida. Solo dominios de esta ejecución/servidor.</p>'
        if shared and shared.partial:
            footer += '<p>Correlación parcial por límites: 2048 minutos, 8 dominios/grupo.</p>'
        footer += '<p>Hasta 100 dominios destacados y 20 coincidencias; muestras pueden ocultar problemas. No atribuye CPU/RAM.</p></section></body></html>'
        self.write(footer, closing=True)
        self.stream.close()
        self.finished = True
        return complete and not self.truncated

    def close(self):
        if not self.finished:
            self.write('<p>INFORME INTERRUMPIDO. No se ha completado la auditoría.</p></body></html>', closing=True)
            self.stream.close()
            self.finished = True


def finish_audit(args, rows):
    if not getattr(args, 'audit', None):
        return
    complete = args.audit.finish(rows)
    print('\nHTML privado guardado en: ' + args.audit.path, flush=True)
    if not complete:
        print('El informe tiene avisos, límites o dominios pendientes; revisa su cobertura.')


def collect_ranked(root, domains, day, zone, args):
    rows = []
    args.shared = SharedIncidents(getattr(args, 'thresholds', THRESHOLDS))
    print('\nUna fila por dominio. Peticiones/porcentajes se refieren a los accesos leídos del período.')
    print('MiB = contenido enviado; NAV. = navegador aparente, no humano demostrado; DESC. = sin identificar; 4xx/5xx = respuestas.')
    print('ESTADO: REV:n = umbrales activados; M = muestra, no total diario; A = avisos; SIN FECHA = sin accesos de la fecha.')
    print('BAJA/MODERADA/ALTA = volumen orientativo del pico; no confirma ni descarta ataques.')
    print('Para explicaciones, rutas, IP y avisos completos: ejecuta el comando indicando un dominio.')
    for number, domain in enumerate(domains, 1):
        try:
            if number > 1 and (number - 1) % PAGE_SIZE == 0 and not next_batch(args):
                break
            if (number - 1) % PAGE_SIZE == 0:
                show_overview_header()
            if getattr(args, 'sample', False):
                reason = pressure(args.gentle, rapid=True)
                if reason:
                    print(f'\nRecorrido incompleto: {reason}', flush=True)
                    break
            else:
                wait_for_capacity(args.gentle, time.monotonic() + 30)
            overview_progress(f'[{number}/{len(domains)}] Leyendo {domain}…')
            result = analyze(root, domain, day, zone, args)
            overview_progress()
            args.shared.add(domain, result)
            if getattr(args, 'audit', None):
                args.audit.append(domain, result)
            summary = compact_summary(result)
            rows.append((domain, summary))
            show_overview_row(domain, summary)
            sys.stdout.flush()
            del result
        except KeyboardInterrupt:
            overview_progress()
            print('\nLectura interrumpida: mostraré el resumen de los dominios ya terminados.', flush=True)
            break
    rows.sort(key=traffic_key)
    print('\n' + '=' * 80)
    print(f' TABLA FINAL · MÁS A MENOS PETICIONES LEÍDAS · {len(rows)}/{len(domains)} dominios')
    print('=' * 80)
    if len(rows) < len(domains):
        print(f'{len(domains) - len(rows)} dominios pendientes; no están incluidos en el ranking.')
    return rows


def arguments(argv=None):
    parser = argparse.ArgumentParser(description='Audithor — steev anderson. Filas progresivas, tabla final por tráfico y diagnóstico de salud/impacto potencial.',
                                     epilog='Diagnóstico basado en lo leído, sin atribuir CPU/RAM. Umbrales: ' +
                                     ', '.join(f'{key}={value:g}' for key, value in THRESHOLDS.items()))
    parser.add_argument('--version', action='version', version='Audithor ' + VERSION)
    parser.add_argument('domain', nargs='?', help='Dominio exacto para informe detallado')
    parser.add_argument('--watch', action='store_true', help='Vigilar manualmente solo eventos nuevos de un dominio; SQLite privado en data/')
    parser.add_argument('--watch-seconds', type=int, default=900, help='Duración manual máxima de --watch (1–3600 s; también rige --run-seconds)')
    dates = parser.add_mutually_exclusive_group()
    dates.add_argument('--yesterday', action='store_true', help='Ayer en la zona horaria elegida')
    dates.add_argument('--date', help='Fecha YYYY-MM-DD; solo si quedan logs')
    dates.add_argument('--week', action='store_true', help='Últimos siete días naturales, incluido hoy, en la zona elegida')
    parser.add_argument('--timezone', default='Europe/Madrid')
    parser.add_argument('--root', default='/var/www/vhosts/system', help='Raíz de logs Plesk; no se modifica')
    parser.add_argument('--gzip', action='store_true', help='Incluir históricos comprimidos dentro del mismo presupuesto')
    parser.add_argument('--no-fail2ban', action='store_true', help='Omitir lectura del historial Fail2Ban')
    parser.add_argument('--fail2ban-active', action='store_true', help='Consultar status actual de jails mediante cliente local; solo lectura, opcional')
    parser.add_argument('--fail2ban-log', default='/var/log/fail2ban.log', help='Archivo de historial Fail2Ban, sin modificarlo')
    parser.add_argument('--report', action='store_true', help='Guardar HTML local de todos los dominios; usa --full para ampliar la lectura')
    parser.add_argument('--seconds', type=int, default=5, help='Segundos por dominio en vista rápida; por tanda con --full (1–1800)')
    parser.add_argument('--max-mib', type=int, default=8, help='MiB descomprimidos por dominio; por tanda con --full (1–1024)')
    parser.add_argument('--once', action='store_true', help=f'Analizar únicamente la primera tanda de {PAGE_SIZE} dominios')
    parser.add_argument('--diagnose', action='store_true', help='Mostrar carga, CPU lógicas y memoria; sin analizar dominios')
    parser.add_argument('--resources', action='store_true', help='Solo instantánea ACTUAL de carga, memoria, PSI, OOM acumulado y procesos; sin logs históricos')
    parser.add_argument('--threshold', action='append', default=[], metavar='NOMBRE=VALOR',
                        help='Ajustar un umbral de diagnóstico; repetible. Valores predeterminados al final de esta ayuda')
    parser.add_argument('--inspect-logs', action='store_true', help='Con un dominio, mostrar archivos y fechas de extractos pequeños, sin tráfico privado')
    parser.add_argument('--gentle', action='store_true', help='Reduce los objetivos de CPU y lectura del propio proceso')
    parser.add_argument('--allow-long-scan', action='store_true', help='Autorizar límites por dominio mayores de 30 s/64 MiB; nunca elimina los límites globales')
    parser.add_argument('--run-seconds', type=int, default=900, help='Límite real global, incluidas esperas y pausas interactivas (1–3600; predeterminado 900 s)')
    parser.add_argument('--cpu-seconds', type=int, default=30, help='Presupuesto CPU del proceso impuesto por kernel (1–120; predeterminado 30 s)')
    parser.add_argument('--run-mib', type=int, default=256, help='Techo acumulado para lectura bruta y, por separado, descomprimida (1–2048; predeterminado 256 MiB cada una)')
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('--full', action='store_true', help='Recorrer todos los históricos; puede tardar mucho y esperar por carga')
    modes.add_argument('--sample', action='store_true', help='Vista rápida limitada (ya es el modo predeterminado)')
    args = parser.parse_args(argv)
    if not 1 <= args.watch_seconds <= 3600:
        parser.error('--watch-seconds fuera de rango.')
    if args.watch and (not args.domain or args.full or args.yesterday or args.date or args.week or args.gzip or
                       args.report or args.diagnose or args.resources or args.inspect_logs or args.fail2ban_active or args.once):
        parser.error('--watch requiere un solo dominio y no admite históricos, --full, --report, diagnósticos ni Fail2Ban activo.')
    if not (1 <= args.run_seconds <= 3600 and 1 <= args.cpu_seconds <= 120 and 1 <= args.run_mib <= 2048):
        parser.error('Límites globales fuera de rango.')
    if not args.allow_long_scan and (args.seconds > 30 or args.max_mib > 64 or args.run_seconds > 900 or args.cpu_seconds > 30 or args.run_mib > 256):
        parser.error('Para ampliar los límites de seguridad usa explícitamente --allow-long-scan.')
    args.thresholds = THRESHOLDS.copy()
    for value in args.threshold:
        try:
            name, raw = value.split('=', 1)
            number = float(raw)
            if name not in THRESHOLDS or not math.isfinite(number) or number <= 0:
                raise ValueError
            if name.endswith('_pct'):
                if number > 100:
                    raise ValueError
            elif name == 'slow_seconds':
                if number > 600:
                    raise ValueError
            elif number != int(number) or number > 1000000:
                raise ValueError
            if name == 'sustained_minutes' and number > 60:
                raise ValueError
            if name == 'shared_domains' and not 2 <= number <= 8:
                raise ValueError
            args.thresholds[name] = number
        except ValueError:
            parser.error('Umbral no válido: usa un nombre de la ayuda y un valor positivo finito dentro de rango.')
    t = args.thresholds
    if (t['health_critical_count'] < t['health_review_count'] or t['health_critical_pct'] < t['health_review_pct'] or
            t['sensitive_high'] < t['sensitive_review']):
        parser.error('Los umbrales críticos/altos no pueden ser menores que los de revisión.')
    args.sample = not args.full
    if args.inspect_logs and not args.domain:
        parser.error('--inspect-logs requiere indicar un dominio.')
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
        args.start_day = args.day - dt.timedelta(days=6) if args.week else args.day
        args.period_label = str(args.start_day) + ' a ' + str(args.day) if args.week else str(args.day)
        args.historical = args.start_day < today
        args.day_offset = (today - args.start_day).days
        # --yesterday debe buscar automáticamente en los históricos comprimidos.
        args.gzip = args.gzip or args.historical
    except (ValueError, ZoneInfoNotFoundError):
        parser.error('Fecha o zona horaria no válida. Comprueba los datos tzdata del sistema.')
    return args


_WATCH_MODULE = None


def watch_module():
    """Cargar el módulo vecino con -I sin añadir directorios de importación."""
    global _WATCH_MODULE
    if _WATCH_MODULE is None:
        folder = directory(os.path.dirname(os.path.abspath(__file__)))
        try:
            with regular(folder, 'audithor_watch.py') as stream:
                info = os.fstat(stream.fileno())
                if info.st_uid not in (0, os.geteuid()) or stat.S_IMODE(info.st_mode) & 0o022:
                    raise RuntimeError('audithor_watch.py no debe ser modificable por otras cuentas.')
                source = stream.read(128 * 1024 + 1)
                if len(source) > 128 * 1024:
                    raise RuntimeError('Módulo watch supera el tamaño permitido.')
        finally:
            os.close(folder)
        module = types.ModuleType('audithor_watch_private')
        try:
            exec(compile(source, 'audithor_watch.py', 'exec'), module.__dict__)
        except (ImportError, SyntaxError) as exc:
            raise RuntimeError('Módulo watch no disponible: comprueba audithor_watch.py y sqlite3/ctypes de Python.') from exc
        _WATCH_MODULE = module
    return _WATCH_MODULE


def saved_history(args):
    try:
        return watch_module().read_history(args, sys.modules[__name__])
    except (OSError, RuntimeError, ValueError):
        return dict(events=[], sessions=[], gaps=[], message='Vigilancia guardada no disponible; no implica ausencia de errores.')


def main(argv=None):
    args = arguments(argv)
    if getattr(args, 'watch', False):
        return watch_module().run_watch(args, sys.modules[__name__])
    with RunGuard(args):
        return guarded_main(args)


def guarded_main(args):
    if getattr(args, 'resources', False):
        if not hasattr(os, 'O_NOFOLLOW'):
            raise RuntimeError('--resources requiere Linux.')
        show_current_resources()
        return 0
    if args.diagnose:
        cpus, loads, available = status = host_status()
        print(BANNER)
        print(f'CPU lógicas detectadas: {cpus}')
        print('Carga media 1/5/15 min: ' + ' / '.join(f'{load:.2f}' for load in loads))
        factor = LOAD_PER_CPU
        print(f'Umbral de espera solo para --full: {cpus * factor:.2f} ({factor:g} por CPU lógica)')
        print(f'MemAvailable: {available:.0f} MiB; mínimo: 256 MiB')
        print('La carga media NO es un porcentaje de CPU; puede incluir espera de disco.')
        print(pressure_reason(status, args.gentle, rapid=True) or 'Vista rápida: memoria suficiente; con carga alta reduce su ritmo, sin esperar indefinidamente.')
        print('Diagnóstico de solo lectura; no se han abierto logs de dominios.')
        return 0
    return run_analysis(args)


def run_analysis(args):
    print(BANNER)
    print('Audithor ' + VERSION)
    args.server_label = clean(os.uname().nodename, 120)
    print('Servidor de esta ejecución: ' + args.server_label)
    print(f'Período: {args.period_label} ({args.timezone}). Secuencial; memoria virtual máxima 128 MiB.')
    print(f'Tandas de {args.seconds}s/{args.max_mib} MiB. ' + ('MUESTRA limitada por dominio.' if args.sample else 'LECTURA CONTINUA: descansa y continúa hasta finalizar los archivos seleccionados.'))
    print(f'Límites efectivos: {args.run_seconds}s reales, {args.cpu_seconds}s CPU, {args.run_mib} MiB acumulados; una sola ejecución.')
    if args.full:
        print(f'--full acotado por dominio: {max(30, args.seconds)}s / {max(64, args.max_mib)} MiB; puede terminar parcial.')
    print('Logs en solo lectura. Sin instalaciones, cron ni cambios en Plesk, servicios o permisos de las webs.')
    if args.report:
        print('Modo auditoría: todos los dominios seleccionados, sin esperar start; HTML privado en reports/.')
    print('Bots declarados, navegadores aparentes y señales de comportamiento no identifican personas ni confirman ataques.')
    print('Diagnóstico: salud, tráfico sospechoso e impacto potencial; sin atribución de CPU/RAM.')
    if args.threshold:
        print('Umbrales personalizados: ' + ', '.join(args.threshold))
    if args.historical:
        print('Fecha histórica: gzip incluido automáticamente; prioridad a logs rotados.')
    if args.gentle:
        print('Modo suave: objetivos aproximados de CPU/lectura más bajos; regulación por bloques.')
    if args.sample or args.inspect_logs:
        reason = pressure(args.gentle, rapid=True)
        if reason:
            raise RuntimeError(reason)
        print('VISTA RÁPIDA: archivos probables de la fecha; límites por dominio, sin espera indefinida por carga.')
    else:
        wait_for_capacity(args.gentle, time.monotonic() + 30)
    root = directory(args.root)
    args.audit = None
    try:
        if args.inspect_logs:
            inspect_logs(root, args)
            return 0
        domains = [args.domain] if args.domain else discover(root)
        if not domains:
            print('No se encontraron dominios accesibles.')
            return 0
        args.bans = None
        args.active_bans = None
        if args.fail2ban_active:
            args.active_bans = read_active_fail2ban()
            show_active_fail2ban(args.active_bans)
        if args.domain or args.report:
            print('\nLeyendo historial Fail2Ban…', flush=True)
            args.bans = read_fail2ban(args)
            if args.domain:
                show_fail2ban(args.bans, args.period_label)
        if args.report:
            args.audit = HtmlAudit(args, len(domains))
            print('Creando informe privado: ' + args.audit.path, flush=True)
        if args.domain:
            print('\nLeyendo ' + args.domain + '…', flush=True)
            result = analyze(root, args.domain, args.day, args.zone, args)
            result['watch_history'] = saved_history(args)
            result['watch_zone'] = args.zone
            show(args.domain, args.day, result, True)
            if args.audit:
                args.audit.append(args.domain, result)
                finish_audit(args, [(args.domain, compact_summary(result))])
            return 0
        rows = collect_ranked(root, domains, args.day, args.zone, args)
        finish_audit(args, rows)
        for offset in range(0, len(rows), PAGE_SIZE):
            show_overview_header()
            for domain, summary in rows[offset:offset+PAGE_SIZE]:
                show_overview_row(domain, summary)
            if offset + PAGE_SIZE >= len(rows) or args.once or args.report or not sys.stdin.isatty():
                break
            if input(f'\nEnter: siguientes {PAGE_SIZE} | q + Enter: salir > ').strip().lower() in ('q', 'salir'):
                break
        show_attention(rows, args.shared)
    finally:
        if args.audit:
            args.audit.close()
        os.close(root)
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (KeyboardInterrupt, EOFError):
        print('\nAudithor detenido; configuración del servidor sin cambios.')
        sys.exit(130)
    except SafetyLimit as error:
        print('Audithor: ' + clean(str(error)) + ' Resultados parciales.', file=sys.stderr)
        sys.exit(75)
    except (OSError, RuntimeError, ValueError, MemoryError) as error:
        print('Audithor: ' + clean(str(error)), file=sys.stderr)
        sys.exit(1)
