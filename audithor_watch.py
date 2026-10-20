"""Vigilancia manual, acotada, sin servicios ni búsquedas por las webs. Python 3.9+."""
import collections
import ctypes
import datetime as dt
import hashlib
import os
import re
import select
import sqlite3
import stat
import struct
import time
from urllib.parse import quote

ERROR_LOGS = ('proxy_error_log', 'error_log', 'php_error.log', 'php_error_log',
              'php_errors.log', 'php-fpm.log', 'php_fpm_error.log')
MAX_LINE = 8192
MAX_FILES = 16
MAX_QUEUE = 128
MAX_EVENTS_MINUTE = 120
MAX_DB = 8 * 1048576


def utc_now():
    return int(time.time())


def private_data(api, create=False, base=None):
    """Descriptor de data: sin enlaces, dueño actual, permisos privados."""
    parent = api.directory(base or os.path.dirname(os.path.abspath(api.__file__)))
    try:
        if create:
            try:
                os.mkdir('data', 0o700, dir_fd=parent)
            except FileExistsError:
                pass
        folder = api.directory('data', parent)
    finally:
        os.close(parent)
    info = os.fstat(folder)
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
        os.close(folder)
        raise ValueError('data/ debe pertenecer al usuario actual y ser privada (700); no se cambian sus permisos.')
    return folder


def check_data_files(folder):
    for name in ('audithor.sqlite', 'audithor.sqlite-journal', 'audithor.sqlite-wal', 'audithor.sqlite-shm'):
        try:
            info = os.stat(name, dir_fd=folder, follow_symlinks=False)
        except FileNotFoundError:
            continue
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or
                stat.S_IMODE(info.st_mode) & 0o077 or info.st_nlink != 1):
            raise ValueError('Archivo SQLite auxiliar inseguro; se cancela sin modificarlo.')
        if info.st_size > (MAX_DB if name == 'audithor.sqlite' else MAX_DB + 65536):
            raise ValueError('SQLite existente supera el límite; no se amplía ni se compacta.')


def db_path(folder):
    # El descriptor mantiene la carpeta autorizada aunque se renombre su ruta.
    return '/proc/self/fd/' + str(folder) + '/audithor.sqlite'


class Store:
    def __init__(self, path, domain, files='', now=None):
        self.domain = domain
        self.files = files[:512]
        self.queue = {}
        self.pending_gaps = collections.Counter()
        self.omitted = 0
        self.omitted_bytes = 0
        self.failures = 0
        self.closed = False
        self.db = sqlite3.connect(path, timeout=.1)
        try:
            self._initialize(files, now)
        except BaseException:
            self.db.close()
            raise

    def _initialize(self, files, now):
        self.db.execute('PRAGMA trusted_schema=OFF')
        self.db.execute('PRAGMA mmap_size=0')
        self.db.execute('PRAGMA cache_size=-512')
        self.db.execute('PRAGMA temp_store=MEMORY')
        self.db.execute('PRAGMA journal_mode=DELETE')
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.execute('PRAGMA page_size=4096')
        if self.db.execute('PRAGMA page_size').fetchone()[0] != 4096:
            self.db.close()
            raise ValueError('Tamaño de página SQLite incompatible.')
        if self.db.execute('PRAGMA max_page_count=2048').fetchone()[0] != 2048:
            raise ValueError('SQLite existente supera el límite de páginas.')
        version = self.db.execute('PRAGMA user_version').fetchone()[0]
        if version not in (0, 1):
            self.db.close()
            raise ValueError('Esquema de incidencias desconocido; no se cambia.')
        self.db.executescript('''
CREATE TABLE IF NOT EXISTS sessions (
 id TEXT PRIMARY KEY, domain TEXT NOT NULL, started INTEGER NOT NULL,
 heartbeat INTEGER NOT NULL, ended INTEGER, reason TEXT, files TEXT,
 omitted INTEGER NOT NULL DEFAULT 0, omitted_bytes INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS sessions_period ON sessions(domain,started,heartbeat);
CREATE TABLE IF NOT EXISTS incidents (
 id INTEGER PRIMARY KEY, domain TEXT NOT NULL, bucket INTEGER NOT NULL,
 signature TEXT NOT NULL, kind TEXT, severity TEXT, code INTEGER, route TEXT,
 php_file TEXT, php_line INTEGER, service TEXT, evidence TEXT,
 first_seen INTEGER, last_seen INTEGER, logged_first INTEGER, logged_last INTEGER,
 frequency INTEGER NOT NULL, UNIQUE(domain,bucket,signature));
CREATE INDEX IF NOT EXISTS incidents_period ON incidents(domain,bucket);
CREATE TABLE IF NOT EXISTS gaps (
 id INTEGER PRIMARY KEY, session TEXT, at INTEGER, reason TEXT, amount INTEGER, bytes INTEGER);
CREATE INDEX IF NOT EXISTS gaps_session ON gaps(session,at);
PRAGMA user_version=1;
''')
        self.session = os.urandom(12).hex()
        now = utc_now() if now is None else now
        self.db.execute('INSERT INTO sessions(id,domain,started,heartbeat,files) VALUES(?,?,?,?,?)',
                        (self.session, self.domain, now, now, self.files))
        self.db.commit()
        self.rate_minute = now // 60
        self.rate_count = 0

    def loss(self, reason, amount=0, byte_count=0):
        self.omitted = min(2 ** 63 - 1, self.omitted + max(0, amount))
        self.omitted_bytes = min(2 ** 63 - 1, self.omitted_bytes + max(0, byte_count))
        # Etiquetas del programa, nunca mensajes libres del log.
        key = reason if reason in self.pending_gaps or len(self.pending_gaps) < 16 else 'otros límites de cobertura'
        old = self.pending_gaps.get(key, (0, 0))
        self.pending_gaps[key] = (min(2 ** 63 - 1, old[0] + max(0, amount)),
                                  min(2 ** 63 - 1, old[1] + max(0, byte_count)))

    def enqueue(self, incident, now=None):
        now = utc_now() if now is None else now
        if now // 60 != self.rate_minute:
            self.rate_minute, self.rate_count = now // 60, 0
        if self.rate_count >= MAX_EVENTS_MINUTE:
            self.loss('límite de incidencias por minuto', 1)
            return False
        self.rate_count += 1
        stamp = incident.get('logged_at')
        bucket = (stamp if stamp is not None else now) // 60 * 60
        fields = tuple(incident.get(k) for k in ('kind', 'severity', 'code', 'route', 'php_file', 'php_line', 'service', 'evidence'))
        signature = hashlib.sha256(repr(fields).encode('utf-8')).hexdigest()[:32]
        key = (bucket, signature)
        if key in self.queue:
            item = self.queue[key]
            item[2] += 1
            item[3] = now
            if stamp is not None:
                item[5] = max(item[5] if item[5] is not None else stamp, stamp)
            return True
        if len(self.queue) >= MAX_QUEUE:
            self.loss('cola de escritura llena', 1)
            return False
        self.queue[key] = [fields, now, 1, now, stamp, stamp]
        return True

    def flush(self, now=None):
        now = utc_now() if now is None else now
        deadline = time.monotonic() + .2
        self.db.set_progress_handler(lambda: int(time.monotonic() >= deadline), 500)
        try:
            with self.db:
                # Retención de siete días, purga incremental y sin VACUUM.
                self.db.execute('DELETE FROM incidents WHERE id IN (SELECT id FROM incidents WHERE bucket<? ORDER BY bucket LIMIT 250)', (now - 7 * 86400,))
                total = self.db.execute('SELECT count(*) FROM incidents').fetchone()[0]
                if total + len(self.queue) > 10000:
                    self.db.execute('DELETE FROM incidents WHERE id IN (SELECT id FROM incidents ORDER BY bucket LIMIT ?)',
                                    (min(250, total + len(self.queue) - 10000),))
                    self.loss('retención por límite de filas')
                for (bucket, signature), item in self.queue.items():
                    if time.monotonic() >= deadline:
                        raise sqlite3.OperationalError('presupuesto de escritura agotado')
                    fields, first, count, last, logged_first, logged_last = item
                    self.db.execute('''INSERT INTO incidents(domain,bucket,signature,kind,severity,code,route,php_file,php_line,service,evidence,
 first_seen,last_seen,logged_first,logged_last,frequency) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
 ON CONFLICT(domain,bucket,signature) DO UPDATE SET last_seen=excluded.last_seen,
 logged_last=COALESCE(excluded.logged_last,incidents.logged_last),frequency=incidents.frequency+excluded.frequency''',
                                    (self.domain, bucket, signature) + fields + (first, last, logged_first, logged_last, count))
                for reason, (amount, byte_count) in self.pending_gaps.items():
                    self.db.execute('INSERT INTO gaps(session,at,reason,amount,bytes) VALUES(?,?,?,?,?)',
                                    (self.session, now, reason, amount, byte_count))
                self.db.execute('UPDATE sessions SET heartbeat=?,omitted=?,omitted_bytes=?,files=? WHERE id=?',
                                (now, self.omitted, self.omitted_bytes, self.files, self.session))
                self.db.execute('DELETE FROM gaps WHERE id IN (SELECT id FROM gaps ORDER BY at LIMIT max(0,(SELECT count(*) FROM gaps)-2000))')
                self.db.execute('DELETE FROM gaps WHERE id IN (SELECT id FROM gaps WHERE at<? LIMIT 250)', (now - 7 * 86400,))
                self.db.execute('DELETE FROM sessions WHERE id IN (SELECT id FROM sessions WHERE id<>? AND heartbeat<? LIMIT 250)',
                                (self.session, now - 7 * 86400))
                self.db.execute('DELETE FROM sessions WHERE id IN (SELECT id FROM sessions WHERE id<>? ORDER BY heartbeat LIMIT max(0,(SELECT count(*) FROM sessions)-500))', (self.session,))
            self.queue.clear()
            self.pending_gaps.clear()
            self.failures = 0
            return True
        except sqlite3.Error:
            self.db.set_progress_handler(None, 0)
            self.db.rollback()
            self.failures += 1
            # Cola limitada: después del fallo no se acumula un histórico en RAM.
            self.loss('SQLite ocupado, lleno o escritura interrumpida', sum(item[2] for item in self.queue.values()))
            self.queue.clear()
            return False
        finally:
            self.db.set_progress_handler(None, 0)

    def close(self, reason='fin manual', now=None):
        if self.closed:
            return
        try:
            now = utc_now() if now is None else now
            if self.flush(now):
                with self.db:
                    self.db.execute('UPDATE sessions SET ended=?,reason=? WHERE id=?', (now, reason[:120], self.session))
        finally:
            self.db.close()
            self.closed = True


def log_stamp(text, zone, api):
    patterns = (
        (r'^(\d{4}/\d\d/\d\d \d\d:\d\d:\d\d)', '%Y/%m/%d %H:%M:%S'),
        (r'^\[\w{3} (\w{3}\s+\d{1,2} \d\d:\d\d:\d\d)(?:\.\d+)? (\d{4})\]', None),
        (r'^\[(\d\d-\w{3}-\d{4} \d\d:\d\d:\d\d)(?: [^\]]{1,40})?\]', '%d-%b-%Y %H:%M:%S'),
        (r'^\[?(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)', '%Y-%m-%d %H:%M:%S'))
    for pattern, fmt in patterns:
        match = re.match(pattern, text)
        if not match:
            continue
        try:
            if fmt is None:
                mon, day, clock = match[1].split()
                h, minute, sec = map(int, clock.split(':'))
                stamp = dt.datetime(int(match[2]), api.MONTHS[mon], int(day), h, minute, sec, tzinfo=zone)
            elif '%b' in fmt:
                # No depender del locale instalado en el servidor.
                date, clock = match[1].split()
                day, mon, year = date.split('-')
                h, minute, sec = map(int, clock.split(':'))
                stamp = dt.datetime(int(year), api.MONTHS[mon], int(day), h, minute, sec, tzinfo=zone)
            else:
                stamp = dt.datetime.strptime(match[1], fmt).replace(tzinfo=zone)
            return int(stamp.timestamp())
        except (ValueError, KeyError, OverflowError):
            return None
    return None


def private_route(raw, api):
    """Conservar estructura y rutas conocidas; ocultar segmentos variables y consultas."""
    known = {'.env', '.git', 'config', 'wp-admin', 'wp-login.php', 'xmlrpc.php', 'wp-json', 'api',
             'admin', 'login', 'cart', 'checkout', 'index.php', 'wp-config.php'}
    route = api.safe_path(raw)
    if not route.startswith('/'):
        return None
    return '/'.join(segment if segment in known or not segment else ':segmento' for segment in route.split('/'))[:180]


def parse_incident(raw, name, zone, api):
    """Evidencia estructurada: nunca conservar mensajes libres, SQL ni trazas."""
    if len(raw) > MAX_LINE:
        return None
    is_access = 'access' in name
    if is_access:
        event = api.parse(raw, zone)
        if not event:
            return None
        code = event[2]
        if code not in (500, 502, 503, 504):
            return None
        match = api.ACCESS.match(raw)
        stamp = int(api.parse_stamp(match[2], zone).timestamp())
        return dict(kind='HTTP ' + str(code), severity='ERROR', code=code, route=private_route(event[1], api),
                    php_file=None, php_line=None, service='Nginx' if name.startswith('proxy_') else 'Apache',
                    evidence=f'Respuesta HTTP {code} registrada en acceso; no demuestra causa interna.', logged_at=stamp)
    text = raw.decode('utf-8', 'replace')
    low = text.lower()
    definitions = (
        (r'allowed memory size|out of memory|cannot allocate memory', 'Límite de memoria', 'CRÍTICA', 'aplicación'),
        (r'php fatal|fatal error', 'PHP Fatal', 'CRÍTICA', 'aplicación'),
        (r'sqlstate|sql syntax|mysql server has gone away|too many connections|deadlock found', 'Error SQL registrado', 'ERROR', 'aplicación'),
        (r'uncaught|\bexception\b|pdoexception|mysqli_sql_exception', 'Excepción registrada', 'ERROR', 'aplicación'),
        (r'pm\.max_children|max_children|unable to fork|pool .*seems busy', 'Límite PHP-FPM', 'ERROR', 'PHP-FPM'),
        (r'\[pool [^\]]+\].*child .*exited|request_terminate_timeout', 'Problema PHP-FPM', 'ERROR', 'PHP-FPM'),
        (r'upstream timed out|request timed out|execution timed out', 'Timeout registrado', 'ERROR', 'Nginx'),
        (r'permission denied|operation not permitted', 'Permiso denegado', 'ERROR', None),
        (r'connect\(\) failed|connection refused|failed to connect to backend', 'Conexión backend fallida', 'ERROR', None),
        (r'php warning', 'PHP Warning', 'AVISO', 'aplicación'),
        (r'\[error\]|:error\]|\[crit\]|\[alert\]', 'Error de servicio', 'ERROR', None))
    found = next(((kind, severity, service) for pattern, kind, severity, service in definitions if re.search(pattern, low)), None)
    if not found:
        return None
    kind, severity, service = found
    service = service or ('Nginx' if name == 'proxy_error_log' else 'Apache' if name == 'error_log' else 'aplicación')
    # Solo un nombre PHP, nunca ruta completa, argumentos, código fuente ni traza.
    file_match = re.search(r'\bin ([/A-Za-z0-9_.-]{1,240}\.php)(?::(\d{1,7})| on line (\d{1,7}))', text)
    php_file = api.safe_path('/' + os.path.basename(file_match[1]))[1:] if file_match else None
    if php_file and re.search(r'password|token|cookie|session|secret|api.key', php_file, re.I):
        php_file = '[archivo PHP redactado]'
    php_line = int(file_match[2] or file_match[3]) if file_match else None
    request = re.search(r'\brequest:\s*"[A-Z]+ ([^" ]{1,2048}) HTTP/[0-9.]+"', text)
    route = private_route(request[1], api) if request else None
    # El marcador es fijo: incluso un SQL con contraseña no puede llegar al almacén.
    evidence = kind + ' registrado en ' + name
    sqlstate = re.search(r'SQLSTATE\[([A-Z0-9]{5})\]', text)
    if sqlstate:
        evidence += '; SQLSTATE[' + sqlstate[1] + ']'
    if php_file:
        evidence += '; archivo PHP ' + php_file + '; línea ' + str(php_line)
    stamp = log_stamp(text, zone, api)
    if stamp is None:
        evidence += '; fecha no interpretable: se indica hora de observación'
    return dict(kind=kind, severity=severity, code=None, route=route, php_file=php_file,
                php_line=php_line, service=service, evidence=evidence[:256], logged_at=stamp)


class Tail:
    def __init__(self, fd, name, at_end=True, api=None):
        self.fd = fd
        self.api = api
        self.name = name
        self.identity = (os.fstat(fd).st_dev, os.fstat(fd).st_ino)
        self.offset = os.fstat(fd).st_size if at_end else 0
        self.pending = b''
        self.discarding = False
        self.retired = False
        self.replaying = not at_end
        self.quiet = 0
        self.anchor = self._anchor()

    def _anchor(self):
        if not self.offset:
            return b''
        maximum = min(64, self.offset)
        guard = self.api.RUN_GUARD if self.api else None
        if guard:
            maximum = guard.allowance(maximum, raw=True)
        value = os.pread(self.fd, maximum, max(0, self.offset - 64))
        if guard:
            guard.debit(len(value), raw=True)
        return value

    def discard(self, store, reason):
        size = os.fstat(self.fd).st_size
        changed = size < self.offset or self._anchor() != self.anchor
        lost = (size if changed else max(0, size - self.offset)) + len(self.pending)
        if lost:
            store.loss(reason, byte_count=lost)
        self.offset = size
        self.pending = b''
        self.discarding = False
        self.anchor = self._anchor()

    def read(self, maximum, store, api):
        size = os.fstat(self.fd).st_size
        if size < self.offset or self._anchor() != self.anchor:
            store.loss('truncamiento/sustitución de contenido; cobertura incierta')
            self.offset, self.pending, self.discarding = 0, b'', False
            self.replaying = True
        if size - self.offset > 1048576:
            self.discard(store, 'atraso superior a 1 MiB; bytes descartados')
            return b''
        maximum = min(maximum, max(0, size - self.offset))
        if not maximum:
            self.quiet += 1
            return b''
        if api.RUN_GUARD:
            maximum = api.RUN_GUARD.allowance(maximum, raw=True)
        data = os.pread(self.fd, maximum, self.offset)
        if api.RUN_GUARD:
            api.RUN_GUARD.debit(len(data), raw=True)
        self.offset += len(data)
        self.anchor = self._anchor()
        self.quiet = 0
        return data

    def lines(self, data, store):
        # Como máximo 16 KiB por lectura; prefijo retenido de hasta MAX_LINE.
        data = self.pending + data
        self.pending = b''
        start = 0
        while start < len(data):
            end = data.find(b'\n', start)
            if end < 0:
                fragment = data[start:]
                if not self.discarding and len(fragment) <= MAX_LINE:
                    self.pending = fragment
                else:
                    if not self.discarding:
                        store.loss('línea excesiva', 1, len(fragment))
                    self.discarding = True
                return
            row = data[start:end + 1]
            start = end + 1
            if self.discarding:
                self.discarding = False
                continue
            if len(row) > MAX_LINE:
                store.loss('línea excesiva', 1, len(row))
                continue
            yield row

    def close(self):
        os.close(self.fd)


class Waiter:
    def __init__(self, folder):
        self.fd = None
        try:
            libc = ctypes.CDLL(None, use_errno=True)
            init = libc.inotify_init1
            init.argtypes, init.restype = [ctypes.c_int], ctypes.c_int
            add = libc.inotify_add_watch
            add.argtypes, add.restype = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32], ctypes.c_int
            self.fd = init(os.O_NONBLOCK | os.O_CLOEXEC)
            if self.fd < 0:
                self.fd = None
                return
            mask = 0x2 | 0x4 | 0x8 | 0x40 | 0x80 | 0x100 | 0x200 | 0x400 | 0x800
            if add(self.fd, ('/proc/self/fd/' + str(folder)).encode('ascii'), mask) < 0:
                self.close()
        except (OSError, AttributeError):
            self.close()

    def wait(self, seconds=2):
        started = time.monotonic()
        overflow = False
        if self.fd is not None and select.select([self.fd], [], [], seconds)[0]:
            data = os.read(self.fd, 8192)
            offset = 0
            while offset + 16 <= len(data):
                wd, mask, cookie, length = struct.unpack_from('iIII', data, offset)
                overflow = overflow or bool(mask & (0x4000 | 0x8000 | 0x2000))
                offset += 16 + length
        remaining = seconds - (time.monotonic() - started)
        if remaining > 0:
            time.sleep(remaining)
        return overflow

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None


class Engine:
    def __init__(self, folder, args, store, api):
        self.folder, self.args, self.store, self.api = folder, args, store, api
        self.tails = []
        self.cursor = 0
        self.access = None
        self.rate = {}
        self.started = utc_now()
        self.reported_missing = set()
        self.recent = {}
        self.reconcile(initial=True)

    def reconcile(self, initial=False):
        # Solo nombres activos conocidos, sin listar los dominios ni recorrer webs.
        if self.access is None:
            self.access = ('proxy_access_log', 'proxy_access_ssl_log') if any(
                self._exists(n) for n in ('proxy_access_log', 'proxy_access_ssl_log')) else ('access_log', 'access_ssl_log')
        for name in ERROR_LOGS + self.access:
            try:
                info = os.stat(name, dir_fd=self.folder, follow_symlinks=False)
                if not stat.S_ISREG(info.st_mode):
                    raise ValueError('no regular')
                identity = (info.st_dev, info.st_ino)
                matching = next((t for t in self.tails if t.identity == identity), None)
                if matching:
                    if matching.name == name:
                        matching.retired = False
                    self.reported_missing.discard(name)
                    continue
                for tail in self.tails:
                    if tail.name == name:
                        tail.retired = True
                if len(self.tails) >= MAX_FILES:
                    self.store.loss('límite de archivos abiertos; rotación no seguida')
                    continue
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self.folder)
                actual = os.fstat(fd)
                if not stat.S_ISREG(actual.st_mode) or (actual.st_dev, actual.st_ino) != identity:
                    os.close(fd)
                    self.store.loss('archivo cambió durante apertura')
                    continue
                self.tails.append(Tail(fd, name, at_end=initial, api=self.api))
                self.reported_missing.discard(name)
                if not initial:
                    self.store.loss('archivo nuevo/rotado; posibles escrituras tardías en anterior')
            except (OSError, ValueError):
                if name not in self.reported_missing:
                    self.reported_missing.add(name)
                    self.store.loss('log ausente/no accesible: ' + name)
        for tail in self.tails[:]:
            if tail.retired and tail.quiet >= 2:
                if tail.pending:
                    self.store.loss('fragmento sin terminar en log rotado', 1, len(tail.pending))
                tail.close()
                self.tails.remove(tail)
        self.store.files = ', '.join(sorted({tail.name for tail in self.tails if not tail.retired}))[:512]

    def _exists(self, name):
        try:
            return stat.S_ISREG(os.stat(name, dir_fd=self.folder, follow_symlinks=False).st_mode)
        except OSError:
            return False

    def cycle(self, maximum=65536):
        wall, cpu = time.monotonic() + .2, time.process_time() + .05
        self.reconcile()
        read = 0
        lines = 0
        tails = self.tails[self.cursor:] + self.tails[:self.cursor]
        self.cursor = (self.cursor + 1) % max(1, len(self.tails))
        for tail in tails:
            if read >= maximum or time.monotonic() >= wall or time.process_time() >= cpu:
                break
            try:
                data = tail.read(min(16384, maximum - read), self.store, self.api)
                read += len(data)
                for raw in tail.lines(data, self.store):
                    if lines >= 1000 or time.monotonic() >= wall or time.process_time() >= cpu:
                        self.store.loss('presupuesto de ciclo agotado; bloque parcialmente descartado', byte_count=len(data))
                        tail.pending = b''
                        break
                    lines += 1
                    recent = self.recent.setdefault(tail.name, collections.deque(maxlen=256))
                    fingerprint = hashlib.blake2b(raw, digest_size=16).digest()
                    if tail.replaying and fingerprint in recent:
                        self.store.loss('posible duplicado tras rotación/truncamiento descartado', 1)
                        continue
                    recent.append(fingerprint)
                    incident = parse_incident(raw, tail.name, self.args.zone, self.api)
                    if 'access' in tail.name:
                        access = self.api.parse(raw, self.args.zone)
                        if access:
                            minute = access[-1]
                            if minute not in self.rate and len(self.rate) >= 4:
                                self.rate.pop(next(iter(self.rate)))
                            self.rate[minute] = self.rate.get(minute, 0) + 1
                            if self.rate[minute] == 600:
                                self.store.enqueue(dict(kind='Ráfaga observada', severity='AVISO', code=None,
                                    route=None, php_file=None, php_line=None, service='acceso', logged_at=None,
                                    evidence='Al menos 600 peticiones del dominio en un minuto leído; no demuestra ataque ni saturación.'))
                    if incident:
                        stamp = incident['logged_at']
                        if stamp is not None and (stamp < self.started - 2 or stamp > utc_now() + 60):
                            self.store.loss('fecha fuera de vigilancia; historial copiado o reloj discrepante', 1)
                            continue
                        self.store.enqueue(incident)
                    elif 'access' not in tail.name and raw.strip():
                        self.store.loss('mensaje no interpretado o traza descartada', 1)
                if tail.offset >= os.fstat(tail.fd).st_size and not tail.pending:
                    tail.replaying = False
            except OSError:
                self.store.loss('falló lectura de un log; cobertura interrumpida')
        return read

    def skip_backlog(self, reason):
        for tail in self.tails:
            try:
                tail.discard(self.store, reason)
            except OSError:
                self.store.loss('no se pudo descartar atraso; lectura suspendida')

    def close(self):
        for tail in self.tails:
            if tail.pending:
                self.store.loss('fragmento incompleto al finalizar', 1, len(tail.pending))
            try:
                tail.close()
            except OSError:
                self.store.loss('falló cierre de descriptor de log')
        self.tails.clear()


def run_watch(args, api):
    folder = private_data(api, create=True)
    guard = None
    try:
        # Bloqueo independiente por dominio, exclusivamente dentro de data/.
        lock_name = 'watch-' + hashlib.sha256(args.domain.encode('ascii')).hexdigest()[:24] + '.lock'
        guard = api.RunGuard(args, lock_path='/proc/self/fd/' + str(folder) + '/' + lock_name)
        with guard:
            return protected_watch(args, api, folder)
    finally:
        os.close(folder)


def protected_watch(args, api, folder):
    import resource
    soft, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
    cap = min(16 * 1048576, hard) if hard != resource.RLIM_INFINITY else 16 * 1048576
    if soft != resource.RLIM_INFINITY:
        cap = min(cap, soft)
    resource.setrlimit(resource.RLIMIT_FSIZE, (cap, hard))
    check_data_files(folder)
    old_umask = os.umask(0o077)
    store = engine = waiter = None
    root = logs = None
    reason = 'tiempo manual terminado'
    exit_code = 0
    try:
        fd = os.open('audithor.sqlite', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600, dir_fd=folder)
        os.close(fd)
        check_data_files(folder)
        root = api.directory(args.root)
        logs = api.directory(args.domain + '/logs', root)
        log_identity = (os.fstat(logs).st_dev, os.fstat(logs).st_ino)
        store = Store(db_path(folder), args.domain, ', '.join(ERROR_LOGS))
        engine = Engine(logs, args, store, api)
        if not engine.tails:
            reason = 'sin logs activos accesibles; vigilancia no iniciada'
            store.loss(reason)
            print(reason, flush=True)
            return 1
        waiter = Waiter(logs)
        store.flush()
        print('WATCH MANUAL · ' + args.domain + ' · solo eventos nuevos, inicio desde EOF.', flush=True)
        print('Escritura privada: data/audithor.sqlite. Ctrl+C para cerrar. Sin históricos ni servicios.', flush=True)
        print('Avisos: ' + ('inotify con pausa mínima de 2 s' if waiter.fd is not None else 'sondeo seguro cada 2 s; inotify no disponible'), flush=True)
        end = time.monotonic() + args.watch_seconds
        last_flush = 0
        pressure_since = None
        while time.monotonic() < end:
            cpus, loads, available = api.host_status()
            delay = 2
            if available < 256:
                reason = 'parada por memoria disponible insuficiente'
                exit_code = 75
                store.loss(reason)
                break
            if loads[0] > cpus:
                if pressure_since is None:
                    pressure_since = time.monotonic()
                    store.loss('pausa por carga del servidor')
                engine.skip_backlog('eventos/bytes omitidos durante presión del servidor')
                delay = 5
                if time.monotonic() - pressure_since >= 30:
                    reason = 'parada por presión sostenida durante 30 s'
                    exit_code = 75
                    store.loss(reason)
                    break
            else:
                if pressure_since is not None:
                    store.loss('fin de pausa por carga; intervalo con cobertura parcial')
                    pressure_since = None
                engine.cycle(16384 if loads[0] > cpus * .8 else 65536)
            # Una sustitución del directorio completo no se sigue silenciosamente.
            current = api.directory(args.domain + '/logs', root)
            try:
                if (os.fstat(current).st_dev, os.fstat(current).st_ino) != log_identity:
                    reason = 'directorio de logs sustituido; vigilancia detenida'
                    exit_code = 75
                    store.loss(reason)
                    break
            finally:
                os.close(current)
            if time.monotonic() - last_flush >= 5:
                store.flush()
                last_flush = time.monotonic()
                if store.failures >= 3:
                    reason = 'SQLite no disponible tras tres intentos; vigilancia detenida'
                    exit_code = 1
                    break
            if waiter.wait(min(delay, max(.01, end - time.monotonic()))):
                store.loss('desbordamiento/pérdida de avisos inotify; cobertura incierta')
        return exit_code
    except KeyboardInterrupt:
        reason = 'Ctrl+C: cierre manual'
        return 0
    except sqlite3.Error:
        reason = 'SQLite no disponible; vigilancia detenida sin reintento ilimitado'
        print(reason + '. La cobertura puede no haberse guardado.', flush=True)
        return 1
    except BaseException:
        reason = 'interrupción por límite o error; cobertura parcial'
        raise
    finally:
        try:
            if waiter:
                waiter.close()
            if engine:
                engine.close()
            if store:
                try:
                    store.close(reason)
                except sqlite3.Error:
                    print('No se pudo marcar el cierre en SQLite; último latido no demuestra cobertura posterior.', flush=True)
                print('Watch cerrado: ' + reason + '. Omitidos conocidos: ' + str(store.omitted) +
                      '; bytes omitidos: ' + str(store.omitted_bytes) + '. Pérdidas desconocidas pueden no contarse.', flush=True)
        finally:
            if logs is not None:
                os.close(logs)
            if root is not None:
                os.close(root)
            os.umask(old_umask)


def read_history(args, api, base=None):
    result = dict(events=[], sessions=[], gaps=[], message='No hay vigilancia guardada para este período; no implica ausencia de errores.')
    folder = connection = None
    try:
        folder = private_data(api, create=False, base=base)
        check_data_files(folder)
        path = db_path(folder)
        connection = sqlite3.connect('file:' + quote(path, safe='/') + '?mode=ro', uri=True, timeout=.1)
        connection.execute('PRAGMA query_only=ON')
        connection.execute('PRAGMA trusted_schema=OFF')
        connection.execute('PRAGMA cache_size=-512')
        end = time.monotonic() + .2
        connection.set_progress_handler(lambda: int(time.monotonic() >= end), 500)
        start_day = getattr(args, 'start_day', args.day)
        start = int(dt.datetime.combine(start_day, dt.time(), tzinfo=args.zone).timestamp())
        stop = int(dt.datetime.combine(args.day + dt.timedelta(days=1), dt.time(), tzinfo=args.zone).timestamp())
        start = max(start, utc_now() - 7 * 86400)
        if start >= stop:
            result['message'] = 'Período fuera de la retención de siete días; no implica ausencia de errores.'
            return result
        result['events'] = connection.execute('''SELECT bucket,frequency,kind,severity,code,route,php_file,php_line,service,evidence,
 logged_first,logged_last,first_seen,last_seen FROM incidents WHERE domain=? AND bucket>=? AND bucket<?
 ORDER BY bucket DESC LIMIT 50''', (args.domain, start, stop)).fetchall()
        result['sessions'] = connection.execute('''SELECT id,started,heartbeat,ended,reason,files,omitted,omitted_bytes
 FROM sessions WHERE domain=? AND started<? AND heartbeat>=? ORDER BY started DESC LIMIT 20''', (args.domain, stop, start)).fetchall()
        result['gaps'] = connection.execute('''SELECT g.at,g.reason,g.amount,g.bytes FROM gaps g JOIN sessions s ON g.session=s.id
 WHERE s.domain=? AND g.at>=? AND g.at<? ORDER BY g.at DESC LIMIT 50''', (args.domain, start, stop)).fetchall()
        if result['sessions']:
            result['message'] = 'Solo intervalos vigilados; hasta 50 grupos, 20 sesiones y 50 avisos. No cubre el día completo por sí solo.'
    except (OSError, RuntimeError, ValueError, sqlite3.Error):
        result['message'] = 'Incidencias guardadas N/D: data/ ausente, privada de otro usuario, SQLite ocupado o no legible. No se modifica.'
    finally:
        if connection:
            connection.close()
        if folder is not None:
            os.close(folder)
    return result


def recommendation(kind):
    if 'memoria' in kind.lower() or 'PHP-FPM' in kind:
        return 'Revisar en Plesk el límite y logs del pool PHP correspondiente; no aumentarlo sin medir.'
    if 'SQL' in kind or 'Excepción' in kind or 'PHP' in kind:
        return 'Revisar archivo/línea y logs de aplicación; sin consultar la base de datos del cliente.'
    if 'Timeout' in kind or 'backend' in kind:
        return 'Revisar el backend y sus tiempos en esa franja; no se ha demostrado saturación.'
    if 'Permiso' in kind:
        return 'Comprobar en Plesk el acceso al archivo indicado; Audithor no cambia permisos.'
    return 'Revisar la ruta y el log del servicio en esa franja; no se ha atribuido una causa.'


def history_rows(result, zone, api):
    clock = lambda stamp: dt.datetime.fromtimestamp(stamp, zone).strftime('%Y-%m-%d %H:%M:%S %z') if stamp is not None else 'N/D'
    events = []
    for row in result['events']:
        bucket, count, kind, severity, code, route, file, line, service, evidence, first, last, seen_first, seen_last = row
        kind = api.clean(kind or 'tipo no interpretable', 80)
        events.append((clock(first) if first is not None else 'obs. ' + clock(seen_first),
                       clock(last) if last is not None else 'obs. ' + clock(seen_last),
                       count, kind, severity, code or '-', route or 'sin relación HTTP demostrada',
                       (file + ':' + str(line)) if file else 'no registrado', service,
                       evidence, recommendation(kind)))
    sessions = [(clock(s), clock(h), clock(e), reason or 'sin cierre: interrupción o sesión aún activa', omitted, byte_count, files)
                for sid, s, h, e, reason, files, omitted, byte_count in result['sessions']]
    gaps = [(clock(stamp), reason, amount, byte_count) for stamp, reason, amount, byte_count in result['gaps']]
    return events, sessions, gaps


def show_history(result, zone, api):
    print('\nINCIDENCIAS GUARDADAS POR --watch')
    print('  ' + result['message'])
    events, sessions, gaps = history_rows(result, zone, api)
    api.table(('PRIMERA HORA', 'ÚLTIMA HORA', 'VECES', 'TIPO', 'GRAVEDAD', 'HTTP', 'RUTA', 'PHP/LÍNEA', 'SERVICIO'),
              [row[:9] for row in events], (25, 25, 6, 25, 9, 5, 25, 30, 12))
    for event in events:
        print('  Evidencia: ' + api.clean(event[9], 256))
        print('  Revisar: ' + event[10])
    api.table(('INICIO', 'ÚLTIMO LATIDO', 'FIN', 'INTERRUPCIÓN/FIN', 'OMITIDOS', 'BYTES OMITIDOS', 'FUENTES'),
              sessions, (25, 25, 25, 35, 9, 14, 65))
    api.table(('HORA', 'PÉRDIDA/AVISO', 'EVENTOS CONOCIDOS', 'BYTES'), gaps, (25, 65, 17, 12))
    print('  Sin sesión o fuera de estos intervalos: cobertura desconocida. Cero incidencias no significa cero errores.')


def history_html(result, zone, api):
    import html
    events, sessions, gaps = history_rows(result, zone, api)
    return ('<h3>Incidencias guardadas por --watch</h3><p>' + html.escape(result['message']) + '</p>' +
            api.html_table(('Primera hora', 'Última hora', 'Frecuencia', 'Tipo', 'Gravedad', 'HTTP', 'Ruta', 'PHP/línea', 'Servicio', 'Evidencia', 'Revisar'), events) +
            api.html_table(('Inicio', 'Último latido', 'Fin', 'Cierre/interrupción', 'Omitidos', 'Bytes', 'Fuentes'), sessions) +
            api.html_table(('Hora', 'Pérdida/aviso', 'Eventos conocidos', 'Bytes'), gaps) +
            '<p>Fuera de intervalos vigilados no hay cobertura demostrada. No se correlacionan errores distintos ni se guardan trazas.</p>')
