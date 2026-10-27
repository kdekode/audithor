"""Diagnóstico acotado por dominio. Sin ejecutar PHP, órdenes, sockets ni HTTP."""
import collections
import datetime as dt
import html
import os
import re
import time
import textwrap

LEVEL = {'SIN DATOS': -1, 'SIN AVISOS': 0, 'BAJA': 1, 'MEDIA': 2, 'ALTA': 3}
MAX_DOMAINS = 512
MAX_ISSUES = 16
FPM_FILE = re.compile(r'plesk-php[0-9]{2,3}-fpm')
STAMP = re.compile(r'^\[(\d{2})-([A-Za-z]{3})-(\d{4}) (\d{2}):(\d{2}):(\d{2})\]')
POOL = re.compile(r'\[pool ([a-z0-9.-]{1,253})\]')
HOOK = re.compile(r'(?:gancho:|hook:)\s*([A-Za-z0-9_-]{1,80})', re.I)
SERVER_COMM = {b'mariadbd': 'MariaDB', b'mysqld': 'MySQL', b'nginx': 'nginx',
               b'apache2': 'Apache', b'httpd': 'Apache', b'statistics_log_': 'Estadísticas Plesk',
               b'statistics_coll': 'Estadísticas Plesk', b'logresolvemerge': 'Fusión de logs'}


class Reader:
    """Presupuesto adicional compartido; los límites efectivos de RunGuard siguen activos."""
    def __init__(self, api, seconds=2, maximum=1048576):
        self.api = api
        self.end = time.monotonic() + seconds
        self.maximum = maximum
        self.read = 0
        self.partial = False

    def check(self):
        if time.monotonic() >= self.end or self.read >= self.maximum:
            self.partial = True
            raise ValueError('Presupuesto de diagnóstico alcanzado')

    def get(self, folder, name, cap, tail=False):
        self.check()
        cap = min(cap, self.maximum - self.read)
        with self.api.regular(folder, name) as stream:
            size = os.fstat(stream.fileno()).st_size
            offset = max(0, size - cap) if tail else 0
            if offset:
                stream.seek(offset)
            data = stream.read(cap)
        self.read += len(data)
        if offset:
            self.partial = True
            data = data.split(b'\n', 1)[-1]
        return data


def local_stamp(text, api, zone):
    """Fechas sin offset: zona LOCAL del host, nunca asumir Europe/Madrid."""
    match = STAMP.match(text)
    if not match:
        return None
    day, mon, year, hour, minute, second = match.groups()
    try:
        value = dt.datetime(int(year), api.MONTHS[mon], int(day), int(hour), int(minute), int(second))
        return value.astimezone(zone)
    except (ValueError, KeyError, OverflowError, OSError):
        return None


def domain_stamp(text, api, zone):
    value = local_stamp(text, api, zone)
    if value:
        return value
    nginx = re.match(r'^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) ', text)
    apache = re.match(r'^\[[A-Za-z]{3} ([A-Za-z]{3})\s+(\d{1,2}) (\d{2}:\d{2}:\d{2})(?:\.\d+)? (\d{4})\]', text)
    try:
        if nginx:
            return dt.datetime.strptime(nginx[1], '%Y/%m/%d %H:%M:%S').astimezone(zone)
        if apache:
            mon, day, clock, year = apache.groups()
            return dt.datetime(int(year), api.MONTHS[mon], int(day), *map(int, clock.split(':'))).astimezone(zone)
    except (KeyError, ValueError, OSError, OverflowError):
        pass
    return None


def log_signal(text):
    """Solo marcadores permitidos; nunca conservar mensajes crudos, SQL o argumentos."""
    low = text.lower()
    if 'max_children' in low and ('reached' in low or 'limit' in low):
        return ('pool_limit', 'PHP alcanzó su límite de procesos', 'ALTA',
                'Se registró el límite max_children; no subirlo sin medir CPU y memoria.')
    if ('cron' in low and ('could_not_set' in low or 'could not be saved' in low)):
        hook = HOOK.search(text)
        name = hook[1] if hook else 'no identificado'
        return ('cron', 'Fallo al guardar tareas de WordPress', 'MEDIA', 'WP-Cron: could_not_set; hook ' + name)
    if 'undefined array key' in low or 'trying to access array offset on null' in low:
        return ('application_warning', 'Advertencias repetidas en el código de la web', 'MEDIA',
                'PHP Warning: clave ausente o acceso a un valor nulo; no equivale a peticiones distintas.')
    if 'allowed memory size' in low and 'exhausted' in low:
        return ('php_memory', 'Límite de memoria PHP alcanzado', 'ALTA',
                'PHP registró Allowed memory size exhausted; es un límite del proceso, no prueba falta de RAM global.')
    if 'fatal error' in low or 'uncaught ' in low:
        return ('php_fatal', 'Error fatal o excepción PHP', 'ALTA', 'PHP registró Fatal error o Uncaught.')
    if 'sqlstate' in low or 'too many connections' in low:
        return ('database', 'Errores de conexión o ejecución SQL', 'MEDIA',
                'Mensaje SQLSTATE o límite de conexiones registrado; no se ha consultado la base de datos.')
    if 'upstream timed out' in low or 'connection refused' in low or 'connect() failed' in low:
        return ('backend', 'Timeout o conexión de backend rechazada', 'MEDIA',
                'Mensaje de timeout/conexión rechazada registrado; no se ha demostrado su causa.')
    if 'permission denied' in low:
        return ('permission', 'Acceso a archivo o recurso denegado', 'MEDIA', 'Permission denied registrado.')
    return None


def add_log(rows, domain, signal, stamp, source):
    if domain not in rows:
        if len(rows) >= MAX_DOMAINS:
            return False
        rows[domain] = {}
    key, title, priority, evidence = signal
    groups = rows[domain]
    if key not in groups:
        if len(groups) >= MAX_ISSUES:
            return False
        groups[key] = dict(key=key, title=title, priority=priority, evidence=evidence,
                           count=0, first=stamp, last=stamp, sources=[], service='PHP-FPM')
    item = groups[key]
    item['count'] += 1
    item['first'] = min(item['first'], stamp)
    item['last'] = max(item['last'], stamp)
    if source not in item['sources'] and len(item['sources']) < 4:
        item['sources'].append(source)
    return True


def add_location(item, text):
    match = re.search(r'/([A-Za-z0-9_.-]{1,80}\.php)(?: on line |:)([0-9]{1,7})(?:\D|$)', text)
    if match:
        name = match[1]
        if re.search(r'password|secret|token|credential', name, re.I):
            name = ':oculto.php'
        location = name + ':' + match[2]
        locations = item.setdefault('locations', [])
        if location not in locations and len(locations) < 3:
            locations.append(location)


def read_fpm(args, api, reader, domains, folder='/var/log'):
    result = dict(domains={}, sources=[], notes=[], read=0, partial=True)
    root = None
    start = reader.read
    try:
        root = api.directory(folder)
        candidates = sorted(n for n in api.names(root, 4096) if FPM_FILE.fullmatch(n))
        if len(candidates) > 16:
            result['notes'].append('Más de 16 versiones PHP: inventario parcial.')
        for name in candidates[:16]:
            child = None
            try:
                reader.check()
                child = api.directory(name, root)
                data = reader.get(child, 'error.log', 128 * 1024, tail=True)
                result['sources'].append(name + '/error.log')
                for raw in data.splitlines(keepends=True):
                    if time.monotonic() >= reader.end:
                        result['partial'] = True
                        break
                    if not raw.endswith(b'\n') or len(raw) > 8192:
                        result['partial'] = True
                        continue
                    text = raw.decode('utf-8', 'replace')
                    pool = POOL.search(text)
                    if not pool or pool[1] not in domains:
                        continue
                    stamp = local_stamp(text, api, args.zone)
                    if not stamp or not args.start_day <= stamp.date() <= args.day:
                        continue
                    signal = log_signal(text)
                    if signal:
                        if add_log(result['domains'], pool[1], signal, stamp.isoformat(timespec='seconds'), name + '/error.log'):
                            add_location(result['domains'][pool[1]][signal[0]], text)
                        else:
                            result['partial'] = True
            except (OSError, ValueError, RuntimeError):
                result['partial'] = True
            finally:
                if child is not None:
                    os.close(child)
    except (OSError, ValueError, RuntimeError):
        result['partial'] = True
    finally:
        if root is not None:
            os.close(root)
    result['read'] = reader.read - start
    result['partial'] |= reader.partial
    result['notes'].append('Solo colas de error.log activos, sin gzip ni históricos; ausencia de mensajes no descarta errores.')
    result['notes'].append('Fecha sin offset interpretada en la zona local del servidor y convertida a la zona elegida; sin cambiar relojes.')
    if not result['sources']:
        result['notes'].append('Logs globales PHP-FPM N/D: ausentes, permisos, enlaces rechazados o presupuesto.')
    return result


def parse_proc(data):
    parts = data.rsplit(b')', 1)[1].split()
    return dict(ticks=int(parts[11]) + int(parts[12]), start=int(parts[19]), rss=int(parts[21]))


def domain_errors(root, domain, args, api):
    """Ambas capas activas: no excluir PHP/Apache cuando los accesos usan nginx."""
    reader = Reader(api, seconds=.5, maximum=256 * 1024)
    rows, sources = {}, []
    folder = None
    try:
        folder = api.directory(domain + '/logs', root)
        for name in ('error_log', 'proxy_error_log', 'php_error.log', 'php_error_log'):
            try:
                data = reader.get(folder, name, 64 * 1024, tail=True)
                sources.append(name)
                for raw in data.splitlines(keepends=True):
                    if time.monotonic() >= reader.end:
                        reader.partial = True
                        break
                    if not raw.endswith(b'\n') or len(raw) > 8192:
                        reader.partial = True
                        continue
                    text = raw.decode('utf-8', 'replace')
                    stamp = domain_stamp(text, api, args.zone)
                    if not stamp or not args.start_day <= stamp.date() <= args.day:
                        continue
                    signal = log_signal(text)
                    if signal:
                        add_log(rows, domain, signal, stamp.isoformat(timespec='seconds'), name)
                        rows[domain][signal[0]]['service'] = 'nginx' if name == 'proxy_error_log' else 'Apache/PHP'
                        add_location(rows[domain][signal[0]], text)
            except FileNotFoundError:
                pass
            except (OSError, ValueError, RuntimeError):
                reader.partial = True
    except (OSError, ValueError, RuntimeError):
        reader.partial = True
    finally:
        if folder is not None:
            os.close(folder)
    return dict(domains=rows, sources=sources, read=reader.read, partial=reader.partial)


def process_sample(api, reader, domains, proc='/proc'):
    result = {}
    root = None
    visited = 0
    try:
        root = api.directory(proc)
        # No generar una lista sin límite de todos los procesos del host.
        with os.scandir(root) as entries:
            for entry in entries:
                reader.check()
                if not entry.name.isascii() or not entry.name.isdecimal():
                    continue
                if visited >= 512:
                    reader.partial = True
                    break
                visited += 1
                child = None
                try:
                    child = api.directory(entry.name, root)
                    comm = reader.get(child, 'comm', 64).strip()
                    if not comm.startswith(b'php-fpm') and comm not in SERVER_COMM:
                        continue
                    if comm.startswith(b'php-fpm'):
                        # Solo leer el destino del enlace /proc, nunca abrirlo o ejecutarlo.
                        executable = os.readlink('exe', dir_fd=child)
                        if not re.fullmatch(r'(?:/opt/plesk/php/[0-9.]+/sbin/php-fpm[0-9.]*|/usr/sbin/php-fpm[0-9.]*)', executable):
                            reader.partial = True
                            continue
                        command = reader.get(child, 'cmdline', 512).replace(b'\x00', b' ').strip()
                        match = re.fullmatch(rb'php-fpm: pool ([a-z0-9.-]{1,253})', command)
                        if not match or match[1].decode('ascii') not in domains:
                            continue
                        domain, role = match[1].decode('ascii'), 'PHP-FPM'
                    else:
                        domain, role = '__server__', SERVER_COMM[comm]
                    item = parse_proc(reader.get(child, 'stat', 2048))
                    item.update(domain=domain, role=role, pid=int(entry.name), sampled=time.monotonic())
                    result[item['pid']] = item
                except (OSError, ValueError, RuntimeError, IndexError):
                    reader.partial = True
                finally:
                    if child is not None:
                        os.close(child)
    except (OSError, ValueError, RuntimeError):
        reader.partial = True
    finally:
        if root is not None:
            os.close(root)
    return result


def process_delta(before, after, ticks, page_size):
    pools = {}
    for pid, last in after.items():
        first = before.get(pid)
        if not first or first['start'] != last['start'] or first['domain'] != last['domain']:
            continue
        elapsed = last['sampled'] - first['sampled']
        delta = last['ticks'] - first['ticks']
        if elapsed < .1 or delta < 0:
            continue
        cpu = 100 * delta / ticks / elapsed
        row = dict(pid=pid, cpu=round(cpu, 1), rss_mib=round(max(0, last['rss']) * page_size / 1048576, 1), role=last.get('role', 'PHP-FPM'))
        pool = pools.setdefault(last['domain'], dict(count=0, cpu=0, processes=[]))
        pool['count'] += 1
        pool['cpu'] += cpu
        pool['processes'].append(row)
    for pool in pools.values():
        pool['cpu'] = round(pool['cpu'], 1)
        pool['processes'] = sorted(pool['processes'], key=lambda row: (-row['cpu'], row['pid']))[:10]
    return pools


def merge_pool_intervals(*intervals):
    """Une intervalos breves y conserva mínimo/máximo, sin convertirlos en histórico."""
    names = set().union(*(set(interval) for interval in intervals))
    merged = {}
    for name in names:
        values = [interval[name] for interval in intervals if name in interval]
        cpus = [value['cpu'] for value in values]
        processes = {}
        for value in values:
            for row in value['processes']:
                previous = processes.get(row['pid'])
                if previous is None or row['cpu'] > previous['cpu']:
                    processes[row['pid']] = row
        merged[name] = dict(count=max(value['count'] for value in values),
                            cpu=round(sum(cpus) / len(cpus), 1),
                            cpu_min=round(min(cpus), 1), cpu_max=round(max(cpus), 1),
                            processes=sorted(processes.values(), key=lambda row: (-row['cpu'], row['pid']))[:10])
    return merged


def host_cpu_sample(api, reader, proc='/proc'):
    root = None
    try:
        root = api.directory(proc)
        stat_data = reader.get(root, 'stat', 16384).decode('ascii', 'replace')
        load_data = reader.get(root, 'loadavg', 256).decode('ascii', 'replace').strip()
        cpu_line = next(line for line in stat_data.splitlines() if line.startswith('cpu '))
        values = [int(value) for value in cpu_line.split()[1:11]]
        running = re.search(r'^procs_running\s+(\d+)$', stat_data, re.M)
        load = load_data.split()
        runnable = int(load[3].split('/', 1)[0]) if len(load) >= 4 and '/' in load[3] else int(running[1])
        return dict(total=sum(values), idle=values[3], iowait=values[4] if len(values) > 4 else 0,
                    runnable=runnable, load1=float(load[0]))
    finally:
        if root is not None:
            os.close(root)


def host_cpu_delta(first, last, cpus, elapsed):
    total = last['total'] - first['total']
    if total <= 0:
        raise ValueError('Contadores CPU sin avance')
    idle = 100 * (last['idle'] - first['idle']) / total
    iowait = 100 * (last['iowait'] - first['iowait']) / total
    return dict(busy=round(max(0.0, 100.0 - idle), 1), idle=round(max(0.0, idle), 1),
                iowait=round(max(0.0, iowait), 1), runnable=last['runnable'],
                load1=last['load1'], cpus=cpus, seconds=round(elapsed, 2))


def capture(args, api, domains):
    selected = set(domains[:MAX_DOMAINS])
    result = dict(logs={}, processes={}, notes=[], captured=dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds'),
                  partial=False, read=0, server=None)
    if len(domains) > MAX_DOMAINS:
        result['notes'].append('Diagnóstico adicional limitado a los primeros 512 dominios; el tráfico conserva su recorrido.')
        result['partial'] = True
    if getattr(args, 'root', '/var/www/vhosts/system') != '/var/www/vhosts/system':
        result['partial'] = True
        result['notes'].append('Raíz alternativa: no se mezclan logs/procesos del host actual con un inventario de otro origen.')
        return result
    # No atribuir recursos de ahora a una fecha pasada, ni cargar más un host en emergencia.
    try:
        cpus, loads, available = api.host_status()
        if available < 256 or loads[0] > max(4, cpus * 2):
            result['partial'] = True
            result['notes'].append('Diagnóstico adicional suspendido por presión del servidor.')
            return result
    except (OSError, ValueError, AttributeError):
        result['partial'] = True
        result['notes'].append('Diagnóstico adicional N/D: presión del host no comprobable.')
        return result
    reader = Reader(api)
    logs = read_fpm(args, api, reader, selected)
    result['logs'] = logs['domains']
    result['sources'] = logs['sources']
    result['notes'].extend(logs['notes'])
    result['partial'] |= logs['partial']
    if args.start_day == args.day == dt.datetime.now(args.zone).date():
        reader = Reader(api, seconds=5, maximum=2 * 1048576)
        try:
            ticks = os.sysconf('SC_CLK_TCK')
            page_size = os.sysconf('SC_PAGE_SIZE')
            cpu_first = host_cpu_sample(api, reader)
            first = process_sample(api, reader, selected)
            if first:
                # Tres capturas en dos segundos: permite mostrar un rango sin monitorizar continuamente.
                time.sleep(1)
                cpus, loads, available = api.host_status()
                if available < 256 or loads[0] > max(4, cpus * 2):
                    raise ValueError('Presión durante instantánea')
                second = process_sample(api, reader, selected)
                time.sleep(1)
                third = process_sample(api, reader, selected)
                cpu_second = host_cpu_sample(api, reader)
                if set(first) != set(third):
                    reader.partial = True
                result['processes'] = merge_pool_intervals(
                    process_delta(first, second, ticks, page_size),
                    process_delta(second, third, ticks, page_size))
                result['server'] = result['processes'].pop('__server__', None)
                elapsed = max((item['sampled'] for item in third.values()), default=time.monotonic()) - \
                          min((item['sampled'] for item in first.values()), default=time.monotonic())
                result['pressure'] = host_cpu_delta(cpu_first, cpu_second, cpus, elapsed)
        except (OSError, ValueError, AttributeError):
            reader.partial = True
        result['partial'] |= reader.partial
        result['read'] += reader.read
        result['notes'].append('CPU ACTUAL: tres capturas durante 2 s; se muestra media y rango de dos intervalos. 100% equivale a un núcleo; no es carga sostenida.')
    else:
        result['notes'].append('Procesos actuales omitidos en consultas históricas o semanales; CPU/RAM históricas por dominio N/D.')
    result['read'] += logs['read']
    return result


def explanation(key):
    return {
        'pool_limit': ('PHP había ocupado todos los procesos permitidos para esta web. Otras solicitudes podían quedar esperando; no demuestra un ataque.',
                       'Revisar en Plesk los errores PHP y las tareas que coincidían con esas horas. No aumentar el límite sin identificar qué ocupaba los procesos.'),
        'cron': ('WordPress no pudo guardar la lista de tareas. Puede ser un fallo de persistencia o concurrencia; no demuestra que el plugin cause la carga.',
                 'Revisar el hook indicado y los errores de WordPress/base de datos; identificar su propietario antes de actuar.'),
        'process_cpu': ('PHP-FPM consumía CPU en el intervalo medido. No identifica la petición, plugin o tarea, ni demuestra ataque.',
                        'Relacionar la hora con accesos y slowlog/estado del pool si ya están disponibles. No reiniciar ni bloquear por esta medición.'),
        'application_warning': ('La aplicación accede a valores ausentes o nulos. Muchos mensajes pueden proceder de una sola petición.',
                                'Revisar la función y los datos que recibe el archivo/línea indicado, en los logs originales. Puede ser código propio, un plugin o módulo.'),
        'php_memory': ('Una ejecución PHP alcanzó su límite propio; no prueba agotamiento global de RAM.',
                       'Revisar el script y su tamaño de trabajo; no elevar memoria automáticamente.'),
        'php_fatal': ('Una ejecución PHP terminó con error; puede ser un fallo del código o de sus dependencias.',
                      'Revisar el archivo/línea del log original y cambios recientes de la aplicación.'),
        'database': ('La aplicación registró un problema SQL o de conexiones; puede ser causa o consecuencia de la incidencia.',
                     'Revisar los logs del servicio y de la aplicación en esa franja; no ejecutar consultas de clientes.'),
    }.get(key, ('Mensaje de error observado; no se ha demostrado su causa.', 'Revisar el log y servicio indicados en esa franja.'))


def workload_issue(key, count, window, api):
    """Convierte contadores cerrados de accesos en una pista, sin afirmar causalidad."""
    if ':' in key:
        return None
    rules = {
        'admin_ajax': (100, 500, 'Muchas llamadas a admin-ajax.php',
            'admin-ajax.php ejecuta WordPress y puede consumir PHP incluso para visitantes anónimos; el contador incluye acciones distintas.',
            'Cruzar el intervalo con las acciones AJAX desglosadas y sus muestras; optimizar o limitar únicamente la acción identificada.'),
        'wp_cron': (20, 100, 'Muchas llamadas a WP-Cron',
            'Se observaron peticiones a wp-cron.php. El log no permite saber qué tarea se ejecutó ni cuánto consumió.',
            'Revisar frecuencia y tareas; en Plesk valorar cron real con DISABLE_WP_CRON tras comprobar que no exista ya.'),
        'wp_rest': (200, 1000, 'Muchas peticiones a la API REST',
            'Se observaron llamadas a wp-json. Pueden ser públicas, internas o de una integración; el namespace se desglosa aparte.',
            'Revisar namespaces, métodos, códigos y agentes de la misma franja antes de limitar una API.'),
        'xmlrpc': (50, 200, 'Muchas peticiones a XML-RPC',
            'XML-RPC puede tener usos legítimos o recibir automatización repetitiva.',
            'Revisar métodos, códigos y agentes; deshabilitar o limitar solo si ninguna integración lo necesita.'),
        'wp_login': (100, 500, 'Muchas peticiones al acceso de WordPress',
            'El endpoint de acceso recibió volumen elevado; no todas las peticiones son intentos fallidos.',
            'Cruzar códigos e IP en el detalle y revisar protecciones existentes antes de añadir bloqueos.'),
        'admin_post': (100, 500, 'Muchas llamadas a admin-post.php',
            'admin-post.php ejecuta acciones de WordPress; las acciones concretas aparecen desglosadas.',
            'Revisar la acción dominante y su origen antes de optimizar o limitar.'),
        'wc_ajax': (100, 500, 'Muchas llamadas AJAX de WooCommerce',
            'Las acciones AJAX pueden ser funcionales o repetitivas y ejecutar PHP.',
            'Revisar la acción dominante, páginas que la generan y tiempos antes de cambiar la configuración.'),
    }
    if key not in rules:
        return None
    medium, high, title, hypothesis, action = rules[key]
    if count < medium:
        return None
    priority = 'ALTA' if high is not None and count >= high else 'MEDIA'
    first, last = (window or [None, None])[:2]
    period = (' entre ' + first + ' y ' + last) if first and last else ''
    return dict(key='workload_' + key, title=title, priority=priority,
                evidence=f'{count} peticiones identificadas{period}.', count=None,
                first=None, last=None, sources=['accesos del dominio'], service='web/WordPress',
                hypothesis=hypothesis, action=action)


def access_correlation(issue, result):
    """Relaciona mensajes internos y accesos por minuto sin afirmar causalidad."""
    try:
        first = dt.datetime.fromisoformat(issue['first']).replace(second=0, microsecond=0)
        last = dt.datetime.fromisoformat(issue['last']).replace(second=0, microsecond=0)
    except (KeyError, TypeError, ValueError):
        return None
    margin_first, margin_last = first - dt.timedelta(minutes=1), last + dt.timedelta(minutes=1)
    selected = []
    for label, row in result.get('minute_context', {}).items():
        try:
            stamp = dt.datetime.strptime(label, '%Y-%m-%d %H:%M %z')
        except ValueError:
            continue
        if margin_first <= stamp <= margin_last:
            selected.append((stamp, row))
    nearby_activities = []
    for row in result.get('activities', {}).values():
        try:
            activity_first = dt.datetime.strptime(row['first'], '%Y-%m-%d %H:%M %z')
            activity_last = dt.datetime.strptime(row['last'], '%Y-%m-%d %H:%M %z')
        except (KeyError, ValueError):
            continue
        if activity_first <= margin_last and activity_last >= margin_first:
            nearby_activities.append(row)
    nearby_activities.sort(key=lambda row: (-row['dynamic'], -row['count'], row['label']))
    activity_labels = [f"{row['label']} ({row['count']} en su ventana; {row['dynamic']} potencialmente PHP)"
                       for row in nearby_activities[:5]]
    if not selected:
        return dict(text='No hay accesos leídos en el minuto del aviso ni en el margen de ±1 minuto.',
                    routes=[], activities=activity_labels)
    total = sum(row['total'] for _, row in selected)
    methods, classes, routes = collections.Counter(), collections.Counter(), collections.Counter()
    partial = False
    for _, row in selected:
        methods.update(row['methods'])
        classes.update(row['classes'])
        routes.update(row['routes'])
        partial |= row.get('routes_partial', False)
    method_text = ', '.join(f'{key} {value}' for key, value in methods.most_common(4)) or 'N/D'
    class_text = (f'dinámicas/potencialmente PHP {classes.get("dynamic", 0)}, '
                  f'estáticas {classes.get("static", 0)}, sin clasificar {classes.get("unknown", 0)}')
    text = f'{total} accesos leídos entre {selected[0][0].strftime("%H:%M")} y {selected[-1][0].strftime("%H:%M")}; {method_text}; {class_text}.'
    if partial:
        text += ' Ranking de rutas parcial.'
    return dict(text=text, routes=routes.most_common(3), activities=activity_labels)


def peak_relation(issue, result):
    peak = result.get('peak_minute')
    if not peak:
        return None
    try:
        stamp = dt.datetime.strptime(peak, '%Y-%m-%d %H:%M %z')
        first = dt.datetime.fromisoformat(issue['first']).replace(second=0, microsecond=0)
        last = dt.datetime.fromisoformat(issue['last']).replace(second=0, microsecond=0)
    except (KeyError, TypeError, ValueError):
        return None
    if first - dt.timedelta(minutes=1) <= stamp <= last + dt.timedelta(minutes=1):
        return f'El pico leído ({result.get("peak", 0)} peticiones/min a las {stamp.strftime("%H:%M")}) coincide temporalmente con el aviso; esto no prueba causalidad.'
    delta = min(abs((stamp - first).total_seconds()), abs((stamp - last).total_seconds())) / 60
    return f'El pico leído ({result.get("peak", 0)} peticiones/min a las {stamp.strftime("%H:%M")}) NO coincide con el aviso; está separado aproximadamente {delta:.0f} minutos.'


def diagnose(domain, result, snapshot, args, api=None):
    issues = []
    for key, item in snapshot.get('logs', {}).get(domain, {}).items():
        row = dict(item)
        row['sources'] = list(item['sources'])
        # Un warning aislado no equivale a una prioridad alta.
        if key == 'application_warning' and row['count'] < 5:
            row['priority'] = 'BAJA'
        if key == 'cron' and row['count'] >= 3:
            row['priority'] = 'ALTA'
        row['hypothesis'], row['action'] = explanation(key)
        issues.append(row)
    pool = snapshot.get('processes', {}).get(domain)
    if pool and pool['cpu'] >= 50:
        # El límite de pool y su consumo son evidencias de un único problema de capacidad.
        capacity = next((row for row in issues if row['key'] == 'pool_limit'), None)
        if capacity is None:
            hypothesis, action = explanation('process_cpu')
            capacity = dict(key='process_cpu', title='Consumo actual de CPU en PHP-FPM', priority='ALTA' if pool['cpu'] >= 100 else 'MEDIA',
                            evidence='', count=None, first=None, last=None, sources=['/proc'], service='PHP-FPM', hypothesis=hypothesis, action=action)
            issues.append(capacity)
        capacity['current_evidence'] = (f"{pool['count']} procesos medidos; CPU media {pool['cpu']:.1f}% "
                                        f"(rango {pool.get('cpu_min', pool['cpu']):.1f}–{pool.get('cpu_max', pool['cpu']):.1f}%), "
                                        f"captura {snapshot['captured']}. No mide duración de peticiones.")
    for key, count in result.get('workloads', {}).items():
        issue = workload_issue(key, count, result.get('workload_windows', {}).get(key), api)
        if issue:
            issues.append(issue)
    generic_bots = [(family, count) for family, count in result.get('bot_families', {}).items() if count >= 100]
    for family, count in sorted(generic_bots, key=lambda item: (-item[1], item[0]))[:3]:
        window = result.get('bot_windows', {}).get(family) or []
        period = f' entre {window[0]} y {window[1]}' if len(window) == 2 else ''
        label = api.clean(family, 72) if api else family[:72]
        issues.append(dict(key='bot_family_' + label, title='Rastreo elevado: ' + label,
                           priority='MEDIA', evidence=f'{count} peticiones identificadas{period}.',
                           count=None, first=None, last=None, sources=['accesos del dominio'], service='web/bot',
                           hypothesis='El User-Agent declara esta familia automatizada; no verifica su identidad ni cuánto CPU consumió.',
                           action='Revisar sus rutas, códigos, bytes y frecuencia. Limitarla solo si no aporta valor y tras medir el resultado.'))
    agents = [row for row in result.get('activities', {}).values()
              if row.get('kind') == 'agent' and (row.get('count', 0) >= 100 or row.get('dynamic', 0) >= 50)]
    for row in sorted(agents, key=lambda item: (-item['dynamic'], -item['count'], item['label']))[:3]:
        label = api.clean(row['label'], 72) if api else row['label'][:72]
        routes = ', '.join(f'{count}× {path}' for path, count in row.get('routes', {}).most_common(3)) or 'sin rutas retenidas'
        priority = 'ALTA' if row['dynamic'] >= 500 or row['count'] >= 1000 else 'MEDIA'
        issues.append(dict(key='agent_family_' + label, title='Agente automatizado con actividad elevada: ' + label,
                           priority=priority,
                           evidence=(f"{row['count']} peticiones ({row['dynamic']} potencialmente PHP, "
                                     f"{row['bytes']/1048576:.2f} MiB) entre {row['first']} y {row['last']}. "
                                     f"Rutas principales: {routes}."),
                           count=None, first=None, last=None, sources=['accesos del dominio'], service='web/agente',
                           hypothesis='El producto se extrajo del User-Agent del log. Puede coincidir con carga, pero no mide CPU por petición ni demuestra causalidad.',
                           action='Revisar las muestras saneadas. Si es prescindible, pausarlo de forma controlada y comparar CPU/TTFB antes y después.'))
    for issue in issues:
        if issue.get('first'):
            context = access_correlation(issue, result)
            if context:
                issue['access_context'] = context['text']
                issue['context_routes'] = context['routes']
                issue['context_activities'] = context.get('activities', [])
            relation = peak_relation(issue, result)
            if relation:
                issue['peak_relation'] = relation
    d = result.get('diagnosis') or {}
    for yes, key, title, priority, evidence, hypothesis, action in (
        (d.get('health') in ('REVISAR', 'CRÍTICO'), 'http5', 'Respuestas HTTP de error del servidor',
         'ALTA' if d.get('health') == 'CRÍTICO' else 'MEDIA', f"{result.get('http5', 0)} respuestas 5xx en la lectura.",
         'Posible fallo de aplicación o backend; el código HTTP no mide CPU.', 'Revisar códigos, rutas y minutos con errores en el detalle.'),
        (d.get('suspicious') in ('MODERADO', 'ALTO'), 'automation', 'Señales de tráfico automatizado o exploración',
         'ALTA' if d.get('suspicious') == 'ALTO' else 'MEDIA', 'Se activaron señales combinadas del diagnóstico de tráfico.',
         'Automatización sospechosa; no confirma ataque ni identidad de personas.', 'Revisar las rutas e IP de la muestra antes de crear reglas o bloqueos.'),
        (bool(api and any(api.EXPOSURE.search(path) and item['codes'].get(200) for path, item in result.get('sensitive_details', {}).items())),
         'exposure', 'Posibles archivos sensibles con respuesta 200', 'ALTA', 'Se observaron respuestas 200 en rutas sensibles; contenido NO verificado.',
         'Puede ser exposición o una página de error personalizada; no se ha descargado contenido.', 'Revisar archivo y reglas desde Plesk antes de concluir que hay exposición.'),
        (d.get('impact') in ('POSIBLE', 'ALTO POTENCIAL') and not any(i['key'] in ('pool_limit', 'backend', 'php_memory') for i in issues),
         'backend_cost', 'Señales de coste o presión de backend', 'ALTA' if d.get('impact') == 'ALTO POTENCIAL' else 'MEDIA',
         'El diagnóstico de accesos/duración o mensajes internos activó impacto potencial.',
         'La duración y los errores no equivalen a CPU consumida.', 'Revisar las métricas y minutos del diagnóstico de impacto en el detalle.'),
    ):
        if yes:
            issues.append(dict(key=key, title=title, priority=priority, evidence=evidence, count=None,
                               first=None, last=None, sources=['accesos del dominio'], service='web', hypothesis=hypothesis, action=action))
    issues = sorted(issues, key=lambda row: (-LEVEL[row['priority']], row['key']))[:MAX_ISSUES]
    known = bool(result.get('read') or pool or snapshot.get('logs', {}).get(domain))
    priority = max((row['priority'] for row in issues), key=LEVEL.get) if issues else 'SIN AVISOS' if known else 'SIN DATOS'
    dominant = None
    pools = snapshot.get('processes', {})
    if pools:
        name, values = max(pools.items(), key=lambda item: item[1].get('cpu', 0))
        if values.get('cpu', 0) >= 50:
            dominant = dict(domain=name, cpu=values['cpu'], cpu_min=values.get('cpu_min', values['cpu']),
                            cpu_max=values.get('cpu_max', values['cpu']), count=values['count'])
    return dict(issues=issues, count=len(issues), priority=priority, processes=pool,
                server_pressure=snapshot.get('pressure'), dominant_pool=dominant,
                captured=snapshot.get('captured'), notes=list(snapshot.get('notes', [])), partial=snapshot.get('partial', True))


def show(result, api, verbose=False):
    if not result['issues'] and not result.get('processes') and not result.get('server_pressure'):
        return
    print('\n  RESUMEN PARA REVISAR · avisos agrupados por problema')
    print(f"  Avisos: {result['count']} | Prioridad: {result['priority']}")
    if result['issues']:
        print('  Empieza por: ' + result['issues'][0]['title'] + '.')
    def say(label, message):
        print(textwrap.fill(message, width=88, initial_indent='     ' + label, subsequent_indent='       '))
    def clock(value):
        try:
            return dt.datetime.fromisoformat(value).strftime('%d/%m %H:%M %z')
        except (TypeError, ValueError):
            return 'hora no disponible'
    for n, row in enumerate(result['issues'], 1):
        print(f"\n  {n}. {row['title']} · {row['priority']} · {row['service']}")
        say('Qué se ha visto: ', row['evidence'])
        if row['count'] is not None:
            say('Cuándo: ', f"{clock(row['first'])} a {clock(row['last'])} · {row['count']} mensajes, no peticiones.")
        if row.get('access_context'):
            say('Accesos cercanos: ', row['access_context'])
            for path, count in row.get('context_routes', []):
                say('Ruta cercana: ', f'{count} peticiones · {path}')
            for activity in row.get('context_activities', []):
                say('Actividad coincidente: ', activity + '. Coincidencia temporal; no prueba consumo de CPU.')
        if row.get('peak_relation'):
            say('Pico de tráfico: ', row['peak_relation'])
        if row.get('current_evidence') and verbose:
            say('AHORA: ', row['current_evidence'])
        if verbose:
            say('Fuente: ', ', '.join(row['sources']))
        if row.get('locations'):
            say('Archivo y línea: ', ', '.join(row['locations']))
        say('Qué puede significar: ', row['hypothesis'])
        say('Qué revisar: ', row['action'])
    pool = result.get('processes')
    if pool:
        print('\n  PROCESOS ACTUALES · captura UTC ' + result['captured'])
        print(f"  {pool['count']} procesos medidos; CPU media {pool['cpu']:.1f}% · "
              f"rango {pool.get('cpu_min', pool['cpu']):.1f}–{pool.get('cpu_max', pool['cpu']):.1f}% (100% = un núcleo).")
        rows = pool['processes'] if verbose else [p for p in pool['processes'] if p['cpu'] >= 1][:3]
        if rows:
            api.table(('PID', 'CPU %', 'RSS MiB'), [(p['pid'], p['cpu'], p['rss_mib']) for p in rows], (10, 10, 12))
            print('  RSS = memoria residente, incluye páginas compartidas; no sumar como RAM exclusiva.')
    pressure = result.get('server_pressure')
    if pressure:
        print('\n  SERVIDOR AHORA · medida global, no atribuida a esta web')
        print(f"  CPU ocupada {pressure['busy']:.1f}% · libre {pressure['idle']:.1f}% · "
              f"espera E/S {pressure['iowait']:.1f}% · ejecutables {pressure['runnable']} · "
              f"carga 1 min {pressure['load1']:.2f} / {pressure['cpus']} CPU lógicas.")
        if pressure['idle'] <= 5 or pressure['runnable'] > pressure['cpus']:
            print('  PRESIÓN ALTA: la captura encontró CPU saturada o cola superior a las CPU disponibles.')
    dominant = result.get('dominant_pool')
    if dominant:
        print(f"  Pool PHP con más CPU: {dominant['domain']} · media {dominant['cpu']:.1f}% · "
              f"rango {dominant['cpu_min']:.1f}–{dominant['cpu_max']:.1f}% · {dominant['count']} procesos.")
    if verbose:
        for note in result['notes']:
            say('Cobertura: ', note)
        print('  Sin avisos no significa ausencia de problemas. Lecturas parciales pueden omitir incidencias.')


def render_html(result, api):
    if not result['issues'] and not result.get('processes') and not result.get('server_pressure'):
        return ''
    esc = html.escape
    output = '<h3>Resumen para revisar</h3><p>Avisos: ' + str(result['count']) + ' · Prioridad: ' + esc(result['priority']) + '</p>'
    if result['issues']:
        output += '<p><strong>Empieza por: ' + esc(result['issues'][0]['title']) + '.</strong></p>'
    for row in result['issues']:
        output += '<article class="' + esc(row['priority'].lower(), quote=True) + '"><h4>' + esc(row['title'] + ' · ' + row['priority']) + '</h4><p>Qué se ha visto: ' + esc(row['evidence']) + '</p>'
        if row['count'] is not None:
            output += '<p>' + esc(f"{row['count']} mensajes, no peticiones; {row['first']} a {row['last']}") + '</p>'
        if row.get('access_context'):
            output += '<p>Accesos cercanos: ' + esc(row['access_context']) + '</p><ul>' + ''.join(
                '<li>' + esc(f'{count} peticiones · {path}') + '</li>' for path, count in row.get('context_routes', [])) + '</ul>'
            if row.get('context_activities'):
                output += '<p>Actividad coincidente:</p><ul>' + ''.join(
                    '<li>' + esc(value) + ' · coincidencia temporal, no prueba CPU.</li>'
                    for value in row['context_activities']) + '</ul>'
        if row.get('peak_relation'):
            output += '<p>Pico de tráfico: ' + esc(row['peak_relation']) + '</p>'
        output += '<p>' + esc(row.get('current_evidence', '')) + '</p><p>Fuente: ' + esc(', '.join(row['sources'])) + '</p>'
        if row.get('locations'):
            output += '<p>PHP: ' + esc(', '.join(row['locations'])) + '</p>'
        output += '<p>Puede ser: ' + esc(row['hypothesis']) + '</p><p>Qué revisar: ' + esc(row['action']) + '</p>'
        output += '</article>'
    if result.get('processes'):
        pool = result['processes']
        output += '<p>Procesos ACTUALES; captura UTC ' + esc(result['captured']) + '. CPU media ' + esc(f"{pool['cpu']:.1f}%") + \
                  ' · rango ' + esc(f"{pool.get('cpu_min', pool['cpu']):.1f}–{pool.get('cpu_max', pool['cpu']):.1f}%") + \
                  '. 100% = un núcleo. RSS compartida, no sumable como memoria exclusiva.</p>'
        output += api.html_table(('PID', 'CPU % / núcleo', 'RSS MiB'), [(p['pid'], p['cpu'], p['rss_mib']) for p in result['processes']['processes']])
    pressure = result.get('server_pressure')
    if pressure:
        output += '<p>Servidor durante la captura: ' + esc(
            f"CPU ocupada {pressure['busy']:.1f}% · libre {pressure['idle']:.1f}% · ejecutables {pressure['runnable']} · "
            f"carga {pressure['load1']:.2f}/{pressure['cpus']} CPU lógicas") + '.</p>'
    dominant = result.get('dominant_pool')
    if dominant:
        output += '<p>Pool PHP con más CPU: ' + esc(
            f"{dominant['domain']} · {dominant['cpu_min']:.1f}–{dominant['cpu_max']:.1f}% · media {dominant['cpu']:.1f}%") + '.</p>'
    output += '<p>Lectura parcial; mensajes repetidos entre fuentes no son incidentes únicos.</p>'
    output += '<details><summary>Ver cobertura del diagnóstico</summary><p>' + esc(' '.join(result['notes'])) + '</p></details>'
    return output
