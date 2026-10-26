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
        # Los hooks arbitrarios podrían contener identificadores privados: no conservarlos.
        label = 'sby_feed_update' if name == 'sby_feed_update' else 'otro hook (oculto)'
        return ('cron', 'Fallo al guardar tareas de WordPress', 'MEDIA', 'WP-Cron: could_not_set; ' + label)
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
        reader = Reader(api, seconds=2, maximum=1048576)
        try:
            ticks = os.sysconf('SC_CLK_TCK')
            page_size = os.sysconf('SC_PAGE_SIZE')
            first = process_sample(api, reader, selected)
            if first:
                # Pausa única, no monitor continuo; revalidar la presión antes de repetir.
                time.sleep(.5)
                cpus, loads, available = api.host_status()
                if available < 256 or loads[0] > max(4, cpus * 2):
                    raise ValueError('Presión durante instantánea')
                second = process_sample(api, reader, selected)
                if set(first) != set(second):
                    reader.partial = True
                result['processes'] = process_delta(first, second, ticks, page_size)
                result['server'] = result['processes'].pop('__server__', None)
        except (OSError, ValueError, AttributeError):
            reader.partial = True
        result['partial'] |= reader.partial
        result['read'] += reader.read
        result['notes'].append('CPU ACTUAL: dos muestras separadas por al menos 0,5 s; 100% equivale a un núcleo. Solo PID presentes en ambas; muestra breve, no carga sostenida.')
    else:
        result['notes'].append('Procesos actuales omitidos en consultas históricas o semanales; CPU/RAM históricas por dominio N/D.')
    result['read'] += logs['read']
    return result


def explanation(key):
    return {
        'pool_limit': ('PHP había ocupado todos los procesos permitidos para esta web. Otras solicitudes podían quedar esperando; no demuestra un ataque.',
                       'Revisar en Plesk los errores PHP y las tareas que coincidían con esas horas. No aumentar el límite sin identificar qué ocupaba los procesos.'),
        'cron': ('WordPress no pudo guardar la lista de tareas. Puede ser un fallo de persistencia o concurrencia; no demuestra que el plugin cause la carga.',
                 'Revisar el hook y los errores de WordPress/base de datos. sby_feed_update es una pista de YouTube Feed; confirmar el plugin instalado antes de actuar.'),
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
    rules = {
        'wp_rocket_preload': (10, 50, 'Precarga de WP Rocket observada',
            'El agente WP Rocket/Preload solicitó páginas. Una precarga grande puede ocupar PHP-FPM y CPU, como se comprobó en Escaparate Digital.',
            'Comprobar en WP Rocket si la precarga está activa y comparar el pool antes/después de pausarla.'),
        'action_scheduler': (20, 100, 'Ejecuciones de Action Scheduler',
            'Se observaron llamadas al runner asíncrono. Pueden proceder de WooCommerce u otros plugins y solaparse con peticiones internas de WordPress.',
            'Revisar en WordPress la cola pendiente y sus hooks principales; no cancelar tareas sin identificar su origen.'),
        'wp_cron': (20, 100, 'Muchas llamadas a WP-Cron',
            'Se observaron peticiones a wp-cron.php. El log no permite saber qué tarea se ejecutó ni cuánto consumió.',
            'Revisar frecuencia y tareas; en Plesk valorar cron real con DISABLE_WP_CRON tras comprobar que no exista ya.'),
        'wordpress_loopback': (50, 200, 'Muchas peticiones internas de WordPress',
            'El User-Agent identifica llamadas HTTP de WordPress a la propia web. Puede incluir cron, colas, precargas u otras integraciones.',
            'Cruzar las horas y rutas con WP-Cron, Action Scheduler y precargas; los contadores pueden solaparse.'),
        'amazonbot': (100, None, 'Tráfico de Amazonbot',
            'Amazonbot se identificó en el User-Agent. El nombre declarado no demuestra el coste de cada respuesta.',
            'Revisar rutas, códigos y bytes; limitarlo en nginx o robots solo si no aporta valor y la política del sitio lo permite.'),
        'geedoshop': (100, None, 'Tráfico de GeedoShopProductFinder',
            'GeedoShopProductFinder se identificó en el User-Agent. Puede generar volumen, pero el log no demuestra CPU consumida.',
            'Revisar rutas y frecuencia; si no es necesario, limitarlo en nginx y comprobar con un User-Agent normal.'),
        'plesk_screenshot': (50, None, 'Capturas automáticas de Plesk frecuentes',
            'Se observó el agente de capturas de Plesk. Normalmente es administrativo, pero una frecuencia alta merece revisión.',
            'Revisar la frecuencia de generación de miniaturas o capturas en Plesk.'),
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
        capacity['current_evidence'] = f"{pool['count']} procesos medidos; CPU conjunta {pool['cpu']:.1f}% de un núcleo, captura {snapshot['captured']}. No son procesos necesariamente ocupados ni duración de peticiones."
    for key, count in result.get('workloads', {}).items():
        issue = workload_issue(key, count, result.get('workload_windows', {}).get(key), api)
        if issue:
            issues.append(issue)
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
    return dict(issues=issues, count=len(issues), priority=priority, processes=pool,
                captured=snapshot.get('captured'), notes=list(snapshot.get('notes', [])), partial=snapshot.get('partial', True))


def show(result, api, verbose=False):
    if not result['issues'] and not result.get('processes'):
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
        print(f"  {pool['count']} procesos medidos; CPU conjunta {pool['cpu']:.1f}% (100% = un núcleo).")
        rows = pool['processes'] if verbose else [p for p in pool['processes'] if p['cpu'] >= 1][:3]
        if rows:
            api.table(('PID', 'CPU %', 'RSS MiB'), [(p['pid'], p['cpu'], p['rss_mib']) for p in rows], (10, 10, 12))
            print('  RSS = memoria residente, incluye páginas compartidas; no sumar como RAM exclusiva.')
    if verbose:
        for note in result['notes']:
            say('Cobertura: ', note)
        print('  Sin avisos no significa ausencia de problemas. Lecturas parciales pueden omitir incidencias.')


def render_html(result, api):
    if not result['issues'] and not result.get('processes'):
        return ''
    esc = html.escape
    output = '<h3>Resumen para revisar</h3><p>Avisos: ' + str(result['count']) + ' · Prioridad: ' + esc(result['priority']) + '</p>'
    if result['issues']:
        output += '<p><strong>Empieza por: ' + esc(result['issues'][0]['title']) + '.</strong></p>'
    for row in result['issues']:
        output += '<article class="' + esc(row['priority'].lower(), quote=True) + '"><h4>' + esc(row['title'] + ' · ' + row['priority']) + '</h4><p>Qué se ha visto: ' + esc(row['evidence']) + '</p>'
        if row['count'] is not None:
            output += '<p>' + esc(f"{row['count']} mensajes, no peticiones; {row['first']} a {row['last']}") + '</p>'
        output += '<p>' + esc(row.get('current_evidence', '')) + '</p><p>Fuente: ' + esc(', '.join(row['sources'])) + '</p>'
        if row.get('locations'):
            output += '<p>PHP: ' + esc(', '.join(row['locations'])) + '</p>'
        output += '<p>Puede ser: ' + esc(row['hypothesis']) + '</p><p>Qué revisar: ' + esc(row['action']) + '</p>'
        output += '</article>'
    if result.get('processes'):
        output += '<p>Procesos ACTUALES; captura UTC ' + esc(result['captured']) + '. CPU: 100% = un núcleo. RSS compartida, no sumable como memoria exclusiva.</p>'
        output += api.html_table(('PID', 'CPU % / núcleo', 'RSS MiB'), [(p['pid'], p['cpu'], p['rss_mib']) for p in result['processes']['processes']])
    output += '<p>Lectura parcial; mensajes repetidos entre fuentes no son incidentes únicos.</p>'
    output += '<details><summary>Ver cobertura del diagnóstico</summary><p>' + esc(' '.join(result['notes'])) + '</p></details>'
    return output
