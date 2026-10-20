"""Logs y SQLite temporales. Nunca usa dominios/servicios del servidor."""
import ast
import contextlib
import datetime as dt
import io
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import types
import unittest
from unittest.mock import patch, MagicMock

import audithor as a
import audithor_watch as w
from test_audithor import line

STAMP = int(dt.datetime(2026, 10, 19, 10, tzinfo=dt.timezone.utc).timestamp())
FATAL = b'2026/10/19 10:00:00 [error] PHP Fatal error: password=very-secret in /private/client/index.php on line 42\n'


def fake_pread(fd, count, offset):
    position = os.lseek(fd, 0, os.SEEK_CUR)
    try:
        os.lseek(fd, offset, os.SEEK_SET)
        return os.read(fd, count)
    finally:
        os.lseek(fd, position, os.SEEK_SET)


class WatchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.pread = patch.object(w.os, 'pread', fake_pread, create=True)
        self.pread.start()
        self.addCleanup(self.pread.stop)
        self.addCleanup(self.temp.cleanup)

    def store(self):
        store = w.Store(str(self.root / 'audithor.sqlite'), 'example.com', now=STAMP)
        self.addCleanup(lambda: store.close(now=STAMP) if not store.closed else None)
        return store

    @contextlib.contextmanager
    def engine(self, store):
        native_open, native_stat = os.open, os.stat
        def opened(name, flags, *args, **kwargs):
            path = self.root / name if 'dir_fd' in kwargs else name
            if sys.platform == 'win32':
                # Emular los handles que Linux deja renombrar mientras siguen abiertos.
                import ctypes
                import msvcrt
                create = ctypes.WinDLL('kernel32', use_last_error=True).CreateFileW
                create.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p,
                                   ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p]
                create.restype = ctypes.c_void_p
                handle = create(str(path), 0x80000000, 7, None, 3, 0x80, None)
                if handle == ctypes.c_void_p(-1).value:
                    raise ctypes.WinError(ctypes.get_last_error())
                return msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
            return native_open(path, flags, *args)
        def metadata(name, **kwargs):
            return native_stat(self.root / name if 'dir_fd' in kwargs else name, follow_symlinks=kwargs.get('follow_symlinks', True))
        args = types.SimpleNamespace(zone=dt.timezone.utc)
        with patch.object(w.os, 'open', side_effect=opened), patch.object(w.os, 'stat', side_effect=metadata), patch.object(w.os, 'O_NOFOLLOW', 0, create=True), patch.object(w.os, 'O_NONBLOCK', 0, create=True), patch.object(w, 'utc_now', return_value=STAMP):
            engine = w.Engine(999, args, store, a)
            try:
                yield engine
            finally:
                engine.close()

    def test_cli_requires_one_domain_and_rejects_history_and_services(self):
        for flags in (['--watch'], ['example.com', '--watch', '--full'], ['example.com', '--watch', '--yesterday'],
                      ['example.com', '--watch', '--report'], ['example.com', '--watch', '--fail2ban-active']):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                a.arguments(flags)
        with patch.object(a, 'ZoneInfo', return_value=dt.timezone.utc):
            args = a.arguments(['example.com', '--watch', '--watch-seconds', '300'])
        self.assertEqual(args.watch_seconds, 300)
        self.assertFalse(args.full)

    def test_start_from_eof_and_only_new_lines(self):
        path = self.root / 'error_log'
        path.write_bytes(FATAL)
        store = self.store()
        with self.engine(store) as engine:
            engine.cycle()
            self.assertEqual(len(store.queue), 0)
            with path.open('ab') as stream:
                stream.write(FATAL)
            engine.cycle()
            self.assertEqual(sum(v[2] for v in store.queue.values()), 1)
            engine.cycle()
            self.assertEqual(sum(v[2] for v in store.queue.values()), 1)

    def test_rotation_drains_old_descriptor_and_reads_new_file_once(self):
        path = self.root / 'error_log'
        path.write_bytes(b'old history\n')
        store = self.store()
        with self.engine(store) as engine:
            path.rename(self.root / 'error_log.1')
            path.write_bytes(FATAL)
            engine.cycle()
            self.assertEqual(sum(v[2] for v in store.queue.values()), 1)
            engine.cycle()
            engine.cycle()
            self.assertEqual(sum(v[2] for v in store.queue.values()), 1)
            self.assertLessEqual(len(engine.tails), w.MAX_FILES)

    def test_repeated_rotation_keeps_descriptors_buffers_and_fingerprints_bounded(self):
        path = self.root / 'error_log'
        path.write_bytes(b'')
        store = self.store()
        with self.engine(store) as engine:
            for n in range(30):
                path.rename(self.root / ('rotated-' + str(n)))
                path.write_bytes(FATAL.replace(b'line 42', ('line ' + str(n + 1)).encode()))
                engine.cycle()
                engine.cycle()
                self.assertLessEqual(len(engine.tails), w.MAX_FILES)
                self.assertTrue(all(len(t.pending) <= w.MAX_LINE for t in engine.tails))
                self.assertTrue(all(len(q) <= 256 for q in engine.recent.values()))
                self.assertLessEqual(len(store.queue), w.MAX_QUEUE)

    def test_truncate_and_regrow_detected_by_anchor(self):
        path = self.root / 'error_log'
        path.write_bytes(b'initial prefix\n')
        store = self.store()
        with self.engine(store) as engine:
            path.write_bytes(FATAL)
            engine.cycle()
            self.assertEqual(sum(v[2] for v in store.queue.values()), 1)
            self.assertTrue(any('truncamiento' in label for label in store.pending_gaps))

    def test_normal_repeated_errors_count_but_copy_replay_is_not_counted_twice(self):
        path = self.root / 'error_log'
        path.write_bytes(b'')
        store = self.store()
        with self.engine(store) as engine:
            path.write_bytes(FATAL * 2)
            engine.cycle()
            self.assertEqual(sum(v[2] for v in store.queue.values()), 2)
            path.write_bytes(b'new prefix\n' + FATAL * 2)
            engine.cycle()
            self.assertEqual(sum(v[2] for v in store.queue.values()), 2)
            self.assertTrue(any('duplicado' in label for label in store.pending_gaps))

    def test_php_sql_nginx_fpm_memory_and_permissions(self):
        cases = [
            (FATAL, 'PHP Fatal', 'aplicación'),
            (b'2026/10/19 10:00:00 [error] SQLSTATE[HY000] SQL syntax password=secret\n', 'Error SQL registrado', 'aplicación'),
            (b'2026/10/19 10:00:00 [error] upstream timed out request: "GET /api/client?token=secret HTTP/1.1"\n', 'Timeout registrado', 'Nginx'),
            (b'[19-Oct-2026 10:00:00] WARNING: [pool example.com] server reached pm.max_children setting\n', 'Límite PHP-FPM', 'PHP-FPM'),
            (b'[19-Oct-2026 10:00:00] PHP Fatal error: Allowed memory size exhausted\n', 'Límite de memoria', 'aplicación'),
            (b'2026/10/19 10:00:00 [error] permission denied\n', 'Permiso denegado', 'Nginx')]
        for raw, kind, service in cases:
            with self.subTest(kind=kind):
                result = w.parse_incident(raw, 'proxy_error_log', dt.timezone.utc, a)
                self.assertEqual((result['kind'], result['service']), (kind, service))
                self.assertNotIn('secret', str(result))
                self.assertEqual(result['logged_at'], STAMP)
        parsed = w.parse_incident(FATAL, 'error_log', dt.timezone.utc, a)
        self.assertEqual((parsed['php_file'], parsed['php_line']), ('index.php', 42))
        self.assertIsNone(parsed['route'])

    def test_sql_and_exception_payloads_and_traces_are_never_stored(self):
        raw = b'2026/10/19 10:00:00 [error] Uncaught PDOException: SQLSTATE[HY000] SELECT password FROM users WHERE token=supersecret cookie=hidden\n'
        result = w.parse_incident(raw, 'error_log', dt.timezone.utc, a)
        for secret in ('supersecret', 'hidden', 'SELECT', 'users', 'password FROM'):
            self.assertNotIn(secret, str(result))
        self.assertIn('SQLSTATE[HY000]', result['evidence'])
        self.assertIsNone(w.parse_incident(b'#0 /private/passwd.php(42): secret\n', 'error_log', dt.timezone.utc, a))

    def test_access_normal_requests_not_stored_and_5xx_route_is_redacted(self):
        self.assertIsNone(w.parse_incident(line('/normal'), 'access_log', dt.timezone.utc, a))
        raw = line('/api/customer/password?token=supersecret', status=503)
        result = w.parse_incident(raw, 'access_log', dt.timezone.utc, a)
        self.assertEqual(result['code'], 503)
        self.assertEqual(result['route'], '/api/:segmento/:segmento')
        self.assertNotIn('supersecret', str(result))

    def test_queue_and_minute_rate_are_bounded_and_losses_visible(self):
        store = self.store()
        incident = w.parse_incident(FATAL, 'error_log', dt.timezone.utc, a)
        for n in range(1000):
            event = dict(incident, evidence='fixed marker ' + str(n))
            store.enqueue(event, now=STAMP + n // 120 * 60)
        self.assertLessEqual(len(store.queue), w.MAX_QUEUE)
        self.assertGreater(store.omitted, 0)
        self.assertLessEqual(len(store.pending_gaps), 16)
        self.assertTrue(store.flush(now=STAMP + 600))
        self.assertGreater(store.db.execute('SELECT omitted FROM sessions').fetchone()[0], 0)

    def test_frequency_grouping_and_clean_close(self):
        store = self.store()
        event = w.parse_incident(FATAL, 'error_log', dt.timezone.utc, a)
        for _ in range(3): store.enqueue(event, now=STAMP)
        self.assertEqual(len(store.queue), 1)
        store.flush(now=STAMP)
        store.enqueue(event, now=STAMP + 1)
        store.close('Ctrl+C: cierre manual', now=STAMP + 2)
        self.assertTrue(store.closed)
        with contextlib.closing(sqlite3.connect(self.root / 'audithor.sqlite')) as connection:
            self.assertEqual(connection.execute('SELECT frequency FROM incidents').fetchone()[0], 4)
            self.assertEqual(connection.execute('SELECT reason FROM sessions').fetchone()[0], 'Ctrl+C: cierre manual')

    def test_retention_rows_and_database_size_are_bounded_without_vacuum(self):
        store = self.store()
        old = dict(w.parse_incident(FATAL, 'error_log', dt.timezone.utc, a), logged_at=STAMP - 9 * 86400)
        store.enqueue(old, now=STAMP)
        store.flush(now=STAMP)
        store.flush(now=STAMP)
        self.assertEqual(store.db.execute('SELECT count(*) FROM incidents').fetchone()[0], 0)
        self.assertEqual(store.db.execute('PRAGMA max_page_count').fetchone()[0], 2048)
        self.assertEqual(store.db.execute('PRAGMA auto_vacuum').fetchone()[0], 0)
        self.assertLessEqual((self.root / 'audithor.sqlite').stat().st_size, w.MAX_DB)

    def test_long_or_incomplete_line_has_fixed_buffer_and_coverage_loss(self):
        path = self.root / 'error_log'
        path.write_bytes(b'')
        store = self.store()
        tail = w.Tail(os.open(path, os.O_RDONLY), 'error_log')
        self.addCleanup(tail.close)
        self.assertEqual(list(tail.lines(b'x' * 20000, store)), [])
        self.assertLessEqual(len(tail.pending), w.MAX_LINE)
        self.assertEqual(list(tail.lines(b'x\n' + FATAL, store)), [FATAL])
        self.assertGreater(store.omitted, 0)

    def test_huge_backlog_skipped_instead_of_scanning_history(self):
        path = self.root / 'error_log'
        path.write_bytes(b'')
        store = self.store()
        tail = w.Tail(os.open(path, os.O_RDONLY), 'error_log')
        self.addCleanup(tail.close)
        path.write_bytes(b'x' * (1048576 + 1))
        self.assertEqual(tail.read(16384, store, a), b'')
        self.assertGreater(store.omitted_bytes, 1048576)

    def test_missing_or_inaccessible_logs_are_not_reported_as_clean(self):
        store = self.store()
        with self.engine(store) as engine:
            self.assertEqual(engine.tails, [])
            self.assertTrue(any('ausente/no accesible' in label for label in store.pending_gaps))

    def test_new_log_without_read_permission_is_skipped_and_reported(self):
        store = self.store()
        with self.engine(store) as engine:
            (self.root / 'error_log').write_bytes(FATAL)
            with patch.object(w.os, 'open', side_effect=PermissionError()):
                engine.reconcile()
            self.assertEqual(engine.tails, [])
            self.assertTrue(any('no accesible' in label for label in store.pending_gaps))

    def test_normal_access_burst_creates_one_incident_without_saving_requests(self):
        path = self.root / 'access_log'
        path.write_bytes(b'')
        store = self.store()
        with self.engine(store) as engine:
            path.write_bytes(line('/private/customer?token=hidden') * 610)
            for _ in range(12):
                engine.cycle()
            self.assertEqual(len(store.queue), 1)
            entry = next(iter(store.queue.values()))
            self.assertEqual(entry[0][0], 'Ráfaga observada')
            self.assertNotIn('hidden', repr(store.queue))
            self.assertNotIn('customer', repr(store.queue))

    def test_row_retention_caps_existing_groups(self):
        store = self.store()
        with store.db:
            store.db.executemany('INSERT INTO incidents(domain,bucket,signature,frequency) VALUES(?,?,?,1)',
                                 [('example.com', STAMP, str(n)) for n in range(10020)])
        self.assertTrue(store.flush(now=STAMP))
        self.assertLessEqual(store.db.execute('SELECT count(*) FROM incidents').fetchone()[0], 10000)

    def test_saved_history_renders_real_fields_and_unknown_route_without_causality(self):
        result = dict(message='Vigilancia parcial', events=[(STAMP, 3, 'PHP Fatal', 'CRÍTICA', None, None,
                      'index.php', 42, 'aplicación', 'PHP Fatal en error_log', STAMP, STAMP, STAMP, STAMP)], sessions=[], gaps=[])
        rows, _, _ = w.history_rows(result, dt.timezone.utc, a)
        self.assertEqual(rows[0][7], 'index.php:42')
        self.assertEqual(rows[0][6], 'sin relación HTTP demostrada')
        self.assertIn('PHP Fatal en error_log', w.history_html(result, dt.timezone.utc, a))

    def test_no_inotify_has_paused_polling_fallback(self):
        with patch.object(w.ctypes, 'CDLL', side_effect=OSError()):
            waiter = w.Waiter(1)
        self.assertIsNone(waiter.fd)
        with patch.object(w.time, 'monotonic', side_effect=[0, 0]), patch.object(w.time, 'sleep') as sleep:
            waiter.wait(2)
        sleep.assert_called_once_with(2)

    def test_inotify_overflow_is_detected_and_minimum_pause_kept(self):
        waiter = object.__new__(w.Waiter)
        waiter.fd = 123
        with patch.object(w.select, 'select', return_value=([123], [], [])), patch.object(w.os, 'read', return_value=w.struct.pack('iIII', -1, 0x4000, 0, 0)), patch.object(w.time, 'monotonic', side_effect=[0, .1]), patch.object(w.time, 'sleep') as sleep:
            self.assertTrue(waiter.wait(2))
        self.assertAlmostEqual(sleep.call_args.args[0], 1.9)

    def test_history_query_is_readonly_and_no_session_is_unknown_coverage(self):
        store = self.store()
        store.close(now=STAMP)
        path = self.root / 'audithor.sqlite'
        before = path.read_bytes()
        args = types.SimpleNamespace(domain='other.com', day=dt.date(2026, 10, 19), zone=dt.timezone.utc)
        with patch.object(w, 'private_data', return_value=99), patch.object(w, 'check_data_files'), patch.object(w, 'db_path', return_value=str(path)), patch.object(w.os, 'close'):
            result = w.read_history(args, a)
        self.assertEqual(result['sessions'], [])
        self.assertIn('no implica ausencia', result['message'])
        self.assertEqual(path.read_bytes(), before)

    def test_watch_module_python39_syntax(self):
        ast.parse(Path(w.__file__).read_text(encoding='utf-8'), feature_version=(3, 9))

    def test_missing_watch_folder_is_distinguished_from_permission_failure(self):
        args = types.SimpleNamespace(domain='example.com')
        with patch.object(w, 'private_data', side_effect=FileNotFoundError()), patch.object(w.sqlite3, 'connect') as connect:
            result = w.read_history(args, a)
        self.assertIn('No hay carpeta', result['message'])
        self.assertIn('no crea ese historial', result['message'])
        connect.assert_not_called()
        with patch.object(w, 'private_data', side_effect=PermissionError()):
            denied = w.read_history(args, a)
        self.assertIn('N/D', denied['message'])
        self.assertNotIn('No hay carpeta', denied['message'])

    def test_empty_watch_history_explains_coverage_without_empty_tables(self):
        result = dict(events=[], sessions=[], gaps=[], message='No hay vigilancia guardada.')
        output = io.StringIO()
        with contextlib.redirect_stdout(output), patch.object(a, 'table') as table:
            w.show_history(result, dt.timezone.utc, a)
        table.assert_not_called()
        self.assertIn('Sin incidencias guardadas disponibles', output.getvalue())
        self.assertIn('cobertura desconocida', output.getvalue())

    def protected_fixture(self, status, wait_action):
        """Ejecutar el bucle con archivos/SQLite propios y adaptadores del SO."""
        original_open = os.open
        marker = self.root / 'directory-marker'
        marker.write_bytes(b'')
        api = types.SimpleNamespace(directory=lambda *x: original_open(marker, os.O_RDONLY), host_status=lambda: status)
        args = types.SimpleNamespace(domain='example.com', root='/unused', watch_seconds=100, zone=dt.timezone.utc)
        resource = types.SimpleNamespace(RLIMIT_FSIZE=1, RLIM_INFINITY=-1,
                      getrlimit=lambda x: (-1, -1), setrlimit=MagicMock())
        def opened(name, flags, *x, **kwargs):
            return original_open(self.root / name if 'dir_fd' in kwargs else name, flags, *x)
        instances = []
        factory = w.Store
        def created(*x, **kwargs):
            store = factory(*x, **kwargs)
            instances.append(store)
            return store
        engine, waiter = MagicMock(), MagicMock()
        engine.tails = [object()]
        waiter.fd = None
        waiter.wait.side_effect = wait_action
        with patch.dict(sys.modules, resource=resource), patch.object(w, 'check_data_files'), patch.object(w, 'db_path', return_value=str(self.root / 'audithor.sqlite')), patch.object(w, 'Store', side_effect=created), patch.object(w, 'Engine', return_value=engine), patch.object(w, 'Waiter', return_value=waiter), patch.object(w.os, 'open', side_effect=opened), patch.object(w.os, 'O_NOFOLLOW', 0, create=True), contextlib.redirect_stdout(io.StringIO()):
            code = w.protected_watch(args, api, 999)
        self.assertTrue(instances[0].closed)
        engine.close.assert_called_once()
        return code, engine, instances[0]

    def test_ctrl_c_closes_database_and_records_manual_interruption(self):
        code, engine, store = self.protected_fixture((8, (1, 1, 1), 8000), KeyboardInterrupt())
        self.assertEqual(code, 0)
        engine.cycle.assert_called_once()
        with contextlib.closing(sqlite3.connect(self.root / 'audithor.sqlite')) as connection:
            self.assertIn('Ctrl+C', connection.execute('SELECT reason FROM sessions').fetchone()[0])

    def test_low_memory_never_processes_logs_and_stops_cleanly(self):
        code, engine, store = self.protected_fixture((8, (1, 1, 1), 100), KeyboardInterrupt())
        engine.cycle.assert_not_called()
        with contextlib.closing(sqlite3.connect(self.root / 'audithor.sqlite')) as connection:
            self.assertIn('memoria', connection.execute('SELECT reason FROM sessions').fetchone()[0])

    def test_high_load_suspends_then_terminates_without_waiting_forever(self):
        clock = [0]
        def wait(seconds):
            clock[0] += seconds
            return False
        with patch.object(w.time, 'monotonic', side_effect=lambda: clock[0]):
            code, engine, store = self.protected_fixture((8, (9, 9, 9), 8000), wait)
        self.assertEqual(code, 75)
        engine.cycle.assert_not_called()
        self.assertLessEqual(clock[0], 35)
        with contextlib.closing(sqlite3.connect(self.root / 'audithor.sqlite')) as connection:
            self.assertIn('presión sostenida', connection.execute('SELECT reason FROM sessions').fetchone()[0])
            self.assertGreater(connection.execute('SELECT count(*) FROM gaps').fetchone()[0], 0)

    def test_sqlite_full_is_effective_not_only_a_configuration_value(self):
        store = self.store()
        with self.assertRaises(sqlite3.DatabaseError):
            with store.db:
                store.db.execute('CREATE TABLE big(value BLOB)')
                store.db.execute('INSERT INTO big VALUES(zeroblob(?))', (w.MAX_DB + 4096,))
        self.assertLessEqual((self.root / 'audithor.sqlite').stat().st_size, w.MAX_DB)

    def test_busy_sqlite_discards_queue_and_reports_loss(self):
        store = self.store()
        incident = w.parse_incident(FATAL, 'error_log', dt.timezone.utc, a)
        store.enqueue(incident, now=STAMP)
        with contextlib.closing(sqlite3.connect(self.root / 'audithor.sqlite')) as other:
            other.execute('BEGIN EXCLUSIVE')
            self.assertFalse(store.flush(now=STAMP))
            self.assertEqual(len(store.queue), 0)
            self.assertGreater(store.omitted, 0)
            other.rollback()
        self.assertTrue(store.flush(now=STAMP))

    def test_watch_uses_only_domain_lock_inside_data_not_global_tmp_lock(self):
        args = types.SimpleNamespace(domain='example.com')
        api = types.SimpleNamespace(RunGuard=MagicMock())
        with patch.object(w, 'private_data', return_value=99), patch.object(w, 'protected_watch', return_value=0), patch.object(w.os, 'close'):
            self.assertEqual(w.run_watch(args, api), 0)
        path = api.RunGuard.call_args.kwargs['lock_path']
        self.assertTrue(path.startswith('/proc/self/fd/99/watch-'))
        self.assertNotIn('/tmp/', path)

    @unittest.skipUnless(sys.platform.startswith('linux'), 'Requiere openat y permisos Linux')
    def test_private_store_refuses_symlinks_and_public_data(self):
        folder = self.root / 'data'
        folder.mkdir(mode=0o700)
        fd = w.private_data(a, base=str(self.root))
        os.close(fd)
        folder.chmod(0o755)
        with self.assertRaises(ValueError): w.private_data(a, base=str(self.root))
        folder.chmod(0o700)
        (folder / 'audithor.sqlite').symlink_to(self.root / 'outside')
        fd = w.private_data(a, base=str(self.root))
        try:
            with self.assertRaises(ValueError): w.check_data_files(fd)
        finally:
            os.close(fd)

    @unittest.skipUnless(sys.platform.startswith('linux'), 'Requiere inotify Linux real')
    def test_native_inotify_on_a_temporary_directory_only(self):
        folder = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        waiter = w.Waiter(folder)
        try:
            if waiter.fd is None:
                self.skipTest('inotify no disponible: queda alternativa con pausa')
            (self.root / 'error_log').write_bytes(FATAL)
            self.assertFalse(waiter.wait(.01))
        finally:
            waiter.close()
            os.close(folder)


if __name__ == '__main__':
    unittest.main()
