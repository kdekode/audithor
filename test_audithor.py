import collections
import contextlib
import datetime as dt
import gzip
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import audithor as a


def line(path='/', ua='Mozilla/5.0 Chrome/130.0 Safari/537.36', stamp='19/Oct/2026:12:00:00 +0200', status=200):
    return f'192.0.2.1 - - [{stamp}] "GET {path} HTTP/1.1" {status} 123 "-" "{ua}"\n'.encode()


class Tests(unittest.TestCase):
    def test_parse_day_and_three_classes(self):
        for ua, expected in [('Googlebot', 'bot'), ('curl/8', 'bot'), ('Mozilla/5.0 Chrome/130.0 Safari/537.36', 'probable'), ('-', 'unknown')]:
            row = a.parse(line(ua=ua), dt.timezone.utc)
            self.assertEqual(row[0], dt.date(2026, 10, 19))
            self.assertEqual(row[4], expected)

    def test_midnight_offset(self):
        self.assertEqual(a.parse(line(stamp='19/Oct/2026:00:30:00 +0200'), dt.timezone.utc)[0], dt.date(2026, 10, 18))

    def test_invalid_and_secret_control_redaction(self):
        self.assertIsNone(a.parse(line(stamp='31/Feb/2026:12:00:00 +0000'), dt.timezone.utc))
        self.assertIsNone(a.parse(b'broken', dt.timezone.utc))
        self.assertNotIn('password', a.parse(line('/login?password=secret'), dt.timezone.utc)[1])
        self.assertNotIn('\x1b', a.clean('\x1b[31m'))
        self.assertIn(':redactado', a.safe_path('/' + 'a'*40))

    def test_counter_is_bounded(self):
        table = collections.Counter()
        for n in range(20000):
            a.increment(table, '/' + str(n))
        self.assertLessEqual(len(table), 2001)
        self.assertEqual(sum(table.values()), 20000)

    def test_single_layer_and_gzip_opt_in(self):
        entries = ['proxy_access_log', 'proxy_access_ssl_log.processed.1.gz', 'access_log', 'proxy_error_log', 'proxy_access_log.evil']
        with patch.object(a, 'names', return_value=entries):
            files, skipped, layer = a.sources(0, False)
            self.assertEqual(files, ['proxy_access_log'])
            self.assertEqual(skipped, 1)
            self.assertEqual(layer, 'nginx')

    def test_stream_budget_gzip_hardlinks_and_partial(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'test'
            path.write_bytes(line() * 5 + b'incomplete')
            @contextlib.contextmanager
            def opening(parent, name):
                with path.open('rb') as stream:
                    yield stream
            state = {'inodes': set(), 'notes': set()}
            with patch.object(a, 'regular', opening), patch.object(a.time, 'sleep'), patch.object(a, 'pressure', return_value=None):
                rows = list(a.scan(0, 'plain', a.Budget(5, 1), state))
                self.assertEqual(len(rows), 5)
                self.assertTrue(state['notes'])

                self.assertEqual(list(a.scan(0, 'same-inode', a.Budget(5, 1), state)), [])
                with path.open('wb') as stream:
                    stream.write(gzip.compress(line() * 100))
                state = {'inodes': set(), 'notes': set()}
                budget = a.Budget(5, 1)
                budget.maximum = 300
                rows = list(a.scan(0, 'test.gz', budget, state))
                self.assertLessEqual(budget.read, 300)
                self.assertLess(len(rows), 100)
                self.assertTrue(state['notes'])

    def test_pressure_aborts_before_reading(self):
        with patch.object(a, 'pressure', return_value='Host ocupado'):
            budget = a.Budget(30, 64)
            self.assertTrue(budget.exhausted())
            self.assertEqual(budget.read, 0)
            self.assertEqual(budget.pressure, 'Host ocupado')

    def test_pressure_reason_has_actual_values(self):
        self.assertIn('8.50', a.pressure_reason((8, (8.5, 6, 5), 1024)))
        self.assertIn('8.00', a.pressure_reason((8, (8.5, 6, 5), 1024)))
        self.assertIsNone(a.pressure_reason((8, (6.94, 7, 7), 8762)))
        self.assertIn('128 MiB', a.pressure_reason((8, (1, 1, 1), 128)))
        self.assertIsNone(a.pressure_reason((8, (1, 1, 1), 1024)))

    def test_diagnose_works_even_if_load_is_high(self):
        args = type('Args', (), {'diagnose': True, 'gentle': False})()
        output = io.StringIO()
        with patch.object(a, 'arguments', return_value=args), patch.object(a, 'host_status', return_value=(8, (9, 6, 5), 1024)), patch.object(a, 'directory') as directory, contextlib.redirect_stdout(output):
            self.assertEqual(a.main([]), 0)
            directory.assert_not_called()
        self.assertIn('8.00', output.getvalue())

    def test_gentle_slows_reads_and_keeps_guards(self):
        self.assertIsNone(a.pressure_reason((8, (6.94, 7, 7), 8762), True))
        self.assertIsNotNone(a.pressure_reason((8, (8.1, 7, 7), 8762), True))
        self.assertIsNotNone(a.pressure_reason((8, (6.94, 7, 7), 128), True))
        with patch.object(a.time, 'sleep') as sleep:
            a.Budget(2, 1, gentle=True).tick(100)
            sleep.assert_called_once_with(.01)

    def test_global_ranking_includes_later_domains_and_discards_routes(self):
        domains = ['a.com', 'b.com', 'c.com', 'd.com', 'unread.com']
        def result(root, domain, day, zone, args):
            totals = {'a.com': 10, 'b.com': 30, 'c.com': 0, 'd.com': 100, 'unread.com': 0}
            return dict(total=totals[domain], bytes=100, earliest=None, latest=None,
                        counts=collections.Counter(bot=1), notes=set(),
                        read=0 if domain == 'unread.com' else 1000,
                        urls={'should-not-be-retained': 100})
        args = type('Args', (), {'gentle': True})()
        with patch.object(a, 'pressure', return_value=None), patch.object(a, 'analyze', side_effect=result) as analyze, contextlib.redirect_stdout(io.StringIO()):
            rows = a.collect_ranked(0, domains, None, None, args)
        self.assertEqual([row[0] for row in rows], ['d.com', 'b.com', 'a.com', 'c.com', 'unread.com'])
        self.assertEqual(analyze.call_count, 5)
        self.assertTrue(all('urls' not in summary for _, summary in rows))

    def test_global_ranking_stops_when_host_pressure_rises(self):
        args = type('Args', (), {'gentle': True})()
        output = io.StringIO()
        with patch.object(a, 'pressure', return_value='Host ocupado'), patch.object(a, 'analyze') as analyze, contextlib.redirect_stdout(output):
            self.assertEqual(a.collect_ranked(0, ['a.com', 'b.com'], None, None, args), [])
            analyze.assert_not_called()
        self.assertIn('2 dominios pendientes', output.getvalue())

    def test_internal_errors_no_raw_secrets(self):
        event = a.error_event(b'2026/10/19 12:30:00 [error] PHP Fatal error: password=secret')
        self.assertEqual(event, (dt.date(2026, 10, 19), 'PHP fatal'))
        event = a.error_event(b'[Mon Oct 19 12:00:00.123 2026] [proxy_fcgi:error] PHP Warning: secret')
        self.assertEqual(event, (dt.date(2026, 10, 19), 'PHP warning'))
        self.assertIsNone(a.error_event(b'undated secret'))

    def test_domain_traversal_rejected(self):
        for domain in ['../../etc', 'https://example.com', 'example.com;id', '-x.com', 'a..com']:
            self.assertIsNone(a.DOMAIN.fullmatch(domain))
        self.assertIsNotNone(a.DOMAIN.fullmatch('sub.example.com'))

    def test_fail2ban_only_new_ban_events(self):
        prefix = b'2026-10-18 12:00:00,123 fail2ban.actions [123]: NOTICE [plesk-apache] '
        self.assertEqual(a.parse_ban(prefix + b'Ban 192.0.2.1\n'),
                         (dt.date(2026, 10, 18), 'plesk-apache', '192.0.2.1'))
        self.assertEqual(a.parse_ban(prefix + b'Ban 2001:db8::1\n')[2], '2001:db8::1')
        self.assertIsNone(a.parse_ban(prefix + b'Unban 192.0.2.1'))
        self.assertIsNone(a.parse_ban(prefix + b'Restore Ban 192.0.2.1'))
        self.assertIsNone(a.parse_ban(prefix + b'Ban not-an-ip'))

    def test_yesterday_includes_gzip_without_extra_flag(self):
        with patch.object(a, 'ZoneInfo', return_value=dt.timezone.utc):
            args = a.arguments(['example.com', '--yesterday', '--timezone', 'UTC'])
            self.assertTrue(args.historical)
            self.assertTrue(args.gzip)
            self.assertEqual(args.day, dt.datetime.now(dt.timezone.utc).date() - dt.timedelta(days=1))

    def test_signals_are_separate_from_bot_percentage(self):
        self.assertEqual(a.signals(dict(total=1000, counts={'bot': 1000})), [])
        findings = a.signals(dict(total=1000, http4=600, http5=150, sensitive=30, peak=400))
        self.assertEqual(len(findings), 4)

    def test_card_layout_has_no_unavailable_cpu_ram(self):
        result = dict(total=100, bytes=12345, counts=collections.Counter(bot=20, probable=80),
                      earliest=None, latest=None, notes=set(), read=1000,
                      http4=25, http5=2, sensitive=3, peak=50, f2b_matches=2)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            a.show('example.com', dt.date(2026, 10, 18), result)
        text = output.getvalue()
        self.assertIn('TRÁFICO', text)
        self.assertIn('HTTP 4xx', text)
        self.assertIn('IP coincidentes F2B', text)
        self.assertNotIn('RAM diaria', text)
        self.assertNotIn('CPU diaria', text)
        self.assertLessEqual(max(map(len, text.splitlines())), 90)
        self.assertEqual(a.PAGE_SIZE, 5)

    def test_history_analysis_and_fail2ban_read_only_fixtures(self):
        # Adaptar openat en Windows para probar el recorrido de datos completo.
        # La prueba Linux separada verifica enlaces/FIFO con descriptores reales.
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'proxy_access_log').write_bytes(line())
            (root / 'proxy_access_log.processed.1.gz').write_bytes(gzip.compress(
                line('/.env', ua='curl/8', stamp='18/Oct/2026:12:00:00 +0000', status=404) * 30))
            (root / 'error_log').write_bytes(b'2026/10/18 12:00:00 [error] PHP Fatal error: secret\n')
            (root / 'fail2ban.log').write_bytes(b'2026-10-18 12:00:00,123 fail2ban.actions [1]: NOTICE [apache] Ban 192.0.2.1\n')
            before = {p.name: p.read_bytes() for p in root.iterdir()}
            original_stat = os.stat
            @contextlib.contextmanager
            def opening(parent, name):
                with (root / name).open('rb') as stream:
                    yield stream
            def metadata(path, **kwargs):
                return original_stat(root / path)
            args = type('Args', (), dict(seconds=10, max_mib=1, gentle=True,
                day=dt.date(2026, 10, 18), historical=True, gzip=True, domain='example.com',
                no_fail2ban=False, fail2ban_log='/var/log/fail2ban.log'))()
            with patch.object(a, 'directory', return_value=999), patch.object(a, 'regular', opening), patch.object(a, 'names', return_value=list(before)), patch.object(a.os, 'stat', side_effect=metadata), patch.object(a.os, 'close'), patch.object(a, 'pressure', return_value=None), patch.object(a.time, 'sleep'):
                args.bans = a.read_fail2ban(args)
                result = a.analyze(0, 'example.com', args.day, dt.timezone.utc, args)
            self.assertEqual(args.bans['events'], 1)
            self.assertEqual(result['total'], 30)
            self.assertEqual(result['http4'], 30)
            self.assertEqual(result['sensitive'], 30)
            self.assertEqual(result['peak'], 30)
            self.assertEqual(result['f2b_matches'], 1)
            self.assertEqual(result['internal']['PHP fatal'], 1)
            self.assertEqual({p.name: p.read_bytes() for p in root.iterdir()}, before)

    @unittest.skipUnless(hasattr(os, 'O_NOFOLLOW'), 'Requiere Linux/openat')
    def test_linux_links_fifo_and_no_mutation(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'real').mkdir()
            (root / 'link').symlink_to(root / 'real', target_is_directory=True)
            with self.assertRaises(OSError):
                a.directory(str(root / 'link'))
            fd = a.directory(str(root))
            try:
                os.mkfifo(root / 'pipe')
                with self.assertRaises(ValueError):
                    with a.regular(fd, 'pipe'):
                        pass
                (root / 'real' / 'file').write_bytes(b'unchanged')
                (root / 'filelink').symlink_to(root / 'real' / 'file')
                with self.assertRaises(OSError):
                    with a.regular(fd, 'filelink'):
                        pass
                self.assertEqual((root / 'real' / 'file').read_bytes(), b'unchanged')
            finally:
                os.close(fd)


if __name__ == '__main__':
    unittest.main()
