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
