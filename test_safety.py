"""Regresiones acotadas para 0.11; nunca consultan el servidor real."""
import ast
import collections
import contextlib
import datetime as dt
import gzip
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch
from unittest.mock import MagicMock
import audithor as a
from test_audithor import line


class SafetyTests(unittest.TestCase):
    @contextlib.contextmanager
    def mocked_linux_guard(self):
        """Exercise startup on every platform without changing real OS limits."""
        fcntl = types.SimpleNamespace(LOCK_EX=2, LOCK_NB=4, flock=MagicMock())
        resource = types.SimpleNamespace(
            RLIMIT_AS=9, RLIMIT_CPU=0, RLIM_INFINITY=-1,
            getrlimit=MagicMock(return_value=(-1, -1)), setrlimit=MagicMock())
        info = types.SimpleNamespace(st_mode=0o100600, st_uid=123, st_nlink=1)
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.dict(sys.modules, fcntl=fcntl, resource=resource))
            stack.enter_context(patch.object(a.sys, 'platform', 'linux'))
            for name, value in dict(O_NOFOLLOW=0, O_NONBLOCK=0).items():
                stack.enter_context(patch.object(a.os, name, value, create=True))
            for name, value in dict(SIGALRM=14, SIGXCPU=24, ITIMER_REAL=0).items():
                stack.enter_context(patch.object(a.signal, name, value, create=True))
            for name, value in dict(open=42, fstat=info, geteuid=123, nice=0, close=None).items():
                stack.enter_context(patch.object(a.os, name, MagicMock(return_value=value), create=True))
            stack.enter_context(patch.object(a.time, 'process_time', return_value=1.2))
            stack.enter_context(patch.object(a.signal, 'signal', return_value='previous-handler'))
            timer = stack.enter_context(patch.object(a.signal, 'setitimer', create=True))
            stack.enter_context(patch.object(a, 'RUN_GUARD', None))
            yield fcntl, resource, timer

    def test_guard_startup_uses_instance_cpu_and_wall_budgets(self):
        args = types.SimpleNamespace(run_mib=256, cpu_seconds=30, run_seconds=900)
        with self.mocked_linux_guard() as (_, resource, timer):
            with a.RunGuard(args) as guard:
                self.assertIs(a.RUN_GUARD, guard)
                resource.setrlimit.assert_any_call(resource.RLIMIT_CPU, (32, 33))
                resource.setrlimit.assert_any_call(resource.RLIMIT_AS, (128 * 1048576, -1))
                timer.assert_called_once_with(a.signal.ITIMER_REAL, 900)
            self.assertIsNone(a.RUN_GUARD)
            timer.assert_called_with(a.signal.ITIMER_REAL, 0)
            a.os.close.assert_called_once_with(42)
            a.signal.signal.assert_any_call(a.signal.SIGALRM, 'previous-handler')
            a.signal.signal.assert_any_call(a.signal.SIGXCPU, 'previous-handler')

    def test_guard_busy_lock_closes_descriptor_without_starting_limits(self):
        args = types.SimpleNamespace(run_mib=256, cpu_seconds=30, run_seconds=900)
        with self.mocked_linux_guard() as (fcntl, resource, timer):
            fcntl.flock.side_effect = BlockingIOError()
            with self.assertRaises(a.SafetyLimit):
                with a.RunGuard(args):
                    self.fail('A concurrent run must not start')
            resource.setrlimit.assert_not_called()
            timer.assert_not_called()
            a.os.close.assert_called_once_with(42)
            self.assertIsNone(a.RUN_GUARD)

    def test_unique_shared_ip_exact_and_categories_can_overlap(self):
        values = {key: a.UniqueIPs() for key in ('all', 'bot', 'probable', 'unknown')}
        for category in ('bot', 'probable', 'unknown', 'probable'):
            values['all'].add('192.0.2.1')
            values[category].add('192.0.2.1')
        self.assertEqual(values['all'].result(), (1, False))
        self.assertEqual(sum(v.result()[0] for k, v in values.items() if k != 'all'), 3)
        self.assertEqual(a.normalized_ip('::ffff:192.0.2.1'), '192.0.2.1')

    def test_unique_switches_to_fixed_memory_approximation(self):
        with patch.object(a.secrets, 'token_bytes', return_value=b'x' * 16):
            counter = a.UniqueIPs()
        for n in range(12000):
            counter.add(f'10.{n // 65536}.{n // 256 % 256}.{n % 256}')
        count, approximate = counter.result()
        self.assertIsNone(counter.exact)
        self.assertEqual(len(counter.registers), 2048)
        self.assertTrue(approximate)
        self.assertLess(abs(count - 12000), 1200)

    def test_fake_browser_behavior_is_suspicious_without_human_probability(self):
        tracker = a.Behavior()
        for n in range(150):
            tracker.add('192.0.2.1', '/wp-login.php', 403, '2026-10-19 12:00 +0000', 'probable', True)
        rows = tracker.findings()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['browser'], 150)
        self.assertIn('repeticiones', rows[0]['reasons'])
        self.assertNotIn('probability', rows[0])
        self.assertEqual(a.parse(line(ua='Mozilla/5.0 Firefox/100'), dt.timezone.utc)[4], 'probable')

    def test_403_404_sequences_exploration_and_minute_gaps(self):
        tracker = a.Behavior()
        for n in range(30):
            tracker.add('192.0.2.2', f'/probe{n}', 404, '2026-10-19 12:00 +0000', 'probable', False)
        self.assertIn('racha', tracker.findings()[0]['reasons'])
        gap = a.Behavior()
        for n in range(30):
            gap.add('192.0.2.2', f'/probe{n}', 404, f'2026-10-19 12:{n:02d} +0000', 'probable', False)
        self.assertEqual(gap.findings(), [])

    def test_behavior_memory_limits_are_enforced(self):
        tracker = a.Behavior()
        for n in range(1200):
            tracker.add(f'10.0.{n // 256}.{n % 256}', '/', 200, '2026-10-19 12:00 +0000', 'unknown', False)
        self.assertEqual(len(tracker.ips), 1024)
        for n in range(100):
            tracker.add('10.0.0.0', f'/route{n}', 200, f'2026-10-19 {n // 60:02d}:{n % 60:02d} +0000', 'unknown', False)
        self.assertEqual(len(tracker.ips['10.0.0.0']['paths']), 32)
        self.assertEqual(len(tracker.ips['10.0.0.0']['minutes']), 64)
        self.assertTrue(tracker.partial)

    def test_sensitive_statuses_and_soft404_do_not_confirm_exposure(self):
        result = dict(sensitive_details={
            '/wp-login.php': dict(codes=collections.Counter({200: 10}), ips={'192.0.2.1': 10}, sizes={100}),
            '/.env': dict(codes=collections.Counter({200: 1, 401: 2, 403: 3, 404: 4, 302: 5}), ips={'192.0.2.2': 15}, sizes={100})},
            notfound_sizes={100: 10})
        rows = a.sensitive_rows(result)
        self.assertEqual(rows[0][0], '/.env')
        self.assertEqual(rows[0][1:7], (15, 1, 2, 3, 4, 5))
        self.assertIn('no verificado', rows[0][-1])
        self.assertIn('posible error personalizado', rows[0][-1])

    def test_coverage_does_not_claim_complete_day_from_first_last_dates(self):
        text = a.coverage_text(dict(observed_days=2, period_days=7, minutes={'2026-10-19 12:00 +0000': 3}))
        self.assertIn('DESCONOCIDA', text)
        self.assertIn('2/7', text)
        self.assertIn('no representa porcentaje', text)

    def test_domain_fake_browser_shared_ip_and_sensitive_codes_end_to_end(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'access_log'
            records = line('/.env', status=403) * 150
            records += b''.join(line('/.env', status=code, ua='curl/8') for code in (200, 401, 404))
            path.write_bytes(records)
            @contextlib.contextmanager
            def opening(parent, name):
                with path.open('rb') as stream:
                    yield stream
            args = types.SimpleNamespace(domain='example.com', sample=True, seconds=5, max_mib=8,
                       gentle=False, gzip=False, historical=False, bans=None, thresholds=a.THRESHOLDS)
            with patch.object(a, 'directory', return_value=99), patch.object(a, 'regular', opening), patch.object(a, 'names', return_value=['access_log']), patch.object(a.os, 'stat', return_value=path.stat()), patch.object(a.os, 'close'), patch.object(a, 'pressure', return_value=None), patch.object(a.time, 'sleep'):
                result = a.analyze(0, 'example.com', dt.date(2026, 10, 19), dt.timezone.utc, args)
            self.assertEqual(result['unique_ips']['all'], (1, False))
            self.assertEqual(result['unique_ips']['probable'], (1, False))
            self.assertEqual(result['unique_ips']['bot'], (1, False))
            self.assertEqual(result['suspect_requests'], 150)
            self.assertEqual(result['indeterminate_requests'], 0)
            self.assertEqual(result['behavior'][0]['browser'], 150)
            sensitive = a.sensitive_rows(result)[0]
            self.assertEqual(sensitive[1:7], (153, 1, 1, 150, 1, 0))
            self.assertTrue(result['diagnosis']['attention'])
            self.assertIn('NO CONFIRMADA', ' '.join(result['diagnosis']['hypotheses']))
            self.assertIn('DESCONOCIDA', result['coverage'])
            self.assertEqual(path.read_bytes(), records)

    def test_historical_gzip_inside_plain_interval_is_not_discarded(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'access_log.processed').write_bytes(line(stamp='17/Oct/2026:12:00:00 +0000') + line(stamp='19/Oct/2026:12:00:00 +0000'))
            (root / 'access_log.processed.1.gz').write_bytes(gzip.compress(line(stamp='18/Oct/2026:12:00:00 +0000')))
            @contextlib.contextmanager
            def opening(parent, name):
                with (root / name).open('rb') as stream:
                    yield stream
            with patch.object(a, 'regular', opening), patch.object(a, 'pressure', return_value=None):
                chosen = a.dated_quick_files(0, [p.name for p in root.iterdir()], dt.date(2026, 10, 18), dt.timezone.utc, a.Budget(5, 8), set())
            self.assertEqual(set(chosen), {'access_log.processed', 'access_log.processed.1.gz'})

    def test_full_has_finite_domain_cap_and_does_not_renew_it(self):
        budget = a.Budget(5, 8, continuous=True)
        budget.read = budget.hard_maximum
        with patch.object(a, 'wait_for_capacity') as wait:
            self.assertTrue(budget.exhausted())
        wait.assert_not_called()
        self.assertEqual(budget.hard_maximum, 64 * 1048576)

    def test_long_scan_requires_explicit_authorization(self):
        with patch.object(a, 'ZoneInfo', return_value=dt.timezone.utc):
            for flags in (['--full', '--seconds', '60'], ['--max-mib', '128'], ['--cpu-seconds', '60']):
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                    a.arguments(flags)
            args = a.arguments(['--full', '--seconds', '60', '--allow-long-scan'])
        self.assertEqual(args.run_seconds, 900)
        self.assertEqual(args.cpu_seconds, 30)

    def test_extreme_host_pressure_stops_and_low_ram_still_stops(self):
        self.assertIsNotNone(a.pressure_reason((8, (20, 8, 8), 8000), rapid=True))
        self.assertIsNotNone(a.pressure_reason((8, (2, 2, 2), 100), rapid=True))

    def test_byte_accounting_has_separate_hard_raw_and_decoded_caps(self):
        guard = a.RunGuard(types.SimpleNamespace(run_mib=1))
        guard.maximum = 10
        guard.debit(8, raw=True)
        guard.debit(9)
        self.assertEqual(guard.allowance(20, raw=True), 2)
        self.assertEqual(guard.allowance(20), 1)
        with self.assertRaises(a.SafetyLimit):
            guard.debit(2)
        self.assertEqual(guard.read, 9)

    def test_cloudflare_official_ipv4_ipv6_and_mapped_ip(self):
        for ip in ('104.16.1.2', '2606:4700::1', '::ffff:104.16.1.2'):
            self.assertTrue(a.cloudflare_ip(ip))
        self.assertFalse(a.cloudflare_ip('192.0.2.1'))
        self.assertFalse(a.cloudflare_ip('not an ip'))

    def test_active_fail2ban_separate_status_and_bounded_ips(self):
        outputs = ['Status\n Jail list: plesk-apache, ssh\n',
                   ' Currently banned: 1\n IP list: 104.16.1.2\n',
                   ' Currently banned: 1\n IP list: 192.0.2.1\n']
        with patch.object(a, 'readonly_f2b_status', side_effect=outputs) as client:
            result = a.read_active_fail2ban()
        self.assertEqual(result['ips'], {'104.16.1.2', '192.0.2.1'})
        self.assertIn('Cloudflare', result['jails'][0][2])
        self.assertEqual(client.call_args_list[1].args, ('plesk-apache',))
        self.assertNotIn('events', result)
        for jail in ('-s', '../../tmp', 'ssh;restart', 'ssh\nstop'):
            with self.assertRaises(ValueError):
                a.readonly_f2b_status(jail)

    def test_active_fail2ban_missing_permissions_or_incompatible_output_is_nd(self):
        for value in (PermissionError('denied'), 'unknown format'):
            with patch.object(a, 'readonly_f2b_status', side_effect=value if isinstance(value, Exception) else None,
                              return_value=value if isinstance(value, str) else ''):
                result = a.read_active_fail2ban()
            self.assertEqual(result['jails'], [])
            self.assertTrue(result['notes'])

    def test_client_uses_only_status_without_shell_and_bounds_output(self):
        file = MagicMock()
        file.fileno.return_value = 12
        process = MagicMock()
        process.stdout.fileno.return_value = 13
        process.returncode = 0
        process.poll.return_value = 0
        selector = MagicMock()
        selector.select.return_value = [(None, None)]
        status = types.SimpleNamespace(st_uid=0, st_mode=0o100755)
        with patch.object(a, 'directory', return_value=8), patch.object(a, 'regular') as opened, patch.object(a.os, 'fstat', return_value=status), patch.object(a.os, 'close'), patch.object(a.subprocess, 'Popen', return_value=process) as popen, patch.object(a.selectors, 'DefaultSelector') as selected, patch.object(a.os, 'read', side_effect=[b'Currently banned: 0\n IP list:\n', b'']):
            opened.return_value.__enter__.return_value = file
            selected.return_value.__enter__.return_value = selector
            text = a.readonly_f2b_status('ssh')
        self.assertIn('Currently banned', text)
        self.assertEqual(popen.call_args.args[0], ['/usr/bin/fail2ban-client', 'status', 'ssh'])
        self.assertFalse(popen.call_args.kwargs['shell'])
        self.assertIsNone(popen.call_args.kwargs['env'].get('PYTHONPATH'))

    def test_client_kills_only_its_own_child_on_oversized_output(self):
        process = MagicMock()
        process.stdout.fileno.return_value = 13
        process.poll.return_value = None
        selector = MagicMock()
        selector.select.return_value = [(None, None)]
        with patch.object(a, 'directory', return_value=8), patch.object(a, 'regular'), patch.object(a.os, 'fstat', return_value=types.SimpleNamespace(st_uid=0, st_mode=0o100755)), patch.object(a.os, 'close'), patch.object(a.subprocess, 'Popen', return_value=process), patch.object(a.selectors, 'DefaultSelector') as selected, patch.object(a.os, 'read', return_value=b'x' * 8192):
            selected.return_value.__enter__.return_value = selector
            with self.assertRaises(ValueError):
                a.readonly_f2b_status('ssh')
        process.kill.assert_called_once()

    def test_safety_limits_cannot_be_swallowed_by_log_recovery(self):
        args = types.SimpleNamespace(no_fail2ban=False, seconds=3, max_mib=2, gentle=False,
                fail2ban_log='/var/log/fail2ban.log', day=dt.date(2026, 10, 19))
        with patch.object(a, 'directory', return_value=99), patch.object(a, 'names', side_effect=a.SafetyLimit('stop')), patch.object(a.os, 'close'), self.assertRaises(a.SafetyLimit):
            a.read_fail2ban(args)

    def test_python39_syntax(self):
        ast.parse(Path(a.__file__).read_text(encoding='utf-8'), feature_version=(3, 9))

    @unittest.skipUnless(sys.platform.startswith('linux'), 'Requiere flock/RLIMIT/señales Linux reales')
    def test_kernel_limits_lock_and_wall_timeout_in_disposable_process(self):
        # Solo duerme: no genera carga para comprobar el temporizador.
        with tempfile.TemporaryDirectory() as tmp:
            script = '''import importlib.util, resource, time, types
spec = importlib.util.spec_from_file_location('audithor', SOURCE)
a = importlib.util.module_from_spec(spec); spec.loader.exec_module(a)
args = types.SimpleNamespace(run_mib=1, run_seconds=1, cpu_seconds=2)
try:
 with a.RunGuard(args, LOCK):
  assert resource.getrlimit(resource.RLIMIT_AS)[0] <= 128*1048576
  assert resource.getrlimit(resource.RLIMIT_CPU)[1] <= 5
  try:
   with a.RunGuard(args, LOCK): raise AssertionError('second run accepted')
  except a.SafetyLimit: pass
  assert a.RUN_GUARD is not None
  time.sleep(2)
except a.SafetyLimit:
 print('limits-and-lock-ok')
'''.replace('SOURCE', repr(a.__file__)).replace('LOCK', repr(str(Path(tmp) / 'lock')))
            process = subprocess.run([sys.executable, '-I', '-B', '-c', script], capture_output=True, timeout=5)
            self.assertEqual(process.returncode, 0, process.stderr)
            self.assertIn(b'limits-and-lock-ok', process.stdout)

    @unittest.skipUnless(sys.platform.startswith('linux'), 'Requiere descriptores Linux')
    def test_raw_reader_never_passes_hard_io_ceiling(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'data'
            path.write_bytes(b'x' * 10000)
            guard = a.RunGuard(types.SimpleNamespace(run_mib=1))
            guard.maximum = 100
            with patch.object(a, 'RUN_GUARD', guard):
                with a.MeteredRaw(os.open(path, os.O_RDONLY)) as raw:
                    self.assertEqual(len(raw.read(1000)), 100)
                    with self.assertRaises(a.SafetyLimit): raw.read(1)
            self.assertEqual(guard.raw_read, 100)


if __name__ == '__main__':
    unittest.main()
