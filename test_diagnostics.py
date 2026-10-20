"""Diagnóstico sin servicios externos ni cambios en el servidor."""
import collections
import contextlib
import datetime as dt
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import audithor as a
from test_audithor import line


def sample(total=100, errors=0, rapid=True, **extra):
    result = dict(total=total, http5=errors, http4=0, bytes=1000, read=1000,
                  counts=collections.Counter(), statuses=collections.Counter({200: total-errors, 500: errors}),
                  minutes={}, error_minutes={}, internal=collections.Counter(), notes=set(), rapid=rapid,
                  earliest=None, latest=None)
    result.update(extra)
    return result


class DiagnosisTests(unittest.TestCase):
    def test_http_codes_and_denominator_include_successes(self):
        result = sample(statuses=collections.Counter({200: 50, 404: 20, 418: 10, 500: 10, 507: 10}))
        rows = {label: (n, pct) for label, n, pct in a.http_rows(result)}
        self.assertEqual(rows['404'], ('20', '20.0%'))
        self.assertEqual(rows['Otros 4xx'], ('10', '10.0%'))
        self.assertEqual(rows['Otros 5xx'], ('10', '10.0%'))
        self.assertEqual(rows['504'], ('0', '0.0%'))
        self.assertEqual(a.http_rows(sample(0))[0][1:], ('N/D', 'N/D'))

    def test_health_requires_count_rate_and_minimum_population(self):
        for total, errors, expected in [(100, 4, 'OK'), (100, 5, 'REVISAR'), (100, 20, 'CRÍTICO'),
                                        (100000, 100, 'OK'), (10, 10, 'INDETERMINADO')]:
            with self.subTest(total=total, errors=errors):
                self.assertEqual(a.diagnose_domain(sample(total, errors))['health'], expected)

    def test_no_data_is_not_a_healthy_site(self):
        d = a.diagnose_domain(sample(0))
        self.assertEqual((d['health'], d['suspicious'], d['impact']),
                         ('INDETERMINADO', 'INDETERMINADO', 'NO DETERMINADO'))
        self.assertFalse(d['attention'])
        self.assertEqual(d['confidence'], 'INSUFICIENTE')

    def test_large_volume_and_bots_alone_do_not_prove_load_or_abuse(self):
        result = sample(100000, counts={'bot': 100000}, peak=10000)
        d = a.diagnose_domain(result)
        self.assertEqual((d['health'], d['suspicious'], d['impact']), ('OK', 'BAJO', 'NO DETERMINADO'))

    def test_suspicious_patterns_require_combined_evidence_for_high(self):
        result = sample(200, sensitive4=20, http4=100, counts={'bot': 150})
        self.assertEqual(a.diagnose_domain(result)['suspicious'], 'MODERADO')
        result['sensitive4'] = 100
        d = a.diagnose_domain(result)
        self.assertEqual(d['suspicious'], 'ALTO')
        self.assertIn('Cloudflare', ' '.join(d['actions']))
        self.assertIn('WooCommerce', ' '.join(d['actions']))

    def test_no_cpu_claim_from_php_looking_404(self):
        result = sample(http4=80, fourxx_hints={'static': 30, 'dynamic': 40, 'unknown': 10})
        d = a.diagnose_domain(result)
        self.assertEqual(d['impact'], 'NO DETERMINADO')
        self.assertIn('no demuestra', ' '.join(d['hypotheses']))

    def test_sustained_minutes_require_continuity_and_distinguish_dst(self):
        minutes = {'2026-10-18 12:00 +0200': 600, '2026-10-18 12:01 +0200': 700,
                   '2026-10-18 12:03 +0200': 900, '2026-10-19 12:04 +0200': 900}
        self.assertEqual(a.sustained_peak(minutes, 600), 2)
        self.assertEqual(a.sustained_peak({'2026-10-25 02:59 +0200': 600,
                                         '2026-10-25 02:00 +0100': 600}, 600), 2)

    def test_timing_only_explicit_suffix_not_ua_or_numeric_column(self):
        self.assertEqual(a.timing_seconds(line() + b' request_time=2.500\n'), 2.5)
        self.assertIsNone(a.timing_seconds(line(ua='curl request_time=999')))
        self.assertIsNone(a.timing_seconds(line() + b' 2500000\n'))
        for suffix in (b'request_time=nan', b'request_time=-2', b'request_time=2 cookie=secret'):
            self.assertIsNone(a.timing_seconds(line() + suffix + b'\n'))

    def test_impact_high_requires_duration_sustained_and_gateway_errors(self):
        minutes = {f'2026-10-18 12:0{m} +0200': 600 for m in range(3)}
        result = sample(1800, 180, minutes=minutes, statuses={503: 180},
                        timing_count=1800, slow_count=1000)
        self.assertEqual(a.diagnose_domain(result)['impact'], 'ALTO POTENCIAL')
        result['timing_count'] = 10
        self.assertEqual(a.diagnose_domain(result)['impact'], 'POSIBLE')
        result['statuses'] = {}
        self.assertEqual(a.diagnose_domain(result)['impact'], 'NO DETERMINADO')

    def test_low_impact_only_with_enough_observed_duration_not_cpu_claim(self):
        result = sample(timing_count=100, slow_count=0)
        self.assertEqual(a.diagnose_domain(result)['impact'], 'BAJO')
        result['timing_count'] = 79
        self.assertEqual(a.diagnose_domain(result)['impact'], 'NO DETERMINADO')

    def test_explicit_pool_limits_support_possible_impact(self):
        result = sample(internal={'Límite de procesos PHP-FPM': 2})
        self.assertEqual(a.diagnose_domain(result)['impact'], 'POSIBLE')
        self.assertEqual(a.error_event(b'2026/10/18 12:00:00 [warn] server reached pm.max_children setting (5)\n')[1],
                         'Límite de procesos PHP-FPM')

    def test_partial_coverage_lowers_confidence_without_extrapolation(self):
        d = a.diagnose_domain(sample(100, 20))
        self.assertEqual(d['health'], 'CRÍTICO')
        self.assertIn('LIMITADA', d['confidence'])
        self.assertIn('100 peticiones', ' '.join(d['facts']))
        self.assertNotIn('diarias', ' '.join(d['facts']))
        full = sample(100, 20, rapid=False, notes={'Límite de tiempo/bytes. Resultado PARCIAL.'})
        self.assertIn('LIMITADA', a.diagnose_domain(full)['confidence'])

    def test_shared_incidents_same_minute_different_domains_this_run_only(self):
        minute = '2026-10-18 12:00 +0200'
        result = sample(minutes={minute: 20}, error_minutes={minute: [0, 10, 8]})
        server_a, server_b = a.SharedIncidents(), a.SharedIncidents()
        server_a.add('one.com', result)
        server_b.add('two.com', result)
        self.assertEqual(server_a.findings(), [])
        self.assertEqual(server_b.findings(), [])
        server_a.add('two.com', result)
        self.assertIn('5xx coincidentes', str(server_a.findings()))
        self.assertIn('502/503/504', str(server_a.findings()))
        server_a.add('two.com', result)  # no contar un dominio dos veces
        self.assertEqual(len(server_a.windows[minute][0]), 2)

    def test_shared_different_days_or_offsets_do_not_match(self):
        shared = a.SharedIncidents()
        for domain, minute in [('one.com', '2026-10-18 12:00 +0200'), ('two.com', '2026-10-19 12:00 +0200'),
                               ('three.com', '2026-10-18 12:00 +0100')]:
            shared.add(domain, sample(minutes={minute: 20}, error_minutes={minute: [0, 10, 8]}))
        self.assertEqual(shared.findings(), [])

    def test_correlation_memory_is_bounded(self):
        shared = a.SharedIncidents()
        stamp = dt.datetime(2026, 10, 18, tzinfo=dt.timezone.utc)
        minutes = {(stamp + dt.timedelta(minutes=n)).strftime('%Y-%m-%d %H:%M %z'): 600 for n in range(2200)}
        for n in range(12):
            shared.add(f'd{n}.com', sample(minutes=minutes))
        self.assertEqual(len(shared.windows), 2048)
        self.assertLessEqual(max(len(group) for groups in shared.windows.values() for group in groups), 8)
        self.assertTrue(shared.partial)
        self.assertLessEqual(len(shared.findings()), 20)

    def test_configurable_thresholds_validate_bounds_and_inconsistency(self):
        with patch.object(a, 'ZoneInfo', return_value=dt.timezone.utc):
            args = a.arguments(['--threshold', 'health_review_pct=10', '--threshold', 'slow_seconds=1.5'])
        self.assertEqual(args.thresholds['slow_seconds'], 1.5)
        self.assertEqual(a.diagnose_domain(sample(100, 5), args.thresholds)['health'], 'OK')
        for value in ('missing=1', 'bot_pct=101', 'slow_seconds=nan', 'health_min=-1',
                      'shared_domains=9', 'health_review_count=0.5', 'health_review_pct=30'):
            with self.subTest(value=value), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                a.arguments(['--threshold', value])

    def test_sensitive_paths_and_encoded_queries_are_removed(self):
        for raw in ('/reset/short-secret', '/api_key=short-secret', '/user%3Fpassword=short-secret',
                    '/token/short-secret?cookie=abc'):
            self.assertNotIn('short-secret', a.safe_path(raw))

    def test_analysis_collects_codes_error_ips_minutes_and_duration_in_same_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / 'access_log'
            data = (line('/style.css?secret=hidden', status=404) +
                    line('/wp-login.php', status=403) + line('/api/items', status=429) +
                    line('/page', status=503) + line('/ok').rstrip(b'\n') + b' request_time=2.5\n')
            path.write_bytes(data)
            @contextlib.contextmanager
            def opening(parent, name):
                with path.open('rb') as stream:
                    yield stream
            args = type('Args', (), dict(domain='example.com', sample=True, seconds=5, max_mib=8,
                        gentle=False, gzip=False, historical=False, bans=None, thresholds=a.THRESHOLDS))()
            with patch.object(a, 'directory', return_value=999), patch.object(a, 'regular', opening), patch.object(a, 'names', return_value=['access_log']), patch.object(a.os, 'stat', return_value=path.stat()), patch.object(a.os, 'close'), patch.object(a, 'pressure', return_value=None), patch.object(a.time, 'sleep'):
                result = a.analyze(0, 'example.com', dt.date(2026, 10, 19), dt.timezone.utc, args)
            self.assertEqual(result['total'], 5)
            self.assertEqual(result['fourxx_hints'], {'static': 1, 'dynamic': 2})
            self.assertEqual(result['error_clients']['192.0.2.1'], 4)
            self.assertEqual(sum(v[1] for v in result['error_minutes'].values()), 1)
            self.assertEqual((result['timing_count'], result['slow_count']), (1, 1))
            summary = a.compact_summary(result)
            self.assertIn('diagnosis', summary)
            self.assertNotIn('minutes', summary)
            self.assertNotIn('error_clients', summary)
            self.assertEqual(path.read_bytes(), data)
            self.assertNotIn('hidden', str(result['errors']))

    def test_attention_order_health_before_volume_and_html_escaping(self):
        rows = [('busy.com', sample(100000)), ('broken.com', sample(100, 40)), ('scan.com', sample(sensitive4=30))]
        self.assertEqual(sorted(rows, key=a.diagnosis_key)[0][0], 'broken.com')
        result = rows[1][1]
        result['diagnosis'] = a.diagnose_domain(result)
        result['diagnosis']['actions'].append('<script>secret</script>')
        args = type('Args', (), {'thresholds': a.THRESHOLDS})()
        markup = a.html_section('broken.com', result, args)
        self.assertIn('Salud web', markup)
        self.assertIn('Hipótesis', markup)
        self.assertIn('&lt;script&gt;', markup)
        self.assertNotIn('<script>', markup)

    def test_optional_resources_never_opens_domain_logs(self):
        args = type('Args', (), dict(resources=True))()
        with patch.object(a, 'RunGuard'), patch.object(a, 'arguments', return_value=args), patch.object(a.os, 'O_NOFOLLOW', 0, create=True), patch.object(a, 'show_current_resources') as show, patch.object(a, 'directory') as logs:
            self.assertEqual(a.main([]), 0)
            show.assert_called_once()
            logs.assert_not_called()

    def test_resources_missing_permissions_degrade_without_shell_or_network(self):
        with patch.object(a, 'host_status', side_effect=OSError()), patch.object(a.os, 'open', side_effect=PermissionError()), patch.object(a.os, 'scandir', side_effect=PermissionError()), patch.object(a.os, 'O_NOFOLLOW', 0, create=True):
            result = a.current_resources()
        self.assertTrue(any('N/D' in text for text in result['notes']))
        self.assertLessEqual(result['read'], 256 * 1024)


if __name__ == '__main__':
    unittest.main()
