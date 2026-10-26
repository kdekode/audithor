"""Diagnóstico con registros y /proc simulados. Nunca ejecuta PHP ni consulta servicios."""
import ast
import collections
import contextlib
import datetime as dt
import io
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch, MagicMock

import audithor as a
import audithor_triage as t


def args(day=dt.date(2026, 10, 26)):
    return types.SimpleNamespace(day=day, start_day=day, zone=dt.timezone.utc, gentle=False)


def result():
    return dict(total=100, bytes=1000, read=1000, counts=collections.Counter(), notes=set(),
                earliest=None, latest=None, rapid=True, http4=0, http5=0)


def log(message, domain='escaparatedigital.com'):
    return ('[26-Oct-2026 12:00:00] WARNING: [pool ' + domain + '] ' + message + '\n').encode()


class TriageTests(unittest.TestCase):
    def fixture_api(self, root):
        def directory(name, parent=None):
            p = Path(parent or root) / name
            if p.is_symlink():
                raise OSError('link rejected')
            if not p.is_dir():
                raise FileNotFoundError()
            return p
        @contextlib.contextmanager
        def regular(folder, name):
            p = Path(folder) / name
            if p.is_symlink():
                raise OSError('link rejected')
            with p.open('rb') as stream:
                yield stream
        return types.SimpleNamespace(directory=directory, regular=regular, names=lambda p, n: [x.name for x in Path(p).iterdir()][:n], MONTHS=a.MONTHS)

    def snapshot(self):
        return dict(logs={}, processes={}, captured='2026-10-26T12:00:00+00:00', notes=[], partial=True)

    def test_real_case_two_issues_not_one_per_message_or_cpu_duplicate(self):
        snapshot = self.snapshot()
        for message in ['server reached max_children setting (10)'] * 5 + ['cron hook: sby_feed_update could_not_set'] * 20:
            t.add_log(snapshot['logs'], 'escaparatedigital.com', t.log_signal(message), '2026-10-26T12:00:00+00:00', 'plesk-php83-fpm/error.log')
        snapshot['processes']['escaparatedigital.com'] = dict(count=10, cpu=350, processes=[])
        report = t.diagnose('escaparatedigital.com', result(), snapshot, args())
        self.assertEqual((report['count'], report['priority']), (2, 'ALTA'))
        self.assertEqual({r['key'] for r in report['issues']}, {'pool_limit', 'cron'})
        self.assertIn('350.0%', report['issues'][1 if report['issues'][0]['key']=='cron' else 0]['current_evidence'])
        self.assertIn('no demuestra', report['issues'][0]['hypothesis'])

    def test_log_signals_never_store_credentials_sql_or_arbitrary_hook(self):
        for message in ['cron hook: customer_secret_123 could_not_set', 'Undefined array key "password=secret"',
                        'SQLSTATE password=secret SELECT * FROM credentials', 'PHP Fatal error: token=secret']:
            value = str(t.log_signal(message))
            self.assertNotIn('password=', value)
            self.assertNotIn('SELECT', value)
            self.assertNotIn('customer_secret', value)

    def test_location_basename_only_bounded_and_sensitive_names_hidden(self):
        item = {}
        for n in range(10):
            t.add_location(item, f'in /private/customer/file{n}.php on line {n}')
        self.assertEqual(item['locations'], ['file0.php:0', 'file1.php:1', 'file2.php:2'])
        other = {}
        t.add_location(other, 'in /private/password.php on line 4')
        self.assertEqual(other['locations'], [':oculto.php:4'])

    def test_global_fpm_filters_exact_pool_and_period(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); folder = root / 'plesk-php83-fpm'; folder.mkdir()
            (folder/'error.log').write_bytes(log('server reached max_children setting (10)') +
                log('cron hook: sby_feed_update could_not_set') * 3 + log('PHP Fatal error: password=secret', 'other.com') +
                log('PHP Fatal error').replace(b'26-Oct', b'20-Oct'))
            api = self.fixture_api(root)
            with patch.object(t.os, 'close'):
                data = t.read_fpm(args(), api, t.Reader(api), {'escaparatedigital.com'}, str(root))
            self.assertEqual(set(data['domains']), {'escaparatedigital.com'})
            self.assertEqual(set(data['domains']['escaparatedigital.com']), {'pool_limit', 'cron'})
            self.assertNotIn('password', str(data))
            self.assertEqual(data['domains']['escaparatedigital.com']['cron']['count'], 3)

    def test_reader_tail_has_fixed_bytes_and_drops_cut_first_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); (root/'log').write_bytes(b'old secret\n' * 200 + b'new\n')
            api = self.fixture_api(root); reader = t.Reader(api, maximum=16)
            data = reader.get(root, 'log', 128, tail=True)
            self.assertLessEqual(reader.read, 16)
            self.assertTrue(data.endswith(b'new\n'))
            self.assertTrue(reader.partial)
            with self.assertRaises(ValueError):
                reader.get(root, 'log', 1)

    def test_no_follow_global_fpm_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); (root/'plesk-php83-fpm').mkdir()
            api = self.fixture_api(root)
            with patch.object(api, 'directory', side_effect=[root, OSError('symlink')]), patch.object(t.os, 'close'):
                data = t.read_fpm(args(), api, t.Reader(api), {'example.com'}, str(root))
            self.assertEqual(data['domains'], {})
            self.assertTrue(data['partial'])

    def test_both_domain_error_layers_and_old_dates_are_excluded(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); folder = root/'example.com'/'logs'; folder.mkdir(parents=True)
            (folder/'error_log').write_bytes(b'[Mon Oct 26 12:00:00.000001 2026] [proxy_fcgi:error] PHP Fatal error: secret\n')
            (folder/'proxy_error_log').write_bytes(b'2026/10/26 12:00:00 [error] upstream timed out\n2026/10/22 12:00:00 [error] permission denied\n')
            api = self.fixture_api(root)
            with patch.object(t.os, 'close'):
                data = t.domain_errors(root, 'example.com', args(), api)
            self.assertEqual(set(data['domains']['example.com']), {'php_fatal', 'backend'})
            self.assertEqual(set(data['sources']), {'error_log', 'proxy_error_log'})

    def test_timestamps_use_host_local_timezone_then_convert(self):
        # Calcular desde fecha local ingenua: no asumir que el host tiene la zona de Audithor.
        zone = dt.timezone(dt.timedelta(hours=-5))
        expected = dt.datetime(2026, 10, 26, 12).astimezone(zone)
        self.assertEqual(t.local_stamp('[26-Oct-2026 12:00:00]', a, zone), expected)
        self.assertEqual(t.domain_stamp('2026/10/26 12:00:00 [error]', a, zone), expected)
        self.assertIsNone(t.local_stamp('[99-Foo-2026 88:88:88]', a, zone))

    def test_process_cpu_is_interval_and_pid_reuse_is_rejected(self):
        def row(pid, start, ticks, now, domain='example.com'):
            return dict(pid=pid, start=start, ticks=ticks, sampled=now, rss=256, domain=domain)
        before = {1: row(1, 10, 20, 0), 2: row(2, 20, 0, 0), 3: row(3, 10, 0, 0)}
        after = {1: row(1, 10, 120, 1), 2: row(2, 99, 100, 1), 3: row(3, 10, 100, 1, 'other.com')}
        pools = t.process_delta(before, after, 100, 4096)
        self.assertEqual(set(pools), {'example.com'})
        self.assertEqual(pools['example.com']['cpu'], 100)
        self.assertEqual(pools['example.com']['processes'][0]['rss_mib'], 1)

    def test_process_row_cap_keeps_total_without_unbounded_rows(self):
        first = {n: dict(pid=n, start=1, ticks=0, sampled=0, rss=10, domain='example.com') for n in range(100)}
        last = {n: dict(row, ticks=100, sampled=1) for n, row in first.items()}
        value = t.process_delta(first, last, 100, 4096)['example.com']
        self.assertEqual(value['count'], 100)
        self.assertEqual(len(value['processes']), 10)

    def test_proc_parser_handles_spaces_in_comm(self):
        fields = ['S'] + ['0']*21
        fields[11], fields[12], fields[19], fields[21] = '10','20','1234','50'
        self.assertEqual(t.parse_proc(('123 (php worker) ' + ' '.join(fields)).encode()), dict(ticks=30, start=1234, rss=50))

    def test_process_sample_exact_pool_no_argv_retained(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); folder=root/'12'; folder.mkdir()
            (folder/'comm').write_bytes(b'php-fpm\n')
            (folder/'cmdline').write_bytes(b'php-fpm: pool example.com\x00')
            fields=['S']+['0']*21; fields[19]='123'
            (folder/'stat').write_bytes(('12 (php-fpm) '+' '.join(fields)).encode())
            api=self.fixture_api(root)
            with patch.object(t.os,'close'), patch.object(t.os,'readlink',return_value='/opt/plesk/php/8.3/sbin/php-fpm'):
                data=t.process_sample(api,t.Reader(api),{'example.com'},str(root))
            self.assertEqual(data[12]['domain'],'example.com')
            self.assertNotIn('cmdline',str(data))

    def test_historical_capture_does_not_read_current_processes(self):
        api=types.SimpleNamespace(host_status=lambda:(8,(1,1,1),1000))
        with patch.object(t,'read_fpm',return_value=dict(domains={},sources=[],notes=[],partial=True,read=0)), patch.object(t,'process_sample') as sample:
            data=t.capture(args(dt.date(2000,1,1)),api,['example.com'])
        sample.assert_not_called()
        self.assertEqual(data['processes'],{})

    def test_high_pressure_suspends_all_additional_reads(self):
        for status in [(8,(20,20,20),1000),(8,(1,1,1),100)]:
            api=types.SimpleNamespace(host_status=lambda:status)
            with patch.object(t,'read_fpm') as reader, patch.object(t,'process_sample') as proc:
                data=t.capture(args(),api,['example.com'])
            reader.assert_not_called(); proc.assert_not_called()
            self.assertTrue(data['partial'])

    def test_capture_samples_only_once_for_all_domains(self):
        api=types.SimpleNamespace(host_status=lambda:(8,(1,1,1),1000))
        today=dt.datetime.now(dt.timezone.utc).date()
        one={1:dict(pid=1,start=1,ticks=10,sampled=1,rss=2,domain='example.com')}
        two={1:dict(one[1],ticks=110,sampled=2)}
        with patch.object(t,'read_fpm',return_value=dict(domains={},sources=['x'],notes=[],partial=False,read=0)), patch.object(t,'process_sample',side_effect=[one,two]) as sample, patch.object(t.time,'sleep') as sleep, patch.object(t.os,'sysconf',return_value=100,create=True):
            data=t.capture(args(today),api,['example.com','other.com'])
        self.assertEqual(sample.call_count,2)
        sleep.assert_called_once_with(.5)
        self.assertEqual(set(data['processes']),{'example.com'})

    def test_no_data_is_not_a_healthy_domain(self):
        r=result(); r['read']=0
        data=t.diagnose('example.com',r,self.snapshot(),args())
        self.assertEqual(data['priority'],'SIN DATOS')
        self.assertEqual(data['count'],0)

    def test_high_cpu_alone_is_not_labelled_attack(self):
        snapshot=self.snapshot(); snapshot['processes']['example.com']=dict(cpu=180,count=3,processes=[])
        data=t.diagnose('example.com',result(),snapshot,args())
        self.assertEqual((data['count'],data['priority']),(1,'ALTA'))
        self.assertIn('ni demuestra ataque',data['issues'][0]['hypothesis'])

    def test_all_existing_http_attention_is_preserved(self):
        r=result(); r['diagnosis']=dict(health='CRÍTICO',suspicious='ALTO',impact='POSIBLE')
        r['sensitive_details']={'/.env':dict(codes={200:1})}
        data=t.diagnose('example.com',r,self.snapshot(),args(),a)
        self.assertEqual({row['key'] for row in data['issues']},{'http5','automation','backend_cost','exposure'})

    def test_console_and_html_explain_two_issues_and_current_processes(self):
        snapshot=self.snapshot(); snapshot['processes']['example.com']=dict(cpu=100,count=1,processes=[dict(pid=1,cpu=100,rss_mib=10)])
        t.add_log(snapshot['logs'],'example.com',t.log_signal('cron hook: sby_feed_update could_not_set'),'2026-10-26T12:00:00+00:00','fpm/error.log')
        data=t.diagnose('example.com',result(),snapshot,args())
        out=io.StringIO()
        with contextlib.redirect_stdout(out): t.show(data,a)
        self.assertIn('Avisos: 2',out.getvalue()); self.assertIn('PROCESOS ACTUALES',out.getvalue())
        data['issues'][0]['evidence']='<script>alert(1)</script>'
        rendered=t.render_html(data,a)
        self.assertNotIn('<script>',rendered); self.assertIn('&lt;script&gt;',rendered)

    def test_global_columns_and_final_attention_include_only_log_issue_without_accesses(self):
        r=result(); r['read']=0; r['total']=0
        snapshot=self.snapshot()
        t.add_log(snapshot['logs'],'example.com',t.log_signal('server reached max_children setting (10)'), '2026-10-26T12:00:00+00:00','fpm/error.log')
        r['triage']=t.diagnose('example.com',r,snapshot,args())
        self.assertTrue(a.requires_attention(r))
        out=io.StringIO()
        with contextlib.redirect_stdout(out): a.show_overview_header(); a.show_overview_row('example.com',r)
        self.assertIn('AVISOS',out.getvalue()); self.assertIn('ALTA',out.getvalue())
        self.assertEqual(a.compact_summary(r)['triage']['count'],1)

    def test_python39_syntax(self):
        ast.parse(Path(t.__file__).read_text(encoding='utf-8'),feature_version=(3,9))

    def test_grouping_limits_are_fixed_even_for_many_domains(self):
        rows={}
        for n in range(600):
            t.add_log(rows,f'example{n}.com',t.log_signal('PHP Fatal error'), '2026-10-26T12:00:00+00:00','fpm/error.log')
        self.assertEqual(len(rows),512)
        for n in range(30):
            t.add_log(rows,'example0.com',(str(n),'event','MEDIA','safe'), '2026-10-26T12:00:00+00:00','fpm/error.log')
        self.assertEqual(len(rows['example0.com']),16)

    def test_attach_merges_sources_without_mutating_shared_snapshot(self):
        snapshot=self.snapshot()
        t.add_log(snapshot['logs'],'example.com',t.log_signal('cron hook: sby_feed_update could_not_set'),'2026-10-26T12:00:00+00:00','fpm/error.log')
        local={}
        t.add_log(local,'example.com',t.log_signal('cron hook: sby_feed_update could_not_set'),'2026-10-26T12:01:00+00:00','error_log')
        opts=args(); opts.root='/unused'; opts.triage_snapshot=snapshot
        r=result()
        with patch.object(a,'triage_module',return_value=t), patch.object(a,'pressure',return_value=None), patch.object(a,'directory',return_value=999), patch.object(a.os,'close'), patch.object(t,'domain_errors',return_value=dict(domains=local,partial=True,read=10,sources=['error_log'])):
            a.attach_triage('example.com',r,opts)
        self.assertEqual(r['triage']['issues'][0]['count'],2)
        self.assertEqual(snapshot['logs']['example.com']['cron']['count'],1)
        self.assertEqual(snapshot['logs']['example.com']['cron']['sources'],['fpm/error.log'])

    def test_current_pressure_skips_local_errors_but_preserves_pool_warning(self):
        snapshot=self.snapshot()
        t.add_log(snapshot['logs'],'example.com',t.log_signal('server reached max_children setting (10)'), '2026-10-26T12:00:00+00:00','fpm/error.log')
        opts=args(); opts.triage_snapshot=snapshot
        r=result()
        with patch.object(a,'triage_module',return_value=t), patch.object(a,'pressure',return_value='high'), patch.object(t,'domain_errors') as reader:
            a.attach_triage('example.com',r,opts)
        reader.assert_not_called()
        self.assertEqual(r['triage']['priority'],'ALTA')
        self.assertTrue(r['triage']['partial'])

    def test_critical_http_appears_in_final_table_even_without_new_logs(self):
        r=result(); r['http5']=30; r['diagnosis']=a.diagnose_domain(r)
        r['triage']=t.diagnose('example.com',r,self.snapshot(),args())
        out=io.StringIO()
        with contextlib.redirect_stdout(out): a.show_attention([('example.com',r)])
        self.assertIn('Respuestas HTTP',out.getvalue())
        self.assertIn('ALTA',out.getvalue())

    def test_missing_processes_in_second_sample_are_not_zero_cpu(self):
        api=types.SimpleNamespace(host_status=lambda:(8,(1,1,1),1000))
        today=dt.datetime.now(dt.timezone.utc).date()
        first={1:dict(pid=1,start=1,ticks=10,sampled=1,rss=2,domain='example.com')}
        with patch.object(t,'read_fpm',return_value=dict(domains={},sources=[],notes=[],partial=True,read=0)), patch.object(t,'process_sample',side_effect=[first,{}]), patch.object(t.time,'sleep'), patch.object(t.os,'sysconf',return_value=100,create=True):
            data=t.capture(args(today),api,['example.com'])
        self.assertNotIn('example.com',data['processes'])

    def test_reader_deadline_stops_before_opening_more_files(self):
        api=types.SimpleNamespace(regular=MagicMock())
        reader=t.Reader(api); reader.end=0
        with self.assertRaises(ValueError): reader.get(1,'log',100)
        api.regular.assert_not_called()

    def test_alternative_log_root_does_not_mix_current_host(self):
        opts=args(); opts.root='/some/archive'
        with patch.object(t,'read_fpm') as logs, patch.object(t,'process_sample') as processes:
            data=t.capture(opts,types.SimpleNamespace(),['example.com'])
        logs.assert_not_called(); processes.assert_not_called()
        self.assertTrue(data['partial'])
        self.assertIn('Raíz alternativa',' '.join(data['notes']))

    def test_global_and_domain_commands_render_new_diagnosis_without_server_access(self):
        import audithor_watch as watch
        snapshot=self.snapshot()
        for text in ['server reached max_children setting (10)'] + ['cron hook: sby_feed_update could_not_set']*3:
            t.add_log(snapshot['logs'],'example.com',t.log_signal(text),'2026-10-26T12:00:00+00:00','fpm/error.log')
        for domain in [[],['example.com']]:
            with patch.object(a,'ZoneInfo',return_value=dt.timezone.utc):
                opts=a.arguments(domain+['--no-fail2ban','--timezone','UTC'])
            r=result(); r['internal']=collections.Counter(); r['diagnosis']=a.diagnose_domain(r)
            output=io.StringIO()
            with contextlib.ExitStack() as stack:
                for target,name,value in [(a,'triage_module',t),(a,'watch_module',watch),(a,'pressure',None),
                    (a,'directory',999),(a,'discover',['example.com']),(a,'analyze',r),
                    (a,'saved_history',dict(events=[],sessions=[],gaps=[],message='Sin vigilancia')),
                    (t,'capture',snapshot),(t,'domain_errors',dict(domains={},partial=True,sources=[],read=0))]:
                    stack.enter_context(patch.object(target,name,return_value=value))
                stack.enter_context(patch.object(a.os,'uname',return_value=types.SimpleNamespace(nodename='fixture'),create=True))
                stack.enter_context(patch.object(a.os,'close'))
                stack.enter_context(contextlib.redirect_stdout(output))
                self.assertEqual(a.run_analysis(opts),0)
            self.assertIn('ALTA',output.getvalue())
            if domain:
                self.assertIn('Avisos: 2',output.getvalue())
                self.assertIn('Qué revisar:',output.getvalue())
            else:
                self.assertIn('2*',output.getvalue())
                self.assertIn('AVISOS',output.getvalue())
                self.assertEqual(output.getvalue().count('IP ÚNICAS'),1)
                self.assertNotIn('TABLA FINAL',output.getvalue())
                self.assertNotIn('    Detalle:',output.getvalue())
                self.assertNotIn('Sin coincidencias compartidas',output.getvalue())

    def test_no_findings_prints_no_empty_attention_sections(self):
        r=result(); r['diagnosis']=a.diagnose_domain(r)
        r['triage']=t.diagnose('example.com',r,self.snapshot(),args())
        output=io.StringIO()
        with contextlib.redirect_stdout(output):
            a.show_attention([('example.com',r)],a.SharedIncidents())
        self.assertEqual(output.getvalue(),'')


if __name__=='__main__':
    unittest.main()
